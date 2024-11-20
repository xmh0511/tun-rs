use crate::platform::linux::checksum::{checksum, pseudo_header_checksum_no_fold};
use byteorder::{BigEndian, ByteOrder};
use bytes::BytesMut;
use libc::IPPROTO_TCP;
use nix::NixPath;
use std::collections::HashMap;
use std::io;

const TCP_FLAGS_OFFSET: usize = 13;

const TCP_FLAG_FIN: u8 = 0x01;
const TCP_FLAG_PSH: u8 = 0x08;
const TCP_FLAG_ACK: u8 = 0x10;
pub const VIRTIO_NET_HDR_GSO_NONE: u8 = 0;
pub const VIRTIO_NET_HDR_F_NEEDS_CSUM: u8 = 1;
pub const VIRTIO_NET_HDR_GSO_TCPV4: u8 = 1;
pub const VIRTIO_NET_HDR_GSO_TCPV6: u8 = 4;
pub const VIRTIO_NET_HDR_GSO_UDP_L4: u8 = 5;
const IPV4_SRC_ADDR_OFFSET: usize = 12;
const IPV6_SRC_ADDR_OFFSET: usize = 8;
const MAX_UINT16: usize = 1 << 16 - 1;
const UDP_HEADER_LEN: usize = 8;
const IDEAL_BATCH_SIZE: usize = 128;
const IPV4_FLAG_MORE_FRAGMENTS: u8 = 0x20;
const UDP_H_LEN: usize = 8;

/// https://github.com/WireGuard/wireguard-go/blob/master/tun/offload_linux.go
///
///  virtioNetHdr is defined in the kernel in include/uapi/linux/virtio_net.h. The
/// kernel symbol is virtio_net_hdr.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct VirtioNetHdr {
    pub flags: u8,
    pub gso_type: u8,
    pub hdr_len: u16,
    pub gso_size: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
}

pub fn decode(buf: &[u8]) -> io::Result<VirtioNetHdr> {
    if buf.len() < VIRTIO_NET_HDR_LEN {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "too short"));
    }
    let hdr: &VirtioNetHdr = unsafe { &*(buf.as_ptr() as *const VirtioNetHdr) };
    Ok(*hdr)
}

pub fn encode(hdr: &VirtioNetHdr, buf: &mut [u8]) -> io::Result<()> {
    if buf.len() < VIRTIO_NET_HDR_LEN {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "too short"));
    }
    unsafe {
        let hdr_ptr = hdr as *const VirtioNetHdr as *const u8;
        std::ptr::copy_nonoverlapping(hdr_ptr, buf.as_mut_ptr(), VIRTIO_NET_HDR_LEN);
        Ok(())
    }
}

// virtioNetHdrLen is the length in bytes of virtioNetHdr. This matches the
// shape of the C ABI for its kernel counterpart -- sizeof(virtio_net_hdr).
pub const VIRTIO_NET_HDR_LEN: usize = std::mem::size_of::<VirtioNetHdr>();

/// tcpFlowKey represents the key for a TCP flow.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
struct TcpFlowKey {
    src_addr: [u8; 16],
    dst_addr: [u8; 16],
    src_port: u16,
    dst_port: u16,
    rx_ack: u32, // varying ack values should not be coalesced. Treat them as separate flows.
    is_v6: bool,
}

/// tcpGROTable holds flow and coalescing information for the purposes of TCP GRO.
struct TcpGROTable {
    items_by_flow: HashMap<TcpFlowKey, Vec<TcpGROItem>>,
    items_pool: Vec<Vec<TcpGROItem>>,
}

impl TcpGROTable {
    fn new() -> Self {
        let mut items_pool = Vec::with_capacity(IDEAL_BATCH_SIZE);
        for _ in 0..IDEAL_BATCH_SIZE {
            items_pool.push(Vec::with_capacity(IDEAL_BATCH_SIZE));
        }
        TcpGROTable {
            items_by_flow: HashMap::with_capacity(IDEAL_BATCH_SIZE),
            items_pool,
        }
    }
}

impl TcpFlowKey {
    fn new(pkt: &[u8], src_addr_offset: usize, dst_addr_offset: usize, tcph_offset: usize) -> Self {
        let mut key = TcpFlowKey {
            src_addr: [0; 16],
            dst_addr: [0; 16],
            src_port: 0,
            dst_port: 0,
            rx_ack: 0,
            is_v6: false,
        };

        let addr_size = dst_addr_offset - src_addr_offset;
        key.src_addr
            .copy_from_slice(&pkt[src_addr_offset..dst_addr_offset]);
        key.dst_addr
            .copy_from_slice(&pkt[dst_addr_offset..dst_addr_offset + addr_size]);
        key.src_port = BigEndian::read_u16(&pkt[tcph_offset..]);
        key.dst_port = BigEndian::read_u16(&pkt[tcph_offset + 2..]);
        key.rx_ack = BigEndian::read_u32(&pkt[tcph_offset + 8..]);
        key.is_v6 = addr_size == 16;
        key
    }
}

impl TcpGROTable {
    /// lookupOrInsert looks up a flow for the provided packet and metadata,
    /// returning the packets found for the flow, or inserting a new one if none
    /// is found.
    fn lookup_or_insert(
        &mut self,
        pkt: &[u8],
        src_addr_offset: usize,
        dst_addr_offset: usize,
        tcph_offset: usize,
        tcph_len: usize,
        bufs_index: usize,
    ) -> Option<&mut Vec<TcpGROItem>> {
        let key = TcpFlowKey::new(pkt, src_addr_offset, dst_addr_offset, tcph_offset);
        if self.items_by_flow.contains_key(&key) {
            return self.items_by_flow.get_mut(&key);
        }
        // Insert the new item into the table
        self.insert(
            pkt,
            src_addr_offset,
            dst_addr_offset,
            tcph_offset,
            tcph_len,
            bufs_index,
        );
        None
    }
    /// insert an item in the table for the provided packet and packet metadata.
    fn insert(
        &mut self,
        pkt: &[u8],
        src_addr_offset: usize,
        dst_addr_offset: usize,
        tcph_offset: usize,
        tcph_len: usize,
        bufs_index: usize,
    ) {
        let key = TcpFlowKey::new(pkt, src_addr_offset, dst_addr_offset, tcph_offset);
        let item = TcpGROItem {
            key,
            bufs_index: bufs_index as u16,
            num_merged: 0,
            gso_size: pkt[tcph_offset + tcph_len..].len() as u16,
            iph_len: tcph_offset as u8,
            tcph_len: tcph_len as u8,
            sent_seq: BigEndian::read_u32(&pkt[tcph_offset + 4..tcph_offset + 8]),
            psh_set: pkt[tcph_offset + TCP_FLAGS_OFFSET] & TCP_FLAG_PSH != 0,
        };

        let items = self
            .items_by_flow
            .entry(key)
            .or_insert_with(|| self.items_pool.pop().unwrap_or_else(Vec::new));
        items.push(item);
    }
    fn update_at(&mut self, item: TcpGROItem, i: usize) {
        if let Some(items) = self.items_by_flow.get_mut(&item.key) {
            items[i] = item;
        }
    }
    fn delete_at(&mut self, key: TcpFlowKey, i: usize) {
        if let Some(mut items) = self.items_by_flow.remove(&key) {
            items.remove(i);
            self.items_by_flow.insert(key, items);
        }
    }
}

/// tcpGROItem represents bookkeeping data for a TCP packet during the lifetime
/// of a GRO evaluation across a vector of packets.
#[derive(Debug, Clone, Copy)]
struct TcpGROItem {
    key: TcpFlowKey,
    sent_seq: u32,   // the sequence number
    bufs_index: u16, // the index into the original bufs slice
    num_merged: u16, // the number of packets merged into this item
    gso_size: u16,   // payload size
    iph_len: u8,     // ip header len
    tcph_len: u8,    // tcp header len
    psh_set: bool,   // psh flag is set
}

impl TcpGROTable {
    fn new_items(&mut self) -> Vec<TcpGROItem> {
        let items = self.items_pool.pop().unwrap_or_else(Vec::new);
        items
    }
    fn reset(&mut self) {
        for (_key, mut items) in self.items_by_flow.drain() {
            items.clear();
            self.items_pool.push(items);
        }
    }
}

/// udpFlowKey represents the key for a UDP flow.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
struct UdpFlowKey {
    src_addr: [u8; 16], // srcAddr
    dst_addr: [u8; 16], // dstAddr
    src_port: u16,      // srcPort
    dst_port: u16,      // dstPort
    is_v6: bool,        // isV6
}

/// udpGROItem represents bookkeeping data for a UDP packet during the lifetime
/// of a GRO evaluation across a vector of packets.
#[derive(Debug, Clone, Copy)]
struct UdpGROItem {
    key: UdpFlowKey,           // udpFlowKey
    bufs_index: u16,           // the index into the original bufs slice
    num_merged: u16,           // the number of packets merged into this item
    gso_size: u16,             // payload size
    iph_len: u8,               // ip header len
    c_sum_known_invalid: bool, // UDP header checksum validity; a false value DOES NOT imply valid, just unknown.
}
pub struct UdpGROTable {
    items_by_flow: HashMap<UdpFlowKey, Vec<UdpGROItem>>,
    items_pool: Vec<Vec<UdpGROItem>>,
}

impl UdpGROTable {
    pub fn new() -> Self {
        let mut items_pool = Vec::with_capacity(IDEAL_BATCH_SIZE);
        for _ in 0..IDEAL_BATCH_SIZE {
            items_pool.push(Vec::with_capacity(IDEAL_BATCH_SIZE));
        }
        UdpGROTable {
            items_by_flow: HashMap::with_capacity(IDEAL_BATCH_SIZE),
            items_pool,
        }
    }
    /// Looks up a flow for the provided packet and metadata.
    /// Returns a reference to the packets found for the flow and a boolean indicating if the flow already existed.
    /// If the flow is not found, inserts a new flow and returns `None` for the items.
    fn lookup_or_insert(
        &mut self,
        pkt: &[u8],
        src_addr_offset: usize,
        dst_addr_offset: usize,
        udph_offset: usize,
        bufs_index: usize,
    ) -> Option<&mut Vec<UdpGROItem>> {
        let key = UdpFlowKey::new(pkt, src_addr_offset, dst_addr_offset, udph_offset);
        if self.items_by_flow.contains_key(&key) {
            self.items_by_flow.get_mut(&key)
        } else {
            // If the flow does not exist, insert a new entry.
            self.insert(
                pkt,
                src_addr_offset,
                dst_addr_offset,
                udph_offset,
                bufs_index,
                false,
            );
            None
        }
    }
    /// Inserts an item in the table for the provided packet and its metadata.
    fn insert(
        &mut self,
        pkt: &[u8],
        src_addr_offset: usize,
        dst_addr_offset: usize,
        udph_offset: usize,
        bufs_index: usize,
        c_sum_known_invalid: bool,
    ) {
        let key = UdpFlowKey::new(pkt, src_addr_offset, dst_addr_offset, udph_offset);
        let item = UdpGROItem {
            key: key.clone(),
            bufs_index: bufs_index as u16,
            num_merged: 0,
            gso_size: (pkt.len() - (udph_offset + UDP_H_LEN)) as u16,
            iph_len: udph_offset as u8,
            c_sum_known_invalid,
        };
        let items = self
            .items_by_flow
            .entry(key)
            .or_insert_with(|| self.items_pool.pop().unwrap_or_else(Vec::new));
        items.push(item);
    }
    fn update_at(&mut self, item: UdpGROItem, i: usize) {
        if let Some(items) = self.items_by_flow.get_mut(&item.key) {
            items[i] = item;
        }
    }
}

impl UdpFlowKey {
    pub fn new(
        pkt: &[u8],
        src_addr_offset: usize,
        dst_addr_offset: usize,
        udph_offset: usize,
    ) -> UdpFlowKey {
        let mut key = UdpFlowKey {
            src_addr: [0; 16],
            dst_addr: [0; 16],
            src_port: 0,
            dst_port: 0,
            is_v6: false,
        };
        let addr_size = dst_addr_offset - src_addr_offset;
        key.src_addr
            .copy_from_slice(&pkt[src_addr_offset..dst_addr_offset]);
        key.dst_addr
            .copy_from_slice(&pkt[dst_addr_offset..dst_addr_offset + addr_size]);
        key.src_port = BigEndian::read_u16(&pkt[udph_offset..]);
        key.dst_port = BigEndian::read_u16(&pkt[udph_offset + 2..]);
        key.is_v6 = addr_size == 16;
        key
    }
}
#[derive(PartialEq, Eq)]
pub enum GroCandidateType {
    NotGROCandidate,
    Tcp4GROCandidate,
    Tcp6GROCandidate,
    Udp4GROCandidate,
    Udp6GROCandidate,
}

pub fn packet_is_gro_candidate(b: &[u8], can_udp_gro: bool) -> GroCandidateType {
    if b.len() < 28 {
        return GroCandidateType::NotGROCandidate;
    }
    if b[0] >> 4 == 4 {
        if b[0] & 0x0F != 5 {
            // IPv4 packets w/IP options do not coalesce
            return GroCandidateType::NotGROCandidate;
        }
        match b[9] {
            6 if b.len() >= 40 => return GroCandidateType::Tcp4GROCandidate,
            17 if can_udp_gro => return GroCandidateType::Udp4GROCandidate,
            _ => {}
        }
    } else if b[0] >> 4 == 6 {
        match b[6] {
            6 if b.len() >= 60 => return GroCandidateType::Tcp6GROCandidate,
            17 if b.len() >= 48 && can_udp_gro => return GroCandidateType::Udp6GROCandidate,
            _ => {}
        }
    }
    GroCandidateType::NotGROCandidate
}
#[derive(PartialEq, Eq)]
enum GroResult {
    Noop,
    TableInsert,
    Coalesced,
}
fn udp_gro(
    bufs: &mut [BytesMut],
    offset: usize,
    pkt_i: usize,
    table: &mut UdpGROTable,
    is_v6: bool,
) -> GroResult {
    let pkt = unsafe { &*(&bufs[pkt_i][offset..] as *const [u8]) };
    if pkt.len() > u16::MAX as usize {
        // A valid IPv4 or IPv6 packet will never exceed this.
        return GroResult::Noop;
    }

    let mut iph_len = ((pkt[0] & 0x0F) * 4) as usize;
    if is_v6 {
        iph_len = 40;
        let ipv6_payload_len = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
        if ipv6_payload_len != pkt.len() - iph_len {
            return GroResult::Noop;
        }
    } else {
        let total_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
        if total_len != pkt.len() {
            return GroResult::Noop;
        }
    }

    if pkt.len() < iph_len || pkt.len() < iph_len + UDP_H_LEN {
        return GroResult::Noop;
    }

    if !is_v6 {
        if pkt[6] & IPV4_FLAG_MORE_FRAGMENTS != 0 || pkt[6] << 3 != 0 || pkt[7] != 0 {
            // No GRO support for fragmented segments for now.
            return GroResult::Noop;
        }
    }

    let gso_size = (pkt.len() - UDP_H_LEN - iph_len) as u16;
    if gso_size < 1 {
        return GroResult::Noop;
    }

    let (src_addr_offset, addr_len) = if is_v6 {
        (IPV6_SRC_ADDR_OFFSET, 16)
    } else {
        (IPV4_SRC_ADDR_OFFSET, 4)
    };

    let items = table.lookup_or_insert(
        pkt,
        src_addr_offset,
        src_addr_offset + addr_len,
        iph_len,
        pkt_i,
    );

    let items = if let Some(items) = items {
        items
    } else {
        return GroResult::TableInsert;
    };

    // Only check the last item to prevent reordering packets for a flow.
    let items_len = items.len();
    let item = &mut items[items_len - 1];
    let can = udp_packets_can_coalesce(pkt, iph_len as u8, gso_size, item, bufs, offset);
    let mut pkt_csum_known_invalid = false;

    if can == CanCoalesce::CoalesceAppend {
        match coalesce_udp_packets(pkt, item, bufs, offset, is_v6) {
            CoalesceResult::Success => {
                // 前面是引用，这里不需要再更新
                // table.update_at(*item, items_len - 1);
                return GroResult::Coalesced;
            }
            CoalesceResult::ItemInvalidCSum => {
                // If the existing item has an invalid checksum, take no action.
                // A new item will be stored, and the existing item won't be revisited.
            }
            CoalesceResult::PktInvalidCSum => {
                // Insert a new item but mark it with invalid checksum to avoid repeat checks.
                pkt_csum_known_invalid = true;
            }
            _ => {}
        }
    }
    let pkt = &bufs[pkt_i][offset..];
    // Failed to coalesce; store the packet in the flow.
    table.insert(
        pkt,
        src_addr_offset,
        src_addr_offset + addr_len,
        iph_len,
        pkt_i,
        pkt_csum_known_invalid,
    );
    GroResult::TableInsert
}

fn tcp_gro(
    bufs: &mut [BytesMut],
    offset: usize,
    pkt_i: usize,
    table: &mut TcpGROTable,
    is_v6: bool,
) -> GroResult {
    let pkt = unsafe { &*(&bufs[pkt_i][offset..] as *const [u8]) };
    if pkt.len() > u16::MAX as usize {
        // A valid IPv4 or IPv6 packet will never exceed this.
        return GroResult::Noop;
    }

    let mut iph_len = ((pkt[0] & 0x0F) * 4) as usize;
    if is_v6 {
        iph_len = 40;
        let ipv6_h_payload_len = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
        if ipv6_h_payload_len != pkt.len() - iph_len {
            return GroResult::Noop;
        }
    } else {
        let total_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
        if total_len != pkt.len() {
            return GroResult::Noop;
        }
    }

    if pkt.len() < iph_len {
        return GroResult::Noop;
    }

    let tcph_len = ((pkt[iph_len + 12] >> 4) * 4) as usize;
    if tcph_len < 20 || tcph_len > 60 {
        return GroResult::Noop;
    }

    if pkt.len() < iph_len + tcph_len {
        return GroResult::Noop;
    }

    if !is_v6 {
        if pkt[6] & IPV4_FLAG_MORE_FRAGMENTS != 0 || pkt[6] << 3 != 0 || pkt[7] != 0 {
            // no GRO support for fragmented segments for now
            return GroResult::Noop;
        }
    }

    let tcp_flags = pkt[iph_len + TCP_FLAGS_OFFSET];
    let mut psh_set = false;

    // not a candidate if any non-ACK flags (except PSH+ACK) are set
    if tcp_flags != TCP_FLAG_ACK {
        if pkt[iph_len + TCP_FLAGS_OFFSET] != TCP_FLAG_ACK | TCP_FLAG_PSH {
            return GroResult::Noop;
        }
        psh_set = true;
    }

    let gso_size = (pkt.len() - tcph_len - iph_len) as u16;
    // not a candidate if payload len is 0
    if gso_size < 1 {
        return GroResult::Noop;
    }

    let seq = u32::from_be_bytes([
        pkt[iph_len + 4],
        pkt[iph_len + 5],
        pkt[iph_len + 6],
        pkt[iph_len + 7],
    ]);

    let mut src_addr_offset = IPV4_SRC_ADDR_OFFSET;
    let mut addr_len = 4;
    if is_v6 {
        src_addr_offset = IPV6_SRC_ADDR_OFFSET;
        addr_len = 16;
    }

    let items = if let Some(items) = table.lookup_or_insert(
        pkt,
        src_addr_offset,
        src_addr_offset + addr_len,
        iph_len,
        tcph_len,
        pkt_i,
    ) {
        items
    } else {
        return GroResult::TableInsert;
    };

    for i in (0..items.len()).rev() {
        // In the best case of packets arriving in order iterating in reverse is
        // more efficient if there are multiple items for a given flow. This
        // also enables a natural table.delete_at() in the
        // coalesce_item_invalid_csum case without the need for index tracking.
        // This algorithm makes a best effort to coalesce in the event of
        // unordered packets, where pkt may land anywhere in items from a
        // sequence number perspective, however once an item is inserted into
        // the table it is never compared across other items later.
        let mut item = &mut items[i];
        let can = tcp_packets_can_coalesce(
            pkt,
            iph_len as u8,
            tcph_len as u8,
            seq,
            psh_set,
            gso_size,
            &item,
            bufs,
            offset,
        );

        match can {
            CanCoalesce::CoalesceUnavailable => {}
            _ => {
                let result = coalesce_tcp_packets(
                    can, pkt, pkt_i, gso_size, seq, psh_set, &mut item, bufs, offset, is_v6,
                );

                match result {
                    CoalesceResult::Success => {
                        // table.update_at(item, i);
                        return GroResult::Coalesced;
                    }
                    CoalesceResult::ItemInvalidCSum => {
                        // delete the item with an invalid csum
                        // table.delete_at(item.key, i);
                        items.remove(i);
                    }
                    CoalesceResult::PktInvalidCSum => {
                        // no point in inserting an item that we can't coalesce
                        return GroResult::Noop;
                    }
                    _ => {}
                }
            }
        }
    }

    // failed to coalesce with any other packets; store the item in the flow
    table.insert(
        pkt,
        src_addr_offset,
        src_addr_offset + addr_len,
        iph_len,
        tcph_len,
        pkt_i,
    );
    GroResult::TableInsert
}
/// coalesceResult represents the result of attempting to coalesce two TCP
/// packets.
enum CoalesceResult {
    InsufficientCap,
    PSHEnding,
    ItemInvalidCSum,
    PktInvalidCSum,
    Success,
}
/// coalesceUDPPackets attempts to coalesce pkt with the packet described by
/// item, and returns the outcome.
fn coalesce_udp_packets(
    pkt: &[u8],
    item: &mut UdpGROItem,
    bufs: &mut [BytesMut],
    bufs_offset: usize,
    is_v6: bool,
) -> CoalesceResult {
    let buf = &bufs[item.bufs_index as usize];
    let pkt_head = &buf[bufs_offset..]; // the packet that will end up at the front
    let pkt_head_len = pkt_head.len();
    let headers_len = item.iph_len as usize + UDP_H_LEN;
    let coalesced_len = buf[bufs_offset..].len() + pkt.len() - headers_len;
    if buf.capacity() < bufs_offset * 2 + coalesced_len {
        // We don't want to allocate a new underlying array if capacity is
        // too small.
        return CoalesceResult::InsufficientCap;
    }

    if item.num_merged == 0 {
        if item.c_sum_known_invalid
            || !checksum_valid(
                &buf[bufs_offset..],
                item.iph_len,
                libc::IPPROTO_UDP as _,
                is_v6,
            )
        {
            return CoalesceResult::ItemInvalidCSum;
        }
    }

    if !checksum_valid(pkt, item.iph_len, libc::IPPROTO_UDP as _, is_v6) {
        return CoalesceResult::PktInvalidCSum;
    }
    bufs[item.bufs_index as usize].extend_from_slice(&pkt[headers_len..]);
    item.num_merged += 1;
    CoalesceResult::Success
}
/// coalesceTCPPackets attempts to coalesce pkt with the packet described by
/// item, and returns the outcome. This function may swap bufs elements in the
/// event of a prepend as item's bufs index is already being tracked for writing
/// to a Device.
fn coalesce_tcp_packets(
    mode: CanCoalesce,
    pkt: &[u8],
    pkt_bufs_index: usize,
    gso_size: u16,
    seq: u32,
    psh_set: bool,
    item: &mut TcpGROItem,
    bufs: &mut [BytesMut],
    bufs_offset: usize,
    is_v6: bool,
) -> CoalesceResult {
    let mut pkt_head: &[u8]; // the packet that will end up at the front
    let headers_len = (item.iph_len + item.tcph_len) as usize;
    let coalesced_len =
        bufs[item.bufs_index as usize][bufs_offset..].len() + pkt.len() - headers_len;
    // Copy data
    if mode == CanCoalesce::CoalescePrepend {
        pkt_head = pkt;
        if bufs[pkt_bufs_index].capacity() < 2 * bufs_offset + coalesced_len {
            // We don't want to allocate a new underlying array if capacity is
            // too small.
            return CoalesceResult::InsufficientCap;
        }
        if psh_set {
            return CoalesceResult::PSHEnding;
        }
        if item.num_merged == 0
            && !checksum_valid(
                &bufs[item.bufs_index as usize][bufs_offset..],
                item.iph_len,
                IPPROTO_TCP as _,
                is_v6,
            )
        {
            return CoalesceResult::ItemInvalidCSum;
        }
        if !checksum_valid(pkt, item.iph_len, IPPROTO_TCP as _, is_v6) {
            return CoalesceResult::PktInvalidCSum;
        }
        item.sent_seq = seq;
        let extend_by = coalesced_len - pkt_head.len();
        bufs[pkt_bufs_index].resize(bufs[pkt_bufs_index].len() + extend_by, 0);
        let src = bufs[item.bufs_index as usize][bufs_offset + headers_len..].as_ptr();
        let dst = bufs[pkt_bufs_index][bufs_offset + pkt.len()..].as_mut_ptr();
        unsafe {
            std::ptr::copy_nonoverlapping(src, dst, extend_by);
        }
        // Flip the slice headers in bufs as part of prepend. The index of item
        // is already being tracked for writing.
        bufs.swap(item.bufs_index as usize, pkt_bufs_index);
    } else {
        pkt_head = &bufs[item.bufs_index as usize][bufs_offset..];
        if bufs[item.bufs_index as usize].capacity() < 2 * bufs_offset + coalesced_len {
            // We don't want to allocate a new underlying array if capacity is
            // too small.
            return CoalesceResult::InsufficientCap;
        }
        if item.num_merged == 0
            && !checksum_valid(
                &bufs[item.bufs_index as usize][bufs_offset..],
                item.iph_len,
                IPPROTO_TCP as _,
                is_v6,
            )
        {
            return CoalesceResult::ItemInvalidCSum;
        }
        if !checksum_valid(pkt, item.iph_len, IPPROTO_TCP as _, is_v6) {
            return CoalesceResult::PktInvalidCSum;
        }
        if psh_set {
            // We are appending a segment with PSH set.
            item.psh_set = psh_set;
            bufs[item.bufs_index as usize]
                [bufs_offset + item.iph_len as usize + TCP_FLAGS_OFFSET] |= TCP_FLAG_PSH;
        }
        bufs[item.bufs_index as usize].extend_from_slice(&pkt[headers_len..]);
    }

    if gso_size > item.gso_size {
        item.gso_size = gso_size;
    }

    item.num_merged += 1;
    CoalesceResult::Success
}

/// ipHeadersCanCoalesce returns true if the IP headers found in pktA and pktB
/// meet all requirements to be merged as part of a GRO operation, otherwise it
/// returns false.
fn ip_headers_can_coalesce(pkt_a: &[u8], pkt_b: &[u8]) -> bool {
    if pkt_a.len() < 9 || pkt_b.len() < 9 {
        return false;
    }

    if pkt_a[0] >> 4 == 6 {
        if pkt_a[0] != pkt_b[0] || pkt_a[1] >> 4 != pkt_b[1] >> 4 {
            // cannot coalesce with unequal Traffic class values
            return false;
        }
        if pkt_a[7] != pkt_b[7] {
            // cannot coalesce with unequal Hop limit values
            return false;
        }
    } else {
        if pkt_a[1] != pkt_b[1] {
            // cannot coalesce with unequal ToS values
            return false;
        }
        if pkt_a[6] >> 5 != pkt_b[6] >> 5 {
            // cannot coalesce with unequal DF or reserved bits. MF is checked
            // further up the stack.
            return false;
        }
        if pkt_a[8] != pkt_b[8] {
            // cannot coalesce with unequal TTL values
            return false;
        }
    }

    true
}

/// udpPacketsCanCoalesce evaluates if pkt can be coalesced with the packet
/// described by item. iphLen and gsoSize describe pkt. bufs is the vector of
/// packets involved in the current GRO evaluation. bufsOffset is the offset at
/// which packet data begins within bufs.
fn udp_packets_can_coalesce(
    pkt: &[u8],
    iph_len: u8,
    gso_size: u16,
    item: &UdpGROItem,
    bufs: &[BytesMut],
    bufs_offset: usize,
) -> CanCoalesce {
    let pkt_target = &bufs[item.bufs_index as usize][bufs_offset..];
    if !ip_headers_can_coalesce(pkt, pkt_target) {
        return CanCoalesce::CoalesceUnavailable;
    }
    if (pkt_target[(iph_len as usize + UDP_HEADER_LEN)..].len()) % (item.gso_size as usize) != 0 {
        // A smaller than gsoSize packet has been appended previously.
        // Nothing can come after a smaller packet on the end.
        return CanCoalesce::CoalesceUnavailable;
    }
    if gso_size > item.gso_size {
        // We cannot have a larger packet following a smaller one.
        return CanCoalesce::CoalesceUnavailable;
    }
    CanCoalesce::CoalesceAppend
}
#[derive(Copy, Clone, Eq, PartialEq)]
enum CanCoalesce {
    CoalescePrepend,
    CoalesceUnavailable,
    CoalesceAppend,
}

/// tcpPacketsCanCoalesce evaluates if pkt can be coalesced with the packet
/// described by item. This function makes considerations that match the kernel's
/// GRO self tests, which can be found in tools/testing/selftests/net/gro.c.
fn tcp_packets_can_coalesce(
    pkt: &[u8],
    iph_len: u8,
    tcph_len: u8,
    seq: u32,
    psh_set: bool,
    gso_size: u16,
    item: &TcpGROItem,
    bufs: &[BytesMut],
    bufs_offset: usize,
) -> CanCoalesce {
    let pkt_target = &bufs[item.bufs_index as usize][bufs_offset..];

    if tcph_len != item.tcph_len {
        // cannot coalesce with unequal tcp options len
        return CanCoalesce::CoalesceUnavailable;
    }

    if tcph_len > 20 {
        if &pkt[iph_len as usize + 20..iph_len as usize + tcph_len as usize]
            != &pkt_target[item.iph_len as usize + 20..item.iph_len as usize + tcph_len as usize]
        {
            // cannot coalesce with unequal tcp options
            return CanCoalesce::CoalesceUnavailable;
        }
    }

    if !ip_headers_can_coalesce(pkt, pkt_target) {
        return CanCoalesce::CoalesceUnavailable;
    }

    // seq adjacency
    let mut lhs_len = item.gso_size as usize;
    lhs_len += (item.num_merged as usize) * (item.gso_size as usize);

    if seq == item.sent_seq + lhs_len as u32 {
        // pkt aligns following item from a seq num perspective
        if item.psh_set {
            // We cannot append to a segment that has the PSH flag set, PSH
            // can only be set on the final segment in a reassembled group.
            return CanCoalesce::CoalesceUnavailable;
        }

        if pkt_target[iph_len as usize + tcph_len as usize..].len() % item.gso_size as usize != 0 {
            // A smaller than gsoSize packet has been appended previously.
            // Nothing can come after a smaller packet on the end.
            return CanCoalesce::CoalesceUnavailable;
        }

        if gso_size > item.gso_size {
            // We cannot have a larger packet following a smaller one.
            return CanCoalesce::CoalesceUnavailable;
        }

        return CanCoalesce::CoalesceAppend;
    } else if seq + gso_size as u32 == item.sent_seq {
        // pkt aligns in front of item from a seq num perspective
        if psh_set {
            // We cannot prepend with a segment that has the PSH flag set, PSH
            // can only be set on the final segment in a reassembled group.
            return CanCoalesce::CoalesceUnavailable;
        }

        if gso_size < item.gso_size {
            // We cannot have a larger packet following a smaller one.
            return CanCoalesce::CoalesceUnavailable;
        }

        if gso_size > item.gso_size && item.num_merged > 0 {
            // There's at least one previous merge, and we're larger than all
            // previous. This would put multiple smaller packets on the end.
            return CanCoalesce::CoalesceUnavailable;
        }

        return CanCoalesce::CoalescePrepend;
    }

    return CanCoalesce::CoalesceUnavailable;
}

/// gsoSplit splits packets from in into outBuffs, writing the size of each
/// element into sizes. It returns the number of buffers populated, and/or an
/// error.
pub fn gso_split(
    input: &mut [u8],
    hdr: VirtioNetHdr,
    out_bufs: &mut [&mut [u8]],
    sizes: &mut [usize],
    is_v6: bool,
) -> io::Result<usize> {
    let iph_len = hdr.csum_start as usize;
    let (src_addr_offset, addr_len) = if is_v6 {
        (IPV6_SRC_ADDR_OFFSET, 16)
    } else {
        input[10] = 0;
        input[11] = 0; // clear IPv4 header checksum
        (IPV4_SRC_ADDR_OFFSET, 4)
    };

    let transport_csum_at = (hdr.csum_start + hdr.csum_offset) as usize;
    input[transport_csum_at] = 0;
    input[transport_csum_at + 1] = 0; // clear TCP/UDP checksum

    let (mut first_tcp_seq_num, protocol) =
        if hdr.gso_type == VIRTIO_NET_HDR_GSO_TCPV4 || hdr.gso_type == VIRTIO_NET_HDR_GSO_TCPV6 {
            (
                BigEndian::read_u32(&input[hdr.csum_start as usize + 4..]),
                IPPROTO_TCP,
            )
        } else {
            (0, libc::IPPROTO_UDP)
        };

    let mut next_segment_data_at = hdr.hdr_len as usize;
    let mut i = 0;

    while next_segment_data_at < input.len() {
        if i == out_bufs.len() {
            return Err(io::Error::new(io::ErrorKind::Other, "ErrTooManySegments"));
        }

        let mut next_segment_end = next_segment_data_at + hdr.gso_size as usize;
        if next_segment_end > input.len() {
            next_segment_end = input.len();
        }
        let segment_data_len = next_segment_end - next_segment_data_at;
        let total_len = hdr.hdr_len as usize + segment_data_len;

        sizes[i] = total_len;
        let out = &mut out_bufs[i];

        out[..iph_len].copy_from_slice(&input[..iph_len]);

        if !is_v6 {
            // For IPv4 we are responsible for incrementing the ID field,
            // updating the total len field, and recalculating the header
            // checksum.
            if i > 0 {
                let mut id = BigEndian::read_u16(&out[4..]);
                id += i as u16;
                BigEndian::write_u16(&mut out[4..6], id);
            }
            BigEndian::write_u16(&mut out[2..4], total_len as u16);
            let ipv4_csum = !checksum(&out[..iph_len], 0);
            BigEndian::write_u16(&mut out[10..12], ipv4_csum);
        } else {
            BigEndian::write_u16(&mut out[4..6], (total_len - iph_len) as u16);
        }

        out[hdr.csum_start as usize..hdr.hdr_len as usize]
            .copy_from_slice(&input[hdr.csum_start as usize..hdr.hdr_len as usize]);

        if protocol == IPPROTO_TCP {
            let tcp_seq = first_tcp_seq_num + hdr.gso_size as u32 * i as u32;
            BigEndian::write_u32(
                &mut out[(hdr.csum_start + 4) as usize..(hdr.csum_start + 8) as usize],
                tcp_seq,
            );
            if next_segment_end != input.len() {
                out[hdr.csum_start as usize + TCP_FLAGS_OFFSET] &= !(TCP_FLAG_FIN | TCP_FLAG_PSH);
            }
        } else {
            let udp_len = (segment_data_len + (hdr.hdr_len - hdr.csum_start) as usize) as u16;
            BigEndian::write_u16(
                &mut out[(hdr.csum_start + 4) as usize..(hdr.csum_start + 6) as usize],
                udp_len,
            );
        }

        out[hdr.hdr_len as usize..total_len]
            .copy_from_slice(&input[next_segment_data_at..next_segment_end]);

        let transport_header_len = (hdr.hdr_len - hdr.csum_start) as usize;
        let len_for_pseudo = (transport_header_len + segment_data_len) as u16;
        let transport_csum_no_fold = pseudo_header_checksum_no_fold(
            protocol as u8,
            &input[src_addr_offset..src_addr_offset + addr_len],
            &input[src_addr_offset + addr_len..src_addr_offset + 2 * addr_len],
            len_for_pseudo,
        );
        let transport_csum = !checksum(
            &out[hdr.csum_start as usize..total_len],
            transport_csum_no_fold,
        );
        BigEndian::write_u16(
            &mut out[transport_csum_at..transport_csum_at + 2],
            transport_csum,
        );

        next_segment_data_at += hdr.gso_size as usize;
        i += 1;
    }

    Ok(i)
}
fn checksum_valid(pkt: &[u8], iph_len: u8, proto: u8, is_v6: bool) -> bool {
    let (src_addr_at, addr_size) = if is_v6 {
        (IPV6_SRC_ADDR_OFFSET, 16)
    } else {
        (IPV4_SRC_ADDR_OFFSET, 4)
    };

    let len_for_pseudo = (pkt.len() as u16).saturating_sub(iph_len as u16);

    let c_sum = pseudo_header_checksum_no_fold(
        proto,
        &pkt[src_addr_at..src_addr_at + addr_size],
        &pkt[src_addr_at + addr_size..src_addr_at + addr_size * 2],
        len_for_pseudo,
    );

    !checksum(&pkt[iph_len as usize..], c_sum) == 0
}

pub fn gso_none_checksum(in_buf: &mut [u8], csum_start: u16, csum_offset: u16) {
    let csum_at = (csum_start + csum_offset) as usize;
    // The initial value at the checksum offset should be summed with the
    // checksum we compute. This is typically the pseudo-header checksum.
    let initial = BigEndian::read_u16(&in_buf[csum_at..]);
    in_buf[csum_at] = 0;
    in_buf[csum_at + 1] = 0;
    let computed_checksum = checksum(&in_buf[csum_start as usize..], initial as u64);
    BigEndian::write_u16(&mut in_buf[csum_at..], !computed_checksum);
}
