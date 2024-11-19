use crate::platform::linux::checksum::{checksum, pseudo_header_checksum_no_fold};
use byteorder::{BigEndian, ByteOrder};
use libc::IPPROTO_TCP;
use std::io;

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
const TCP_FLAG_FIN: u8 = 0x01;
const TCP_FLAG_PSH: u8 = 0x08;
const TCP_FLAG_ACK: u8 = 0x10;
const TCP_FLAGS_OFFSET: usize = 13;
pub const VIRTIO_NET_HDR_GSO_NONE: u8 = 0;
pub const VIRTIO_NET_HDR_F_NEEDS_CSUM: u8 = 1;
pub const VIRTIO_NET_HDR_GSO_TCPV4: u8 = 1;
pub const VIRTIO_NET_HDR_GSO_TCPV6: u8 = 4;
pub const VIRTIO_NET_HDR_GSO_UDP_L4: u8 = 5;
const IPV4_SRC_ADDR_OFFSET: usize = 12;
const IPV6_SRC_ADDR_OFFSET: usize = 8;
const MAX_UINT16: usize = 1 << 16 - 1;
pub const VIRTIO_NET_HDR_LEN: usize = std::mem::size_of::<VirtioNetHdr>();
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
