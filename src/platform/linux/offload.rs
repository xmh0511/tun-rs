use std::io;
use byteorder::{BigEndian, ByteOrder};
use crate::platform::linux::checksum::checksum;

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
pub const VIRTIO_NET_HDR_GSO_NONE: u8 = 0;
pub const VIRTIO_NET_HDR_F_NEEDS_CSUM: u8 = 1;
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


pub fn gso_none_checksum(
    in_buf: &mut [u8],
    csum_start: u16,
    csum_offset: u16,
) {
    let csum_at = (csum_start + csum_offset) as usize;
    // The initial value at the checksum offset should be summed with the
    // checksum we compute. This is typically the pseudo-header checksum.
    let initial = BigEndian::read_u16(&in_buf[csum_at..]);
    in_buf[csum_at] = 0;
    in_buf[csum_at + 1] = 0;
    let computed_checksum = checksum(&in_buf[csum_start as usize..], initial as u64);
    BigEndian::write_u16(&mut in_buf[csum_at..], !computed_checksum);
}