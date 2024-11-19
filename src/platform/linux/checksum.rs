use byteorder::{BigEndian, ByteOrder};
/// https://github.com/WireGuard/wireguard-go/blob/master/tun/checksum.go
pub fn checksum_no_fold(mut b: &[u8], initial: u64) -> u64 {
    let mut ac = initial;

    // Process chunks of 128 bytes
    while b.len() >= 128 {
        ac += BigEndian::read_u32(&b[0..4]) as u64;
        ac += BigEndian::read_u32(&b[4..8]) as u64;
        ac += BigEndian::read_u32(&b[8..12]) as u64;
        ac += BigEndian::read_u32(&b[12..16]) as u64;
        ac += BigEndian::read_u32(&b[16..20]) as u64;
        ac += BigEndian::read_u32(&b[20..24]) as u64;
        ac += BigEndian::read_u32(&b[24..28]) as u64;
        ac += BigEndian::read_u32(&b[28..32]) as u64;
        ac += BigEndian::read_u32(&b[32..36]) as u64;
        ac += BigEndian::read_u32(&b[36..40]) as u64;
        ac += BigEndian::read_u32(&b[40..44]) as u64;
        ac += BigEndian::read_u32(&b[44..48]) as u64;
        ac += BigEndian::read_u32(&b[48..52]) as u64;
        ac += BigEndian::read_u32(&b[52..56]) as u64;
        ac += BigEndian::read_u32(&b[56..60]) as u64;
        ac += BigEndian::read_u32(&b[60..64]) as u64;
        ac += BigEndian::read_u32(&b[64..68]) as u64;
        ac += BigEndian::read_u32(&b[68..72]) as u64;
        ac += BigEndian::read_u32(&b[72..76]) as u64;
        ac += BigEndian::read_u32(&b[76..80]) as u64;
        ac += BigEndian::read_u32(&b[80..84]) as u64;
        ac += BigEndian::read_u32(&b[84..88]) as u64;
        ac += BigEndian::read_u32(&b[88..92]) as u64;
        ac += BigEndian::read_u32(&b[92..96]) as u64;
        ac += BigEndian::read_u32(&b[96..100]) as u64;
        ac += BigEndian::read_u32(&b[100..104]) as u64;
        ac += BigEndian::read_u32(&b[104..108]) as u64;
        ac += BigEndian::read_u32(&b[108..112]) as u64;
        ac += BigEndian::read_u32(&b[112..116]) as u64;
        ac += BigEndian::read_u32(&b[116..120]) as u64;
        ac += BigEndian::read_u32(&b[120..124]) as u64;
        ac += BigEndian::read_u32(&b[124..128]) as u64;
        b = &b[128..];
    }

    // Process chunks of 64 bytes
    if b.len() >= 64 {
        ac += BigEndian::read_u32(&b[0..4]) as u64;
        ac += BigEndian::read_u32(&b[4..8]) as u64;
        ac += BigEndian::read_u32(&b[8..12]) as u64;
        ac += BigEndian::read_u32(&b[12..16]) as u64;
        ac += BigEndian::read_u32(&b[16..20]) as u64;
        ac += BigEndian::read_u32(&b[20..24]) as u64;
        ac += BigEndian::read_u32(&b[24..28]) as u64;
        ac += BigEndian::read_u32(&b[28..32]) as u64;
        ac += BigEndian::read_u32(&b[32..36]) as u64;
        ac += BigEndian::read_u32(&b[36..40]) as u64;
        ac += BigEndian::read_u32(&b[40..44]) as u64;
        ac += BigEndian::read_u32(&b[44..48]) as u64;
        ac += BigEndian::read_u32(&b[48..52]) as u64;
        ac += BigEndian::read_u32(&b[52..56]) as u64;
        ac += BigEndian::read_u32(&b[56..60]) as u64;
        ac += BigEndian::read_u32(&b[60..64]) as u64;
        b = &b[64..];
    }

    // Process chunks of 32 bytes
    if b.len() >= 32 {
        ac += BigEndian::read_u32(&b[0..4]) as u64;
        ac += BigEndian::read_u32(&b[4..8]) as u64;
        ac += BigEndian::read_u32(&b[8..12]) as u64;
        ac += BigEndian::read_u32(&b[12..16]) as u64;
        ac += BigEndian::read_u32(&b[16..20]) as u64;
        ac += BigEndian::read_u32(&b[20..24]) as u64;
        ac += BigEndian::read_u32(&b[24..28]) as u64;
        ac += BigEndian::read_u32(&b[28..32]) as u64;
        b = &b[32..];
    }

    // Process chunks of 16 bytes
    if b.len() >= 16 {
        ac += BigEndian::read_u32(&b[0..4]) as u64;
        ac += BigEndian::read_u32(&b[4..8]) as u64;
        ac += BigEndian::read_u32(&b[8..12]) as u64;
        ac += BigEndian::read_u32(&b[12..16]) as u64;
        b = &b[16..];
    }

    // Process chunks of 8 bytes
    if b.len() >= 8 {
        ac += BigEndian::read_u32(&b[0..4]) as u64;
        ac += BigEndian::read_u32(&b[4..8]) as u64;
        b = &b[8..];
    }

    // Process chunks of 4 bytes
    if b.len() >= 4 {
        ac += BigEndian::read_u32(&b[0..4]) as u64;
        b = &b[4..];
    }

    // Process chunks of 2 bytes
    if b.len() >= 2 {
        ac += BigEndian::read_u16(&b[0..2]) as u64;
        b = &b[2..];
    }

    // Process remaining 1 byte
    if b.len() == 1 {
        ac += (b[0] as u64) << 8;
    }
    ac
}

pub fn checksum(b: &[u8], initial: u64) -> u16 {
    let mut ac = checksum_no_fold(b, initial);
    ac = (ac >> 16) + (ac & 0xffff);
    ac = (ac >> 16) + (ac & 0xffff);
    ac = (ac >> 16) + (ac & 0xffff);
    ac = (ac >> 16) + (ac & 0xffff);
    ac as u16
}

pub fn pseudo_header_checksum_no_fold(
    protocol: u8,
    src_addr: &[u8],
    dst_addr: &[u8],
    total_len: u16,
) -> u64 {
    let mut sum = checksum_no_fold(src_addr, 0);
    sum = checksum_no_fold(dst_addr, sum);

    // Process protocol
    let protocol_bytes = [0, protocol];
    sum = checksum_no_fold(&protocol_bytes, sum);

    // Process total_len
    let mut tmp = [0u8; 2];
    BigEndian::write_u16(&mut tmp, total_len);
    checksum_no_fold(&tmp, sum)
}
