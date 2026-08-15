//! Packet builders and the independent checksum oracle the packet tests assert
//! against.
//!
//! The oracle is a full ones-complement recompute written on its own, so a
//! test that checks an incrementally updated checksum never asks the
//! incremental code whether it was right.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Full RFC 1071 ones-complement checksum over `data`, folded from a `u64`
/// accumulator, with `seed` carrying any pseudo-header sum.
pub(crate) fn ones_sum(seed: u64, data: &[u8]) -> u16 {
    let mut sum = seed;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u64::from(u16::from_be_bytes([data[i], data[i + 1]]));
        i += 2;
    }
    if i < data.len() {
        sum += u64::from(data[i]) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    #[allow(clippy::cast_possible_truncation)]
    let folded = sum as u16;
    !folded
}

fn pseudo_v4(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, l4_len: usize) -> u64 {
    let mut sum = 0u64;
    for w in src
        .octets()
        .chunks_exact(2)
        .chain(dst.octets().chunks_exact(2))
    {
        sum += u64::from(u16::from_be_bytes([w[0], w[1]]));
    }
    sum + u64::from(proto) + l4_len as u64
}

fn pseudo_v6(src: Ipv6Addr, dst: Ipv6Addr, proto: u8, l4_len: usize) -> u64 {
    let mut sum = 0u64;
    for w in src
        .octets()
        .chunks_exact(2)
        .chain(dst.octets().chunks_exact(2))
    {
        sum += u64::from(u16::from_be_bytes([w[0], w[1]]));
    }
    sum + u64::from(proto) + l4_len as u64
}

fn pseudo(src: IpAddr, dst: IpAddr, proto: u8, l4_len: usize) -> u64 {
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => pseudo_v4(s, d, proto, l4_len),
        (IpAddr::V6(s), IpAddr::V6(d)) => pseudo_v6(s, d, proto, l4_len),
        _ => panic!("mixed address families"),
    }
}

/// Builds the IP header in front of an already assembled `l4` block, without
/// touching the transport checksum.
fn with_ip_header(src: IpAddr, dst: IpAddr, proto: u8, l4: &[u8]) -> Vec<u8> {
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let mut pkt = vec![0u8; 20 + l4.len()];
            pkt[0] = 0x45;
            #[allow(clippy::cast_possible_truncation)]
            let total = (20 + l4.len()) as u16;
            pkt[2..4].copy_from_slice(&total.to_be_bytes());
            pkt[8] = 64;
            pkt[9] = proto;
            pkt[12..16].copy_from_slice(&s.octets());
            pkt[16..20].copy_from_slice(&d.octets());
            let ck = ones_sum(0, &pkt[..20]);
            pkt[10..12].copy_from_slice(&ck.to_be_bytes());
            pkt[20..].copy_from_slice(l4);
            pkt
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let mut pkt = vec![0u8; 40 + l4.len()];
            pkt[0] = 0x60;
            #[allow(clippy::cast_possible_truncation)]
            let payload = l4.len() as u16;
            pkt[4..6].copy_from_slice(&payload.to_be_bytes());
            pkt[6] = proto;
            pkt[7] = 64;
            pkt[8..24].copy_from_slice(&s.octets());
            pkt[24..40].copy_from_slice(&d.octets());
            pkt[40..].copy_from_slice(l4);
            pkt
        }
        _ => panic!("mixed address families"),
    }
}

/// A UDP datagram with a valid transport checksum.
pub(crate) fn udp(src: IpAddr, sport: u16, dst: IpAddr, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut l4 = vec![0u8; 8 + payload.len()];
    l4[0..2].copy_from_slice(&sport.to_be_bytes());
    l4[2..4].copy_from_slice(&dport.to_be_bytes());
    #[allow(clippy::cast_possible_truncation)]
    let len = (8 + payload.len()) as u16;
    l4[4..6].copy_from_slice(&len.to_be_bytes());
    l4[8..].copy_from_slice(payload);
    let ck = ones_sum(pseudo(src, dst, 17, l4.len()), &l4);
    // RFC 768: an all-zero result is transmitted as 0xFFFF, zero means "none".
    let ck = if ck == 0 { 0xffff } else { ck };
    l4[6..8].copy_from_slice(&ck.to_be_bytes());
    with_ip_header(src, dst, 17, &l4)
}

/// A TCP segment with a valid transport checksum. `flags` is the raw flag byte.
pub(crate) fn tcp(
    src: IpAddr,
    sport: u16,
    dst: IpAddr,
    dport: u16,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut l4 = vec![0u8; 20 + payload.len()];
    l4[0..2].copy_from_slice(&sport.to_be_bytes());
    l4[2..4].copy_from_slice(&dport.to_be_bytes());
    l4[12] = 5 << 4;
    l4[13] = flags;
    l4[14..16].copy_from_slice(&8192u16.to_be_bytes());
    l4[20..].copy_from_slice(payload);
    let ck = ones_sum(pseudo(src, dst, 6, l4.len()), &l4);
    l4[16..18].copy_from_slice(&ck.to_be_bytes());
    with_ip_header(src, dst, 6, &l4)
}

/// An ICMP echo request (v4 type 8, v6 type 128) with a valid checksum.
pub(crate) fn echo(src: IpAddr, dst: IpAddr, id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    let v6 = src.is_ipv6();
    let mut l4 = vec![0u8; 8 + payload.len()];
    l4[0] = if v6 { 128 } else { 8 };
    l4[4..6].copy_from_slice(&id.to_be_bytes());
    l4[6..8].copy_from_slice(&seq.to_be_bytes());
    l4[8..].copy_from_slice(payload);
    let proto = if v6 { 58 } else { 1 };
    let seed = if v6 {
        pseudo(src, dst, proto, l4.len())
    } else {
        0
    };
    let ck = ones_sum(seed, &l4);
    l4[2..4].copy_from_slice(&ck.to_be_bytes());
    with_ip_header(src, dst, proto, &l4)
}

/// Recomputes every checksum a packet carries and compares it with what the
/// packet says, so a rewritten packet can be checked against arithmetic that
/// never ran incrementally.
pub(crate) fn checksums_valid(pkt: &[u8]) -> bool {
    let (l4_off, proto, src, dst) = match pkt.first().map(|b| b >> 4) {
        Some(4) => {
            let ihl = usize::from(pkt[0] & 0x0f) * 4;
            let stored = u16::from_be_bytes([pkt[10], pkt[11]]);
            let mut hdr = pkt[..ihl].to_vec();
            hdr[10] = 0;
            hdr[11] = 0;
            if ones_sum(0, &hdr) != stored {
                return false;
            }
            let src = IpAddr::V4(Ipv4Addr::from(
                <[u8; 4]>::try_from(&pkt[12..16]).expect("v4 source"),
            ));
            let dst = IpAddr::V4(Ipv4Addr::from(
                <[u8; 4]>::try_from(&pkt[16..20]).expect("v4 destination"),
            ));
            (ihl, pkt[9], src, dst)
        }
        Some(6) => {
            let src = IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&pkt[8..24]).expect("v6 source"),
            ));
            let dst = IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&pkt[24..40]).expect("v6 destination"),
            ));
            (40, pkt[6], src, dst)
        }
        _ => return false,
    };
    let l4 = &pkt[l4_off..];
    let (ck_at, seeded) = match proto {
        6 => (16, true),
        17 => (6, true),
        1 => (2, false),
        58 => (2, true),
        _ => return true,
    };
    let stored = u16::from_be_bytes([l4[ck_at], l4[ck_at + 1]]);
    if proto == 17 && stored == 0 {
        // A zero UDP checksum means "not computed"; legal on IPv4 only.
        return src.is_ipv4();
    }
    let mut body = l4.to_vec();
    body[ck_at] = 0;
    body[ck_at + 1] = 0;
    let seed = if seeded {
        pseudo(src, dst, proto, l4.len())
    } else {
        0
    };
    let mut recomputed = ones_sum(seed, &body);
    if proto == 17 && recomputed == 0 {
        recomputed = 0xffff;
    }
    recomputed == stored
}
