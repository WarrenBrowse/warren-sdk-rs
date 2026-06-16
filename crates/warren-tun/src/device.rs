//! The TUN device seam and the framing adapter.
//!
//! A real kernel TUN device does packet-atomic I/O: each read returns exactly one
//! frame, each write submits exactly one frame. [`RawTunDevice`] models that, and
//! [`FramedTun`] layers the per-OS [`Framing`](crate::Framing) on top so the
//! datapath above always speaks bare IP packets ([`TunIo`]).
//!
//! The actual per-OS device open ([`open_tun`]) is compiled ONLY under the
//! `experimental-tun` feature and is NOT exercised by any test (it needs root and
//! a real kernel device). The framing adapter IS tested, over an in-memory mock.

use std::io;

use crate::frame::Framing;

/// Whole-frame, packet-atomic device I/O, as a kernel TUN fd provides.
pub trait RawTunDevice {
    /// Reads the next frame into `buf`, returning its length. `buf` must be at
    /// least MTU + the framing header.
    ///
    /// # Errors
    ///
    /// Propagates the underlying device read error.
    fn read_frame(&mut self, buf: &mut [u8]) -> io::Result<usize>;

    /// Writes one whole `frame` to the device.
    ///
    /// # Errors
    ///
    /// Propagates the underlying device write error.
    fn write_frame(&mut self, frame: &[u8]) -> io::Result<()>;
}

/// The datapath-facing seam: send and receive bare IP packets, framing handled
/// underneath.
pub trait TunIo {
    /// Receives the next bare IP packet from the device.
    ///
    /// # Errors
    ///
    /// A device read error, or [`io::ErrorKind::InvalidData`] if the frame could
    /// not be decoded (a malformed or unknown-family frame).
    fn recv_packet(&mut self) -> io::Result<Vec<u8>>;

    /// Sends one bare IP `packet` to the device.
    ///
    /// # Errors
    ///
    /// A device write error, or [`io::ErrorKind::InvalidData`] if the packet has
    /// no recognizable IP version (so it cannot be framed).
    fn send_packet(&mut self, packet: &[u8]) -> io::Result<()>;
}

/// Adapts a [`RawTunDevice`] to [`TunIo`] by applying the per-OS [`Framing`].
#[derive(Debug)]
pub struct FramedTun<D: RawTunDevice> {
    device: D,
    framing: Framing,
    read_buf: Vec<u8>,
}

impl<D: RawTunDevice> FramedTun<D> {
    /// Wraps `device` with `framing`, sizing the read buffer for `mtu` plus the
    /// 4-byte worst-case header.
    #[must_use]
    pub fn new(device: D, framing: Framing, mtu: u16) -> Self {
        Self {
            device,
            framing,
            read_buf: vec![0u8; mtu as usize + 4],
        }
    }

    /// Consumes the adapter, returning the wrapped device.
    #[must_use]
    pub fn into_inner(self) -> D {
        self.device
    }
}

impl<D: RawTunDevice> TunIo for FramedTun<D> {
    fn recv_packet(&mut self) -> io::Result<Vec<u8>> {
        let n = self.device.read_frame(&mut self.read_buf)?;
        self.framing
            .decode(&self.read_buf[..n])
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "undecodable tun frame"))
    }

    fn send_packet(&mut self, packet: &[u8]) -> io::Result<()> {
        let frame = self
            .framing
            .encode(packet)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "unframable ip packet"))?;
        self.device.write_frame(&frame)
    }
}

/// Opens the kernel TUN device named `name` (EXPERIMENTAL, requires root /
/// `CAP_NET_ADMIN`). Compiled only under the `experimental-tun` feature.
///
/// NOT YET VALIDATED against a real exit: do not rely on this in production.
///
/// # Errors
///
/// An OS error if the device cannot be opened or configured.
#[cfg(all(target_os = "linux", feature = "experimental-tun"))]
pub fn open_tun(name: &str) -> io::Result<linux::TunFd> {
    linux::TunFd::open(name)
}

#[cfg(all(target_os = "linux", feature = "experimental-tun"))]
mod linux {
    use super::RawTunDevice;
    use std::io;
    use std::os::fd::{FromRawFd, OwnedFd};

    const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
    const IFF_TUN: libc::c_short = 0x0001;
    const IFF_NO_PI: libc::c_short = 0x1000;
    const IFNAMSIZ: usize = 16;

    /// An owned Linux TUN file descriptor.
    #[derive(Debug)]
    pub struct TunFd {
        fd: OwnedFd,
    }

    impl TunFd {
        /// Opens `/dev/net/tun` and binds it to a TUN interface named `name`
        /// (truncated to `IFNAMSIZ - 1`), with no packet-info header (`IFF_NO_PI`,
        /// so reads/writes are bare IP packets, matching [`crate::Framing::Bare`]).
        pub fn open(name: &str) -> io::Result<Self> {
            use std::os::fd::AsRawFd;

            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/net/tun")?;

            // ifreq: char ifr_name[IFNAMSIZ]; then a union whose first field here
            // is the short flags. We zero the struct and fill name + flags.
            let mut ifr = [0u8; IFNAMSIZ + 64];
            let bytes = name.as_bytes();
            let take = bytes.len().min(IFNAMSIZ - 1);
            ifr[..take].copy_from_slice(&bytes[..take]);
            let flags = (IFF_TUN | IFF_NO_PI) as u16;
            ifr[IFNAMSIZ..IFNAMSIZ + 2].copy_from_slice(&flags.to_ne_bytes());

            // SAFETY: `file` is a valid open fd for the lifetime of this call;
            // `ifr` is a correctly sized, fully initialized buffer matching the
            // kernel's `struct ifreq` layout (name array + flags short). `ioctl`
            // reads `IFNAMSIZ + 2` bytes from it and writes back the resolved
            // name into the same buffer; no aliasing, no escape of the pointer.
            let rc = unsafe {
                libc::ioctl(
                    file.as_raw_fd(),
                    TUNSETIFF,
                    ifr.as_mut_ptr().cast::<libc::c_void>(),
                )
            };
            if rc < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: `OpenOptions::open` succeeded, so the fd is open and owned;
            // `into_raw_fd` transfers ownership exactly once into `OwnedFd`.
            let fd = unsafe { OwnedFd::from_raw_fd(into_raw(file)) };
            Ok(Self { fd })
        }
    }

    fn into_raw(file: std::fs::File) -> std::os::fd::RawFd {
        use std::os::fd::IntoRawFd;
        file.into_raw_fd()
    }

    impl RawTunDevice for TunFd {
        fn read_frame(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            use std::os::fd::AsRawFd;
            // SAFETY: `buf` is a valid, writable slice of `buf.len()` bytes; the
            // fd is open for the lifetime of `self`. `read` writes at most
            // `buf.len()` bytes and returns the count or a negative error.
            let n = unsafe {
                libc::read(
                    self.fd.as_raw_fd(),
                    buf.as_mut_ptr().cast::<libc::c_void>(),
                    buf.len(),
                )
            };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(n as usize)
        }

        fn write_frame(&mut self, frame: &[u8]) -> io::Result<()> {
            use std::os::fd::AsRawFd;
            // SAFETY: `frame` is a valid, readable slice of `frame.len()` bytes;
            // the fd is open for the lifetime of `self`. `write` reads at most
            // `frame.len()` bytes and returns the count or a negative error.
            let n = unsafe {
                libc::write(
                    self.fd.as_raw_fd(),
                    frame.as_ptr().cast::<libc::c_void>(),
                    frame.len(),
                )
            };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }
}

/// Opens a macOS `utun` device (EXPERIMENTAL, requires root). `name` of the form
/// `utunN` requests that unit; anything else lets the kernel pick a free unit.
/// Compiled only under the `experimental-tun` feature.
///
/// NOT YET VALIDATED against a real exit: do not rely on this in production.
///
/// # Errors
///
/// An OS error if the control socket cannot be opened or connected.
#[cfg(all(target_os = "macos", feature = "experimental-tun"))]
pub fn open_tun(name: &str) -> io::Result<macos::Utun> {
    // utun control unit U creates utun(U-1); unit 0 = kernel picks a free one.
    let unit = name
        .strip_prefix("utun")
        .and_then(|n| n.parse::<u32>().ok())
        .map_or(0, |n| n + 1);
    macos::Utun::open(unit)
}

#[cfg(all(target_os = "macos", feature = "experimental-tun"))]
mod macos {
    use super::RawTunDevice;
    use std::io;
    use std::os::fd::{FromRawFd, OwnedFd};

    const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control";

    /// An owned macOS `utun` control-socket file descriptor.
    #[derive(Debug)]
    pub struct Utun {
        fd: OwnedFd,
    }

    impl Utun {
        /// Opens the `utun` control socket and connects it to `unit` (0 = auto).
        pub fn open(unit: u32) -> io::Result<Self> {
            use std::os::fd::AsRawFd;

            // SAFETY: a plain socket(2) with constant arguments; the return is an
            // fd (>= 0) or -1 on error, checked immediately. No pointers.
            let raw =
                unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
            if raw < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: `raw` is a fresh, owned, valid socket fd from the call above;
            // ownership is transferred exactly once into `OwnedFd`.
            let fd = unsafe { OwnedFd::from_raw_fd(raw) };

            // Resolve the utun control id by name.
            let mut info: libc::ctl_info = unsafe { std::mem::zeroed() };
            let name = UTUN_CONTROL_NAME;
            // ctl_name is a fixed C char array; copy the NUL-terminated name in.
            for (dst, src) in info.ctl_name.iter_mut().zip(name.iter()) {
                *dst = *src as libc::c_char;
            }
            // SAFETY: `fd` is valid; `&mut info` is a correctly typed, fully
            // initialized `ctl_info` the ioctl fills in (writes `ctl_id`).
            let rc = unsafe { libc::ioctl(fd.as_raw_fd(), libc::CTLIOCGINFO, &mut info) };
            if rc < 0 {
                return Err(io::Error::last_os_error());
            }

            let addr = libc::sockaddr_ctl {
                sc_len: std::mem::size_of::<libc::sockaddr_ctl>() as u8,
                sc_family: libc::AF_SYSTEM as u8,
                ss_sysaddr: libc::AF_SYS_CONTROL as u16,
                sc_id: info.ctl_id,
                sc_unit: unit,
                sc_reserved: [0; 5],
            };
            // SAFETY: `fd` is valid; `&addr` is a fully initialized `sockaddr_ctl`
            // and the length matches its size, as connect(2) requires.
            let rc = unsafe {
                libc::connect(
                    fd.as_raw_fd(),
                    std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
                    std::mem::size_of::<libc::sockaddr_ctl>() as libc::socklen_t,
                )
            };
            if rc < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self { fd })
        }
    }

    impl RawTunDevice for Utun {
        fn read_frame(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            use std::os::fd::AsRawFd;
            // SAFETY: `buf` is a valid writable slice of `buf.len()` bytes; the fd
            // is open for the lifetime of `self`. read(2) writes at most that many
            // bytes and returns the count or a negative error.
            let n = unsafe {
                libc::read(
                    self.fd.as_raw_fd(),
                    buf.as_mut_ptr().cast::<libc::c_void>(),
                    buf.len(),
                )
            };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(n as usize)
        }

        fn write_frame(&mut self, frame: &[u8]) -> io::Result<()> {
            use std::os::fd::AsRawFd;
            // SAFETY: `frame` is a valid readable slice of `frame.len()` bytes; the
            // fd is open for the lifetime of `self`. write(2) reads at most that
            // many bytes and returns the count or a negative error.
            let n = unsafe {
                libc::write(
                    self.fd.as_raw_fd(),
                    frame.as_ptr().cast::<libc::c_void>(),
                    frame.len(),
                )
            };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::PacketFamily;
    use std::collections::VecDeque;

    /// An in-memory packet-atomic device: reads pop queued inbound frames, writes
    /// push onto an outbound queue. Models the TUN fd's framing without a kernel.
    #[derive(Default)]
    struct MockDevice {
        inbound: VecDeque<Vec<u8>>,
        outbound: Vec<Vec<u8>>,
    }

    impl RawTunDevice for MockDevice {
        fn read_frame(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let frame = self
                .inbound
                .pop_front()
                .ok_or_else(|| io::Error::new(io::ErrorKind::WouldBlock, "no frame"))?;
            buf[..frame.len()].copy_from_slice(&frame);
            Ok(frame.len())
        }

        fn write_frame(&mut self, frame: &[u8]) -> io::Result<()> {
            self.outbound.push(frame.to_vec());
            Ok(())
        }
    }

    fn ipv4_packet() -> Vec<u8> {
        let mut p = vec![0x45u8];
        p.extend_from_slice(&[7u8; 19]);
        p
    }

    #[test]
    fn framed_tun_round_trips_a_packet_over_bare_framing() {
        let mut dev = MockDevice::default();
        dev.inbound.push_back(ipv4_packet());
        let mut tun = FramedTun::new(dev, Framing::Bare, 1280);
        assert_eq!(tun.recv_packet().unwrap(), ipv4_packet());
        tun.send_packet(&ipv4_packet()).unwrap();
        assert_eq!(tun.into_inner().outbound, vec![ipv4_packet()]);
    }

    #[test]
    fn framed_tun_applies_and_strips_the_utun_header() {
        let mut dev = MockDevice::default();
        // An inbound utun frame: 4-byte AF header + the IP packet.
        let mut inbound = PacketFamily::V4.darwin_af().to_ne_bytes().to_vec();
        inbound.extend_from_slice(&ipv4_packet());
        dev.inbound.push_back(inbound);

        let mut tun = FramedTun::new(dev, Framing::DarwinUtun, 1280);
        // recv strips the header.
        assert_eq!(tun.recv_packet().unwrap(), ipv4_packet());
        // send prepends it.
        tun.send_packet(&ipv4_packet()).unwrap();
        let out = tun.into_inner().outbound;
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].len(), ipv4_packet().len() + 4);
        assert_eq!(&out[0][4..], ipv4_packet().as_slice());
    }

    #[test]
    fn framed_tun_rejects_an_unframable_packet() {
        let dev = MockDevice::default();
        let mut tun = FramedTun::new(dev, Framing::DarwinUtun, 1280);
        let err = tun.send_packet(&[0xF0, 0x00]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn framed_tun_rejects_an_undecodable_inbound_frame() {
        let mut dev = MockDevice::default();
        dev.inbound.push_back(vec![0x00, 0x00]); // too short for a utun header
        let mut tun = FramedTun::new(dev, Framing::DarwinUtun, 1280);
        let err = tun.recv_packet().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
