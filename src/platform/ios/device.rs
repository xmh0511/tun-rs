//            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//                    Version 2, December 2004
//
// Copyleft (ↄ) meh. <meh@schizofreni.co> | http://meh.schizofreni.co
//
// Everyone is permitted to copy and distribute verbatim or modified
// copies of this license document, and changing it is allowed as long
// as the name is changed.
//
//            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION
//
//  0. You just DO WHAT THE FUCK YOU WANT TO.
#![allow(unused_variables)]

use std::os::fd::FromRawFd;
use std::os::unix::io::{AsRawFd, IntoRawFd, RawFd};

use crate::{
    device::AbstractDevice,
    platform::posix::{Fd, Tun},
};

/// A TUN device for iOS.
pub struct Device {
    tun: Tun,
}

impl FromRawFd for Device {
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        let tun = Fd::new(fd, true).unwrap();
        Device {
            tun: Tun::new(tun, true),
        }
    }
}

impl Device {
    /// Set non-blocking mode
    pub fn set_nonblock(&self) -> std::io::Result<()> {
        self.tun.set_nonblock()
    }

    /// Recv a packet from tun device
    pub(crate) fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.tun.recv(buf)
    }

    /// Send a packet to tun device
    pub(crate) fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
        self.tun.send(buf)
    }

    #[cfg(feature = "experimental")]
    pub(crate) fn shutdown(&self) -> std::io::Result<()> {
        self.tun.shutdown()
    }
}

impl AbstractDevice for Device {
    fn packet_information(&self) -> bool {
        self.tun.packet_information()
    }
}

impl AsRawFd for Device {
    fn as_raw_fd(&self) -> RawFd {
        self.tun.as_raw_fd()
    }
}

impl IntoRawFd for Device {
    fn into_raw_fd(self) -> RawFd {
        self.tun.into_raw_fd()
    }
}
