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

use crate::{
    configuration::Configuration,
    device::AbstractDevice,
    error::{Error, Result},
    platform::posix::{Fd, Tun},
};
use std::os::unix::io::{AsRawFd, IntoRawFd, RawFd};

/// A TUN device for iOS.
pub struct Device {
    tun: Tun,
}

impl AsRef<dyn AbstractDevice + 'static> for Device {
    fn as_ref(&self) -> &(dyn AbstractDevice + 'static) {
        self
    }
}

impl AsMut<dyn AbstractDevice + 'static> for Device {
    fn as_mut(&mut self) -> &mut (dyn AbstractDevice + 'static) {
        self
    }
}

impl Device {
    /// Create a new `Device` for the given `Configuration`.
    pub fn new(config: &Configuration) -> Result<Self> {
        let close_fd_on_drop = config.close_fd_on_drop.unwrap_or(true);
        let fd = match config.raw_fd {
            Some(raw_fd) => raw_fd,
            _ => return Err(Error::InvalidConfig),
        };
        let device = {
            let fd = Fd::new(fd, close_fd_on_drop).map_err(|_| std::io::Error::last_os_error())?;
            Device {
                tun: Tun::new(fd, config.platform_config.packet_information),
            }
        };

        Ok(device)
    }

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
