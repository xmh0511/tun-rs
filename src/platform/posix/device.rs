use crate::platform::posix::Fd;
use crate::platform::{Device, Tun};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
impl FromRawFd for Device {
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        Device::from_fd(fd).unwrap()
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
impl Device {
    pub fn from_fd(fd: RawFd) -> std::io::Result<Self> {
        let tun = Fd::new(fd, true)?;
        Ok(Device::from_tun(Tun::new(tun)))
    }
    /// Set non-blocking mode
    pub fn set_nonblock(&self) -> std::io::Result<()> {
        self.tun.set_nonblock()
    }

    /// Recv a packet from tun device
    pub fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.tun.recv(buf)
    }

    /// Send a packet to tun device
    pub fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
        self.tun.send(buf)
    }
    /// Do not use nonblocking fd when you want to use shutdown
    #[cfg_attr(docsrs, doc(cfg(feature = "experimental")))]
    #[cfg(feature = "experimental")]
    pub fn shutdown(&self) -> std::io::Result<()> {
        self.tun.shutdown()
    }
}
