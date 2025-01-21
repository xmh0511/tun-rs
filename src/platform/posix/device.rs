use crate::platform::posix::Fd;
use crate::platform::{Device, Tun};
use std::io;
use std::io::{IoSlice, IoSliceMut};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, RawFd};

impl FromRawFd for Device {
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        Device::from_fd(fd)
    }
}
impl AsRawFd for Device {
    fn as_raw_fd(&self) -> RawFd {
        self.tun.as_raw_fd()
    }
}
impl AsFd for Device {
    fn as_fd(&self) -> BorrowedFd<'_> {
        unsafe { BorrowedFd::borrow_raw(self.as_raw_fd()) }
    }
}

impl IntoRawFd for Device {
    fn into_raw_fd(self) -> RawFd {
        self.tun.into_raw_fd()
    }
}
impl Device {
    /// # Safety
    /// The fd passed in must be an owned file descriptor; in particular, it must be open.
    pub unsafe fn from_fd(fd: RawFd) -> Self {
        let tun = Fd::new_uncheck(fd);
        Device::from_tun(Tun::new(tun))
    }
    pub fn is_nonblocking(&self) -> io::Result<bool> {
        self.tun.is_nonblocking()
    }
    /// Moves this Device into or out of nonblocking mode.
    pub fn set_nonblocking(&self, nonblocking: bool) -> std::io::Result<()> {
        self.tun.set_nonblocking(nonblocking)
    }

    /// Recv a packet from tun device
    pub(crate) fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.tun.recv(buf)
    }
    pub(crate) fn recv_vectored(&self, bufs: &mut [IoSliceMut<'_>]) -> std::io::Result<usize> {
        self.tun.recv_vectored(bufs)
    }

    /// Send a packet to tun device
    pub(crate) fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
        self.tun.send(buf)
    }
    pub(crate) fn send_vectored(&self, bufs: &[IoSlice<'_>]) -> std::io::Result<usize> {
        self.tun.send_vectored(bufs)
    }
    #[cfg_attr(docsrs, doc(cfg(feature = "experimental")))]
    #[cfg(feature = "experimental")]
    pub(crate) fn shutdown(&self) -> std::io::Result<()> {
        self.tun.shutdown()
    }
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
    pub(crate) fn get_if_index(name: &str) -> std::io::Result<u32> {
        let ifname = std::ffi::CString::new(name)?;
        unsafe { Ok(libc::if_nametoindex(ifname.as_ptr())) }
    }
}
