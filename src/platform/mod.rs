#[cfg(unix)]
pub mod unix;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub(crate) use self::linux::DeviceInner;

#[cfg(target_os = "linux")]
pub use self::linux::*;

#[cfg(target_os = "freebsd")]
pub mod freebsd;
#[cfg(target_os = "freebsd")]
pub(crate) use self::freebsd::DeviceInner;

#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "macos")]
pub(crate) use self::macos::DeviceInner;

#[cfg(target_os = "ios")]
pub mod ios;
#[cfg(target_os = "ios")]
pub(crate) use self::ios::DeviceInner;

#[cfg(target_os = "android")]
pub mod android;
#[cfg(target_os = "android")]
pub(crate) use self::android::DeviceInner;

#[cfg(unix)]
#[cfg(any(feature = "async_std", feature = "async_tokio"))]
pub use crate::platform::unix::{async_device, async_device::*};

#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "windows")]
pub(crate) use self::windows::DeviceInner;

#[cfg(target_os = "windows")]
#[cfg(any(feature = "async_std", feature = "async_tokio"))]
pub use self::windows::{async_device, async_device::*};

use getifaddrs::Interface;
#[cfg(unix)]
use std::io::{IoSlice, IoSliceMut};
use std::ops::Deref;
#[cfg(unix)]
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, RawFd};

#[allow(dead_code)]
pub(crate) const ETHER_ADDR_LEN: u8 = 6;

#[allow(dead_code)]
pub(crate) fn get_if_addrs_by_name(if_name: String) -> std::io::Result<Vec<Interface>> {
    let addrs = getifaddrs::getifaddrs()?;
    let ifs = addrs.filter(|v| v.name == if_name).collect();
    Ok(ifs)
}

#[repr(transparent)]
pub struct SyncDevice(pub(crate) DeviceInner);

impl SyncDevice {
    /// # Safety
    /// The fd passed in must be an owned file descriptor; in particular, it must be open.
    #[cfg(unix)]
    pub unsafe fn from_fd(fd: RawFd) -> Self {
        SyncDevice(DeviceInner::from_fd(fd))
    }
    pub fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.recv(buf)
    }
    pub fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.send(buf)
    }
    #[cfg(target_os = "windows")]
    pub fn try_recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.try_recv(buf)
    }
    #[cfg(target_os = "windows")]
    pub fn try_send(&self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.try_send(buf)
    }
    #[cfg(target_os = "windows")]
    pub fn shutdown(&self) -> std::io::Result<()> {
        self.0.shutdown()
    }

    #[cfg(all(unix, feature = "experimental"))]
    pub fn shutdown(&self) -> std::io::Result<()> {
        self.0.shutdown()
    }
    #[cfg(unix)]
    pub fn recv_vectored(&self, bufs: &mut [IoSliceMut<'_>]) -> std::io::Result<usize> {
        self.0.recv_vectored(bufs)
    }
    #[cfg(unix)]
    pub fn send_vectored(&self, bufs: &[IoSlice<'_>]) -> std::io::Result<usize> {
        self.0.send_vectored(bufs)
    }
    #[cfg(unix)]
    pub fn is_nonblocking(&self) -> std::io::Result<bool> {
        self.0.is_nonblocking()
    }

    /// Moves this Device into or out of nonblocking mode.
    #[cfg(unix)]
    pub fn set_nonblocking(&self, nonblocking: bool) -> std::io::Result<()> {
        self.0.set_nonblocking(nonblocking)
    }
}

impl Deref for SyncDevice {
    type Target = DeviceInner;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(unix)]
impl FromRawFd for SyncDevice {
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        SyncDevice::from_fd(fd)
    }
}
#[cfg(unix)]
impl AsRawFd for SyncDevice {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}
#[cfg(unix)]
impl AsFd for SyncDevice {
    fn as_fd(&self) -> BorrowedFd<'_> {
        unsafe { BorrowedFd::borrow_raw(self.as_raw_fd()) }
    }
}
#[cfg(unix)]
impl IntoRawFd for SyncDevice {
    fn into_raw_fd(self) -> RawFd {
        self.0.into_raw_fd()
    }
}

#[cfg(any(
    target_os = "windows",
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
))]
#[cfg(test)]
mod test {
    use crate::DeviceBuilder;
    use std::net::Ipv4Addr;

    #[test]
    fn create() {
        let dev = DeviceBuilder::new()
            .name("utun6")
            .ipv4("192.168.50.1".parse().unwrap(), 24, None)
            .mtu(1400)
            .build_sync()
            .unwrap();

        assert!(dev
            .addresses()
            .unwrap()
            .into_iter()
            .any(|v| v == "192.168.50.1".parse::<Ipv4Addr>().unwrap()));

        assert_eq!(1400, dev.mtu().unwrap());
    }
}
