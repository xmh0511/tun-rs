use crate::Device;
use getifaddrs::Interface;
#[cfg(unix)]
use std::io::{IoSlice, IoSliceMut};
use std::ops::Deref;
#[cfg(unix)]
use std::os::fd::{FromRawFd, IntoRawFd, RawFd};

#[allow(dead_code)]
pub(crate) const ETHER_ADDR_LEN: u8 = 6;

#[allow(dead_code)]
pub(crate) fn get_if_addrs_by_name(if_name: String) -> std::io::Result<Vec<Interface>> {
    let addrs = getifaddrs::getifaddrs()?;
    let ifs = addrs.filter(|v| v.name == if_name).collect();
    Ok(ifs)
}

#[cfg(unix)]
impl IntoRawFd for SyncDevice {
    fn into_raw_fd(self) -> RawFd {
        self.0.into_raw_fd()
    }
}

#[cfg(unix)]
impl FromRawFd for SyncDevice {
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        SyncDevice::from_fd(fd)
    }
}

#[repr(transparent)]
pub struct SyncDevice(pub(crate) Device);

impl SyncDevice {
    /// # Safety
    /// The fd passed in must be an owned file descriptor; in particular, it must be open and valid.
    #[cfg(unix)]
    pub unsafe fn from_fd(fd: RawFd) -> Self {
        SyncDevice(Device::from_fd(fd))
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
}

impl Deref for SyncDevice {
    type Target = Device;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
