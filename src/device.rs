use crate::Device;
use getifaddrs::Interface;
#[cfg(unix)]
use std::io::{IoSlice, IoSliceMut};
use std::ops::Deref;

#[allow(dead_code)]
pub(crate) const ETHER_ADDR_LEN: u8 = 6;

#[allow(dead_code)]
pub(crate) fn get_if_addrs_by_name(if_name: String) -> std::io::Result<Vec<Interface>> {
    let addrs = getifaddrs::getifaddrs()?;
    let ifs = addrs.filter(|v| v.name == if_name).collect();
    Ok(ifs)
}

#[repr(transparent)]
pub struct SyncDevice(pub(crate) Device);

impl SyncDevice {
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
    pub fn shutdown(&self) -> io::Result<()> {
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
