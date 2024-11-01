use std::io::IoSlice;
#[cfg(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "windows",
    target_os = "ios",
    target_os = "android"
))]
use std::os::fd::{FromRawFd, RawFd};

use crate::platform::Device;
use crate::AbstractDevice;

use crate::r#async::async_device::AsyncFd;
#[allow(unused_imports)]
use std::net::IpAddr;

/// An async TUN device wrapper around a TUN device.
pub struct AsyncDevice {
    inner: AsyncFd,
}

impl FromRawFd for AsyncDevice {
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        AsyncDevice::from_fd(fd).unwrap()
    }
}

impl AsyncDevice {
    /// Create a new `AsyncDevice` wrapping around a `Device`.
    pub fn new(device: Device) -> std::io::Result<AsyncDevice> {
        Ok(AsyncDevice {
            inner: AsyncFd::new(device)?,
        })
    }

    /// # Safety
    /// This method is safe if the provided fd is valid
    /// Construct a AsyncDevice from an existing file descriptor
    pub unsafe fn from_fd(fd: RawFd) -> std::io::Result<AsyncDevice> {
        AsyncDevice::new(Device::from_fd(fd)?)
    }

    /// Recv a packet from tun device
    pub async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.recv(buf).await
    }
    pub fn try_recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.get_ref().recv(buf)
    }

    /// Send a packet to tun device
    pub async fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.send(buf).await
    }
    pub fn try_send(&self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.get_ref().send(buf)
    }
    pub async fn send_vectored(&self, bufs: &[IoSlice<'_>]) -> std::io::Result<usize> {
        self.inner.send_vectored(bufs).await
    }
}
impl AsyncDevice {
    #[cfg(target_os = "linux")]
    pub fn tx_queue_len(&self) -> crate::Result<u32> {
        self.inner.get_ref().tx_queue_len()
    }
    #[cfg(target_os = "linux")]
    pub fn set_tx_queue_len(&self, tx_queue_len: u32) -> crate::Result<()> {
        self.inner.get_ref().set_tx_queue_len(tx_queue_len)
    }
}
impl AbstractDevice for AsyncDevice {
    #[cfg(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd"
    ))]
    fn name(&self) -> crate::Result<String> {
        self.inner.get_ref().name()
    }
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "freebsd"))]
    fn set_name(&self, name: &str) -> crate::Result<()> {
        self.inner.get_ref().set_name(name)
    }
    #[cfg(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
    ))]
    fn if_index(&self) -> crate::Result<u32> {
        self.inner.get_ref().if_index()
    }
    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "windows"
    ))]
    fn enabled(&self, value: bool) -> crate::Result<()> {
        self.inner.get_ref().enabled(value)
    }
    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "windows"
    ))]
    fn addresses(&self) -> crate::Result<Vec<crate::getifaddrs::Interface>> {
        self.inner.get_ref().addresses()
    }

    #[cfg(target_os = "linux")]
    fn broadcast(&self) -> crate::Result<IpAddr> {
        self.inner.get_ref().broadcast()
    }
    #[cfg(target_os = "linux")]
    fn set_broadcast<A: crate::IntoAddress>(&self, value: A) -> crate::Result<()> {
        self.inner.get_ref().set_broadcast(value)
    }

    #[cfg(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd"
    ))]
    fn set_network_address<A: crate::IntoAddress>(
        &self,
        address: A,
        netmask: A,
        destination: Option<A>,
    ) -> crate::Result<()> {
        self.inner
            .get_ref()
            .set_network_address(address, netmask, destination)
    }
    #[cfg(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd"
    ))]
    fn remove_network_address(&self, addrs: Vec<(IpAddr, u8)>) -> crate::Result<()> {
        self.inner.get_ref().remove_network_address(addrs)
    }
    #[cfg(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd"
    ))]
    fn add_address_v6(&self, addr: IpAddr, prefix: u8) -> crate::Result<()> {
        self.inner.get_ref().add_address_v6(addr, prefix)
    }
    #[cfg(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd"
    ))]
    fn mtu(&self) -> crate::Result<u16> {
        self.inner.get_ref().mtu()
    }
    #[cfg(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd"
    ))]
    fn set_mtu(&self, value: u16) -> crate::Result<()> {
        self.inner.get_ref().set_mtu(value)
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    fn ignore_packet_info(&self) -> bool {
        self.inner.get_ref().ignore_packet_info()
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    fn set_ignore_packet_info(&self, ign: bool) {
        self.inner.get_ref().set_ignore_packet_info(ign)
    }

    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "freebsd",))]
    fn set_mac_address(
        &self,
        eth_addr: [u8; crate::device::ETHER_ADDR_LEN as usize],
    ) -> crate::Result<()> {
        self.inner.get_ref().set_mac_address(eth_addr)
    }
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "freebsd",))]
    fn get_mac_address(&self) -> crate::Result<[u8; crate::device::ETHER_ADDR_LEN as usize]> {
        self.inner.get_ref().get_mac_address()
    }
}
