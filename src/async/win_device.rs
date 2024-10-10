use crate::device::ETHER_ADDR_LEN;
use crate::getifaddrs::Interface;
use crate::platform::Device;
use crate::{AbstractDevice, IntoAddress};
use std::io;
use std::sync::Arc;

use crate::platform::windows::PacketVariant;

/// An async TUN device wrapper around a TUN device.
pub struct AsyncDevice {
    inner: Arc<Device>,
}

impl Drop for AsyncDevice {
    fn drop(&mut self) {
        let _ = self.inner.shutdown();
    }
}

impl AsyncDevice {
    /// Create a new `AsyncDevice` wrapping around a `Device`.
    pub fn new(device: Device) -> io::Result<AsyncDevice> {
        let inner = Arc::new(device);

        Ok(AsyncDevice { inner })
    }

    /// Recv a packet from tun device - Not implemented for windows
    pub async fn recv(&self, mut buf: &mut [u8]) -> io::Result<usize> {
        match self.try_recv(buf) {
            Ok(len) => return Ok(len),
            Err(e) => {
                if e.kind() != io::ErrorKind::WouldBlock {
                    Err(e)?
                }
            }
        }
        let device = self.inner.clone();
        let packet = tokio::task::spawn_blocking(move || device.driver.receive_blocking())
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))??;

        let mut packet = match &packet {
            PacketVariant::Tun(packet) => packet.bytes(),
            PacketVariant::Tap(packet) => packet.as_ref(),
        };

        match io::copy(&mut packet, &mut buf) {
            Ok(n) => Ok(n as usize),
            Err(e) => Err(e),
        }
    }
    pub fn try_recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.try_recv(buf)
    }

    /// Send a packet to tun device - Not implemented for windows
    pub async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.inner.send(buf)
    }
    pub fn try_send(&self, buf: &[u8]) -> io::Result<usize> {
        self.inner.try_send(buf)
    }
}

impl AbstractDevice for AsyncDevice {
    fn name(&self) -> crate::Result<String> {
        self.inner.name()
    }

    fn set_name(&self, name: &str) -> crate::Result<()> {
        self.inner.set_name(name)
    }

    fn if_index(&self) -> crate::Result<u32> {
        self.inner.if_index()
    }

    fn enabled(&self, value: bool) -> crate::Result<()> {
        self.inner.enabled(value)
    }

    fn addresses(&self) -> crate::Result<Vec<Interface>> {
        self.inner.addresses()
    }

    fn set_network_address<A: IntoAddress>(
        &self,
        address: A,
        netmask: A,
        destination: Option<A>,
    ) -> crate::Result<()> {
        self.inner
            .set_network_address(address, netmask, destination)
    }

    fn mtu(&self) -> crate::Result<u16> {
        self.inner.mtu()
    }

    fn set_mtu(&self, value: u16) -> crate::Result<()> {
        self.inner.set_mtu(value)
    }

    fn set_mac_address(&self, eth_addr: [u8; ETHER_ADDR_LEN as usize]) -> crate::Result<()> {
        self.inner.set_mac_address(eth_addr)
    }

    fn get_mac_address(&self) -> crate::Result<[u8; ETHER_ADDR_LEN as usize]> {
        self.inner.get_mac_address()
    }

    fn remove_network_address(&self, addrs: Vec<(std::net::IpAddr, u8)>) -> crate::Result<()> {
        self.inner.remove_network_address(addrs)
    }

    fn add_address_v6(&self, addr: std::net::IpAddr, prefix: u8) -> crate::Result<()> {
        self.inner.add_address_v6(addr, prefix)
    }
}
