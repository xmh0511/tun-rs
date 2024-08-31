use crate::device::ETHER_ADDR_LEN;
use crate::platform::Device;
use crate::{AbstractDevice, IntoAddress};
use std::io;
use std::net::IpAddr;
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
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let device = self.inner.clone();
        let packet = tokio::task::spawn_blocking(move || device.driver.receive_blocking())
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))??;
        let packet = match &packet {
            PacketVariant::Tun(packet) => packet.bytes(),
            PacketVariant::Tap(packet) => packet.as_ref(),
        };
        let len = packet.len();
        if buf.len() < len {
            Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "buffer too small",
            ))?;
        }
        buf[0..len].copy_from_slice(packet);
        Ok(len)
    }

    /// Send a packet to tun device - Not implemented for windows
    pub async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.inner.send(buf)
    }
}

impl AbstractDevice for AsyncDevice {
    fn name(&self) -> crate::Result<String> {
        self.inner.name()
    }

    fn set_name(&self, name: &str) -> crate::Result<()> {
        self.inner.set_name(name)
    }

    fn enabled(&self, value: bool) -> crate::Result<()> {
        self.inner.enabled(value)
    }

    fn address(&self) -> crate::Result<IpAddr> {
        self.inner.address()
    }

    fn destination(&self) -> crate::Result<IpAddr> {
        self.inner.destination()
    }

    fn netmask(&self) -> crate::Result<IpAddr> {
        self.inner.netmask()
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
}
