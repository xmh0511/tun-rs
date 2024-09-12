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
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let packet = match self.inner.driver.try_receive()? {
            None => {
                let device = self.inner.clone();
                tokio::task::spawn_blocking(move || device.driver.receive_blocking())
                    .await
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))??
            }
            Some(packet) => packet,
        };
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
}
