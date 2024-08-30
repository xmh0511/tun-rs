use std::io;
use std::sync::Arc;

use crate::platform::windows::PacketVariant;
use crate::platform::DeviceInner;

/// An async TUN device wrapper around a TUN device.
pub struct AsyncDevice {
    inner: Arc<DeviceInner>,
}

/// Returns a shared reference to the underlying Device object.
impl core::ops::Deref for AsyncDevice {
    type Target = DeviceInner;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}
impl Drop for AsyncDevice {
    fn drop(&mut self) {
        let _ = self.inner.shutdown();
    }
}

impl AsyncDevice {
    /// Create a new `AsyncDevice` wrapping around a `Device`.
    pub(crate) fn new(device: DeviceInner) -> io::Result<AsyncDevice> {
        let inner = Arc::new(device);

        Ok(AsyncDevice { inner })
    }

    /// Recv a packet from tun device - Not implemented for windows
    pub async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
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
    pub async fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.send(buf)
    }
}
