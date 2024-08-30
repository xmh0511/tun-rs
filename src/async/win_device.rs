//            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//                    Version 2, December 2004
//
// Copyleft (ↄ) meh. <meh@schizofreni.co> | http://meh.schizofreni.co
//
// Everyone is permitted to copy and distribute verbatim or modified
// copies of this license document, and changing it is allowed as long
// as the name is changed.
//
//            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION
//
//  0. You just DO WHAT THE FUCK YOU WANT TO.

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
