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

use crate::platform::DeviceInner;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;

/// An async TUN device wrapper around a TUN device.
pub struct AsyncDevice {
    inner: AsyncFd<DeviceInner>,
}

/// Returns a shared reference to the underlying Device object.
impl core::ops::Deref for AsyncDevice {
    type Target = DeviceInner;

    fn deref(&self) -> &Self::Target {
        self.inner.get_ref()
    }
}

/// Returns a mutable reference to the underlying Device object.
impl core::ops::DerefMut for AsyncDevice {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.inner.get_mut()
    }
}

impl AsyncDevice {
    /// Create a new `AsyncDevice` wrapping around a `Device`.
    pub fn new(device: DeviceInner) -> std::io::Result<AsyncDevice> {
        device.set_nonblock()?;
        Ok(AsyncDevice {
            inner: AsyncFd::new(device)?,
        })
    }

    /// Recv a packet from tun device
    pub async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner
            .async_io(Interest::READABLE, |device| device.recv(buf))
            .await
    }

    /// Send a packet to tun device
    pub async fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner
            .async_io(Interest::READABLE, |device| device.send(buf))
            .await
    }
    pub fn shutdown(&self) -> std::io::Result<()> {
        todo!()
    }
}
