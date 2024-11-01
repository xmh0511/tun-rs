use crate::platform::Device;
use async_io::Async;
use std::io;
use std::io::IoSlice;

pub struct AsyncFd(Async<Device>);
impl AsyncFd {
    pub fn new(device: Device) -> io::Result<Self> {
        Ok(Self(Async::new(device)?))
    }
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read_with(|device| device.recv(buf)).await
    }
    pub async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.0.write_with(|device| device.send(buf)).await
    }
    pub async fn send_vectored(&self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        self.0.write_with(|device| device.send_vectored(bufs)).await
    }

    pub fn get_ref(&self) -> &Device {
        self.0.get_ref()
    }
}
