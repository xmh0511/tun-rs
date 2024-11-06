use crate::platform::Device;
use ::tokio::io::unix::AsyncFd as TokioAsyncFd;
use ::tokio::io::Interest;
use std::io;
use std::io::IoSlice;

pub struct AsyncFd(TokioAsyncFd<Device>);
impl AsyncFd {
    pub fn new(device: Device) -> io::Result<Self> {
        device.set_nonblock()?;
        Ok(Self(TokioAsyncFd::new(device)?))
    }
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.0
            .async_io(Interest::READABLE.add(Interest::ERROR), |device| {
                device.recv(buf)
            })
            .await
    }
    pub async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.0
            .async_io(Interest::WRITABLE, |device| device.send(buf))
            .await
    }
    pub async fn send_vectored(&self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        self.0
            .async_io(Interest::WRITABLE, |device| device.send_vectored(bufs))
            .await
    }

    pub fn get_ref(&self) -> &Device {
        self.0.get_ref()
    }
}
