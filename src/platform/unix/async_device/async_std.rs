use crate::platform::DeviceInner;
use ::async_io::Async;
use std::io;
use std::io::{IoSlice, IoSliceMut};
use std::task::{Context, Poll};
pub struct AsyncFd(Async<DeviceInner>);
impl AsyncFd {
    pub fn new(device: DeviceInner) -> io::Result<Self> {
        Ok(Self(Async::new(device)?))
    }
    pub fn into_device(self) -> io::Result<DeviceInner> {
        self.0.into_inner()
    }
    pub async fn readable(&self) -> io::Result<()> {
        self.0.readable().await
    }
    pub fn poll_readable(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0.poll_readable(cx)
    }
    pub async fn writable(&self) -> io::Result<()> {
        self.0.writable().await
    }
    pub fn poll_writable(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0.poll_writable(cx)
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
    pub async fn recv_vectored(&self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        self.0.read_with(|device| device.recv_vectored(bufs)).await
    }

    pub fn get_ref(&self) -> &DeviceInner {
        self.0.get_ref()
    }
}
