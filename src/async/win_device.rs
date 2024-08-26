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

use core::pin::Pin;
use core::task::{Context, Poll};
use std::io;
use std::io::Error;
use std::sync::Arc;

use super::TunPacketCodec;
use crate::device::AbstractDevice;
use crate::platform::windows::{Driver, PacketVariant};
use crate::platform::DeviceInner;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc::error::TrySendError;
use tokio_util::codec::Framed;

/// An async TUN device wrapper around a TUN device.
pub struct AsyncDevice {
    inner: DeviceInner,
    session_reader: DeviceReader,
    session_writer: DeviceWriter,
}

/// Returns a shared reference to the underlying Device object.
impl core::ops::Deref for AsyncDevice {
    type Target = DeviceInner;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// Returns a mutable reference to the underlying Device object.
impl core::ops::DerefMut for AsyncDevice {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl AsyncDevice {
    /// Create a new `AsyncDevice` wrapping around a `Device`.
    pub fn new(device: DeviceInner) -> io::Result<AsyncDevice> {
        let session_reader = DeviceReader::new(device.driver.clone())?;
        let session_writer = DeviceWriter::new(device.driver.clone())?;
        Ok(AsyncDevice {
            inner: device,
            session_reader,
            session_writer,
        })
    }

    /// Consumes this AsyncDevice and return a Framed object (unified Stream and Sink interface)
    pub fn into_framed(self) -> Framed<Self, TunPacketCodec> {
        let mtu = self.mtu().unwrap_or(crate::DEFAULT_MTU);
        let codec = TunPacketCodec::new(mtu as usize);
        // guarantee to avoid the mtu of wintun may far away larger than the default provided capacity of ReadBuf of Framed
        Framed::with_capacity(self, codec, mtu as usize)
    }
    pub fn split(self) -> io::Result<(DeviceWriter, DeviceReader)> {
        Ok((self.session_writer, self.session_reader))
    }

    /// Recv a packet from tun device - Not implemented for windows
    pub async fn recv(&self, _buf: &mut [u8]) -> std::io::Result<usize> {
        unimplemented!()
    }

    /// Send a packet to tun device - Not implemented for windows
    pub async fn send(&self, _buf: &[u8]) -> std::io::Result<usize> {
        unimplemented!()
    }
}

impl AsyncRead for AsyncDevice {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.session_reader).poll_read(cx, buf)
    }
}

impl AsyncWrite for AsyncDevice {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        Pin::new(&mut self.session_writer).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.session_writer).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.session_writer).poll_shutdown(cx)
    }
}

pub struct DeviceReader {
    receiver: tokio::sync::mpsc::Receiver<PacketVariant>,
    _task: std::thread::JoinHandle<()>,
}
impl DeviceReader {
    fn new(session: Arc<Driver>) -> Result<DeviceReader, io::Error> {
        let (receiver_tx, receiver_rx) = tokio::sync::mpsc::channel(1024);
        let task = std::thread::spawn(move || loop {
            match session.receive_blocking() {
                Ok(packet) => {
                    if let Err(err) = receiver_tx.try_send(packet) {
                        match err {
                            TrySendError::Full(_) => {
                                log::error!("receiver_tx Full");
                                continue;
                            }
                            TrySendError::Closed(_) => {
                                log::error!("receiver_tx Closed");
                                break;
                            }
                        }
                    }
                }
                Err(err) => {
                    log::info!("{}", err);
                    break;
                }
            }
        });
        Ok(DeviceReader {
            receiver: receiver_rx,
            _task: task,
        })
    }
}
pub struct DeviceWriter {
    session: Arc<Driver>,
}
impl DeviceWriter {
    fn new(session: Arc<Driver>) -> Result<DeviceWriter, io::Error> {
        Ok(Self { session })
    }
}

impl AsyncRead for DeviceReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match std::task::ready!(self.receiver.poll_recv(cx)) {
            Some(bytes) => {
                match bytes {
                    PacketVariant::Tap(bytes) => {
                        buf.put_slice(&bytes);
                    }
                    PacketVariant::Tun(bytes) => {
                        buf.put_slice(bytes.bytes());
                    }
                }
                std::task::Poll::Ready(Ok(()))
            }
            None => std::task::Poll::Ready(Ok(())),
        }
    }
}

impl AsyncWrite for DeviceWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        let len = self.session.write_by_ref(buf)?;
        Poll::Ready(Ok(len))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }
}
