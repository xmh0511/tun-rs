#[cfg(target_os = "linux")]
use crate::platform::offload::{handle_gro, VirtioNetHdr, VIRTIO_NET_HDR_LEN};
use crate::platform::Device;
#[cfg(target_os = "linux")]
use crate::platform::GROTable;
use crate::r#async::async_device::AsyncFd;
use std::io;
use std::io::IoSlice;
#[allow(unused_imports)]
use std::net::IpAddr;
#[cfg(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "ios",
    target_os = "android"
))]
use std::os::fd::{FromRawFd, RawFd};

/// An async TUN device wrapper around a TUN device.
pub struct AsyncDevice {
    inner: AsyncFd,
}

impl FromRawFd for AsyncDevice {
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        AsyncDevice::from_fd(fd).unwrap()
    }
}

impl AsyncDevice {
    /// Create a new `AsyncDevice` wrapping around a `Device`.
    pub fn new(device: Device) -> io::Result<AsyncDevice> {
        Ok(AsyncDevice {
            inner: AsyncFd::new(device)?,
        })
    }

    /// # Safety
    /// This method is safe if the provided fd is valid
    /// Construct a AsyncDevice from an existing file descriptor
    pub unsafe fn from_fd(fd: RawFd) -> io::Result<AsyncDevice> {
        AsyncDevice::new(Device::from_fd(fd)?)
    }

    /// Recv a packet from tun device
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.recv(buf).await
    }
    pub fn try_recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.get_ref().recv(buf)
    }

    /// Send a packet to tun device
    pub async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.inner.send(buf).await
    }
    pub fn try_send(&self, buf: &[u8]) -> io::Result<usize> {
        self.inner.get_ref().send(buf)
    }
    pub async fn send_vectored(&self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        self.inner.send_vectored(bufs).await
    }
}

impl AsyncDevice {
    /// Recv a packet from tun device.
    /// If offload is enabled. This method can be used to obtain processed data.
    ///
    /// original_buffer is used to store raw data, including the VirtioNetHdr and the unsplit IP packet. The recommended size is 10 + 65535.
    /// bufs and sizes are used to store the segmented IP packets. bufs.len == sizes.len > 65535/MTU
    /// offset: Starting position
    #[cfg(target_os = "linux")]
    pub async fn recv_multiple<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        original_buffer: &mut [u8],
        bufs: &mut [B],
        sizes: &mut [usize],
        offset: usize,
    ) -> io::Result<usize> {
        if bufs.is_empty() || bufs.len() != sizes.len() {
            return Err(io::Error::new(io::ErrorKind::Other, "bufs error"));
        }
        let tun = self.inner.get_ref();
        if tun.vnet_hdr {
            let len = self.recv(original_buffer).await?;
            if len <= VIRTIO_NET_HDR_LEN {
                Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!(
                        "length of packet ({len}) <= VIRTIO_NET_HDR_LEN ({VIRTIO_NET_HDR_LEN})",
                    ),
                ))?
            }
            let hdr = VirtioNetHdr::decode(&original_buffer[..VIRTIO_NET_HDR_LEN])?;
            tun.handle_virtio_read(
                hdr,
                &mut original_buffer[VIRTIO_NET_HDR_LEN..len],
                bufs,
                sizes,
                offset,
            )
        } else {
            let len = self.recv(bufs[0].as_mut()).await?;
            sizes[0] = len;
            Ok(1)
        }
    }
    /// send multiple fragmented data packets.
    /// GROTable can be reused, as it is used to assist in data merging.
    /// Offset is the starting position of the data. Need to meet offset>10.
    #[cfg(target_os = "linux")]
    pub async fn send_multiple<B: crate::platform::ExpandBuffer>(
        &self,
        gro_table: &mut GROTable,
        bufs: &mut [B],
        mut offset: usize,
    ) -> io::Result<usize> {
        gro_table.reset();
        let tun = self.inner.get_ref();
        if tun.vnet_hdr {
            handle_gro(
                bufs,
                offset,
                &mut gro_table.tcp_gro_table,
                &mut gro_table.udp_gro_table,
                tun.udp_gso,
                &mut gro_table.to_write,
            )?;
            offset -= VIRTIO_NET_HDR_LEN;
        } else {
            for i in 0..bufs.len() {
                gro_table.to_write.push(i);
            }
        }

        let mut total = 0;
        let mut err = Ok(());
        for buf_idx in &gro_table.to_write {
            match self.send(&bufs[*buf_idx].as_ref()[offset..]).await {
                Ok(n) => {
                    total += n;
                }
                Err(e) => {
                    if let Some(code) = e.raw_os_error() {
                        if libc::EBADFD == code {
                            return Err(e);
                        }
                    }
                    err = Err(e)
                }
            }
        }
        err?;
        Ok(total)
    }
}

impl AsyncDevice {
    #[cfg(target_os = "linux")]
    pub fn tx_queue_len(&self) -> crate::Result<u32> {
        self.inner.get_ref().tx_queue_len()
    }
    #[cfg(target_os = "linux")]
    pub fn set_tx_queue_len(&self, tx_queue_len: u32) -> crate::Result<()> {
        self.inner.get_ref().set_tx_queue_len(tx_queue_len)
    }
    #[cfg(target_os = "linux")]
    pub fn udp_gso(&self) -> bool {
        self.inner.get_ref().udp_gso()
    }
    #[cfg(target_os = "linux")]
    pub fn tcp_gso(&self) -> bool {
        self.inner.get_ref().tcp_gso()
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
    pub fn name(&self) -> crate::Result<String> {
        self.inner.get_ref().name()
    }
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    pub fn set_name(&self, name: &str) -> crate::Result<()> {
        self.inner.get_ref().set_name(name)
    }
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd",))]
    pub fn if_index(&self) -> crate::Result<u32> {
        self.inner.get_ref().if_index()
    }
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd",))]
    pub fn enabled(&self, value: bool) -> crate::Result<()> {
        self.inner.get_ref().enabled(value)
    }
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd",))]
    pub fn addresses(&self) -> crate::Result<Vec<crate::getifaddrs::Interface>> {
        self.inner.get_ref().addresses()
    }

    #[cfg(target_os = "linux")]
    pub fn broadcast(&self) -> crate::Result<IpAddr> {
        self.inner.get_ref().broadcast()
    }
    #[cfg(target_os = "linux")]
    pub fn set_broadcast<A: crate::IntoAddress>(&self, value: A) -> crate::Result<()> {
        self.inner.get_ref().set_broadcast(value)
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
    pub fn set_network_address<A: crate::IntoAddress>(
        &self,
        address: A,
        netmask: A,
        destination: Option<A>,
    ) -> crate::Result<()> {
        self.inner
            .get_ref()
            .set_network_address(address, netmask, destination)
    }
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
    pub fn remove_network_address(&self, addrs: Vec<(IpAddr, u8)>) -> crate::Result<()> {
        self.inner.get_ref().remove_network_address(addrs)
    }
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
    pub fn add_address_v6(&self, addr: IpAddr, prefix: u8) -> crate::Result<()> {
        self.inner.get_ref().add_address_v6(addr, prefix)
    }
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
    pub fn mtu(&self) -> crate::Result<u16> {
        self.inner.get_ref().mtu()
    }
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
    pub fn set_mtu(&self, value: u16) -> crate::Result<()> {
        self.inner.get_ref().set_mtu(value)
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    pub fn ignore_packet_info(&self) -> bool {
        self.inner.get_ref().ignore_packet_info()
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    pub fn set_ignore_packet_info(&self, ign: bool) {
        self.inner.get_ref().set_ignore_packet_info(ign)
    }

    #[cfg(any(target_os = "linux", target_os = "freebsd",))]
    pub fn set_mac_address(
        &self,
        eth_addr: [u8; crate::device::ETHER_ADDR_LEN as usize],
    ) -> crate::Result<()> {
        self.inner.get_ref().set_mac_address(eth_addr)
    }
    #[cfg(any(target_os = "linux", target_os = "freebsd",))]
    pub fn mac_address(&self) -> crate::Result<[u8; crate::device::ETHER_ADDR_LEN as usize]> {
        self.inner.get_ref().get_mac_address()
    }
}
