use crate::configuration::configure;
use crate::getifaddrs::{self, Interface};
use crate::platform::linux::offload::{
    gso_none_checksum, gso_split, handle_gro, VirtioNetHdr, VIRTIO_NET_HDR_F_NEEDS_CSUM,
    VIRTIO_NET_HDR_GSO_NONE, VIRTIO_NET_HDR_GSO_TCPV4, VIRTIO_NET_HDR_GSO_TCPV6,
    VIRTIO_NET_HDR_GSO_UDP_L4, VIRTIO_NET_HDR_LEN,
};
use crate::platform::{AsMutRefBytesMut, GROTable};
use crate::{
    configuration::{Configuration, Layer},
    device::{AbstractDevice, ETHER_ADDR_LEN},
    error::{Error, Result},
    platform::linux::sys::*,
    platform::posix::{ipaddr_to_sockaddr, sockaddr_union, Fd, Tun},
    IntoAddress,
};
use libc::{
    self, c_char, c_short, ifreq, in6_ifreq, AF_INET, AF_INET6, ARPHRD_ETHER, IFF_MULTI_QUEUE,
    IFF_NO_PI, IFF_RUNNING, IFF_TAP, IFF_TUN, IFF_UP, IFNAMSIZ, O_RDWR, SOCK_DGRAM,
};
use mac_address::mac_address_by_name;
use std::{
    ffi::CString,
    io, mem,
    net::{IpAddr, Ipv4Addr},
    os::unix::io::{AsRawFd, RawFd},
    ptr,
};

const OVERWRITE_SIZE: usize = mem::size_of::<libc::__c_anonymous_ifr_ifru>();

/// A TUN device using the TUN/TAP Linux driver.
pub struct Device {
    pub(crate) tun: Tun,
    pub(crate) vnet_hdr: bool,
    pub(crate) udp_gso: bool,
}

impl Device {
    /// Create a new `Device` for the given `Configuration`.
    pub fn new(config: &Configuration) -> Result<Self> {
        let dev_name = match config.name.as_ref() {
            Some(tun_name) => {
                let tun_name = CString::new(tun_name.clone())?;

                if tun_name.as_bytes_with_nul().len() > IFNAMSIZ {
                    return Err(Error::NameTooLong);
                }

                Some(tun_name)
            }

            None => None,
        };
        unsafe {
            let mut req: ifreq = mem::zeroed();

            if let Some(dev_name) = dev_name.as_ref() {
                ptr::copy_nonoverlapping(
                    dev_name.as_ptr() as *const c_char,
                    req.ifr_name.as_mut_ptr(),
                    dev_name.as_bytes_with_nul().len(),
                );
            }

            let device_type: c_short = config.layer.unwrap_or(Layer::L3).into();
            let queues_num = 1;
            let iff_no_pi = IFF_NO_PI as c_short;
            let iff_multi_queue = IFF_MULTI_QUEUE as c_short;
            let iff_vnet_hdr = libc::IFF_VNET_HDR as c_short;
            let packet_information = config.platform_config.packet_information;
            let offload = config.platform_config.offload;
            req.ifr_ifru.ifru_flags = device_type
                | if packet_information { 0 } else { iff_no_pi }
                | if queues_num > 1 { iff_multi_queue } else { 0 }
                | if offload { iff_vnet_hdr } else { 0 };

            let fd = libc::open(b"/dev/net/tun\0".as_ptr() as *const _, O_RDWR);
            let tun_fd = Fd::new(fd, true)?;
            if let Err(err) = tunsetiff(tun_fd.inner, &mut req as *mut _ as *mut _) {
                return Err(io::Error::from(err).into());
            }
            let (vnet_hdr, udp_gso) = if offload && libc::IFF_VNET_HDR != 0 {
                // tunTCPOffloads were added in Linux v2.6. We require their support if IFF_VNET_HDR is set.
                let tun_tcp_offloads = libc::TUN_F_CSUM | libc::TUN_F_TSO4 | libc::TUN_F_TSO6;
                let tun_udp_offloads = libc::TUN_F_USO4 | libc::TUN_F_USO6;
                if let Err(err) = tunsetoffload(tun_fd.inner, tun_tcp_offloads as _) {
                    log::warn!("unsupported offload: {err:?}");
                    (false, false)
                } else {
                    // tunUDPOffloads were added in Linux v6.2. We do not return an
                    // error if they are unsupported at runtime.
                    let rs =
                        tunsetoffload(tun_fd.inner, (tun_tcp_offloads | tun_udp_offloads) as _);
                    (true, rs.is_ok())
                }
            } else {
                (false, false)
            };

            let device = Device {
                tun: Tun::new(tun_fd),
                vnet_hdr,
                udp_gso,
            };
            configure(&device, config)?;
            if let Some(tx_queue_len) = config.platform_config.tx_queue_len {
                let mut ifreq = device.request()?;
                ifreq.ifr_ifru.ifru_metric = tx_queue_len as _;
                if let Err(err) = change_tx_queue_len(ctl()?.as_raw_fd(), &ifreq) {
                    return Err(io::Error::from(err).into());
                }
            }
            Ok(device)
        }
    }
    pub(crate) fn from_tun(tun: Tun) -> Self {
        Self {
            tun,
            vnet_hdr: false,
            udp_gso: false,
        }
    }
    pub fn udp_gso(&self) -> bool {
        self.udp_gso
    }
    pub fn tcp_gso(&self) -> bool {
        self.vnet_hdr
    }
    pub fn set_tx_queue_len(&self, tx_queue_len: u32) -> Result<()> {
        unsafe {
            let mut ifreq = self.request()?;
            ifreq.ifr_ifru.ifru_metric = tx_queue_len as _;
            if let Err(err) = change_tx_queue_len(ctl()?.as_raw_fd(), &ifreq) {
                return Err(io::Error::from(err).into());
            }
        }
        Ok(())
    }
    pub fn tx_queue_len(&self) -> Result<u32> {
        unsafe {
            let mut ifreq = self.request()?;
            if let Err(err) = tx_queue_len(ctl()?.as_raw_fd(), &mut ifreq) {
                return Err(io::Error::from(err).into());
            }
            Ok(ifreq.ifr_ifru.ifru_metric as _)
        }
    }
    /// Make the device persistent.
    pub fn persist(&self) -> Result<()> {
        unsafe {
            if let Err(err) = tunsetpersist(self.as_raw_fd(), &1) {
                Err(io::Error::from(err).into())
            } else {
                Ok(())
            }
        }
    }

    /// Set the owner of the device.
    pub fn user(&self, value: i32) -> Result<()> {
        unsafe {
            if let Err(err) = tunsetowner(self.as_raw_fd(), &value) {
                Err(io::Error::from(err).into())
            } else {
                Ok(())
            }
        }
    }

    /// Set the group of the device.
    pub fn group(&self, value: i32) -> Result<()> {
        unsafe {
            if let Err(err) = tunsetgroup(self.as_raw_fd(), &value) {
                Err(io::Error::from(err).into())
            } else {
                Ok(())
            }
        }
    }
    /// send multiple fragmented data packets.
    /// GROTable can be reused, as it is used to assist in data merging.
    /// Offset is the starting position of the data. Need to meet offset>10.
    pub fn send_multiple<B: AsMutRefBytesMut>(
        &self,
        gro_table: &mut GROTable,
        bufs: &mut [B],
        mut offset: usize,
    ) -> io::Result<usize> {
        gro_table.reset();
        if self.vnet_hdr {
            handle_gro(
                bufs,
                offset,
                &mut gro_table.tcp_gro_table,
                &mut gro_table.udp_gro_table,
                self.udp_gso,
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
            match self.send(&bufs[*buf_idx].as_ref()[offset..]) {
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
    /// Recv a packet from tun device.
    /// If offload is enabled. This method can be used to obtain processed data.
    ///
    /// original_buffer is used to store raw data, including the VirtioNetHdr and the unsplit IP packet. The recommended size is 10 + 65535.
    /// bufs and sizes are used to store the segmented IP packets. bufs.len == sizes.len > 65535/MTU
    /// offset: Starting position
    pub fn recv_multiple<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        original_buffer: &mut [u8],
        bufs: &mut [B],
        sizes: &mut [usize],
        offset: usize,
    ) -> io::Result<usize> {
        if bufs.is_empty() || bufs.len() != sizes.len() {
            return Err(io::Error::new(io::ErrorKind::Other, "bufs error"));
        }
        if self.vnet_hdr {
            let len = self.recv(original_buffer)?;
            if len <= VIRTIO_NET_HDR_LEN {
                Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!(
                        "length of packet ({len}) <= VIRTIO_NET_HDR_LEN ({VIRTIO_NET_HDR_LEN})",
                    ),
                ))?
            }
            let hdr = VirtioNetHdr::decode(&original_buffer[..VIRTIO_NET_HDR_LEN])?;
            self.handle_virtio_read(
                hdr,
                &mut original_buffer[VIRTIO_NET_HDR_LEN..len],
                bufs,
                sizes,
                offset,
            )
        } else {
            let len = self.recv(bufs[0].as_mut())?;
            sizes[0] = len;
            Ok(1)
        }
    }
    /// https://github.com/WireGuard/wireguard-go/blob/12269c2761734b15625017d8565745096325392f/tun/tun_linux.go#L375
    /// handleVirtioRead splits in into bufs, leaving offset bytes at the front of
    /// each buffer. It mutates sizes to reflect the size of each element of bufs,
    /// and returns the number of packets read.
    pub(crate) fn handle_virtio_read<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        mut hdr: VirtioNetHdr,
        input: &mut [u8],
        bufs: &mut [B],
        sizes: &mut [usize],
        offset: usize,
    ) -> io::Result<usize> {
        let len = input.len();
        if hdr.gso_type == VIRTIO_NET_HDR_GSO_NONE {
            if hdr.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM != 0 {
                // This means CHECKSUM_PARTIAL in skb context. We are responsible
                // for computing the checksum starting at hdr.csumStart and placing
                // at hdr.csumOffset.
                gso_none_checksum(input, hdr.csum_start, hdr.csum_offset);
            }
            if bufs[0].as_ref()[offset..].len() < len {
                Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!(
                        "read len {len} overflows bufs element len {}",
                        bufs[0].as_ref().len()
                    ),
                ))?
            }
            sizes[0] = len;
            bufs[0].as_mut()[offset..offset + len].copy_from_slice(input);
            return Ok(1);
        }
        if hdr.gso_type != VIRTIO_NET_HDR_GSO_TCPV4
            && hdr.gso_type != VIRTIO_NET_HDR_GSO_TCPV6
            && hdr.gso_type != VIRTIO_NET_HDR_GSO_UDP_L4
        {
            Err(io::Error::new(
                io::ErrorKind::Other,
                format!("unsupported virtio GSO type: {}", hdr.gso_type),
            ))?
        }
        let ip_version = input[0] >> 4;
        match ip_version {
            4 => {
                if hdr.gso_type != VIRTIO_NET_HDR_GSO_TCPV4
                    && hdr.gso_type != VIRTIO_NET_HDR_GSO_UDP_L4
                {
                    Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("ip header version: 4, GSO type: {}", hdr.gso_type),
                    ))?
                }
            }
            6 => {
                if hdr.gso_type != VIRTIO_NET_HDR_GSO_TCPV6
                    && hdr.gso_type != VIRTIO_NET_HDR_GSO_UDP_L4
                {
                    Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("ip header version: 6, GSO type: {}", hdr.gso_type),
                    ))?
                }
            }
            ip_version => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("invalid ip header version: {}", ip_version),
            ))?,
        }
        // Don't trust hdr.hdrLen from the kernel as it can be equal to the length
        // of the entire first packet when the kernel is handling it as part of a
        // FORWARD path. Instead, parse the transport header length and add it onto
        // csumStart, which is synonymous for IP header length.
        if hdr.gso_type == VIRTIO_NET_HDR_GSO_UDP_L4 {
            hdr.hdr_len = hdr.csum_start + 8
        } else {
            if len <= hdr.csum_start as usize + 12 {
                Err(io::Error::new(io::ErrorKind::Other, "packet is too short"))?
            }

            let tcp_h_len = ((input[hdr.csum_start as usize + 12] as u16) >> 4) * 4;
            if !(20..=60).contains(&tcp_h_len) {
                // A TCP header must be between 20 and 60 bytes in length.
                Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("tcp header len is invalid: {tcp_h_len}"),
                ))?
            }
            hdr.hdr_len = hdr.csum_start + tcp_h_len
        }
        if len < hdr.hdr_len as usize {
            Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "length of packet ({len}) < virtioNetHdr.hdr_len ({})",
                    hdr.hdr_len
                ),
            ))?
        }
        if hdr.hdr_len < hdr.csum_start {
            Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "virtioNetHdr.hdrLen ({}) < virtioNetHdr.csumStart ({})",
                    hdr.hdr_len, hdr.csum_start
                ),
            ))?
        }
        let c_sum_at = (hdr.csum_start + hdr.csum_offset) as usize;
        if c_sum_at + 1 >= len {
            Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "end of checksum offset ({}) exceeds packet length ({len})",
                    c_sum_at + 1,
                ),
            ))?
        }
        gso_split(input, hdr, bufs, sizes, offset, ip_version == 6)
    }
}

impl Device {
    /// Prepare a new request.
    unsafe fn request(&self) -> Result<ifreq> {
        request(&self.name()?)
    }

    fn set_address(&self, value: IpAddr, mask: Option<u32>) -> Result<()> {
        unsafe {
            if let Ok(addrs) = self.addresses() {
                for addr in addrs {
                    match addr.address {
                        IpAddr::V4(_) => {
                            let mut req = self.request()?;
                            ipaddr_to_sockaddr(
                                IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                                0,
                                &mut req.ifr_ifru.ifru_addr,
                                OVERWRITE_SIZE,
                            );
                            if let Err(err) = siocsifaddr(ctl()?.as_raw_fd(), &req) {
                                log::error!("{err:?}");
                            }
                        }
                        IpAddr::V6(_) => {
                            let if_index = {
                                let name = self.name()?;
                                let name = CString::new(name)?;
                                libc::if_nametoindex(name.as_ptr())
                            };
                            let ctl = ctl_v6()?;
                            let mut ifrv6: in6_ifreq = mem::zeroed();
                            ifrv6.ifr6_ifindex = if_index as i32;
                            ifrv6.ifr6_prefixlen = if let Some(v) = addr.netmask {
                                ipnet::ip_mask_to_prefix(v).unwrap_or(64) as u32
                            } else {
                                64
                            };
                            ifrv6.ifr6_addr =
                                sockaddr_union::from(std::net::SocketAddr::new(addr.address, 0))
                                    .addr6
                                    .sin6_addr;
                            if let Err(e) = siocdifaddr_in6(ctl.as_raw_fd(), &ifrv6) {
                                log::error!("{e:?}");
                            }
                        }
                    }
                }
            }
            match value {
                IpAddr::V4(addr) => {
                    let mut req = self.request()?;
                    ipaddr_to_sockaddr(addr, 0, &mut req.ifr_ifru.ifru_addr, OVERWRITE_SIZE);
                    if let Err(err) = siocsifaddr(ctl()?.as_raw_fd(), &req) {
                        return Err(io::Error::from(err).into());
                    }
                }
                IpAddr::V6(_) => {
                    let if_index = {
                        let name = self.name()?;
                        let name = CString::new(name)?;
                        libc::if_nametoindex(name.as_ptr())
                    };
                    let ctl = ctl_v6()?;
                    let mut ifrv6: in6_ifreq = mem::zeroed();
                    ifrv6.ifr6_ifindex = if_index as i32;
                    if let Ok(addrs) = self.addresses() {
                        for addr in addrs {
                            if addr.address.is_ipv6() {
                                ifrv6.ifr6_prefixlen = if let Some(v) = addr.netmask {
                                    ipnet::ip_mask_to_prefix(v).unwrap_or(64) as u32
                                } else {
                                    64
                                };
                                ifrv6.ifr6_addr = sockaddr_union::from(std::net::SocketAddr::new(
                                    addr.address,
                                    0,
                                ))
                                .addr6
                                .sin6_addr;
                                if let Err(e) = siocdifaddr_in6(ctl.as_raw_fd(), &ifrv6) {
                                    log::error!("{e:?}");
                                }
                            }
                        }
                    }
                    ifrv6.ifr6_prefixlen = mask.unwrap_or(64);
                    ifrv6.ifr6_addr = sockaddr_union::from(std::net::SocketAddr::new(value, 0))
                        .addr6
                        .sin6_addr;
                    if let Err(err) = siocsifaddr_in6(ctl.as_raw_fd(), &ifrv6) {
                        return Err(io::Error::from(err).into());
                    }
                }
            }
            Ok(())
        }
    }
    fn set_netmask(&self, value: IpAddr) -> Result<()> {
        unsafe {
            match value {
                IpAddr::V4(addr) => {
                    let mut req = self.request()?;
                    ipaddr_to_sockaddr(addr, 0, &mut req.ifr_ifru.ifru_netmask, OVERWRITE_SIZE);
                    if let Err(err) = siocsifnetmask(ctl()?.as_raw_fd(), &req) {
                        return Err(io::Error::from(err).into());
                    }
                }
                IpAddr::V6(_) => {
                    unreachable!()
                }
            }
            Ok(())
        }
    }

    fn set_destination<A: IntoAddress>(&self, value: A) -> Result<()> {
        let value = value.into_address()?;
        unsafe {
            match value {
                IpAddr::V4(addr) => {
                    let mut req = self.request()?;
                    ipaddr_to_sockaddr(addr, 0, &mut req.ifr_ifru.ifru_dstaddr, OVERWRITE_SIZE);
                    if let Err(err) = siocsifdstaddr(ctl()?.as_raw_fd(), &req) {
                        return Err(io::Error::from(err).into());
                    }
                }
                IpAddr::V6(_) => {
                    unreachable!()
                }
            }
            Ok(())
        }
    }
}

unsafe fn ctl() -> io::Result<Fd> {
    Fd::new(libc::socket(AF_INET, SOCK_DGRAM, 0), true)
}

unsafe fn ctl_v6() -> io::Result<Fd> {
    Fd::new(libc::socket(AF_INET6, SOCK_DGRAM, 0), true)
}

unsafe fn name(fd: RawFd) -> io::Result<String> {
    let mut req: ifreq = mem::zeroed();
    if let Err(err) = tungetiff(fd, &mut req as *mut _ as *mut _) {
        return Err(io::Error::from(err));
    }
    let c_str = std::ffi::CStr::from_ptr(req.ifr_name.as_ptr() as *const c_char);
    let tun_name = c_str.to_string_lossy().into_owned();
    Ok(tun_name)
}

unsafe fn request(name: &str) -> Result<ifreq> {
    let mut req: ifreq = mem::zeroed();
    ptr::copy_nonoverlapping(
        name.as_ptr() as *const c_char,
        req.ifr_name.as_mut_ptr(),
        name.len(),
    );
    Ok(req)
}

impl AbstractDevice for Device {
    fn name(&self) -> Result<String> {
        unsafe { name(self.as_raw_fd()).map_err(|e| e.into()) }
    }

    fn set_name(&self, value: &str) -> Result<()> {
        unsafe {
            let tun_name = CString::new(value)?;

            if tun_name.as_bytes_with_nul().len() > IFNAMSIZ {
                return Err(Error::NameTooLong);
            }

            let mut req = self.request()?;
            ptr::copy_nonoverlapping(
                tun_name.as_ptr() as *const c_char,
                req.ifr_ifru.ifru_newname.as_mut_ptr(),
                value.len(),
            );

            if let Err(err) = siocsifname(ctl()?.as_raw_fd(), &req) {
                return Err(io::Error::from(err).into());
            }

            Ok(())
        }
    }

    fn if_index(&self) -> Result<u32> {
        let if_name = self.name()?;
        let index = Self::get_if_index(&if_name)?;
        Ok(index)
    }

    fn enabled(&self, value: bool) -> Result<()> {
        unsafe {
            let ctl = ctl()?;
            let mut req = self.request()?;

            if let Err(err) = siocgifflags(ctl.as_raw_fd(), &mut req) {
                return Err(io::Error::from(err).into());
            }

            if value {
                req.ifr_ifru.ifru_flags |= (IFF_UP | IFF_RUNNING) as c_short;
            } else {
                req.ifr_ifru.ifru_flags &= !(IFF_UP as c_short);
            }

            if let Err(err) = siocsifflags(ctl.as_raw_fd(), &req) {
                return Err(io::Error::from(err).into());
            }

            Ok(())
        }
    }

    fn addresses(&self) -> Result<Vec<Interface>> {
        let if_name = self.name()?;
        let addrs = getifaddrs::getifaddrs()?;
        let ifs = addrs
            .filter(|v| v.name == if_name)
            .collect::<Vec<Interface>>();
        Ok(ifs)
    }

    fn broadcast(&self) -> Result<IpAddr> {
        unsafe {
            let mut req = self.request()?;
            if let Err(err) = siocgifbrdaddr(ctl()?.as_raw_fd(), &mut req) {
                return Err(io::Error::from(err).into());
            }
            let sa = sockaddr_union::from(req.ifr_ifru.ifru_broadaddr);
            Ok(std::net::SocketAddr::try_from(sa)?.ip())
        }
    }

    fn set_broadcast<A: IntoAddress>(&self, value: A) -> Result<()> {
        let value = value.into_address()?;
        unsafe {
            let mut req = self.request()?;
            ipaddr_to_sockaddr(value, 0, &mut req.ifr_ifru.ifru_broadaddr, OVERWRITE_SIZE);
            if let Err(err) = siocsifbrdaddr(ctl()?.as_raw_fd(), &req) {
                return Err(io::Error::from(err).into());
            }
            Ok(())
        }
    }

    fn set_network_address<A: IntoAddress>(
        &self,
        address: A,
        netmask: A,
        destination: Option<A>,
    ) -> Result<()> {
        let addr = address.into_address()?;
        if addr.is_ipv6() {
            self.set_address(addr, {
                let prefix_len = ipnet::ip_mask_to_prefix(netmask.into_address()?)
                    .map_err(|_| Error::InvalidConfig)?;
                Some(prefix_len as u32)
            })?;
        } else {
            self.set_address(addr, None)?;
            self.set_netmask(netmask.into_address()?)?;
            if let Some(destination) = destination {
                self.set_destination(destination.into_address()?)?;
            }
        }
        Ok(())
    }

    fn remove_network_address(&self, addrs: Vec<(IpAddr, u8)>) -> Result<()> {
        unsafe {
            for addr in addrs {
                match addr.0 {
                    IpAddr::V4(_) => {
                        let mut req = self.request()?;
                        ipaddr_to_sockaddr(
                            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                            0,
                            &mut req.ifr_ifru.ifru_addr,
                            OVERWRITE_SIZE,
                        );
                        if let Err(err) = siocsifaddr(ctl()?.as_raw_fd(), &req) {
                            return Err(io::Error::from(err).into());
                        }
                    }
                    IpAddr::V6(_) => {
                        let if_index = {
                            let name = self.name()?;
                            let name = CString::new(name)?;
                            libc::if_nametoindex(name.as_ptr())
                        };
                        let ctl = ctl_v6()?;
                        let mut ifrv6: in6_ifreq = mem::zeroed();
                        ifrv6.ifr6_ifindex = if_index as i32;
                        ifrv6.ifr6_prefixlen = addr.1 as u32;
                        ifrv6.ifr6_addr =
                            sockaddr_union::from(std::net::SocketAddr::new(addr.0, 0))
                                .addr6
                                .sin6_addr;
                        if let Err(err) = siocdifaddr_in6(ctl.as_raw_fd(), &ifrv6) {
                            return Err(io::Error::from(err).into());
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn add_address_v6(&self, addr: IpAddr, prefix: u8) -> Result<()> {
        if !addr.is_ipv6() {
            return Err(Error::InvalidAddress);
        }
        unsafe {
            let if_index = {
                let name = self.name()?;
                let name = CString::new(name)?;
                libc::if_nametoindex(name.as_ptr())
            };
            let ctl = ctl_v6()?;
            let mut ifrv6: in6_ifreq = mem::zeroed();
            ifrv6.ifr6_ifindex = if_index as i32;
            ifrv6.ifr6_prefixlen = prefix as u32;
            ifrv6.ifr6_addr = sockaddr_union::from(std::net::SocketAddr::new(addr, 0))
                .addr6
                .sin6_addr;
            if let Err(err) = siocsifaddr_in6(ctl.as_raw_fd(), &ifrv6) {
                return Err(io::Error::from(err).into());
            }
        }
        Ok(())
    }

    fn mtu(&self) -> Result<u16> {
        unsafe {
            let mut req = self.request()?;

            if let Err(err) = siocgifmtu(ctl()?.as_raw_fd(), &mut req) {
                return Err(io::Error::from(err).into());
            }

            req.ifr_ifru
                .ifru_mtu
                .try_into()
                .map_err(|_| Error::TryFromIntError)
        }
    }

    fn set_mtu(&self, value: u16) -> Result<()> {
        unsafe {
            let mut req = self.request()?;
            req.ifr_ifru.ifru_mtu = value as i32;

            if let Err(err) = siocsifmtu(ctl()?.as_raw_fd(), &req) {
                return Err(io::Error::from(err).into());
            }
            Ok(())
        }
    }

    fn set_mac_address(&self, eth_addr: [u8; ETHER_ADDR_LEN as usize]) -> Result<()> {
        unsafe {
            let mut req = self.request()?;
            req.ifr_ifru.ifru_hwaddr.sa_family = ARPHRD_ETHER;
            req.ifr_ifru.ifru_hwaddr.sa_data[0..ETHER_ADDR_LEN as usize]
                .copy_from_slice(eth_addr.map(|c| c as _).as_slice());
            if let Err(err) = siocsifhwaddr(ctl()?.as_raw_fd(), &req) {
                return Err(io::Error::from(err).into());
            }
            Ok(())
        }
    }

    fn get_mac_address(&self) -> Result<[u8; ETHER_ADDR_LEN as usize]> {
        let mac = mac_address_by_name(&self.name()?)
            .map_err(|e| Error::String(e.to_string()))?
            .ok_or(Error::InvalidConfig)?;
        Ok(mac.bytes())
    }
}

impl From<Layer> for c_short {
    fn from(layer: Layer) -> Self {
        match layer {
            Layer::L2 => IFF_TAP as c_short,
            Layer::L3 => IFF_TUN as c_short,
        }
    }
}
