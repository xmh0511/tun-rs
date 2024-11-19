use std::{
    ffi::CString,
    io, mem,
    net::{IpAddr, Ipv4Addr},
    os::unix::io::{AsRawFd, RawFd},
    ptr,
};
use std::io::IoSliceMut;
use crate::getifaddrs::{self, Interface};
use libc::{
    self, c_char, c_short, ifreq, in6_ifreq, AF_INET, AF_INET6, ARPHRD_ETHER, IFF_MULTI_QUEUE,
    IFF_NO_PI, IFF_RUNNING, IFF_TAP, IFF_TUN, IFF_UP, IFNAMSIZ, O_RDWR, SOCK_DGRAM,
};
use mac_address::mac_address_by_name;

use crate::configuration::configure;
use crate::{
    configuration::{Configuration, Layer},
    device::{AbstractDevice, ETHER_ADDR_LEN},
    error::{Error, Result},
    platform::linux::sys::*,
    platform::posix::{ipaddr_to_sockaddr, sockaddr_union, Fd, Tun},
    IntoAddress,
};
use crate::platform::linux::offload::{gso_none_checksum, VIRTIO_NET_HDR_F_NEEDS_CSUM, VIRTIO_NET_HDR_GSO_NONE, VIRTIO_NET_HDR_LEN, VirtioNetHdr};

const OVERWRITE_SIZE: usize = std::mem::size_of::<libc::__c_anonymous_ifr_ifru>();

/// A TUN device using the TUN/TAP Linux driver.
pub struct Device {
    pub(crate) tun: Tun,
    vnet_hdr: bool,
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
            if offload {
                let tun_tcp_offloads = libc::TUN_F_CSUM | libc::TUN_F_TSO4 | libc::TUN_F_TSO6;
                let tun_udp_offloads = libc::TUN_F_USO4 | libc::TUN_F_USO6;
                if let Err(err) = tunsetoffload(tun_fd.inner, tun_tcp_offloads as _) {
                    return Err(Error::UnsupportedOffload(err as _));
                }
                // tunUDPOffloads were added in Linux v6.2. We do not return an
                // error if they are unsupported at runtime.
                _ = tunsetoffload(tun_fd.inner, (tun_tcp_offloads | tun_udp_offloads) as _)
            }

            let device = Device {
                tun: Tun::new(tun_fd),
                vnet_hdr: offload,
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
        Self { tun, vnet_hdr: false }
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
    /// Recv a packet from tun device
    /// transfer_buffer is used to assist in reading data The size needs to be 10+65535
    pub fn recv_multiple(&self, transfer_buffer: &mut [u8], bufs: &mut [IoSliceMut<'_>], size: &mut [usize]) -> io::Result<usize> {
        if self.vnet_hdr{
            let mut head = [0u8; VIRTIO_NET_HDR_LEN];
            let bufs = &mut [IoSliceMut::new(&mut head), IoSliceMut::new(transfer_buffer)];
            let mut len = self.tun.recv_vectored(bufs)?;
            if len < VIRTIO_NET_HDR_LEN{
                return Err(io::Error::new(io::ErrorKind::Other,"too short"));
            }
            len -= VIRTIO_NET_HDR_LEN;
            let hdr = crate::platform::linux::offload::decode(&head)?;

            self.handle_virtio_read(hdr,&mut transfer_buffer[..len],bufs,size)?;
            todo!()
        }else{
            self.tun.recv(&mut bufs[0])
        }
    }
    fn handle_virtio_read(&self, hdr:VirtioNetHdr, buf: &mut [u8], bufs: &mut [IoSliceMut<'_>], size: &mut [usize]) -> io::Result<usize> {
        if hdr.gso_type == VIRTIO_NET_HDR_GSO_NONE  {
            if hdr.flags& VIRTIO_NET_HDR_F_NEEDS_CSUM != 0 {
                // This means CHECKSUM_PARTIAL in skb context. We are responsible
                // for computing the checksum starting at hdr.csumStart and placing
                // at hdr.csumOffset.
                gso_none_checksum(buf,hdr.csum_start,hdr.csum_offset);
            }
            let len = buf.len();
            size[0] = len;
            bufs[0][..len].copy_from_slice(buf);
            return Ok(1)
        }
        todo!()
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
