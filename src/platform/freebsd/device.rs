use crate::{
    configuration::{Configuration, Layer},
    device::{AbstractDevice, ETHER_ADDR_LEN},
    error::{Error, Result},
    platform::freebsd::sys::*,
    platform::posix::{self, sockaddr_union, Fd, Tun},
    IntoAddress,
};
use libc::{
    self, c_char, c_short, fcntl, ifreq, kinfo_file, AF_INET, AF_INET6, AF_LINK, F_KINFO,
    IFF_RUNNING, IFF_UP, IFNAMSIZ, KINFO_FILE_SIZE, O_RDWR, SOCK_DGRAM,
};
use std::{ffi::CStr, io, mem, net::IpAddr, os::unix::io::AsRawFd, ptr, sync::Mutex};

use crate::getifaddrs::{self, Interface};
use mac_address::mac_address_by_name;

#[derive(Clone, Copy, Debug)]
struct Route {
    addr: IpAddr,
    netmask: IpAddr,
    #[allow(dead_code)]
    dest: IpAddr,
}

/// A TUN device using the TUN/TAP Linux driver.
pub struct Device {
    pub(crate) tun: Tun,
    alias_lock: Mutex<()>,
}

unsafe fn ctl() -> io::Result<Fd> {
    Fd::new(libc::socket(AF_INET, SOCK_DGRAM, 0), true)
}
unsafe fn ctl_v6() -> io::Result<Fd> {
    Fd::new(libc::socket(AF_INET6, SOCK_DGRAM, 0), true)
}
impl Device {
    /// Create a new `Device` for the given `Configuration`.
    pub fn new(config: &Configuration) -> Result<Self> {
        let layer = config.layer.unwrap_or(Layer::L3);
        let device_prefix = if layer == Layer::L3 {
            "tun".to_string()
        } else {
            "tap".to_string()
        };
        let device = unsafe {
            let dev_index = match config.name.as_ref() {
                Some(tun_name) => {
                    let tun_name = tun_name.clone();

                    if tun_name.len() > IFNAMSIZ {
                        return Err(Error::NameTooLong);
                    }

                    if layer == Layer::L3 && !tun_name.starts_with("tun") {
                        return Err(Error::InvalidName);
                    }
                    if layer == Layer::L2 && !tun_name.starts_with("tap") {
                        return Err(Error::InvalidName);
                    }
                    Some(tun_name[3..].parse::<u32>()? + 1_u32)
                }

                None => None,
            };

            let (tun, _tun_name) = {
                if let Some(name_index) = dev_index.as_ref() {
                    let device_name = format!("{}{}", device_prefix, name_index);
                    let device_path = format!("/dev/{}\0", device_name);
                    let fd = libc::open(device_path.as_ptr() as *const _, O_RDWR);
                    let tun = Fd::new(fd, true).map_err(|_| io::Error::last_os_error())?;
                    (tun, device_name)
                } else {
                    let (tun, device_name) = 'End: {
                        for i in 0..256 {
                            let device_name = format!("{device_prefix}{i}");
                            let device_path = format!("/dev/{device_name}\0");
                            let fd = libc::open(device_path.as_ptr() as *const _, O_RDWR);
                            if fd > 0 {
                                let tun =
                                    Fd::new(fd, true).map_err(|_| io::Error::last_os_error())?;
                                break 'End (tun, device_name);
                            }
                        }
                        return Err(Error::Io(std::io::Error::new(
                            std::io::ErrorKind::AlreadyExists,
                            "no avaiable file descriptor",
                        )));
                    };
                    (tun, device_name)
                }
            };

            Device {
                tun: Tun::new(tun),
                alias_lock: Mutex::new(()),
            }
        };

        crate::configuration::configure(&device, config)?;

        Ok(device)
    }
    pub fn from_tun(tun: Tun) -> Self {
        Self {
            tun,
            alias_lock: Mutex::new(()),
        }
    }
    // fn current_route(&self) -> Option<Route> {
    //     let addr = self.address().ok()?;
    //     let netmask = self.netmask().ok()?;
    //     let dest = self
    //         .destination()
    //         .unwrap_or(self.calc_dest_addr(addr, netmask).ok()?);
    //     Some(Route {
    //         addr,
    //         netmask,
    //         dest,
    //     })
    // }

    fn calc_dest_addr(&self, addr: IpAddr, netmask: IpAddr) -> Result<IpAddr> {
        let prefix_len = ipnet::ip_mask_to_prefix(netmask).map_err(|_| Error::InvalidConfig)?;
        Ok(ipnet::IpNet::new(addr, prefix_len)
            .map_err(|_| Error::InvalidConfig)?
            .broadcast())
    }

    /// Set the IPv4 alias of the device.
    fn set_alias(&self, addr: IpAddr, dest: IpAddr, mask: IpAddr) -> Result<()> {
        let _guard = self.alias_lock.lock().unwrap();
        // let old_route = self.current_route();
        unsafe {
            if let Ok(addrs) = self.addresses() {
                for addr in addrs {
                    match addr.address {
                        IpAddr::V4(addr) => {
                            let mut req_v4 = self.request()?;
                            req_v4.ifr_ifru.ifru_addr = sockaddr_union::from((addr, 0)).addr;
                            if let Err(err) = siocdifaddr(ctl()?.as_raw_fd(), &req_v4) {
                                log::error!("{err:?}");
                            }
                        }
                        IpAddr::V6(addr) => {
                            let mut req_v6 = self.request_v6()?;
                            req_v6.ifr_ifru.ifru_addr = sockaddr_union::from((addr, 0)).addr6;
                            if let Err(err) = siocdifaddr_in6(ctl_v6()?.as_raw_fd(), &req_v6) {
                                log::error!("{err:?}");
                            }
                        }
                    }
                }
            }
            match addr {
                IpAddr::V4(_) => {
                    let ctl = ctl()?;
                    let mut req: ifaliasreq = mem::zeroed();
                    let tun_name = self.name()?;
                    ptr::copy_nonoverlapping(
                        tun_name.as_ptr() as *const c_char,
                        req.ifran.as_mut_ptr(),
                        tun_name.len(),
                    );

                    req.addr = posix::sockaddr_union::from((addr, 0)).addr;
                    req.dstaddr = posix::sockaddr_union::from((dest, 0)).addr;
                    req.mask = posix::sockaddr_union::from((mask, 0)).addr;

                    if let Err(err) = siocaifaddr(ctl.as_raw_fd(), &req) {
                        return Err(io::Error::from(err).into());
                    }
                    if let Ok(addrs) = self.addresses() {
                        let ip_v6: Vec<IpAddr> = addrs
                            .into_iter()
                            .filter(|v| v.address.is_ipv6())
                            .map(|v| v.address)
                            .collect();
                        let mut req_v6 = self.request_v6()?;
                        let ctl_v6 = ctl_v6()?;
                        let ctl_v6 = ctl_v6.as_raw_fd();
                        for addrv6 in ip_v6 {
                            req_v6.ifr_ifru.ifru_addr = sockaddr_union::from((addrv6, 0)).addr6;
                            if let Err(err) = siocdifaddr_in6(ctl_v6, &req_v6) {
                                log::error!("{err:?}");
                            }
                        }
                    }
                }
                IpAddr::V6(_) => {
                    let IpAddr::V6(_) = mask else {
                        return Err(Error::InvalidAddress);
                    };
                    let tun_name = self.name()?;
                    let mut req: in6_ifaliasreq = mem::zeroed();
                    ptr::copy_nonoverlapping(
                        tun_name.as_ptr() as *const c_char,
                        req.ifra_name.as_mut_ptr(),
                        tun_name.len(),
                    );
                    req.ifra_addr = sockaddr_union::from((addr, 0)).addr6;
                    req.ifra_prefixmask = sockaddr_union::from((mask, 0)).addr6;
                    req.in6_addrlifetime.ia6t_vltime = 0xffffffff_u32;
                    req.in6_addrlifetime.ia6t_pltime = 0xffffffff_u32;
                    req.ifra_flags = IN6_IFF_NODAD;
                    if let Err(err) = siocaifaddr_in6(ctl_v6()?.as_raw_fd(), &req) {
                        return Err(io::Error::from(err).into());
                    }
                }
            }

            let new_route = Route {
                addr,
                netmask: mask,
                dest,
            };
            if let Err(e) = self.set_route(None, new_route) {
                log::warn!("{e:?}");
            }

            Ok(())
        }
    }

    /// Prepare a new request.
    unsafe fn request(&self) -> Result<ifreq> {
        let mut req: ifreq = mem::zeroed();
        let tun_name = self.name()?;
        ptr::copy_nonoverlapping(
            tun_name.as_ptr() as *const c_char,
            req.ifr_name.as_mut_ptr(),
            tun_name.len(),
        );

        Ok(req)
    }

    /// # Safety
    unsafe fn request_v6(&self) -> Result<in6_ifreq> {
        let tun_name = self.name()?;
        let mut req: in6_ifreq = mem::zeroed();
        ptr::copy_nonoverlapping(
            tun_name.as_ptr() as *const c_char,
            req.ifra_name.as_mut_ptr(),
            tun_name.len(),
        );
        req.ifr_ifru.ifru_flags = IN6_IFF_NODAD as _;
        Ok(req)
    }

    fn set_route(&self, _old_route: Option<Route>, new_route: Route) -> Result<()> {
        if new_route.addr.is_ipv6() {
            return Ok(());
        }
        let if_name = self.name()?;
        let prefix_len =
            ipnet::ip_mask_to_prefix(new_route.netmask).map_err(|_| Error::InvalidConfig)?;
        let args = [
            "-n",
            "add",
            if new_route.addr.is_ipv4() {
                "-net"
            } else {
                "-inet6"
            },
            &format!("{}/{}", new_route.addr, prefix_len),
            "-iface",
            &if_name,
        ];
        run_command("route", &args)?;
        log::info!("route {}", args.join(" "));
        Ok(())
    }

    // fn set_address(&self, value: IpAddr) -> Result<()> {
    //     unsafe {
    //         let req = self.request();
    //         if let Err(err) = siocdifaddr(self.ctl.as_raw_fd(), &req) {
    //             return Err(io::Error::from(err).into());
    //         }
    //         let previous = self.current_route().ok_or(Error::InvalidConfig)?;
    //         self.set_alias(value, previous.dest, previous.netmask)?;
    //     }
    //     Ok(())
    // }

    // fn set_netmask(&self, value: IpAddr) -> Result<()> {
    //     unsafe {
    //         let req = self.request();
    //         if let Err(err) = siocdifaddr(self.ctl.as_raw_fd(), &req) {
    //             return Err(io::Error::from(err).into());
    //         }
    //         let previous = self.current_route().ok_or(Error::InvalidConfig)?;
    //         self.set_alias(previous.addr, previous.dest, value)?;
    //     }
    //     Ok(())
    // }

    // fn set_destination<A: IntoAddress>(&self, value: A) -> Result<()> {
    //     let value = value.into_address()?;
    //     unsafe {
    //         let req = self.request();
    //         if let Err(err) = siocdifaddr(self.ctl.as_raw_fd(), &req) {
    //             return Err(io::Error::from(err).into());
    //         }
    //         let previous = self.current_route().ok_or(Error::InvalidConfig)?;
    //         self.set_alias(previous.addr, value, previous.netmask)?;
    //     }
    //     Ok(())
    // }
}

impl AbstractDevice for Device {
    fn name(&self) -> Result<String> {
        use std::path::PathBuf;
        unsafe {
            let mut path_info: kinfo_file = std::mem::zeroed();
            path_info.kf_structsize = KINFO_FILE_SIZE;
            if fcntl(self.tun.as_raw_fd(), F_KINFO, &mut path_info as *mut _) < 0 {
                return Err(io::Error::last_os_error().into());
            }
            let dev_path = CStr::from_ptr(path_info.kf_path.as_ptr() as *const c_char)
                .to_string_lossy()
                .into_owned();
            let path = PathBuf::from(dev_path);
            let device_name = path
                .file_name()
                .ok_or(Error::InvalidConfig)?
                .to_string_lossy()
                .to_string();
            Ok(device_name)
        }
    }

    fn set_name(&self, value: &str) -> Result<()> {
        use std::ffi::CString;
        unsafe {
            if value.len() > IFNAMSIZ {
                return Err(Error::NameTooLong);
            }
            let mut req = self.request()?;
            let tun_name = CString::new(value)?;
            let mut tun_name: Vec<i8> = tun_name
                .into_bytes_with_nul()
                .into_iter()
                .map(|c| c as i8)
                .collect::<_>();
            req.ifr_ifru.ifru_data = tun_name.as_mut_ptr();
            if let Err(err) = siocsifname(ctl()?.as_raw_fd(), &req) {
                return Err(io::Error::from(err).into());
            }

            Ok(())
        }
    }

    fn enabled(&self, value: bool) -> Result<()> {
        unsafe {
            let mut req = self.request()?;
            let ctl = ctl()?;
            if let Err(err) = siocgifflags(ctl.as_raw_fd(), &mut req) {
                return Err(io::Error::from(err).into());
            }

            if value {
                req.ifr_ifru.ifru_flags[0] |= (IFF_UP | IFF_RUNNING) as c_short;
            } else {
                req.ifr_ifru.ifru_flags[0] &= !(IFF_UP as c_short);
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

    // fn broadcast(&self) -> Result<IpAddr> {
    //     unsafe {
    //         let mut req = self.request()?;
    //         if let Err(err) = siocgifbrdaddr(ctl()?.as_raw_fd(), &mut req) {
    //             return Err(io::Error::from(err).into());
    //         }
    //         let sa = sockaddr_union::from(req.ifr_ifru.ifru_broadaddr);
    //         Ok(std::net::SocketAddr::try_from(sa)?.ip())
    //     }
    // }

    // fn set_broadcast<A: IntoAddress>(&self, value: A) -> Result<()> {
    //     let value = value.into_address()?;
    //     let IpAddr::V4(_) = value else {
    //         unimplemented!("do not support IPv6 yet")
    //     };
    //     unsafe {
    //         let ctl = ctl()?;
    //         let mut req = self.request()?;
    //         req.ifr_ifru.ifru_broadaddr = posix::sockaddr_union::from((value, 0)).addr;
    //         if let Err(err) = siocsifbrdaddr(ctl.as_raw_fd(), &req) {
    //             return Err(io::Error::from(err).into());
    //         }
    //         Ok(())
    //     }
    // }

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

    fn set_network_address<A: IntoAddress>(
        &self,
        address: A,
        netmask: A,
        destination: Option<A>,
    ) -> Result<()> {
        let addr = address.into_address()?;
        let netmask = netmask.into_address()?;
        let default_dest = self.calc_dest_addr(addr, netmask)?;
        let dest = destination
            .map(|d| d.into_address().unwrap_or(default_dest))
            .unwrap_or(default_dest);
        self.set_alias(addr, dest, netmask)?;
        Ok(())
    }

    fn remove_network_address(&self, addrs: Vec<IpAddr>) -> Result<()> {
        unsafe {
            for addr in addrs {
                match addr {
                    IpAddr::V4(addr) => {
                        let mut req_v4 = self.request()?;
                        req_v4.ifr_ifru.ifru_addr = sockaddr_union::from((addr, 0)).addr;
                        if let Err(err) = siocdifaddr(ctl()?.as_raw_fd(), &req_v4) {
                            return Err(io::Error::from(err).into());
                        }
                    }
                    IpAddr::V6(addr) => {
                        let mut req_v6 = self.request_v6()?;
                        req_v6.ifr_ifru.ifru_addr = sockaddr_union::from((addr, 0)).addr6;
                        if let Err(err) = siocdifaddr_in6(ctl_v6()?.as_raw_fd(), &req_v6) {
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
            let tun_name = self.name()?;
            let mut req: in6_ifaliasreq = mem::zeroed();
            ptr::copy_nonoverlapping(
                tun_name.as_ptr() as *const c_char,
                req.ifra_name.as_mut_ptr(),
                tun_name.len(),
            );
            req.ifra_addr = sockaddr_union::from((addr, 0)).addr6;
            let network_addr =
                ipnet::IpNet::new(addr, prefix).map_err(|e| Error::String(e.to_string()))?;
            let mask = network_addr.netmask();
            req.ifra_prefixmask = sockaddr_union::from((mask, 0)).addr6;
            req.in6_addrlifetime.ia6t_vltime = 0xffffffff_u32;
            req.in6_addrlifetime.ia6t_pltime = 0xffffffff_u32;
            req.ifra_flags = IN6_IFF_NODAD;
            if let Err(err) = siocaifaddr_in6(ctl_v6()?.as_raw_fd(), &req) {
                return Err(io::Error::from(err).into());
            }
        }
        Ok(())
    }

    fn set_mac_address(&self, eth_addr: [u8; ETHER_ADDR_LEN as usize]) -> Result<()> {
        unsafe {
            let mut req = self.request()?;
            req.ifr_ifru.ifru_addr.sa_len = ETHER_ADDR_LEN;
            req.ifr_ifru.ifru_addr.sa_family = AF_LINK as u8;
            req.ifr_ifru.ifru_addr.sa_data[0..ETHER_ADDR_LEN as usize]
                .copy_from_slice(eth_addr.map(|c| c as i8).as_slice());
            if let Err(err) = siocsiflladdr(ctl()?.as_raw_fd(), &req) {
                return Err(io::Error::from(err).into());
            }
            Ok(())
        }
    }

    fn get_mac_address(&self) -> Result<[u8; ETHER_ADDR_LEN as usize]> {
        let mac = mac_address_by_name(&self.name()?)
            .map_err(|e| io::Error::other(e.to_string()))?
            .ok_or(Error::InvalidConfig)?;
        Ok(mac.bytes())
    }
}

impl From<Layer> for c_short {
    fn from(layer: Layer) -> Self {
        match layer {
            Layer::L2 => 2,
            Layer::L3 => 3,
        }
    }
}

/// Runs a command and returns an error if the command fails, just convenience for users.
#[doc(hidden)]
pub fn run_command(command: &str, args: &[&str]) -> std::io::Result<Vec<u8>> {
    let out = std::process::Command::new(command).args(args).output()?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(if out.stderr.is_empty() {
            &out.stdout
        } else {
            &out.stderr
        });
        let info = format!("{} failed with: \"{}\"", command, err);
        return Err(std::io::Error::new(std::io::ErrorKind::Other, info));
    }
    Ok(out.stdout)
}
