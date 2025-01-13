#![allow(unused_variables)]

use crate::{
    configuration::Configuration,
    error::{Error, Result},
    platform::{
        macos::sys::*,
        posix::{self, sockaddr_union, Fd},
    },
    IntoAddress,
};

//const OVERWRITE_SIZE: usize = std::mem::size_of::<libc::__c_anonymous_ifr_ifru>();

use crate::platform::Tun;
use getifaddrs::{self, Interface};
use libc::{
    self, c_char, c_short, c_uint, c_void, sockaddr, socklen_t, AF_INET, AF_INET6, AF_SYSTEM,
    AF_SYS_CONTROL, IFF_RUNNING, IFF_UP, IFNAMSIZ, PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL,
    UTUN_OPT_IFNAME,
};
use std::{ffi::CStr, io, mem, net::IpAddr, os::unix::io::AsRawFd, ptr, sync::Mutex};

#[derive(Clone, Copy, Debug)]
struct Route {
    addr: IpAddr,
    netmask: IpAddr,
    #[allow(dead_code)]
    dest: IpAddr,
}

/// A TUN device using the TUN macOS driver.
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
        let mtu = config.mtu.unwrap_or(crate::DEFAULT_MTU);

        let id = if let Some(tun_name) = config.name.as_ref() {
            if tun_name.len() > IFNAMSIZ {
                return Err(Error::NameTooLong);
            }

            if !tun_name.starts_with("utun") {
                return Err(Error::InvalidName);
            }
            tun_name[4..].parse::<u32>()? + 1_u32
        } else {
            0_u32
        };

        let device = unsafe {
            let fd = libc::socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
            let tun = posix::Fd::new(fd, true).map_err(|_| io::Error::last_os_error())?;

            let mut info = ctl_info {
                ctl_id: 0,
                ctl_name: {
                    let mut buffer = [0; 96];
                    for (i, o) in UTUN_CONTROL_NAME.as_bytes().iter().zip(buffer.iter_mut()) {
                        *o = *i as _;
                    }
                    buffer
                },
            };

            if let Err(err) = ctliocginfo(tun.inner, &mut info as *mut _ as *mut _) {
                return Err(io::Error::from(err).into());
            }

            let addr = libc::sockaddr_ctl {
                sc_id: info.ctl_id,
                sc_len: mem::size_of::<libc::sockaddr_ctl>() as _,
                sc_family: AF_SYSTEM as _,
                ss_sysaddr: AF_SYS_CONTROL as _,
                sc_unit: id as c_uint,
                sc_reserved: [0; 5],
            };

            let address = &addr as *const libc::sockaddr_ctl as *const sockaddr;
            if libc::connect(tun.inner, address, mem::size_of_val(&addr) as socklen_t) < 0 {
                return Err(io::Error::last_os_error().into());
            }

            let mut tun_name = [0u8; 64];
            let mut name_len: socklen_t = 64;

            let optval = &mut tun_name as *mut _ as *mut c_void;
            let optlen = &mut name_len as *mut socklen_t;
            if libc::getsockopt(tun.inner, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, optval, optlen) < 0 {
                return Err(io::Error::last_os_error().into());
            }

            let ctl = Some(posix::Fd::new(libc::socket(AF_INET, SOCK_DGRAM, 0), true)?);

            Device {
                tun: posix::Tun::new(tun),
                alias_lock: Mutex::new(()),
            }
        };
        crate::configuration::configure(&device, config)?;
        Ok(device)
    }
    pub(crate) fn from_tun(tun: Tun) -> Self {
        Self {
            tun,
            alias_lock: Mutex::new(()),
        }
    }
    /// Prepare a new request.
    /// # Safety
    unsafe fn request(&self) -> Result<libc::ifreq> {
        let tun_name = self.name()?;
        let mut req: libc::ifreq = mem::zeroed();
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

    fn current_route(&self) -> Option<Route> {
        let addr = self.addresses().ok()?;
        let addr = addr
            .into_iter()
            .filter(|v| v.address.is_ipv4())
            .collect::<Vec<Interface>>();
        let addr = addr.first()?;
        let addr_ = addr.address;
        let netmask = addr.netmask?;
        let dest = addr
            .associated_address
            .unwrap_or(self.calc_dest_addr(addr_, netmask).ok()?);
        Some(Route {
            addr: addr_,
            netmask,
            dest,
        })
    }

    fn calc_dest_addr(&self, addr: IpAddr, netmask: IpAddr) -> Result<IpAddr> {
        let prefix_len = ipnet::ip_mask_to_prefix(netmask).map_err(|_| Error::InvalidConfig)?;
        Ok(ipnet::IpNet::new(addr, prefix_len)
            .map_err(|_| Error::InvalidConfig)?
            .broadcast())
    }

    /// Set the IPv4 alias of the device.
    fn set_alias(&self, addr: IpAddr, dest: IpAddr, mask: IpAddr) -> Result<()> {
        let _guard = self.alias_lock.lock().unwrap();
        let old_route = self.current_route();
        let tun_name = self.name()?;
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
                    let mut req: ifaliasreq = mem::zeroed();
                    ptr::copy_nonoverlapping(
                        tun_name.as_ptr() as *const c_char,
                        req.ifra_name.as_mut_ptr(),
                        tun_name.len(),
                    );
                    req.ifra_addr = sockaddr_union::from((addr, 0)).addr;
                    req.ifra_broadaddr = sockaddr_union::from((dest, 0)).addr;
                    req.ifra_mask = sockaddr_union::from((mask, 0)).addr;

                    if let Err(err) = siocaifaddr(ctl()?.as_raw_fd(), &req) {
                        return Err(io::Error::from(err).into());
                    }
                }
                IpAddr::V6(_) => {
                    let IpAddr::V6(_) = mask else {
                        return Err(Error::InvalidAddress);
                    };
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
            if let Err(e) = self.set_route(old_route, new_route) {
                log::warn!("{e:?}");
            }
            Ok(())
        }
    }

    fn set_route(&self, old_route: Option<Route>, new_route: Route) -> Result<()> {
        let if_name = self.name()?;
        if let Some(v) = old_route {
            let prefix_len =
                ipnet::ip_mask_to_prefix(v.netmask).map_err(|_| Error::InvalidConfig)?;
            let network = ipnet::IpNet::new(v.addr, prefix_len)
                .map_err(|e| Error::InvalidConfig)?
                .network();
            // command: route -n delete -net 10.0.0.0/24 10.0.0.1
            let args = [
                "-n",
                "delete",
                if v.addr.is_ipv4() { "-net" } else { "-inet6" },
                &format!("{}/{}", network, prefix_len),
                "-iface",
                &if_name,
            ];
            if run_command("route", &args).is_err() {
                log::error!("route {}", args.join(" "));
            } else {
                log::info!("route {}", args.join(" "));
            }
        }

        // command: route -n add -net 10.0.0.9/24 10.0.0.1
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
    //     let IpAddr::V4(value) = value else {
    //         unimplemented!("do not support IPv6 yet")
    //     };
    //     let ctl = self.ctl.as_ref().ok_or(Error::InvalidConfig)?;
    //     unsafe {
    //         let mut req = self.request()?;
    //         ipaddr_to_sockaddr(value, 0, &mut req.ifr_ifru.ifru_addr, OVERWRITE_SIZE);
    //         if let Err(err) = siocsifaddr(ctl.as_raw_fd(), &req) {
    //             return Err(io::Error::from(err).into());
    //         }
    //         let route = { *self.route.lock().unwrap() };
    //         if let Some(mut route) = route {
    //             route.addr = value;
    //             self.set_route(route)?;
    //         }
    //         Ok(())
    //     }
    // }
    // fn set_netmask(&self, value: IpAddr) -> Result<()> {
    //     let IpAddr::V4(value) = value else {
    //         unimplemented!("do not support IPv6 yet")
    //     };
    //     let ctl = self.ctl.as_ref().ok_or(Error::InvalidConfig)?;
    //     unsafe {
    //         let mut req = self.request()?;
    //         // Note: Here should be `ifru_netmask`, but it is not defined in `ifreq`.
    //         ipaddr_to_sockaddr(value, 0, &mut req.ifr_ifru.ifru_addr, OVERWRITE_SIZE);
    //         if let Err(err) = siocsifnetmask(ctl.as_raw_fd(), &req) {
    //             return Err(io::Error::from(err).into());
    //         }
    //         let route = { *self.route.lock().unwrap() };
    //         if let Some(mut route) = route {
    //             route.netmask = value;
    //             self.set_route(route)?;
    //         }
    //         Ok(())
    //     }
    // }

    // fn set_destination<A: IntoAddress>(&self, value: A) -> Result<()> {
    //     let value = value.into_address()?;
    //     let IpAddr::V4(value) = value else {
    //         unimplemented!("do not support IPv6 yet")
    //     };
    //     let ctl = self.ctl.as_ref().ok_or(Error::InvalidConfig)?;
    //     unsafe {
    //         let mut req = self.request()?;
    //         ipaddr_to_sockaddr(value, 0, &mut req.ifr_ifru.ifru_dstaddr, OVERWRITE_SIZE);
    //         if let Err(err) = siocsifdstaddr(ctl.as_raw_fd(), &req) {
    //             return Err(io::Error::from(err).into());
    //         }
    //         let route = { *self.route.lock().unwrap() };
    //         if let Some(mut route) = route {
    //             route.dest = value;
    //             self.set_route(route)?;
    //         }
    //         Ok(())
    //     }
    // }

    pub fn name(&self) -> Result<String> {
        let mut tun_name = [0u8; 64];
        let mut name_len: socklen_t = 64;

        let optval = &mut tun_name as *mut _ as *mut c_void;
        let optlen = &mut name_len as *mut socklen_t;
        unsafe {
            if libc::getsockopt(
                self.tun.as_raw_fd(),
                SYSPROTO_CONTROL,
                UTUN_OPT_IFNAME,
                optval,
                optlen,
            ) < 0
            {
                return Err(io::Error::last_os_error().into());
            }
            Ok(CStr::from_ptr(tun_name.as_ptr() as *const c_char)
                .to_string_lossy()
                .into())
        }
    }

    pub fn if_index(&self) -> Result<u32> {
        let if_name = self.name()?;
        let index = Self::get_if_index(&if_name)?;
        Ok(index)
    }

    pub fn enabled(&self, value: bool) -> Result<()> {
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

    pub fn addresses(&self) -> Result<Vec<Interface>> {
        let if_name = self.name()?;
        let addrs = getifaddrs::getifaddrs()?;
        let ifs = addrs
            .filter(|v| v.name == if_name)
            .collect::<Vec<Interface>>();
        Ok(ifs)
    }

    // /// Question on macOS
    // fn broadcast(&self) -> Result<IpAddr> {
    //     unsafe {
    //         let ctl = ctl()?;
    //         let mut req = self.request()?;
    //         if let Err(err) = siocgifbrdaddr(ctl.as_raw_fd(), &mut req) {
    //             return Err(io::Error::from(err).into());
    //         }
    //         let sa = sockaddr_union::from(req.ifr_ifru.ifru_broadaddr);
    //         Ok(std::net::SocketAddr::try_from(sa)?.ip())
    //     }
    // }

    // /// Question on macOS
    // fn set_broadcast<A: IntoAddress>(&self, value: A) -> Result<()> {
    //     let value = value.into_address()?;
    //     let IpAddr::V4(value) = value else {
    //         unimplemented!("do not support IPv6 yet")
    //     };
    //     unsafe {
    //         let ctl = ctl()?;
    //         let mut req = self.request()?;
    //         ipaddr_to_sockaddr(value, 0, &mut req.ifr_ifru.ifru_broadaddr, OVERWRITE_SIZE);
    //         if let Err(err) = siocsifbrdaddr(ctl.as_raw_fd(), &req) {
    //             return Err(io::Error::from(err).into());
    //         }
    //         Ok(())
    //     }
    // }

    pub fn mtu(&self) -> Result<u16> {
        unsafe {
            let ctl = ctl()?;
            let mut req = self.request()?;

            if let Err(err) = siocgifmtu(ctl.as_raw_fd(), &mut req) {
                return Err(io::Error::from(err).into());
            }

            req.ifr_ifru
                .ifru_mtu
                .try_into()
                .map_err(|_| Error::TryFromIntError)
        }
    }

    pub fn set_mtu(&self, value: u16) -> Result<()> {
        unsafe {
            let ctl = ctl()?;
            let mut req = self.request()?;
            req.ifr_ifru.ifru_mtu = value as i32;

            if let Err(err) = siocsifmtu(ctl.as_raw_fd(), &req) {
                return Err(io::Error::from(err).into());
            }
            Ok(())
        }
    }

    pub fn set_network_address<A: IntoAddress>(
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

    pub fn remove_network_address(&self, addrs: Vec<(IpAddr, u8)>) -> Result<()> {
        unsafe {
            for addr in addrs {
                match addr.0 {
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

    pub fn add_address_v6(&self, addr: IpAddr, prefix: u8) -> Result<()> {
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

    pub fn ignore_packet_info(&self) -> bool {
        self.tun.ignore_packet_info()
    }

    pub fn set_ignore_packet_info(&self, ign: bool) {
        self.tun.set_ignore_packet_info(ign)
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
