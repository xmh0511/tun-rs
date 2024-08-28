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
#![allow(unused_variables)]

use crate::{
    configuration::Configuration,
    device::AbstractDevice,
    error::{Error, Result},
    platform::{
        macos::sys::*,
        posix::{self, ipaddr_to_sockaddr, sockaddr_union, Fd},
    },
    IntoAddress,
};

const OVERWRITE_SIZE: usize = std::mem::size_of::<libc::__c_anonymous_ifr_ifru>();

use libc::{
    self, c_char, c_short, c_uint, c_void, sockaddr, socklen_t, AF_INET, AF_SYSTEM, AF_SYS_CONTROL,
    IFF_RUNNING, IFF_UP, IFNAMSIZ, PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL, UTUN_OPT_IFNAME,
};
use std::{
    ffi::CStr,
    io, mem,
    net::IpAddr,
    os::unix::io::{AsRawFd, IntoRawFd, RawFd},
    ptr,
    sync::Mutex,
};

#[derive(Clone, Copy, Debug)]
struct Route {
    addr: IpAddr,
    netmask: IpAddr,
    dest: IpAddr,
}

/// A TUN device using the TUN macOS driver.
pub struct Device {
    tun_name: Option<String>,
    tun: posix::Tun,
    ctl: Option<posix::Fd>,
    alias_lock: Mutex<()>,
}

impl Device {
    /// Create a new `Device` for the given `Configuration`.
    pub fn new(config: &Configuration) -> Result<Self> {
        let mtu = config.mtu.unwrap_or(crate::DEFAULT_MTU);
        if let Some(fd) = config.raw_fd {
            let close_fd_on_drop = config.close_fd_on_drop.unwrap_or(true);
            let tun = Fd::new(fd, close_fd_on_drop).map_err(|_| io::Error::last_os_error())?;
            let device = Device {
                tun_name: None,
                tun: posix::Tun::new(tun, config.platform_config.packet_information),
                ctl: None,
                alias_lock: Mutex::new(()),
            };
            return Ok(device);
        }

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
                tun_name: Some(
                    CStr::from_ptr(tun_name.as_ptr() as *const c_char)
                        .to_string_lossy()
                        .into(),
                ),
                tun: posix::Tun::new(tun, config.platform_config.packet_information),
                ctl,
                alias_lock: Mutex::new(()),
            }
        };
        crate::configuration::configure(&device, config)?;
        Ok(device)
    }

    /// Prepare a new request.
    /// # Safety
    unsafe fn request(&self) -> Result<libc::ifreq> {
        let tun_name = self.tun_name.as_ref().ok_or(Error::InvalidConfig)?;
        let mut req: libc::ifreq = mem::zeroed();
        ptr::copy_nonoverlapping(
            tun_name.as_ptr() as *const c_char,
            req.ifr_name.as_mut_ptr(),
            tun_name.len(),
        );

        Ok(req)
    }

    fn current_route(&self) -> Option<Route> {
        let addr = self.address().ok()?;
        let netmask = self.netmask().ok()?;
        let dest = self
            .destination()
            .unwrap_or(self.calc_dest_addr(addr, netmask).ok()?);
        Some(Route {
            addr,
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
        let IpAddr::V4(_) = addr else {
            unimplemented!("do not support IPv6 yet")
        };
        let IpAddr::V4(_) = dest else {
            unimplemented!("do not support IPv6 yet")
        };
        let IpAddr::V4(_) = mask else {
            unimplemented!("do not support IPv6 yet")
        };
        let _guard = self.alias_lock.lock().unwrap();
        let old_route = self.current_route();
        let tun_name = self.tun_name.as_ref().ok_or(Error::InvalidConfig)?;
        let ctl = self.ctl.as_ref().ok_or(Error::InvalidConfig)?;
        unsafe {
            let mut req: ifaliasreq = mem::zeroed();
            ptr::copy_nonoverlapping(
                tun_name.as_ptr() as *const c_char,
                req.ifra_name.as_mut_ptr(),
                tun_name.len(),
            );

            req.ifra_addr = sockaddr_union::from((addr, 0)).addr;
            req.ifra_broadaddr = sockaddr_union::from((dest, 0)).addr;
            req.ifra_mask = sockaddr_union::from((mask, 0)).addr;

            if let Err(err) = siocaifaddr(ctl.as_raw_fd(), &req) {
                return Err(io::Error::from(err).into());
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

    /// Set non-blocking mode
    pub fn set_nonblock(&self) -> io::Result<()> {
        self.tun.set_nonblock()
    }

    fn set_route(&self, old_route: Option<Route>, new_route: Route) -> Result<()> {
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
                "-net",
                &format!("{}/{}", network, prefix_len),
                &v.dest.to_string(),
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
            "-net",
            &format!("{}/{}", new_route.addr, prefix_len),
            &new_route.dest.to_string(),
        ];
        run_command("route", &args)?;
        log::info!("route {}", args.join(" "));
        Ok(())
    }

    /// Recv a packet from tun device
    pub(crate) fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.tun.recv(buf)
    }

    /// Send a packet to tun device
    pub(crate) fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.tun.send(buf)
    }

    #[cfg(feature = "experimental")]
    pub(crate) fn shutdown(&self) -> io::Result<()> {
        self.tun.shutdown()
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
}

impl AbstractDevice for Device {
    fn tun_name(&self) -> Result<String> {
        self.tun_name.as_ref().cloned().ok_or(Error::InvalidConfig)
    }

    fn enabled(&self, value: bool) -> Result<()> {
        let ctl = self.ctl.as_ref().ok_or(Error::InvalidConfig)?;
        unsafe {
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

    fn address(&self) -> Result<IpAddr> {
        let ctl = self.ctl.as_ref().ok_or(Error::InvalidConfig)?;
        unsafe {
            let mut req = self.request()?;
            if let Err(err) = siocgifaddr(ctl.as_raw_fd(), &mut req) {
                return Err(io::Error::from(err).into());
            }
            let sa = sockaddr_union::from(req.ifr_ifru.ifru_addr);
            Ok(std::net::SocketAddr::try_from(sa)?.ip())
        }
    }

    fn destination(&self) -> Result<IpAddr> {
        let ctl = self.ctl.as_ref().ok_or(Error::InvalidConfig)?;
        unsafe {
            let mut req = self.request()?;
            if let Err(err) = siocgifdstaddr(ctl.as_raw_fd(), &mut req) {
                return Err(io::Error::from(err).into());
            }
            let sa = sockaddr_union::from(req.ifr_ifru.ifru_dstaddr);
            Ok(std::net::SocketAddr::try_from(sa)?.ip())
        }
    }

    /// Question on macOS
    fn broadcast(&self) -> Result<IpAddr> {
        let ctl = self.ctl.as_ref().ok_or(Error::InvalidConfig)?;
        unsafe {
            let mut req = self.request()?;
            if let Err(err) = siocgifbrdaddr(ctl.as_raw_fd(), &mut req) {
                return Err(io::Error::from(err).into());
            }
            let sa = sockaddr_union::from(req.ifr_ifru.ifru_broadaddr);
            Ok(std::net::SocketAddr::try_from(sa)?.ip())
        }
    }

    /// Question on macOS
    fn set_broadcast<A: IntoAddress>(&self, value: A) -> Result<()> {
        let value = value.into_address()?;
        let IpAddr::V4(value) = value else {
            unimplemented!("do not support IPv6 yet")
        };
        let ctl = self.ctl.as_ref().ok_or(Error::InvalidConfig)?;
        unsafe {
            let mut req = self.request()?;
            ipaddr_to_sockaddr(value, 0, &mut req.ifr_ifru.ifru_broadaddr, OVERWRITE_SIZE);
            if let Err(err) = siocsifbrdaddr(ctl.as_raw_fd(), &req) {
                return Err(io::Error::from(err).into());
            }
            Ok(())
        }
    }

    fn netmask(&self) -> Result<IpAddr> {
        let ctl = self.ctl.as_ref().ok_or(Error::InvalidConfig)?;
        unsafe {
            let mut req = self.request()?;
            if let Err(err) = siocgifnetmask(ctl.as_raw_fd(), &mut req) {
                return Err(io::Error::from(err).into());
            }
            let sa = sockaddr_union::from(req.ifr_ifru.ifru_addr);
            Ok(std::net::SocketAddr::try_from(sa)?.ip())
        }
    }

    fn mtu(&self) -> Result<u16> {
        let ctl = self.ctl.as_ref().ok_or(Error::InvalidConfig)?;
        unsafe {
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

    fn set_mtu(&self, value: u16) -> Result<()> {
        let ctl = self.ctl.as_ref().ok_or(Error::InvalidConfig)?;
        unsafe {
            let mut req = self.request()?;
            req.ifr_ifru.ifru_mtu = value as i32;

            if let Err(err) = siocsifmtu(ctl.as_raw_fd(), &req) {
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

    fn packet_information(&self) -> bool {
        self.tun.packet_information()
    }
}

impl AsRawFd for Device {
    fn as_raw_fd(&self) -> RawFd {
        self.tun.as_raw_fd()
    }
}

impl IntoRawFd for Device {
    fn into_raw_fd(self) -> RawFd {
        self.tun.into_raw_fd()
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
