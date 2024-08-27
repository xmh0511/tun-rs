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

use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use winapi::shared::ifdef::NET_LUID;
use winapi::shared::minwindef::DWORD;
use winapi::um::fileapi::OPEN_EXISTING;
use winapi::um::winbase::FILE_FLAG_OVERLAPPED;
use winapi::um::winioctl::{FILE_ANY_ACCESS, FILE_DEVICE_UNKNOWN, METHOD_BUFFERED};
use winapi::um::winnt::{
    FILE_ATTRIBUTE_SYSTEM, FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_READ, GENERIC_WRITE, HANDLE,
};
use wintun::{Packet, Session};

use crate::configuration::{configure, Configuration};
use crate::device::AbstractDevice;
use crate::error::{Error, Result};
use crate::platform::windows::netsh;
use crate::platform::windows::verify_dll_file::{
    get_dll_absolute_path, get_signer_name, verify_embedded_signature,
};
use crate::Layer;

use super::ffi;

/* Present in 8.1 */
const TAP_WIN_IOCTL_GET_MAC: DWORD =
    ctl_code(FILE_DEVICE_UNKNOWN, 1, METHOD_BUFFERED, FILE_ANY_ACCESS);
#[allow(dead_code)]
const TAP_WIN_IOCTL_GET_VERSION: DWORD =
    ctl_code(FILE_DEVICE_UNKNOWN, 2, METHOD_BUFFERED, FILE_ANY_ACCESS);
const TAP_WIN_IOCTL_GET_MTU: DWORD =
    ctl_code(FILE_DEVICE_UNKNOWN, 3, METHOD_BUFFERED, FILE_ANY_ACCESS);
#[allow(dead_code)]
const TAP_WIN_IOCTL_GET_INFO: DWORD =
    ctl_code(FILE_DEVICE_UNKNOWN, 4, METHOD_BUFFERED, FILE_ANY_ACCESS);
#[allow(dead_code)]
const TAP_WIN_IOCTL_CONFIG_POINT_TO_POINT: DWORD =
    ctl_code(FILE_DEVICE_UNKNOWN, 5, METHOD_BUFFERED, FILE_ANY_ACCESS);
const TAP_WIN_IOCTL_SET_MEDIA_STATUS: DWORD =
    ctl_code(FILE_DEVICE_UNKNOWN, 6, METHOD_BUFFERED, FILE_ANY_ACCESS);
#[allow(dead_code)]
const TAP_WIN_IOCTL_CONFIG_DHCP_MASQ: DWORD =
    ctl_code(FILE_DEVICE_UNKNOWN, 7, METHOD_BUFFERED, FILE_ANY_ACCESS);
#[allow(dead_code)]
const TAP_WIN_IOCTL_GET_LOG_LINE: DWORD =
    ctl_code(FILE_DEVICE_UNKNOWN, 8, METHOD_BUFFERED, FILE_ANY_ACCESS);
#[allow(dead_code)]
const TAP_WIN_IOCTL_CONFIG_DHCP_SET_OPT: DWORD =
    ctl_code(FILE_DEVICE_UNKNOWN, 9, METHOD_BUFFERED, FILE_ANY_ACCESS);
/* Added in 8.2 */
/* obsoletes TAP_WIN_IOCTL_CONFIG_POINT_TO_POINT */
#[allow(dead_code)]
const TAP_WIN_IOCTL_CONFIG_TUN: DWORD =
    ctl_code(FILE_DEVICE_UNKNOWN, 10, METHOD_BUFFERED, FILE_ANY_ACCESS);

pub enum Driver {
    Tun(Tun),
    #[allow(dead_code)]
    Tap(Tap),
}
pub enum PacketVariant {
    Tun(Packet),
    Tap(Box<[u8]>),
}
impl Driver {
    pub fn index(&self) -> Result<u32> {
        match self {
            Driver::Tun(tun) => {
                let index = tun.session.get_adapter().get_adapter_index()?;
                Ok(index)
            }
            Driver::Tap(tap) => Ok(tap.index),
        }
    }
    pub fn name(&self) -> Result<String> {
        match self {
            Driver::Tun(tun) => {
                let name = tun.session.get_adapter().get_name()?;
                Ok(name)
            }
            Driver::Tap(tap) => {
                let name = tap.name()?;
                Ok(name)
            }
        }
    }
    pub fn read_by_ref(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Driver::Tap(tap) => tap.read_by_ref(buf),
            Driver::Tun(tun) => tun.read_by_ref(buf),
        }
    }
    pub fn write_by_ref(&self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Driver::Tap(tap) => tap.write_by_ref(buf),
            Driver::Tun(tun) => tun.write_by_ref(buf),
        }
    }
    pub fn receive_blocking(&self) -> std::io::Result<PacketVariant> {
        match self {
            Driver::Tun(tun) => {
                let packet = tun.session.receive_blocking()?;
                Ok(PacketVariant::Tun(packet))
            }
            Driver::Tap(tap) => {
                let mut buf = [0u8; u16::MAX as usize];
                let len = tap.read_by_ref(&mut buf)?;
                let mut vec = vec![];
                vec.extend_from_slice(&buf[..len]);
                Ok(PacketVariant::Tap(vec.into_boxed_slice()))
            }
        }
    }
}

/// A TUN device using the wintun driver.
pub struct Device {
    pub(crate) driver: Driver,
}

macro_rules! driver_case {
    ($driver:expr; $tun:ident =>  $tun_branch:block; $tap:ident => $tap_branch:block) => {
        match $driver {
            Driver::Tun($tun) => $tun_branch
            Driver::Tap($tap) => $tap_branch
        }
    };
}

impl Device {
    /// Create a new `Device` for the given `Configuration`.
    pub fn new(config: &Configuration) -> Result<Self> {
        let layer = config.layer.unwrap_or(Layer::L3);
        let tun_name = config.name.as_deref().unwrap_or("wintun");

        let device = if layer == Layer::L3 {
            let wintun_file = &config.platform_config.wintun_file;
            let wintun = unsafe {
                // Ensure the dll file has not been tampered with.
                let abs_path = get_dll_absolute_path(wintun_file)?;
                verify_embedded_signature(&abs_path)?;
                let signer_name = get_signer_name(&abs_path)?;
                let wp = super::WINTUN_PROVIDER;
                if signer_name != wp {
                    return Err(format!("Signer \"{}\" not match \"{}\"", signer_name, wp).into());
                }

                let wintun = libloading::Library::new(wintun_file)?;
                wintun::load_from_library(wintun)?
            };
            let guid = config.platform_config.device_guid;
            let adapter = match wintun::Adapter::open(&wintun, tun_name) {
                Ok(a) => a,
                Err(_) => wintun::Adapter::create(&wintun, tun_name, tun_name, guid)?,
            };

            #[cfg(feature = "wintun-dns")]
            if let Some(dns_servers) = &config.platform_config.dns_servers {
                adapter.set_dns_servers(dns_servers)?;
            }

            let session =
                adapter.start_session(config.ring_capacity.unwrap_or(wintun::MAX_RING_CAPACITY))?;
            Device {
                driver: Driver::Tun(Tun {
                    session: Arc::new(session),
                }),
            }
        } else if layer == Layer::L2 {
            let tap = Tap::new(tun_name.to_owned())?;
            Device {
                driver: Driver::Tap(tap),
            }
        } else {
            panic!("unknow layer {:?}", layer);
        };
        configure(&device, config)?;
        if let Some(metric) = config.metric {
            netsh::set_interface_metric(device.driver.index()?, metric)?;
        }
        Ok(device)
    }

    /// Recv a packet from tun device
    pub(crate) fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        driver_case!(
            &self.driver;
            tun =>{
                tun.recv(buf)
            };
            tap=>{
               tap.recv(buf)
            }
        )
    }

    /// Send a packet to tun device
    pub(crate) fn send(&self, buf: &[u8]) -> io::Result<usize> {
        driver_case!(
            &self.driver;
            tun=>{
                tun.send(buf)
            };
            tap=>{
               tap.send(buf)
            }
        )
    }
    pub(crate) fn shutdown(&self) -> io::Result<()> {
        driver_case!(
            &self.driver;
            tun=>{
                tun.get_session().shutdown().map_err(|e|io::Error::new(io::ErrorKind::Other,format!("{:?}",e)))
            };
            tap=>{
               tap.shutdown()
            }
        )
    }
}

impl AbstractDevice for Device {
    fn tun_name(&self) -> Result<String> {
        driver_case!(
            &self.driver;
            tun=>{
                Ok(tun.session.get_adapter().get_name()?)
            };
            tap=>{
               Ok(tap.name()?)
            }
        )
    }

    fn set_tun_name(&self, value: &str) -> Result<()> {
        driver_case!(
            &self.driver;
            tun=>{
                tun.session.get_adapter().set_name(value)?;
            };
            tap=>{
               tap.set_name(value)?
            }
        );
        Ok(())
    }

    fn enabled(&self, value: bool) -> Result<()> {
        driver_case!(
            &self.driver;
            tun=>{
                if !value{
                    tun.session.shutdown()?;
                }
            };
            tap=>{
               tap.enabled(value)?;
            }
        );
        Ok(())
    }

    fn address(&self) -> Result<IpAddr> {
        driver_case!(
            &self.driver;
            tun=>{
                let addresses =tun.session.get_adapter().get_addresses()?;
                addresses
                    .iter()
                    .find_map(|a| match a {
                        std::net::IpAddr::V4(a) => Some(std::net::IpAddr::V4(*a)),
                        _ => None,
                    })
                    .ok_or(Error::InvalidConfig)
            };
            tap=>{
                tap.address()
            }
        )
    }

    fn destination(&self) -> Result<IpAddr> {
        // It's just the default gateway in windows.
        driver_case!(
            &self.driver;
            tun=>{
               tun
                .session
                .get_adapter()
                .get_gateways()?
                .iter()
                .find_map(|a| match a {
                    std::net::IpAddr::V4(a) => Some(std::net::IpAddr::V4(*a)),
                    _ => None,
                })
                .ok_or(Error::InvalidConfig)
            };
            tap=>{
                tap.destination()
            }
        )
    }

    fn netmask(&self) -> Result<IpAddr> {
        let current_addr = self.address()?;
        driver_case!(
            &self.driver;
            tun=>{
                tun .session
                .get_adapter()
                .get_netmask_of_address(&current_addr)
                .map_err(Error::WintunError)
            };
            tap=>{
               tap.netmask()
            }
        )
    }

    fn set_network_address(
        &self,
        address: IpAddr,
        netmask: IpAddr,
        destination: Option<IpAddr>,
    ) -> Result<()> {
        netsh::set_interface_ip(
            self.driver.index()?,
            &address,
            &netmask,
            destination.as_ref(),
        )?;
        Ok(())
    }

    /// The return value is always `Ok(65535)` due to wintun
    fn mtu(&self) -> Result<u16> {
        driver_case!(
              &self.driver;
            tun=>{
                let mtu = tun.session.get_adapter().get_mtu()?;
                Ok(mtu as _)
            };
            tap=>{
                let mtu = tap.mtu()?;
                 Ok(mtu as _)
            }
        )
    }

    /// This setting has no effect since the mtu of wintun is always 65535
    fn set_mtu(&self, mtu: u16) -> Result<()> {
        driver_case!(
            &self.driver;
            tun=>{
                tun.session.get_adapter().set_mtu(mtu as _)?;
                Ok(())
            };
            tap=>{
                tap.set_mtu(mtu as u32).map_err(|e|e.into())
            }
        )
    }
}

pub struct Tun {
    session: Arc<Session>,
}

impl Tun {
    pub fn get_session(&self) -> Arc<Session> {
        self.session.clone()
    }
    fn read_by_ref(&self, mut buf: &mut [u8]) -> io::Result<usize> {
        match self.session.receive_blocking() {
            Ok(pkt) => match io::copy(&mut pkt.bytes(), &mut buf) {
                Ok(n) => Ok(n as usize),
                Err(e) => Err(e),
            },
            Err(e) => Err(io::Error::new(io::ErrorKind::ConnectionAborted, e)),
        }
    }
    fn write_by_ref(&self, mut buf: &[u8]) -> io::Result<usize> {
        let size = buf.len();
        match self.session.allocate_send_packet(size as u16) {
            Err(e) => Err(io::Error::new(io::ErrorKind::OutOfMemory, e)),
            Ok(mut packet) => match io::copy(&mut buf, &mut packet.bytes_mut()) {
                Ok(s) => {
                    self.session.send_packet(packet);
                    Ok(s as usize)
                }
                Err(e) => Err(e),
            },
        }
    }

    /// Recv a packet from tun device
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.read_by_ref(buf)
    }

    /// Send a packet to tun device
    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.write_by_ref(buf)
    }
}

pub struct Tap {
    handle: HANDLE,
    index: u32,
    luid: NET_LUID,
    #[allow(dead_code)]
    mac: [u8; 6],
}
unsafe impl Send for Tap {}
unsafe impl Sync for Tap {}
impl Drop for Tap {
    fn drop(&mut self) {
        if let Err(e) = self.shutdown() {
            log::warn!("shutdown={:?}", e)
        }
        if let Err(e) = ffi::close_handle(self.handle) {
            log::warn!("close_handle={:?}", e)
        }
    }
}
impl Tap {
    pub(crate) fn new(name: String) -> std::io::Result<Self> {
        let luid = ffi::alias_to_luid(&encode_utf16(&name)).map_err(|e| {
            io::Error::new(e.kind(), format!("alias_to_luid name={},err={:?}", name, e))
        })?;
        let guid = ffi::luid_to_guid(&luid)
            .and_then(|guid| ffi::string_from_guid(&guid))
            .map_err(|e| {
                io::Error::new(e.kind(), format!("luid_to_guid name={},err={:?}", name, e))
            })?;
        let path = format!(r"\\.\Global\{}.tap", decode_utf16(&guid));
        let handle = ffi::create_file(
            &encode_utf16(&path),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
        )
        .map_err(|e| io::Error::new(e.kind(), format!("tap name={},err={:?}", name, e)))?;

        let mut mac = [0u8; 6];
        ffi::device_io_control(handle, TAP_WIN_IOCTL_GET_MAC, &(), &mut mac)
            .map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("TAP_WIN_IOCTL_CONFIG_TUN name={},err={:?}", name, e),
                )
            })
            .map_err(|e| io::Error::new(e.kind(), format!("TAP_WIN_IOCTL_GET_MAC,err={:?}", e)))?;
        let index = ffi::luid_to_index(&luid)?;
        let tap = Self {
            handle,
            index,
            luid,
            mac,
        };
        Ok(tap)
    }

    pub fn write_by_ref(&self, buf: &[u8]) -> io::Result<usize> {
        ffi::write_file(self.handle, buf).map(|res| res as _)
    }
    pub fn read_by_ref(&self, buf: &mut [u8]) -> io::Result<usize> {
        ffi::read_file(self.handle, buf).map(|res| res as usize)
    }
    pub fn enabled(&self, value: bool) -> io::Result<()> {
        let status: u32 = if value { 1 } else { 0 };
        ffi::device_io_control(
            self.handle,
            TAP_WIN_IOCTL_SET_MEDIA_STATUS,
            &status,
            &mut (),
        )
    }
    /// Recv a packet from tun device
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.read_by_ref(buf)
    }

    /// Send a packet to tun device
    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.write_by_ref(buf)
    }
    pub fn name(&self) -> std::io::Result<String> {
        ffi::luid_to_alias(&self.luid).map(|name| decode_utf16(&name))
    }
    pub fn set_name(&self, _name: &str) -> std::io::Result<()> {
        unimplemented!()
    }
    pub fn shutdown(&self) -> io::Result<()> {
        self.enabled(false)
    }

    pub fn set_ip(&self, address: IpAddr, mask: IpAddr) -> io::Result<()> {
        netsh::set_interface_ip(self.index, &address, &mask, None)
    }

    pub fn address(&self) -> Result<IpAddr> {
        unimplemented!()
    }
    pub fn netmask(&self) -> Result<IpAddr> {
        unimplemented!()
    }
    pub fn set_address(&self, _address: Ipv4Addr) -> io::Result<()> {
        unimplemented!()
    }
    pub fn mtu(&self) -> io::Result<u32> {
        let mut mtu = 0;
        ffi::device_io_control(self.handle, TAP_WIN_IOCTL_GET_MTU, &(), &mut mtu).map(|_| mtu)
    }

    pub fn set_mtu(&self, value: u32) -> io::Result<()> {
        netsh::set_interface_mtu(self.index, value)
    }
    pub fn destination(&self) -> Result<IpAddr> {
        unimplemented!()
    }
    pub fn set_destination(&self, _address: Ipv4Addr) -> Result<()> {
        unimplemented!()
    }
}

fn encode_utf16(string: &str) -> Vec<u16> {
    use std::iter::once;
    string.encode_utf16().chain(once(0)).collect()
}

fn decode_utf16(string: &[u16]) -> String {
    let end = string.iter().position(|b| *b == 0).unwrap_or(string.len());
    String::from_utf16_lossy(&string[..end])
}
const fn ctl_code(device_type: DWORD, function: DWORD, method: DWORD, access: DWORD) -> DWORD {
    (device_type << 16) | (access << 14) | (function << 2) | method
}
