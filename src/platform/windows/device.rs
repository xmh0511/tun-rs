use std::collections::HashSet;
use std::io;

use crate::configuration::{configure, Configuration};
use crate::device::ETHER_ADDR_LEN;
use crate::error::Result;
use crate::platform::windows::netsh;
use crate::platform::windows::tap::TapDevice;
use crate::platform::windows::tun::TunDevice;
use crate::{Error, IntoAddress, Layer};
use getifaddrs::Interface;
use network_interface::NetworkInterfaceConfig;
use std::net::IpAddr;

pub enum Driver {
    Tun(TunDevice),
    #[allow(dead_code)]
    Tap(TapDevice),
}

impl Driver {
    pub(crate) fn index(&self) -> Result<u32> {
        match self {
            Driver::Tun(tun) => Ok(tun.index()),
            Driver::Tap(tap) => Ok(tap.index()),
        }
    }
    pub fn read_by_ref(&self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Driver::Tap(tap) => tap.read(buf),
            Driver::Tun(tun) => tun.recv(buf),
        }
    }
    pub fn try_read_by_ref(&self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Driver::Tap(tap) => tap.try_read(buf),
            Driver::Tun(tun) => tun.try_recv(buf),
        }
    }
    pub fn write_by_ref(&self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Driver::Tap(tap) => tap.write(buf),
            Driver::Tun(tun) => tun.send(buf),
        }
    }
    pub fn try_write_by_ref(&self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Driver::Tap(tap) => tap.try_write(buf),
            Driver::Tun(tun) => tun.try_send(buf),
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
fn hash_name(input_str: &str) -> u128 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::hash::DefaultHasher::new();
    8765028472139845610u64.hash(&mut hasher);
    input_str.hash(&mut hasher);
    let front = hasher.finish();

    let mut hasher = std::hash::DefaultHasher::new();
    12874056902134875693u64.hash(&mut hasher);
    input_str.hash(&mut hasher);
    let back = hasher.finish();
    (u128::from(front) << 64) | u128::from(back)
}

impl Device {
    /// Create a new `Device` for the given `Configuration`.
    pub fn new(config: &Configuration) -> Result<Self> {
        let layer = config.layer.unwrap_or(Layer::L3);
        let mut count = 0;
        let interfaces = network_interface::NetworkInterface::show().map_err(|e| {
            Error::String(format!(
                "Failed to retrieve the network interface list. {e:?}"
            ))
        })?;
        let interfaces: HashSet<String> = interfaces.into_iter().map(|v| v.name).collect();
        let device = if layer == Layer::L3 {
            let wintun_file = &config.platform_config.wintun_file;
            let ring_capacity = config
                .platform_config
                .ring_capacity
                .unwrap_or(crate::platform::windows::tun::MAX_RING_CAPACITY);
            let mut attempts = 0;
            let tun_device = loop {
                let default_name = format!("tun{count}");
                count += 1;
                let name = config.name.as_deref().unwrap_or(&default_name);

                if interfaces.contains(name) {
                    if config.name.is_none() {
                        continue;
                    }
                    Err(Error::String(format!(
                        "The network adapter [{name}] already exists."
                    )))?
                }
                let guid = config
                    .platform_config
                    .device_guid
                    .unwrap_or_else(|| hash_name(name));
                match TunDevice::create(&wintun_file, name, name, guid, ring_capacity) {
                    Ok(tun_device) => break tun_device,
                    Err(e) => {
                        if attempts > 3 {
                            Err(e)?
                        }
                        attempts += 1;
                    }
                }
            };

            Device {
                driver: Driver::Tun(tun_device),
            }
        } else if layer == Layer::L2 {
            const HARDWARE_ID: &str = "tap0901";
            let tap = loop {
                let default_name = format!("tap{count}");
                let name = config.name.as_deref().unwrap_or(&default_name);
                if interfaces.contains(name) {
                    if config.name.is_none() {
                        continue;
                    }
                }
                if let Ok(tap) = TapDevice::open(HARDWARE_ID, name) {
                    if config.name.is_none() {
                        count += 1;
                        continue;
                    }
                    break tap;
                } else {
                    let tap = TapDevice::create(HARDWARE_ID)?;
                    if let Err(e) = tap.set_name(name) {
                        if config.name.is_some() {
                            Err(e)?
                        }
                    }
                    break tap;
                }
            };
            Device {
                driver: Driver::Tap(tap),
            }
        } else {
            panic!("unknown layer {:?}", layer);
        };
        configure(&device, config)?;
        if let Some(metric) = config.platform_config.metric {
            device.set_metric(metric)?;
        }
        Ok(device)
    }

    /// Recv a packet from tun device
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.driver.read_by_ref(buf)
    }
    pub fn try_recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.driver.try_read_by_ref(buf)
    }

    /// Send a packet to tun device
    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.driver.write_by_ref(buf)
    }
    pub fn try_send(&self, buf: &[u8]) -> io::Result<usize> {
        self.driver.try_write_by_ref(buf)
    }
    pub fn shutdown(&self) -> io::Result<()> {
        driver_case!(
            &self.driver;
            tun=>{
                tun.shutdown()
            };
            tap=>{
               tap.down()
            }
        )
    }
    pub fn get_all_adapter_address(&self) -> Result<Vec<Interface>, crate::Error> {
        Ok(getifaddrs::getifaddrs()?.collect())
    }

    pub fn name(&self) -> Result<String> {
        driver_case!(
            &self.driver;
            tun=>{
                Ok(tun.get_name()?)
            };
            tap=>{
               Ok(tap.get_name()?)
            }
        )
    }

    pub fn set_name(&self, value: &str) -> Result<()> {
        driver_case!(
            &self.driver;
            tun=>{
                tun.set_name(value)?;
            };
            tap=>{
               tap.set_name(value)?
            }
        );
        Ok(())
    }

    pub fn if_index(&self) -> Result<u32> {
        self.driver.index()
    }

    pub fn enabled(&self, value: bool) -> Result<()> {
        driver_case!(
            &self.driver;
            _tun=>{
                // Unsupported
            };
            tap=>{
                 if value{
                    tap.up()?
                 }else{
                     tap.down()?
                }
            }
        );
        Ok(())
    }

    pub fn addresses(&self) -> Result<Vec<Interface>> {
        let index = self.if_index()?;
        let r = self
            .get_all_adapter_address()?
            .into_iter()
            .filter(|v| v.index == Some(index))
            .collect();
        Ok(r)
    }

    pub fn set_network_address<A: IntoAddress>(
        &self,
        address: A,
        netmask: A,
        destination: Option<A>,
    ) -> Result<()> {
        let destination = if let Some(destination) = destination {
            Some(destination.into_address()?)
        } else {
            None
        };
        if let Ok(addr) = self.addresses() {
            for e in addr {
                if e.address.is_ipv6() {
                    if let Err(e) = netsh::delete_interface_ip(self.driver.index()?, e.address) {
                        log::error!("{e:?}");
                    }
                }
            }
        }

        netsh::set_interface_ip(
            self.driver.index()?,
            address.into_address()?,
            netmask.into_address()?,
            destination,
        )?;
        Ok(())
    }

    pub fn remove_network_address(&self, addrs: Vec<(IpAddr, u8)>) -> Result<()> {
        for addr in addrs {
            if let Err(e) = netsh::delete_interface_ip(self.driver.index()?, addr.0) {
                return Err(crate::Error::String(e.to_string()));
            }
        }
        Ok(())
    }

    pub fn add_address_v6(&self, addr: IpAddr, prefix: u8) -> Result<()> {
        if !addr.is_ipv6() {
            return Err(crate::Error::InvalidAddress);
        }
        let network_addr =
            ipnet::IpNet::new(addr, prefix).map_err(|e| Error::String(e.to_string()))?;
        let mask = network_addr.netmask();
        netsh::set_interface_ip(self.driver.index()?, addr, mask, None)?;
        Ok(())
    }

    /// The return value is always `Ok(65535)` due to wintun
    pub fn mtu(&self) -> Result<u16> {
        driver_case!(
              &self.driver;
            tun=>{
                let mtu = tun.get_mtu()?;
                Ok(mtu as _)
            };
            tap=>{
                let mtu = tap.get_mtu()?;
                 Ok(mtu as _)
            }
        )
    }

    /// This setting has no effect since the mtu of wintun is always 65535
    pub fn set_mtu(&self, mtu: u16) -> Result<()> {
        driver_case!(
            &self.driver;
            tun=>{
                tun.set_mtu(mtu as _)?;
            };
            tap=>{
                tap.set_mtu(mtu)?;
            }
        );
        Ok(())
    }

    pub fn set_mac_address(&self, eth_addr: [u8; ETHER_ADDR_LEN as usize]) -> Result<()> {
        driver_case!(
            &self.driver;
            _tun=>{
                Err(io::Error::from(io::ErrorKind::Unsupported))?
            };
            tap=>{
                tap.set_mac(&eth_addr).map_err(|e|e.into())
            }
        )
    }

    pub fn mac_address(&self) -> Result<[u8; ETHER_ADDR_LEN as usize]> {
        driver_case!(
            &self.driver;
            _tun=>{
                Err(io::Error::from(io::ErrorKind::Unsupported))?
            };
            tap=>{
                tap.get_mac().map_err(|e|e.into())
            }
        )
    }

    pub fn set_metric(&self, metric: u16) -> Result<()> {
        netsh::set_interface_metric(self.if_index()?, metric)?;
        Ok(())
    }
}
