use std::collections::HashSet;
use std::io;

use crate::configuration::Configuration;
use crate::device::ETHER_ADDR_LEN;
use crate::platform::windows::netsh;
use crate::platform::windows::tap::TapDevice;
use crate::platform::windows::tun::TunDevice;
use crate::{Error, Layer, ToIpv4Netmask, ToIpv6Netmask};
use getifaddrs::Interface;
use network_interface::NetworkInterfaceConfig;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub(crate) enum Driver {
    Tun(TunDevice),
    Tap(TapDevice),
}

/// A TUN device using the wintun driver.
pub struct Device {
    pub(crate) driver: Driver,
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
    pub fn new(config: Configuration) -> std::io::Result<Self> {
        let layer = config.layer.unwrap_or(Layer::L3);
        let mut count = 0;
        let interfaces = network_interface::NetworkInterface::show().map_err(|e| {
            Error::String(format!(
                "Failed to retrieve the network interface list. {e:?}"
            ))
        })?;
        let interfaces: HashSet<String> = interfaces.into_iter().map(|v| v.name).collect();
        let device = if layer == Layer::L3 {
            let default_wintun_file = "wintun.dll".to_string();
            let wintun_file = config
                .wintun_file
                .as_deref()
                .unwrap_or(&default_wintun_file);
            let ring_capacity = config
                .ring_capacity
                .unwrap_or(crate::platform::windows::tun::MAX_RING_CAPACITY);
            let mut attempts = 0;
            let tun_device = loop {
                let default_name = format!("tun{count}");
                count += 1;
                let name = config.dev_name.as_deref().unwrap_or(&default_name);

                if interfaces.contains(name) {
                    if config.dev_name.is_none() {
                        continue;
                    }
                    Err(Error::String(format!(
                        "The network adapter [{name}] already exists."
                    )))?
                }
                let guid = config.device_guid.unwrap_or_else(|| hash_name(name));
                match TunDevice::create(wintun_file, name, name, guid, ring_capacity) {
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
                let name = config.dev_name.as_deref().unwrap_or(&default_name);
                if interfaces.contains(name) && config.dev_name.is_none() {
                    continue;
                }
                if let Ok(tap) = TapDevice::open(HARDWARE_ID, name) {
                    if config.dev_name.is_none() {
                        count += 1;
                        continue;
                    }
                    break tap;
                } else {
                    let tap = TapDevice::create(HARDWARE_ID)?;
                    if let Err(e) = tap.set_name(name) {
                        if config.dev_name.is_some() {
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
        config.config(&device)?;
        Ok(device)
    }

    /// Recv a packet from tun device
    pub(crate) fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        match &self.driver {
            Driver::Tap(tap) => tap.read(buf),
            Driver::Tun(tun) => tun.recv(buf),
        }
    }
    pub(crate) fn try_recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        match &self.driver {
            Driver::Tap(tap) => tap.try_read(buf),
            Driver::Tun(tun) => tun.try_recv(buf),
        }
    }

    /// Send a packet to tun device
    pub(crate) fn send(&self, buf: &[u8]) -> io::Result<usize> {
        match &self.driver {
            Driver::Tap(tap) => tap.write(buf),
            Driver::Tun(tun) => tun.send(buf),
        }
    }
    pub(crate) fn try_send(&self, buf: &[u8]) -> io::Result<usize> {
        match &self.driver {
            Driver::Tap(tap) => tap.try_write(buf),
            Driver::Tun(tun) => tun.try_send(buf),
        }
    }
    pub(crate) fn shutdown(&self) -> io::Result<()> {
        match &self.driver {
            Driver::Tun(tun) => tun.shutdown(),
            Driver::Tap(tap) => tap.down(),
        }
    }
    fn get_all_adapter_address(&self) -> std::io::Result<Vec<Interface>> {
        Ok(getifaddrs::getifaddrs()?.collect())
    }

    pub fn name(&self) -> io::Result<String> {
        match &self.driver {
            Driver::Tun(tun) => tun.get_name(),
            Driver::Tap(tap) => tap.get_name(),
        }
    }

    pub fn set_name(&self, value: &str) -> io::Result<()> {
        let name = self.name()?;
        if value == name {
            return Ok(());
        }
        netsh::set_interface_name(&name, value)
    }

    pub fn if_index(&self) -> io::Result<u32> {
        match &self.driver {
            Driver::Tun(tun) => Ok(tun.index()),
            Driver::Tap(tap) => Ok(tap.index()),
        }
    }

    pub fn enabled(&self, value: bool) -> io::Result<()> {
        match &self.driver {
            Driver::Tun(_tun) => {
                if value {
                    Ok(())
                } else {
                    Err(io::Error::from(io::ErrorKind::Unsupported))
                }
            }
            Driver::Tap(tap) => tap.set_status(value),
        }
    }

    pub fn addresses(&self) -> io::Result<Vec<IpAddr>> {
        let index = self.if_index()?;
        let r = self
            .get_all_adapter_address()?
            .into_iter()
            .filter(|v| v.index == Some(index))
            .map(|v| v.address)
            .collect();
        Ok(r)
    }

    pub fn set_network_address<Netmask: ToIpv4Netmask>(
        &self,
        address: Ipv4Addr,
        netmask: Netmask,
        destination: Option<Ipv4Addr>,
    ) -> io::Result<()> {
        let netmask = ipnet::Ipv4Net::new(address, netmask.prefix())
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?
            .netmask();
        netsh::set_interface_ip(
            self.if_index()?,
            address.into(),
            netmask.into(),
            destination.map(|v| v.into()),
        )
    }

    pub fn remove_address(&self, addr: IpAddr) -> io::Result<()> {
        netsh::delete_interface_ip(self.if_index()?, addr)
    }

    pub fn add_address_v6<Netmask: ToIpv6Netmask>(
        &self,
        addr: Ipv6Addr,
        netmask: Netmask,
    ) -> io::Result<()> {
        let network_addr = ipnet::Ipv6Net::new(addr, netmask.prefix())
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
        let mask = network_addr.netmask();
        netsh::set_interface_ip(self.if_index()?, addr.into(), mask.into(), None)
    }
    pub fn mtu(&self) -> io::Result<u16> {
        let index = self.if_index()?;
        let mtu = crate::platform::windows::ffi::get_mtu_by_index(index, true)?;
        Ok(mtu as _)
    }
    pub fn mtu_v6(&self) -> io::Result<u16> {
        let index = self.if_index()?;
        let mtu = crate::platform::windows::ffi::get_mtu_by_index(index, false)?;
        Ok(mtu as _)
    }

    pub fn set_mtu(&self, mtu: u16) -> io::Result<()> {
        netsh::set_interface_mtu(self.if_index()?, mtu as _)
    }
    pub fn set_mtu_v6(&self, mtu: u16) -> io::Result<()> {
        netsh::set_interface_mtu_v6(self.if_index()?, mtu as _)
    }

    pub fn set_mac_address(&self, eth_addr: [u8; ETHER_ADDR_LEN as usize]) -> io::Result<()> {
        match &self.driver {
            Driver::Tun(_tun) => Err(io::Error::from(io::ErrorKind::Unsupported)),
            Driver::Tap(tap) => tap.set_mac(&eth_addr),
        }
    }

    pub fn mac_address(&self) -> io::Result<[u8; ETHER_ADDR_LEN as usize]> {
        match &self.driver {
            Driver::Tun(_tun) => Err(io::Error::from(io::ErrorKind::Unsupported)),
            Driver::Tap(tap) => tap.get_mac(),
        }
    }

    pub fn set_metric(&self, metric: u16) -> io::Result<()> {
        netsh::set_interface_metric(self.if_index()?, metric)
    }
    pub fn version(&self) -> io::Result<String> {
        match &self.driver {
            Driver::Tun(tun) => tun.version(),
            Driver::Tap(tap) => tap.get_version().map(|v| {
                v.iter()
                    .map(|v| v.to_string())
                    .collect::<Vec<String>>()
                    .join(".")
            }),
        }
    }
}
