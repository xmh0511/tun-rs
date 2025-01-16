use crate::Device;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};

/// TUN interface OSI layer of operation.
#[derive(Clone, Copy, Default, Debug, Eq, PartialEq)]
pub enum Layer {
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "freebsd"))]
    L2,
    #[default]
    L3,
}

/// Configuration builder for a TUN interface.
#[derive(Clone, Default, Debug)]
pub struct Configuration {
    pub dev_name: Option<String>,
    pub mtu: Option<u16>,
    #[cfg(windows)]
    pub mtu_v6: Option<u16>,
    pub ipv4: Option<(Ipv4Addr, u8, Option<Ipv4Addr>)>,
    pub ipv6: Option<Vec<(Ipv6Addr, u8)>>,
    pub layer: Option<Layer>,
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "freebsd"))]
    pub mac_addr: Option<[u8; 6]>,
    #[cfg(windows)]
    pub device_guid: Option<u128>,
    #[cfg(windows)]
    pub wintun_file: Option<String>,
    #[cfg(windows)]
    pub ring_capacity: Option<u32>,
}
impl Configuration {
    pub(crate) fn config(self, device: &Device) -> io::Result<()> {
        if let Some(dev_name) = self.dev_name {
            device.set_name(&dev_name)?;
        }
        if let Some(mtu) = self.mtu {
            device.set_mtu(mtu)?;
        }
        #[cfg(windows)]
        if let Some(mtu) = self.mtu_v6 {
            device.set_mtu_v6(mtu)?;
        }
        #[cfg(any(target_os = "windows", target_os = "linux", target_os = "freebsd"))]
        if let Some(mac_addr) = self.mac_addr {
            if self.layer.unwrap_or_default() == Layer::L2 {
                device.set_mac_address(mac_addr)?;
            }
        }

        if let Some((address, netmask, destination)) = self.ipv4 {
            device.set_network_address(address, netmask, destination)?;
        }
        if let Some(ipv6) = self.ipv6 {
            for (ip, prefix) in ipv6 {
                device.add_address_v6(ip, prefix)?;
            }
        }

        Ok(())
    }
}

#[derive(Default)]
pub struct DeviceBuilder {
    config: Configuration,
}

impl DeviceBuilder {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn name<S: Into<String>>(mut self, dev_name: S) -> Self {
        self.config.dev_name = Some(dev_name.into());
        self
    }
    pub fn mtu(mut self, mtu: u16) -> Self {
        self.config.mtu = Some(mtu);
        self
    }
    #[cfg(windows)]
    pub fn mtu_v6(mut self, mtu: u16) -> Self {
        self.config.mtu = Some(mtu);
        self
    }
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "freebsd"))]
    pub fn mac_addr(mut self, mac_addr: [u8; 6]) -> Self {
        self.config.mac_addr = Some(mac_addr);
        self
    }
    pub fn ipv4<Netmask: ToIpv4Netmask>(
        mut self,
        address: Ipv4Addr,
        mask: Netmask,
        destination: Option<Ipv4Addr>,
    ) -> Self {
        self.config.ipv4 = Some((address, mask.prefix(), destination));
        self
    }
    pub fn ipv6<Netmask: ToIpv6Netmask>(mut self, address: Ipv6Addr, mask: Netmask) -> Self {
        if let Some(v) = &mut self.config.ipv6 {
            v.push((address, mask.prefix()));
        } else {
            self.config.ipv6 = Some(vec![(address, mask.prefix())]);
        }

        self
    }
    pub fn ipv6_tuple<Netmask: ToIpv6Netmask>(mut self, addrs: Vec<(Ipv6Addr, Netmask)>) -> Self {
        if let Some(v) = &mut self.config.ipv6 {
            for (address, mask) in addrs {
                v.push((address, mask.prefix()));
            }
        } else {
            self.config.ipv6 = Some(
                addrs
                    .into_iter()
                    .map(|(ip, mask)| (ip, mask.prefix()))
                    .collect(),
            );
        }
        self
    }
    pub fn layer(mut self, layer: Layer) -> Self {
        self.config.layer = Some(layer);
        self
    }

    pub fn build_sync(self) -> std::io::Result<Device> {
        let device = Device::new(self.config)?;
        Ok(device)
    }
    #[cfg(any(feature = "async_std", feature = "async_tokio"))]
    pub fn build_async(self) -> std::io::Result<crate::AsyncDevice> {
        let device = crate::AsyncDevice::new(self.build_sync()?)?;
        Ok(device)
    }
}
pub trait ToIpv4Netmask {
    fn prefix(self) -> u8;
}
impl ToIpv4Netmask for u8 {
    fn prefix(self) -> u8 {
        self
    }
}
impl ToIpv4Netmask for Ipv4Addr {
    fn prefix(self) -> u8 {
        u32::from_be_bytes(self.octets()).count_ones() as u8
    }
}
pub trait ToIpv6Netmask {
    fn prefix(self) -> u8;
}
impl ToIpv6Netmask for u8 {
    fn prefix(self) -> u8 {
        self
    }
}
impl ToIpv6Netmask for Ipv6Addr {
    fn prefix(self) -> u8 {
        u128::from_be_bytes(self.octets()).count_ones() as u8
    }
}
