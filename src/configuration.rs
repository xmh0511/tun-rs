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
    pub enabled: Option<bool>,
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
    #[cfg(windows)]
    pub metric: Option<u16>,
    /// switch of Enable/Disable packet information for network driver
    #[cfg(unix)]
    pub packet_information: Option<bool>,
    #[cfg(target_os = "linux")]
    pub tx_queue_len: Option<u32>,
    /// Enable/Disable TUN offloads
    #[cfg(target_os = "linux")]
    pub offload: Option<bool>,
    /// Enable multi queue support
    #[cfg(target_os = "linux")]
    pub iff_multi_queue: Option<bool>,
}

impl Configuration {
    pub(crate) fn config(self, device: &Device) -> io::Result<()> {
        if let Some(mtu) = self.mtu {
            device.set_mtu(mtu)?;
        }
        #[cfg(windows)]
        if let Some(mtu) = self.mtu_v6 {
            device.set_mtu_v6(mtu)?;
        }
        #[cfg(windows)]
        if let Some(metric) = self.metric {
            device.set_metric(metric)?;
        }
        #[cfg(target_os = "linux")]
        if let Some(tx_queue_len) = self.tx_queue_len {
            device.set_tx_queue_len(tx_queue_len)?;
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
        device.enabled(self.enabled.unwrap_or(true))?;
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
    #[cfg(windows)]
    pub fn device_guid(mut self, device_guid: u128) -> Self {
        self.config.device_guid = Some(device_guid);
        self
    }
    #[cfg(windows)]
    pub fn wintun_file(mut self, wintun_file: String) -> Self {
        self.config.wintun_file = Some(wintun_file);
        self
    }
    #[cfg(windows)]
    pub fn ring_capacity(mut self, ring_capacity: u32) -> Self {
        self.config.ring_capacity = Some(ring_capacity);
        self
    }
    #[cfg(windows)]
    pub fn metric(mut self, metric: u16) -> Self {
        self.config.metric = Some(metric);
        self
    }
    #[cfg(target_os = "linux")]
    pub fn tx_queue_len(mut self, tx_queue_len: u32) -> Self {
        self.config.tx_queue_len = Some(tx_queue_len);
        self
    }
    #[cfg(target_os = "linux")]
    pub fn offload(mut self, offload: bool) -> Self {
        self.config.offload = Some(offload);
        self
    }
    #[cfg(target_os = "linux")]
    pub fn iff_multi_queue(mut self, iff_multi_queue: bool) -> Self {
        self.config.iff_multi_queue = Some(iff_multi_queue);
        self
    }

    #[cfg(unix)]
    pub fn packet_information(mut self, packet_information: bool) -> Self {
        self.config.packet_information = Some(packet_information);
        self
    }
    pub fn enable(mut self, enable: bool) -> Self {
        self.config.enabled = Some(enable);
        self
    }
    pub fn build_sync(self) -> io::Result<Device> {
        let device = Device::new(self.config)?;
        Ok(device)
    }
    #[cfg(any(feature = "async_std", feature = "async_tokio"))]
    pub fn build_async(self) -> io::Result<crate::AsyncDevice> {
        let device = crate::AsyncDevice::new(self.build_sync()?)?;
        Ok(device)
    }
}
pub trait ToIpv4Netmask {
    fn prefix(&self) -> u8;
    fn netmask(&self) -> Ipv4Addr {
        let ip = u32::MAX.checked_shl(32 - self.prefix() as u32).unwrap_or(0);
        Ipv4Addr::from(ip)
    }
}
impl ToIpv4Netmask for u8 {
    fn prefix(&self) -> u8 {
        *self
    }
}
impl ToIpv4Netmask for Ipv4Addr {
    fn prefix(&self) -> u8 {
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
