use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use crate::platform::{DeviceImpl, SyncDevice};

/// TUN interface OSI layer of operation.
#[derive(Clone, Copy, Default, Debug, Eq, PartialEq)]
pub enum Layer {
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "freebsd"))]
    L2,
    #[default]
    L3,
}

/// Configuration for a TUN/TAP interface.
#[derive(Clone, Default, Debug)]
pub(crate) struct DeviceConfig {
    pub dev_name: Option<String>,
    #[allow(dead_code)]
    pub layer: Option<Layer>,
    #[cfg(windows)]
    pub device_guid: Option<u128>,
    #[cfg(windows)]
    pub wintun_file: Option<String>,
    #[cfg(windows)]
    pub ring_capacity: Option<u32>,
    /// switch of Enable/Disable packet information for network driver
    #[cfg(any(target_os = "ios", target_os = "macos", target_os = "linux"))]
    pub packet_information: Option<bool>,
    /// Enable/Disable TUN offloads.
    /// After enabling, use `recv_multiple`/`send_multiple` for data transmission.
    #[cfg(target_os = "linux")]
    pub offload: Option<bool>,
    /// Enable multi queue support
    #[cfg(target_os = "linux")]
    pub multi_queue: Option<bool>,
}
type IPV4 = (
    io::Result<Ipv4Addr>,
    io::Result<u8>,
    Option<io::Result<Ipv4Addr>>,
);
/// Builder for a TUN/TAP interface.
#[derive(Default)]
pub struct DeviceBuilder {
    dev_name: Option<String>,
    enabled: Option<bool>,
    mtu: Option<u16>,
    #[cfg(windows)]
    mtu_v6: Option<u16>,
    ipv4: Option<IPV4>,
    ipv6: Option<Vec<(io::Result<Ipv6Addr>, io::Result<u8>)>>,
    layer: Option<Layer>,
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "freebsd"))]
    mac_addr: Option<[u8; 6]>,
    #[cfg(windows)]
    device_guid: Option<u128>,
    #[cfg(windows)]
    wintun_file: Option<String>,
    #[cfg(windows)]
    ring_capacity: Option<u32>,
    #[cfg(windows)]
    metric: Option<u16>,
    /// switch of Enable/Disable packet information for network driver
    #[cfg(any(target_os = "ios", target_os = "macos", target_os = "linux"))]
    packet_information: Option<bool>,
    #[cfg(target_os = "linux")]
    tx_queue_len: Option<u32>,
    /// Enable/Disable TUN offloads.
    /// After enabling, use `recv_multiple`/`send_multiple` for data transmission.
    #[cfg(target_os = "linux")]
    offload: Option<bool>,
    /// Enable multi queue support
    #[cfg(target_os = "linux")]
    multi_queue: Option<bool>,
}

impl DeviceBuilder {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn name<S: Into<String>>(mut self, dev_name: S) -> Self {
        self.dev_name = Some(dev_name.into());
        self
    }
    pub fn mtu(mut self, mtu: u16) -> Self {
        self.mtu = Some(mtu);
        #[cfg(windows)]
        {
            self.mtu_v6 = Some(mtu);
        }
        self
    }
    #[cfg(windows)]
    pub fn mtu_v4(mut self, mtu: u16) -> Self {
        self.mtu = Some(mtu);
        self
    }
    #[cfg(windows)]
    pub fn mtu_v6(mut self, mtu: u16) -> Self {
        self.mtu_v6 = Some(mtu);
        self
    }
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "freebsd"))]
    pub fn mac_addr(mut self, mac_addr: [u8; 6]) -> Self {
        self.mac_addr = Some(mac_addr);
        self
    }
    pub fn ipv4<IPv4: ToIpv4Address, Netmask: ToIpv4Netmask>(
        mut self,
        address: IPv4,
        mask: Netmask,
        destination: Option<IPv4>,
    ) -> Self {
        self.ipv4 = Some((address.ipv4(), mask.prefix(), destination.map(|v| v.ipv4())));
        self
    }
    pub fn ipv6<IPv6: ToIpv6Address, Netmask: ToIpv6Netmask>(
        mut self,
        address: IPv6,
        mask: Netmask,
    ) -> Self {
        if let Some(v) = &mut self.ipv6 {
            v.push((address.ipv6(), mask.prefix()));
        } else {
            self.ipv6 = Some(vec![(address.ipv6(), mask.prefix())]);
        }

        self
    }
    pub fn ipv6_tuple<IPv6: ToIpv6Address, Netmask: ToIpv6Netmask>(
        mut self,
        addrs: &[(IPv6, Netmask)],
    ) -> Self {
        if let Some(v) = &mut self.ipv6 {
            for (address, mask) in addrs {
                v.push((address.ipv6(), mask.prefix()));
            }
        } else {
            self.ipv6 = Some(
                addrs
                    .iter()
                    .map(|(ip, mask)| (ip.ipv6(), mask.prefix()))
                    .collect(),
            );
        }
        self
    }
    pub fn layer(mut self, layer: Layer) -> Self {
        self.layer = Some(layer);
        self
    }
    #[cfg(windows)]
    pub fn device_guid(mut self, device_guid: u128) -> Self {
        self.device_guid = Some(device_guid);
        self
    }
    #[cfg(windows)]
    pub fn wintun_file(mut self, wintun_file: String) -> Self {
        self.wintun_file = Some(wintun_file);
        self
    }
    #[cfg(windows)]
    pub fn ring_capacity(mut self, ring_capacity: u32) -> Self {
        self.ring_capacity = Some(ring_capacity);
        self
    }
    #[cfg(windows)]
    pub fn metric(mut self, metric: u16) -> Self {
        self.metric = Some(metric);
        self
    }
    #[cfg(target_os = "linux")]
    pub fn tx_queue_len(mut self, tx_queue_len: u32) -> Self {
        self.tx_queue_len = Some(tx_queue_len);
        self
    }
    /// After enabling, use `recv_multiple`/`send_multiple` for data transmission.
    #[cfg(target_os = "linux")]
    pub fn offload(mut self, offload: bool) -> Self {
        self.offload = Some(offload);
        self
    }
    #[cfg(target_os = "linux")]
    pub fn multi_queue(mut self, multi_queue: bool) -> Self {
        self.multi_queue = Some(multi_queue);
        self
    }

    #[cfg(any(target_os = "ios", target_os = "macos", target_os = "linux"))]
    pub fn packet_information(mut self, packet_information: bool) -> Self {
        self.packet_information = Some(packet_information);
        self
    }
    pub fn enable(mut self, enable: bool) -> Self {
        self.enabled = Some(enable);
        self
    }
    pub(crate) fn build_config(&mut self) -> DeviceConfig {
        DeviceConfig {
            dev_name: self.dev_name.take(),
            layer: self.layer.take(),
            #[cfg(windows)]
            device_guid: self.device_guid.take(),
            #[cfg(windows)]
            wintun_file: self.wintun_file.take(),
            #[cfg(windows)]
            ring_capacity: self.ring_capacity.take(),
            #[cfg(any(target_os = "ios", target_os = "macos", target_os = "linux"))]
            packet_information: self.packet_information.take(),
            #[cfg(target_os = "linux")]
            offload: self.offload.take(),
            #[cfg(target_os = "linux")]
            multi_queue: self.multi_queue.take(),
        }
    }
    pub(crate) fn config(self, device: &DeviceImpl) -> io::Result<()> {
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

        if let Some((address, prefix, destination)) = self.ipv4 {
            let prefix = prefix?;
            let address = address?;
            let destination = destination.transpose()?;
            device.set_network_address(address, prefix, destination)?;
        }
        if let Some(ipv6) = self.ipv6 {
            for (address, prefix) in ipv6 {
                let prefix = prefix?;
                let address = address?;
                device.add_address_v6(address, prefix)?;
            }
        }
        device.enabled(self.enabled.unwrap_or(true))?;
        Ok(())
    }
    pub fn build_sync(mut self) -> io::Result<SyncDevice> {
        let device = DeviceImpl::new(self.build_config())?;
        self.config(&device)?;
        Ok(SyncDevice(device))
    }
    #[cfg(any(feature = "async_std", feature = "async_tokio"))]
    pub fn build_async(self) -> io::Result<crate::AsyncDevice> {
        let sync_device = self.build_sync()?;
        let device = crate::AsyncDevice::new_dev(sync_device.0)?;
        Ok(device)
    }
}

pub trait ToIpv4Address {
    fn ipv4(&self) -> io::Result<Ipv4Addr>;
}
impl ToIpv4Address for Ipv4Addr {
    fn ipv4(&self) -> io::Result<Ipv4Addr> {
        Ok(*self)
    }
}
impl ToIpv4Address for IpAddr {
    fn ipv4(&self) -> io::Result<Ipv4Addr> {
        match self {
            IpAddr::V4(ip) => Ok(*ip),
            IpAddr::V6(_) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid address",
            )),
        }
    }
}
impl ToIpv4Address for String {
    fn ipv4(&self) -> io::Result<Ipv4Addr> {
        self.as_str().ipv4()
    }
}
impl ToIpv4Address for &str {
    fn ipv4(&self) -> io::Result<Ipv4Addr> {
        match Ipv4Addr::from_str(self) {
            Ok(ip) => Ok(ip),
            Err(_e) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid IPv4 str",
            )),
        }
    }
}

pub trait ToIpv6Address {
    fn ipv6(&self) -> io::Result<Ipv6Addr>;
}

impl ToIpv6Address for Ipv6Addr {
    fn ipv6(&self) -> io::Result<Ipv6Addr> {
        Ok(*self)
    }
}
impl ToIpv6Address for IpAddr {
    fn ipv6(&self) -> io::Result<Ipv6Addr> {
        match self {
            IpAddr::V4(_) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid address",
            )),
            IpAddr::V6(ip) => Ok(*ip),
        }
    }
}
impl ToIpv6Address for String {
    fn ipv6(&self) -> io::Result<Ipv6Addr> {
        self.as_str().ipv6()
    }
}
impl ToIpv6Address for &str {
    fn ipv6(&self) -> io::Result<Ipv6Addr> {
        match Ipv6Addr::from_str(self) {
            Ok(ip) => Ok(ip),
            Err(_e) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid IPv6 str",
            )),
        }
    }
}

pub trait ToIpv4Netmask {
    fn prefix(&self) -> io::Result<u8>;
    fn netmask(&self) -> io::Result<Ipv4Addr> {
        let ip = u32::MAX
            .checked_shl(32 - self.prefix()? as u32)
            .unwrap_or(0);
        Ok(Ipv4Addr::from(ip))
    }
}

impl ToIpv4Netmask for u8 {
    fn prefix(&self) -> io::Result<u8> {
        if *self > 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid IP prefix length",
            ));
        }
        Ok(*self)
    }
}

impl ToIpv4Netmask for Ipv4Addr {
    fn prefix(&self) -> io::Result<u8> {
        let ip = u32::from_be_bytes(self.octets());
        if ip.leading_ones() != ip.count_ones() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid netmask",
            ));
        }
        Ok(ip.leading_ones() as u8)
    }
}
impl ToIpv4Netmask for String {
    fn prefix(&self) -> io::Result<u8> {
        ToIpv4Netmask::prefix(&self.as_str())
    }
}
impl ToIpv4Netmask for &str {
    fn prefix(&self) -> io::Result<u8> {
        match Ipv4Addr::from_str(self) {
            Ok(ip) => ip.prefix(),
            Err(_e) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid netmask str",
            )),
        }
    }
}

pub trait ToIpv6Netmask {
    fn prefix(&self) -> io::Result<u8>;
    fn netmask(&self) -> io::Result<Ipv6Addr> {
        let ip = u128::MAX
            .checked_shl(32 - self.prefix()? as u32)
            .unwrap_or(0);
        Ok(Ipv6Addr::from(ip))
    }
}

impl ToIpv6Netmask for u8 {
    fn prefix(&self) -> io::Result<u8> {
        if *self > 128 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid IP prefix length",
            ));
        }
        Ok(*self)
    }
}

impl ToIpv6Netmask for Ipv6Addr {
    fn prefix(&self) -> io::Result<u8> {
        let ip = u128::from_be_bytes(self.octets());
        if ip.leading_ones() != ip.count_ones() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid netmask",
            ));
        }
        Ok(ip.leading_ones() as u8)
    }
}
impl ToIpv6Netmask for String {
    fn prefix(&self) -> io::Result<u8> {
        ToIpv6Netmask::prefix(&self.as_str())
    }
}
impl ToIpv6Netmask for &str {
    fn prefix(&self) -> io::Result<u8> {
        match Ipv6Addr::from_str(self) {
            Ok(ip) => ip.prefix(),
            Err(_e) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid netmask str",
            )),
        }
    }
}
