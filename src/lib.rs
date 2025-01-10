#![cfg_attr(docsrs, feature(doc_cfg))]
mod error;

pub use crate::error::{BoxError, Error, Result};
use std::net::{Ipv4Addr, Ipv6Addr};

mod address;
pub use crate::address::IntoAddress;

mod device;
pub use crate::device::AbstractDevice;

mod configuration;
use crate::configuration::Configuration;
pub use crate::configuration::Layer;

pub mod platform;
pub use crate::platform::create;
#[cfg(unix)]
pub use crate::platform::create_with_fd;

#[cfg(any(feature = "async_std", feature = "async_tokio"))]
pub mod r#async;
#[cfg(any(feature = "async_std", feature = "async_tokio"))]
pub use r#async::*;

#[cfg(unix)]
pub const DEFAULT_MTU: u16 = 1500;
#[cfg(windows)]
pub const DEFAULT_MTU: u16 = 0xFFFF; // 65535

pub const PACKET_INFORMATION_LENGTH: usize = 4;

use crate::platform::Device;
pub use ::getifaddrs;

pub struct DeviceBuilder {
    dev_name: Option<String>,
    mtu: Option<u16>,
    ipv4: Option<(Ipv4Addr, u8, Option<Ipv4Addr>)>,
    ipv6: Option<Vec<(Ipv6Addr, u8)>>,
    layer: Option<Layer>,
}

impl DeviceBuilder {
    pub fn new() -> Self {
        Self {
            dev_name: None,
            mtu: None,
            ipv4: None,
            ipv6: None,
            layer: None,
        }
    }
    pub fn name<S: Into<String>>(mut self, dev_name: S) -> Self {
        self.dev_name = Some(dev_name.into());
        self
    }
    pub fn mtu(mut self, mtu: u16) -> Self {
        self.mtu = Some(mtu);
        self
    }
    pub fn ipv4(mut self, addr_tup: (Ipv4Addr, u8, Option<Ipv4Addr>)) -> Self {
        self.ipv4 = Some(addr_tup);
        self
    }
    pub fn ipv6(mut self, addrs: Vec<(Ipv6Addr, u8)>) -> Self {
        self.ipv6 = Some(addrs);
        self
    }
    pub fn layer(mut self, layer: Layer) -> Self {
        self.layer = Some(layer);
        self
    }

    fn config(self) -> std::io::Result<Configuration> {
        let mut config = Configuration::default();
        config.name = self.dev_name;
        config.mtu = self.mtu;
        config.address_prefix_v6 = self
            .ipv6
            .map(|v| v.into_iter().map(|addr| (addr.0.into(), addr.1)).collect());
        if let Some(v) = self.ipv4 {
            let addr = v.0.into();
            let ip_net = ipnet::IpNet::new(addr, v.1)
                .map_err(|e| std::io::Error::other(format!("invalid prefix: {e:?}")))?;
            config.address_mask_v4 = Some((addr, ip_net.netmask()));
        }
        config.layer = self.layer;
        Ok(config)
    }
    pub fn build_sync(self) -> std::io::Result<Device> {
        let config = self.config()?;
        let device = create(&config)?;
        Ok(device)
    }
    #[cfg(any(feature = "async_std", feature = "async_tokio"))]
    pub fn build_async(self) -> std::io::Result<AsyncDevice> {
        let config = self.config()?;
        let device = create_as_async(&config)?;
        Ok(device)
    }
}
