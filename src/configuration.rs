#[allow(unused_imports)]
use crate::address::IntoAddress;
use crate::platform::PlatformConfig;
#[allow(unused_imports)]
use std::net::IpAddr;

/// TUN interface OSI layer of operation.
#[derive(Clone, Copy, Default, Debug, Eq, PartialEq)]
pub enum Layer {
    L2,
    #[default]
    L3,
}

/// Configuration builder for a TUN interface.
#[derive(Clone, Default, Debug)]
pub(crate) struct Configuration {
    #[cfg(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd"
    ))]
    pub(crate) name: Option<String>,
    pub(crate) platform_config: PlatformConfig,
    #[cfg(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd"
    ))]
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "freebsd"))]
    pub(crate) mac_addr: Option<[u8; 6]>,
    #[cfg(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd"
    ))]
    pub(crate) address_prefix_v6: Option<Vec<(IpAddr, u8)>>,
    #[cfg(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd"
    ))]
    pub(crate) address_mask_v4: Option<(IpAddr, IpAddr)>,
    #[cfg(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd"
    ))]
    pub(crate) destination: Option<IpAddr>,
    #[cfg(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd"
    ))]
    pub(crate) broadcast: Option<IpAddr>,
    #[cfg(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd"
    ))]
    pub(crate) mtu: Option<u16>,
    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "windows"
    ))]
    pub(crate) enabled: Option<bool>,
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "freebsd",))]
    pub(crate) layer: Option<Layer>,
}

impl Configuration {
    /// Access the platform-dependent configuration.
    pub fn platform_config<F>(&mut self, f: F) -> &mut Self
    where
        F: FnOnce(&mut PlatformConfig),
    {
        f(&mut self.platform_config);
        self
    }

    /// Set the tun name.
    ///
    /// [Note: on macOS, the tun name must be the form `utunx` where `x` is a number, such as `utun3`. -- end note]
    #[cfg(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd"
    ))]
    pub fn name<S: AsRef<str>>(&mut self, name: S) -> &mut Self {
        self.name = Some(name.as_ref().into());
        self
    }

    /// Set the address.
    #[cfg(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd"
    ))]
    pub fn address_with_prefix<A: IntoAddress>(&mut self, value: A, prefix: u8) -> &mut Self {
        let address = value.into_address().unwrap();
        if address.is_ipv4() {
            let ip_net = ipnet::IpNet::new(address, prefix).unwrap();
            self.address_mask_v4.replace((address, ip_net.netmask()));
        } else {
            self.address_prefix_v6.replace(vec![(address, prefix)]);
        }
        self
    }
    /// Set the address.
    #[cfg(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd"
    ))]
    pub fn address_with_netmask<A: IntoAddress>(&mut self, value: A, netmask: A) -> &mut Self {
        let address = value.into_address().unwrap();
        let netmask = netmask.into_address().unwrap();
        let prefix = ipnet::ip_mask_to_prefix(netmask).unwrap();
        self.address_with_prefix(address, prefix)
    }
    /// Set the address.
    #[cfg(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd"
    ))]
    pub fn address_with_prefix_multi<A: IntoAddress>(&mut self, values: &[(A, u8)]) -> &mut Self {
        let mut address_mask_v4 = None;
        let mut address_mask_v6 = Vec::new();
        for (value, prefix) in values {
            let address = value.into_address().unwrap();
            if address.is_ipv4() {
                let ip_net = ipnet::IpNet::new(address, *prefix).unwrap();
                address_mask_v4.replace((address, ip_net.netmask()));
            } else {
                address_mask_v6.push((address, *prefix));
            }
        }
        self.address_mask_v4 = address_mask_v4;
        if !address_mask_v6.is_empty() {
            self.address_prefix_v6.replace(address_mask_v6);
        }
        self
    }
    /// Set the destination address.
    #[cfg(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd"
    ))]
    pub fn destination<A: IntoAddress>(&mut self, value: A) -> &mut Self {
        self.destination = Some(value.into_address().unwrap());
        self
    }

    /// Set the broadcast address.
    #[cfg(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd"
    ))]
    pub fn broadcast<A: IntoAddress>(&mut self, value: A) -> &mut Self {
        self.broadcast = Some(value.into_address().unwrap());
        self
    }

    /// Set the MTU.
    ///
    #[cfg(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd"
    ))]
    pub fn mtu(&mut self, value: u16) -> &mut Self {
        self.mtu = Some(value);
        self
    }

    /// Set the interface to be enabled once created.
    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "windows"
    ))]
    pub fn up(&mut self) -> &mut Self {
        self.enabled = Some(true);
        self
    }

    /// Set the interface to be disabled once created.
    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "windows"
    ))]
    pub fn down(&mut self) -> &mut Self {
        self.enabled = Some(false);
        self
    }

    /// Set the OSI layer of operation.
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "freebsd",))]
    pub fn layer(&mut self, value: Layer) -> &mut Self {
        self.layer = Some(value);
        self
    }
}

use super::Device;

/// Reconfigure the device.
#[allow(dead_code)]
pub(crate) fn configure(device: &Device, config: &Configuration) -> crate::error::Result<()> {
    #[cfg(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd"
    ))]
    {
        if let Some(mtu) = config.mtu {
            device.set_mtu(mtu)?;
        }
        if let Some((address, netmask)) = config.address_mask_v4 {
            device.set_network_address(address, netmask, config.destination)?;
        }
        if let Some(values) = &config.address_prefix_v6 {
            for (address, prefix) in values {
                device.add_address_v6(*address, *prefix)?
            }
        }
    }
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "freebsd",))]
    if config.layer == Some(Layer::L2) {
        if let Some(mac_addr) = config.mac_addr {
            device.set_mac_address(mac_addr)?;
        }
    }
    #[cfg(target_os = "linux")]
    if let Some(ip) = config.broadcast {
        device.set_broadcast(ip)?;
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "windows"
    ))]
    device.enabled(config.enabled.unwrap_or(true))?;
    _ = device;
    _ = config;
    Ok(())
}
