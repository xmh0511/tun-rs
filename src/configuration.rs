#[allow(unused_imports)]
use crate::address::IntoAddress;
use crate::platform::PlatformConfig;
use crate::AbstractDevice;
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
pub struct Configuration {
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
    #[allow(dead_code)]
    pub(crate) address: Option<IpAddr>,
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
    pub(crate) netmask: Option<IpAddr>,
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
    #[cfg(windows)]
    pub(crate) metric: Option<u16>,
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
        self.address = Some(address);
        let ip_net = ipnet::IpNet::new(address, prefix).unwrap();
        self.netmask = Some(ip_net.netmask());
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

    #[cfg(windows)]
    pub fn metric(&mut self, metric: u16) -> &mut Self {
        self.metric = Some(metric);
        self
    }
}

/// Reconfigure the device.
#[allow(dead_code)]
pub(crate) fn configure<D: AbstractDevice>(
    device: &D,
    config: &Configuration,
) -> crate::error::Result<()> {
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
        if let (Some(address), Some(netmask)) = (config.address, config.netmask) {
            device.set_network_address(address, netmask, config.destination)?;
        }
    }
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "freebsd",))]
    if config.layer == Some(Layer::L2) {
        if let Some(mac_addr) = config.mac_addr {
            device.set_mac_address(mac_addr)?;
        }
    }
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
    if let Some(ip) = config.broadcast {
        device.set_broadcast(ip)?;
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "windows"
    ))]
    if let Some(enabled) = config.enabled {
        device.enabled(enabled)?;
    }
    _ = device;
    _ = config;
    Ok(())
}
