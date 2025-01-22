/*!
# Example:
```rust
use tun_rs::DeviceBuilder;
use std::net::Ipv4Addr;
let dev = DeviceBuilder::new()
            .name("utun7")
            .ipv4(Ipv4Addr::new(10, 0, 0, 12), 24, None)
            .ipv6(
                "CDCD:910A:2222:5498:8475:1111:3900:2021".parse().unwrap(),
                64,
            )
            .mtu(1400)
            .build_sync()?;
let mut buf = [0;65535];
loop {
    let len = dev.recv(&mut buf).unwrap();
    println!("buf= {:?}",&buf[..len]);
}
```
# Example IOS/Android:
```rust
use tun_rs::SyncDevice;
// use PacketTunnelProvider/VpnService create tun fd
let fd = 7799;
let dev = unsafe{SyncDevice::from_fd(fd)};
let mut buf = [0;65535];
loop {
    let len = dev.recv(&mut buf).unwrap();
    println!("buf= {:?}",&buf[..len]);
}
```
*/

#![cfg_attr(docsrs, feature(doc_cfg))]
#[cfg(any(feature = "async_std", feature = "async_tokio"))]
pub use r#async::*;

#[cfg(any(
    target_os = "windows",
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd"
))]
pub use crate::configuration::*;
pub use crate::error::{BoxError, Error, Result};
pub use crate::platform::Device;

mod error;

mod device;
pub use device::SyncDevice;

#[cfg(any(feature = "async_std", feature = "async_tokio"))]
pub mod r#async;
#[cfg(any(
    target_os = "windows",
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd"
))]
mod configuration;
pub mod platform;
pub const PACKET_INFORMATION_LENGTH: usize = 4;
