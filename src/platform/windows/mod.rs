mod device;
mod ffi;
mod netsh;
mod tap;
mod tun;

#[cfg_attr(docsrs, doc(cfg(any(feature = "async_std", feature = "async_tokio"))))]
#[cfg(any(feature = "async_std", feature = "async_tokio"))]
pub mod async_device;
#[cfg_attr(docsrs, doc(cfg(any(feature = "async_std", feature = "async_tokio"))))]
#[cfg(any(feature = "async_std", feature = "async_tokio"))]
pub use async_device::*;

pub(crate) use device::DeviceInner;
