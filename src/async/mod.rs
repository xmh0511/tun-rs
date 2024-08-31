use crate::error;

use crate::configuration::Configuration;
use crate::platform::create;

#[cfg(unix)]
mod unix_device;
#[cfg(unix)]
pub use unix_device::AsyncDevice;

#[cfg(target_os = "windows")]
mod win_device;
#[cfg(target_os = "windows")]
pub use win_device::AsyncDevice;

/// Create a TUN device with the given name.
pub fn create_as_async(configuration: &Configuration) -> Result<AsyncDevice, error::Error> {
    let device = create(configuration)?;
    AsyncDevice::new(device).map_err(|err| err.into())
}
