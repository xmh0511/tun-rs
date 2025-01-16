#[cfg(unix)]
mod async_device;

#[cfg(unix)]
mod unix_device;
#[cfg(unix)]
pub use unix_device::AsyncDevice;
#[cfg(target_os = "windows")]
mod win_device;
#[cfg(target_os = "windows")]
pub use win_device::AsyncDevice;
