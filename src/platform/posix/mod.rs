mod sockaddr;
#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "macos"))]
pub(crate) use sockaddr::sockaddr_union;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) use sockaddr::ipaddr_to_sockaddr;

mod fd;
pub(crate) use self::fd::Fd;

mod tun;
pub use self::tun::Tun;

pub mod device;
