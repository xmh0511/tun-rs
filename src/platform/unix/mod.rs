mod sockaddr;
#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "macos"))]
pub(crate) use sockaddr::sockaddr_union;

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
#[allow(unused_imports)]
pub(crate) use sockaddr::ipaddr_to_sockaddr;

mod fd;
pub(crate) use self::fd::Fd;

mod tun;
pub(crate) use self::tun::Tun;

pub(crate) mod device;
