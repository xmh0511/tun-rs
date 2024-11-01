use crate::platform::posix::Fd;
use crate::platform::{Device, Tun};
use std::io::{IoSlice, IoSliceMut};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, RawFd};

impl FromRawFd for Device {
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        Device::from_fd(fd).unwrap()
    }
}
impl AsRawFd for Device {
    fn as_raw_fd(&self) -> RawFd {
        self.tun.as_raw_fd()
    }
}
impl AsFd for Device {
    fn as_fd(&self) -> BorrowedFd<'_> {
        unsafe { BorrowedFd::borrow_raw(self.as_raw_fd()) }
    }
}

impl IntoRawFd for Device {
    fn into_raw_fd(self) -> RawFd {
        self.tun.into_raw_fd()
    }
}
impl Device {
    pub fn from_fd(fd: RawFd) -> std::io::Result<Self> {
        let tun = Fd::new(fd, true)?;
        Ok(Device::from_tun(Tun::new(tun)))
    }
    /// Set non-blocking mode
    pub fn set_nonblock(&self) -> std::io::Result<()> {
        self.tun.set_nonblock()
    }

    /// Recv a packet from tun device
    pub fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.tun.recv(buf)
    }
    pub fn recv_vectored(&self, bufs: &mut [IoSliceMut<'_>]) -> std::io::Result<usize> {
        self.tun.recv_vectored(bufs)
    }

    /// Send a packet to tun device
    pub fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
        self.tun.send(buf)
    }
    pub fn send_vectored(&self, bufs: &[IoSlice<'_>]) -> std::io::Result<usize> {
        self.tun.send_vectored(bufs)
    }
    /// Do not use nonblocking fd when you want to use shutdown
    #[cfg_attr(docsrs, doc(cfg(feature = "experimental")))]
    #[cfg(feature = "experimental")]
    pub fn shutdown(&self) -> std::io::Result<()> {
        self.tun.shutdown()
    }
    #[allow(dead_code)]
    pub(crate) fn get_if_index(name: &str) -> std::io::Result<u32> {
        let ifname = std::ffi::CString::new(name)?;
        unsafe { Ok(libc::if_nametoindex(ifname.as_ptr())) }
    }
}

// #[derive(Debug)]
// pub struct InterFace{
// 	pub name:String,
// 	pub flags:u32,
// 	pub addr:Option<sockaddr>,
// 	pub netmask:Option<sockaddr>,
// 	pub dstaddr:Option<sockaddr>,
// }

// pub(crate) fn getifaddrs(name:String)->std::io::Result<InterFace>{
// 	unsafe{
// 		let mut ifaddrs_r:* mut ifaddrs = std::ptr::null_mut();
// 		if libc::getifaddrs(& mut ifaddrs_r) < 0 {
// 			return Err(std::io::Error::last_os_error().into());
// 		}
// 		println!("{:?}",ifaddrs_r);
// 		let head = ifaddrs_r;
// 		let mut ve = Vec::new();
// 		while !ifaddrs_r.is_null(){
// 			let if_name = CStr::from_ptr((*ifaddrs_r).ifa_name).to_string_lossy().to_string();
// 			let addr_ptr = (*ifaddrs_r).ifa_addr;
// 			let addr = addr_ptr.as_ref().map(|v|*v);
// 			println!("{}",line!());
// 			let netmask_ptr = (*ifaddrs_r).ifa_netmask;
// 			let netmask = netmask_ptr.as_ref().map(|v|*v);
// 			let dest_ptr =  (*ifaddrs_r).ifa_dstaddr;
// 			let dest_addr = dest_ptr.as_ref().map(|v|*v);
// 			ve.push(InterFace{
// 				name: CStr::from_ptr((*ifaddrs_r).ifa_name).to_string_lossy().to_string(),
// 				flags:(*ifaddrs_r).ifa_flags,
// 				addr,
// 				netmask,
// 				dstaddr:dest_addr,
// 			});
// 			ifaddrs_r = (*ifaddrs_r).ifa_next;
// 		}
// 		libc::freeifaddrs(head);
// 		println!("{ve:?}");
// 		Err(std::io::Error::new(std::io::ErrorKind::NotFound, ""))
// 	}
// }
