use crate::platform::windows::{ffi, netsh};
use std::{io, net, time};
use libc::time;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::System::Ioctl::{FILE_ANY_ACCESS, FILE_DEVICE_UNKNOWN, METHOD_BUFFERED};

mod iface;

pub struct TapDevice {
    luid: NET_LUID_LH,
    handle: HANDLE,
    component_id: String,
    index: u32,
}
unsafe impl Send for TapDevice {}
unsafe impl Sync for TapDevice {}
impl Drop for TapDevice {
    fn drop(&mut self) {
        let _ = iface::delete_interface(&self.component_id, &self.luid);
        let _ = ffi::close_handle(self.handle);
        println!("dddd");
    }
}
fn get_version(handle: HANDLE) -> io::Result<[u64; 3]> {
    let in_version: [u64; 3] = [0; 3];
    let mut out_version: [u64; 3] = [0; 3];
    ffi::device_io_control(
        handle,
        TAP_IOCTL_GET_VERSION,
        &in_version,
        &mut out_version,
    )
        .map(|_| out_version)
}
impl TapDevice {
    pub fn index(&self) -> u32 {
        self.index
    }
    /// Creates a new tap-windows device
    pub fn create(component_id: &str) -> io::Result<Self> {
        let luid = iface::create_interface(component_id)?;
        // Even after retrieving the luid, we might need to wait
        let start = time::Instant::now();
        let handle = loop {
            // If we surpassed 2 seconds just return
            let now = time::Instant::now();
            if now - start > time::Duration::from_secs(3) {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Interface timed out",
                ));
            }

            match iface::open_interface(&luid) {
                Err(_) => {
                    std::thread::yield_now();
                    continue;
                }
                Ok(handle) => {
                    if get_version(handle).is_err() {
                        std::thread::sleep(time::Duration::from_millis(200));
                        continue;
                    }
                    break handle;
                }
            };
        };

        let index = ffi::luid_to_index(&luid)?;
        Ok(Self {
            luid,
            handle,
            index,
            component_id: component_id.to_owned(),
        })
    }

    /// Opens an existing tap-windows device by name
    pub fn open(component_id: &str, name: &str) -> io::Result<Self> {
        let luid = ffi::alias_to_luid(name)?;
        iface::check_interface(component_id, &luid)?;

        let handle = iface::open_interface(&luid)?;
        let index = ffi::luid_to_index(&luid)?;
        Ok(Self {
            index,
            luid,
            handle,
            component_id: component_id.to_owned(),
        })
    }

    /// Deletes the interface before closing it.
    /// By default interfaces are never deleted on Drop,
    /// with this you can choose if you want deletion or not
    /// ```
    pub fn delete(self) -> io::Result<()> {
        iface::delete_interface(&self.component_id, &self.luid)?;

        Ok(())
    }

    /// Sets the status of the interface to connected.
    /// Equivalent to `.set_status(true)`
    pub fn up(&self) -> io::Result<()> {
        self.set_status(true)
    }

    /// Sets the status of the interface to disconnected.
    /// Equivalent to `.set_status(false)`
    pub fn down(&self) -> io::Result<()> {
        self.set_status(false)
    }

    /// Retieve the mac of the interface
    pub fn get_mac(&self) -> io::Result<[u8; 6]> {
        let mut mac = [0; 6];
        ffi::device_io_control(self.handle, TAP_IOCTL_GET_MAC, &(), &mut mac).map(|_| mac)
    }

    /// Retrieve the version of the driver
    pub fn get_version(&self) -> io::Result<[u64; 3]> {
        get_version(self.handle)
    }

    /// Retieve the mtu of the interface
    pub fn get_mtu(&self) -> io::Result<u32> {
        let in_mtu: u32 = 0;
        let mut out_mtu = 0;
        ffi::device_io_control(self.handle, TAP_IOCTL_GET_MTU, &in_mtu, &mut out_mtu)
            .map(|_| out_mtu)
    }
    pub fn set_mtu(&self, mtu: u16) -> io::Result<()> {
        netsh::set_interface_mtu(self.index, mtu as _)
    }
    pub fn get_address(&self) -> io::Result<net::IpAddr> {
        unimplemented!()
    }
    pub fn get_netmask(&self) -> io::Result<net::IpAddr> {
        unimplemented!()
    }
    pub fn get_destination(&self) -> io::Result<net::IpAddr> {
        unimplemented!()
    }
    /// Retrieve the name of the interface
    pub fn get_name(&self) -> io::Result<String> {
        ffi::luid_to_alias(&self.luid)
    }

    /// Set the name of the interface
    pub fn set_name(&self, newname: &str) -> io::Result<()> {
        let name = self.get_name()?;
        netsh::set_interface_name(&name, newname)
    }

    // /// Set the ip of the interface
    // pub fn set_ip<A, B>(&self, address: A, mask: B) -> io::Result<()>
    // where
    //     A: Into<net::Ipv4Addr>,
    //     B: Into<net::Ipv4Addr>,
    // {
    //     let address = address.into().to_string();
    //     let mask = mask.into().to_string();
    //
    //     netsh::set_interface_ip(self.index, address.into(), mask.into(), None)
    // }

    /// Set the status of the interface, true for connected,
    /// false for disconnected.
    pub fn set_status(&self, status: bool) -> io::Result<()> {
        let status: u32 = if status { 1 } else { 0 };
        let mut out_status: u32 = 0;
        ffi::device_io_control(
            self.handle,
            TAP_IOCTL_SET_MEDIA_STATUS,
            &status,
            &mut out_status,
        )
    }
    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        ffi::read_file(self.handle, buf).map(|res| res as _)
    }
    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        ffi::write_file(self.handle, buf).map(|res| res as _)
    }
}

#[allow(non_snake_case)]
#[inline]
const fn CTL_CODE(DeviceType: u32, Function: u32, Method: u32, Access: u32) -> u32 {
    (DeviceType << 16) | (Access << 14) | (Function << 2) | Method
}

const TAP_IOCTL_GET_MAC: u32 = CTL_CODE(FILE_DEVICE_UNKNOWN, 1, METHOD_BUFFERED, FILE_ANY_ACCESS);
const TAP_IOCTL_GET_VERSION: u32 =
    CTL_CODE(FILE_DEVICE_UNKNOWN, 2, METHOD_BUFFERED, FILE_ANY_ACCESS);
const TAP_IOCTL_GET_MTU: u32 = CTL_CODE(FILE_DEVICE_UNKNOWN, 3, METHOD_BUFFERED, FILE_ANY_ACCESS);
const TAP_IOCTL_SET_MEDIA_STATUS: u32 =
    CTL_CODE(FILE_DEVICE_UNKNOWN, 6, METHOD_BUFFERED, FILE_ANY_ACCESS);
