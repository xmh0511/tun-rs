use crate::platform::windows::ffi::encode_utf16;
use crate::platform::windows::{ffi, netsh};
use std::{io, ptr};
use windows_sys::Win32::Foundation::{
    GetLastError, ERROR_BUFFER_OVERFLOW, ERROR_NO_MORE_ITEMS, FALSE, HANDLE, WAIT_FAILED,
    WAIT_OBJECT_0,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::System::Threading::{
    CreateEventW, SetEvent, WaitForMultipleObjects, INFINITE,
};
mod wintun_log;
mod wintun_raw;

/// The maximum size of wintun's internal ring buffer (in bytes)
pub const MAX_RING_CAPACITY: u32 = 0x400_0000;

/// The minimum size of wintun's internal ring buffer (in bytes)
pub const MIN_RING_CAPACITY: u32 = 0x2_0000;

/// Maximum pool name length including zero terminator
pub const MAX_POOL: usize = 256;

pub struct TunDevice {
    index: u32,
    luid: NET_LUID_LH,
    session: SessionHandle,
}
struct AdapterHandle {
    win_tun: wintun_raw::wintun,
    handle: wintun_raw::WINTUN_ADAPTER_HANDLE,
}
impl Drop for AdapterHandle {
    fn drop(&mut self) {
        unsafe {
            self.win_tun.WintunCloseAdapter(self.handle);
            self.win_tun.WintunDeleteDriver();
        }
    }
}
struct SessionHandle {
    adapter: AdapterHandle,
    handle: wintun_raw::WINTUN_SESSION_HANDLE,
    read_event: HANDLE,
    shutdown_event: HANDLE,
}
impl Drop for SessionHandle {
    fn drop(&mut self) {
        if let Err(e) = ffi::close_handle(self.shutdown_event) {
            log::warn!("close shutdown_event={:?}", e)
        }
        unsafe {
            self.adapter.win_tun.WintunEndSession(self.handle);
        }
    }
}
unsafe impl Send for TunDevice {}

unsafe impl Sync for TunDevice {}
impl TunDevice {
    pub fn create(
        wintun_path: &str,
        name: &str,
        tunnel_type: &str,
        guid: u128,
        ring_capacity: u32,
    ) -> crate::error::Result<Self> {
        let range = MIN_RING_CAPACITY..=MAX_RING_CAPACITY;
        if !range.contains(&ring_capacity) {
            Err(io::Error::new(
                io::ErrorKind::Other,
                format!("ring capacity {ring_capacity} not in [{MIN_RING_CAPACITY},{MAX_RING_CAPACITY}]"),
            ))?;
        }
        let name_utf16 = encode_utf16(&name);
        let tunnel_type_utf16 = encode_utf16(&tunnel_type);
        if name_utf16.len() > MAX_POOL {
            Err(io::Error::new(io::ErrorKind::Other, "name too long"))?;
        }
        if tunnel_type_utf16.len() > MAX_POOL {
            Err(io::Error::new(io::ErrorKind::Other, "tunnel type too long"))?;
        }
        unsafe {
            let win_tun = wintun_raw::wintun::new(wintun_path)?;

            //SAFETY: guid is a unique integer so transmuting either all zeroes or the user's preferred
            //guid to the wintun_raw guid type is safe and will allow the windows kernel to see our GUID

            let guid_struct: wintun_raw::GUID = std::mem::transmute(guid);
            let guid_ptr = &guid_struct as *const wintun_raw::GUID;

            //SAFETY: the function is loaded from the wintun dll properly, we are providing valid
            //pointers, and all the strings are correct null terminated UTF-16. This safety rationale
            //applies for all Wintun* functions below
            let adapter = win_tun.WintunCreateAdapter(
                name_utf16.as_ptr(),
                tunnel_type_utf16.as_ptr(),
                guid_ptr,
            );
            if adapter.is_null() {
                Err(io::Error::last_os_error())?
            }
            let adapter = AdapterHandle {
                win_tun,
                handle: adapter,
            };
            let mut luid: wintun_raw::NET_LUID = std::mem::zeroed();
            adapter
                .win_tun
                .WintunGetAdapterLUID(adapter.handle, &mut luid as *mut wintun_raw::NET_LUID);
            let session = adapter
                .win_tun
                .WintunStartSession(adapter.handle, ring_capacity);
            if session.is_null() {
                Err(io::Error::last_os_error())?
            }
            let shutdown_event = CreateEventW(ptr::null_mut(), 0, 0, ptr::null_mut());
            let read_event = adapter.win_tun.WintunGetReadWaitEvent(session) as HANDLE;
            let session = SessionHandle {
                adapter,
                handle: session,
                read_event,
                shutdown_event,
            };

            let index = ffi::luid_to_index(&std::mem::transmute(luid))?;

            let tun = Self {
                luid: std::mem::transmute(luid),
                index,
                session,
            };
            Ok(tun)
        }
    }
    pub fn index(&self) -> u32 {
        self.index
    }
    pub fn get_name(&self) -> io::Result<String> {
        ffi::luid_to_alias(&self.luid)
    }
    pub fn set_name(&self, newname: &str) -> io::Result<()> {
        let name = self.get_name()?;
        netsh::set_interface_name(&name, newname)
    }
    pub fn get_mtu(&self) -> io::Result<u32> {
        ffi::get_mtu_by_index(self.index)
    }
    pub fn set_mtu(&self, mtu: u16) -> io::Result<()> {
        netsh::set_interface_mtu(self.index, mtu as _)
    }
    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.session.send(buf)
    }
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.session.recv(buf)
    }
    pub fn try_send(&self, buf: &[u8]) -> io::Result<usize> {
        self.session.try_send(buf)
    }
    pub fn try_recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.session.try_recv(buf)
    }
    pub fn shutdown(&self) -> io::Result<()> {
        self.session.shutdown()
    }
}

impl SessionHandle {
    fn send(&self, buf: &[u8]) -> io::Result<usize> {
        let mut count = 0;
        loop {
            return match self.try_send(buf) {
                Ok(len) => Ok(len),
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    count += 1;
                    if count > 50 {
                        return Err(io::Error::from(io::ErrorKind::TimedOut));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(1));
                    continue;
                }
                Err(e) => Err(e),
            };
        }
    }
    fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            return match self.try_recv(buf) {
                Ok(n) => Ok(n),
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    self.wait_readable()?;
                    continue;
                }
                Err(e) => Err(e),
            };
        }
    }
    fn try_send(&self, buf: &[u8]) -> io::Result<usize> {
        assert!(buf.len() <= u32::MAX as _);
        let win_tun = &self.adapter.win_tun;
        let handle = self.handle;
        let bytes_ptr = unsafe { win_tun.WintunAllocateSendPacket(handle, buf.len() as u32) };
        if bytes_ptr.is_null() {
            match unsafe { GetLastError() } {
                ERROR_BUFFER_OVERFLOW => Err(std::io::Error::from(io::ErrorKind::WouldBlock)),
                e => Err(io::Error::from_raw_os_error(e as i32)),
            }
        } else {
            unsafe { ptr::copy_nonoverlapping(buf.as_ptr(), bytes_ptr, buf.len()) };
            unsafe { win_tun.WintunSendPacket(handle, bytes_ptr) };
            Ok(buf.len())
        }
    }
    fn try_recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut size = 0u32;

        let win_tun = &self.adapter.win_tun;
        let handle = self.handle;
        let ptr = unsafe { win_tun.WintunReceivePacket(handle, &mut size as *mut u32) };

        if ptr.is_null() {
            // Wintun returns ERROR_NO_MORE_ITEMS instead of blocking if packets are not available
            return match unsafe { GetLastError() } {
                ERROR_NO_MORE_ITEMS => Err(std::io::Error::from(io::ErrorKind::WouldBlock)),
                e => Err(io::Error::from_raw_os_error(e as i32)),
            };
        }
        let size = size as usize;
        if size > buf.len() {
            unsafe { win_tun.WintunReleaseReceivePacket(handle, ptr) };
            use std::io::{Error, ErrorKind::InvalidInput};
            return Err(Error::new(InvalidInput, "destination buffer too small"));
        }
        unsafe { ptr::copy_nonoverlapping(ptr, buf.as_mut_ptr(), size) };
        unsafe { win_tun.WintunReleaseReceivePacket(handle, ptr) };
        Ok(size)
    }
    fn wait_readable(&self) -> io::Result<()> {
        //Wait on both the read handle and the shutdown handle so that we stop when requested
        let handles = [self.read_event, self.shutdown_event];
        let result = unsafe {
            //SAFETY: We abide by the requirements of WaitForMultipleObjects, handles is a
            //pointer to valid, aligned, stack memory
            WaitForMultipleObjects(2, &handles as _, 0, INFINITE)
        };
        match result {
            WAIT_FAILED => Err(io::Error::last_os_error()),
            _ => {
                if result == WAIT_OBJECT_0 {
                    //We have data!
                    Ok(())
                } else {
                    //Shutdown event triggered
                    Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("Shutdown event triggered {}", io::Error::last_os_error()),
                    ))
                }
            }
        }
    }
    fn shutdown(&self) -> io::Result<()> {
        unsafe {
            if FALSE == SetEvent(self.shutdown_event) {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }
}
