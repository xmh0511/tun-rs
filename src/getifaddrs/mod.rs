use bitflags::bitflags;

bitflags! {
    /// Flags representing the status and capabilities of a network interface.
    ///
    /// These flags provide information about the current state and features of a network interface.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct InterfaceFlags: u32 {
        /// The interface is up and running.
        const UP = 0x1;
        /// The interface is in a running state.
        const RUNNING = 0x2;
        /// The interface supports broadcast.
        const BROADCAST = 0x4;
        /// The interface is a loopback interface.
        const LOOPBACK = 0x8;
        /// The interface is a point-to-point link.
        const POINTTOPOINT = 0x10;
        /// The interface supports multicast.
        const MULTICAST = 0x20;
    }
}

/// Represents a network interface.
///
/// This struct contains information about a network interface, including its name,
/// IP address, netmask, flags, and index.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Interface {
    /// The name of the interface.
    pub name: String,
    /// The description of the interface (Windows-specific).
    #[cfg(windows)]
    pub description: String,
    /// The IP address associated with the interface.
    pub address: std::net::IpAddr,
    /// The netmask of the interface, if available.
    pub netmask: Option<std::net::IpAddr>,
    /// The destination of the interface, if available.
    pub dest_addr: Option<std::net::IpAddr>,
    /// The flags indicating the interface's properties and state.
    pub flags: InterfaceFlags,
    /// The index of the interface, if available.
    pub index: Option<u32>,
}

enum InterfaceFilterCriteria {
    Loopback,
    Index(u32),
    Name(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddressFilterCriteria {
    V4,
    V6,
}

/// A filter for network interfaces.
///
/// This struct allows you to specify criteria for filtering network interfaces.
/// You can chain multiple filter methods to narrow down the selection.
///
/// By default, this returns all types of addresses for all interfaces.
///
/// # Examples
///
/// ```
/// # use std::io;
/// # use getifaddrs::InterfaceFilter;
/// # fn main() -> io::Result<()> {
/// // Get all IPv4 interfaces
/// let v4_interfaces = InterfaceFilter::new().v4().get()?;
///
/// // Get all IPv6 interfaces
/// let v6_interfaces = InterfaceFilter::new().v6().get()?;
///
/// // Get loopback interfaces
/// let loopback_interfaces = InterfaceFilter::new().loopback().get()?;
/// # Ok(())
/// # }
/// ```
#[derive(Default)]
pub struct InterfaceFilter {
    criteria: Option<InterfaceFilterCriteria>,
    address: Option<AddressFilterCriteria>,
}

impl InterfaceFilter {
    /// Creates a new `InterfaceFilter` with no criteria set.
    pub fn new() -> Self {
        InterfaceFilter::default()
    }

    /// Filters for loopback interfaces.
    pub fn loopback(mut self) -> Self {
        self.criteria = Some(InterfaceFilterCriteria::Loopback);
        self
    }

    /// Filters for interfaces with the specified index.
    pub fn index(mut self, index: u32) -> Self {
        self.criteria = Some(InterfaceFilterCriteria::Index(index));
        self
    }

    /// Filters for interfaces with the specified name.
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.criteria = Some(InterfaceFilterCriteria::Name(name.into()));
        self
    }

    /// Filters for IPv4 interfaces.
    pub fn v4(mut self) -> Self {
        self.address = Some(AddressFilterCriteria::V4);
        self
    }

    /// Filters for IPv6 interfaces.
    pub fn v6(mut self) -> Self {
        self.address = Some(AddressFilterCriteria::V6);
        self
    }

    /// Applies the filter and returns an iterator over the matching interfaces.
    ///
    /// # Errors
    ///
    /// Returns an `std::io::Error` if there's an issue retrieving the network interfaces.
    pub fn get(self) -> std::io::Result<impl Iterator<Item = Interface>> {
        #[cfg(unix)]
        {
            unix::InterfaceIterator::new(self)
        }
        #[cfg(windows)]
        {
            windows::InterfaceIterator::new(self)
        }
    }
}

#[cfg(unix)]
mod unix {
    use super::{
        AddressFilterCriteria, Interface, InterfaceFilter, InterfaceFilterCriteria, InterfaceFlags,
    };
    use libc::{self, c_int};
    use std::ffi::CStr;
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    pub struct InterfaceIterator {
        ifaddrs: *mut libc::ifaddrs,
        current: *mut libc::ifaddrs,
        filter: InterfaceFilter,
    }

    impl InterfaceIterator {
        pub fn new(filter: InterfaceFilter) -> Result<Self, io::Error> {
            let mut ifaddrs: *mut libc::ifaddrs = std::ptr::null_mut();
            let result = unsafe { libc::getifaddrs(&mut ifaddrs) };
            if result != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(InterfaceIterator {
                ifaddrs,
                current: ifaddrs,
                filter,
            })
        }
    }

    impl Iterator for InterfaceIterator {
        type Item = Interface;

        fn next(&mut self) -> Option<Self::Item> {
            while !self.current.is_null() {
                let ifaddr = unsafe { &*self.current };
                self.current = ifaddr.ifa_next;

                if let Some(addr) = unsafe { ifaddr.ifa_addr.as_ref() } {
                    if addr.sa_family == libc::AF_INET as libc::sa_family_t
                        || addr.sa_family == libc::AF_INET6 as libc::sa_family_t
                    {
                        if let Some(address) = self.filter.address {
                            match address {
                                AddressFilterCriteria::V4 => {
                                    if addr.sa_family != libc::AF_INET as libc::sa_family_t {
                                        continue;
                                    }
                                }
                                AddressFilterCriteria::V6 => {
                                    if addr.sa_family != libc::AF_INET6 as libc::sa_family_t {
                                        continue;
                                    }
                                }
                            }
                        }

                        if let Some(InterfaceFilterCriteria::Name(name)) = &self.filter.criteria {
                            let ifname = unsafe { CStr::from_ptr(ifaddr.ifa_name) };
                            if !name.as_bytes().eq(ifname.to_bytes()) {
                                continue;
                            }
                        }

                        let flags = {
                            let mut flags = InterfaceFlags::empty();
                            let raw_flags: c_int = ifaddr.ifa_flags as _;
                            if raw_flags & libc::IFF_UP != 0 {
                                flags |= InterfaceFlags::UP;
                            }
                            if raw_flags & libc::IFF_RUNNING != 0 {
                                flags |= InterfaceFlags::RUNNING;
                            }
                            if raw_flags & libc::IFF_LOOPBACK != 0 {
                                flags |= InterfaceFlags::LOOPBACK;
                            }
                            if raw_flags & libc::IFF_POINTOPOINT != 0 {
                                flags |= InterfaceFlags::POINTTOPOINT;
                            }
                            if raw_flags & libc::IFF_BROADCAST != 0 {
                                flags |= InterfaceFlags::BROADCAST;
                            }
                            if raw_flags & libc::IFF_MULTICAST != 0 {
                                flags |= InterfaceFlags::MULTICAST;
                            }
                            flags
                        };

                        if let Some(InterfaceFilterCriteria::Loopback) = &self.filter.criteria {
                            if !flags.contains(InterfaceFlags::LOOPBACK) {
                                continue;
                            }
                        }

                        let index = unsafe {
                            let index = libc::if_nametoindex(ifaddr.ifa_name);
                            if index != 0 {
                                Some(index as u32)
                            } else {
                                None
                            }
                        };

                        if let Some(InterfaceFilterCriteria::Index(filter_index)) =
                            &self.filter.criteria
                        {
                            if index != Some(*filter_index) {
                                continue;
                            }
                        }

                        let name = unsafe { CStr::from_ptr(ifaddr.ifa_name) }
                            .to_string_lossy()
                            .into_owned();
                        let address = match unsafe { sockaddr_to_ipaddr(addr) } {
                            Ok(addr) => addr,
                            Err(_) => continue, // Skip invalid address families
                        };
                        let netmask = unsafe {
                            ifaddr
                                .ifa_netmask
                                .as_ref()
                                .and_then(|sa| sockaddr_to_ipaddr(sa).ok())
                        };

                        #[cfg(any(target_os = "macos", target_os = "freebsd"))]
                        let dest_addr = unsafe {
                            ifaddr
                                .ifa_dstaddr
                                .as_ref()
                                .and_then(|sa| sockaddr_to_ipaddr(sa).ok())
                        };

                        #[cfg(all(not(target_os = "macos"), not(target_os = "freebsd")))]
                        let dest_addr = None;

                        return Some(Interface {
                            name,
                            address,
                            netmask,
                            dest_addr,
                            flags,
                            index,
                        });
                    }
                }
            }
            None
        }
    }

    impl Drop for InterfaceIterator {
        fn drop(&mut self) {
            unsafe { libc::freeifaddrs(self.ifaddrs) };
        }
    }

    unsafe fn sockaddr_to_ipaddr(sa: *const libc::sockaddr) -> Result<IpAddr, io::Error> {
        match (*sa).sa_family as i32 {
            libc::AF_INET => {
                let addr_in = sa as *const libc::sockaddr_in;
                let ip_bytes = (*addr_in).sin_addr.s_addr.to_ne_bytes();
                Ok(IpAddr::V4(Ipv4Addr::from(ip_bytes)))
            }
            libc::AF_INET6 => {
                let addr_in6 = sa as *const libc::sockaddr_in6;
                let ip_bytes = (*addr_in6).sin6_addr.s6_addr;
                Ok(IpAddr::V6(Ipv6Addr::from(ip_bytes)))
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid address family",
            )),
        }
    }

    pub fn _if_indextoname(index: usize) -> std::io::Result<String> {
        let mut buffer = vec![0u8; libc::IF_NAMESIZE];
        let result = unsafe {
            libc::if_indextoname(
                index as libc::c_uint,
                buffer.as_mut_ptr() as *mut libc::c_char,
            )
        };
        if result.is_null() {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(unsafe {
                std::ffi::CStr::from_ptr(result)
                    .to_string_lossy()
                    .into_owned()
            })
        }
    }

    pub fn _if_nametoindex(name: impl AsRef<str>) -> std::io::Result<u32> {
        let name_cstr = std::ffi::CString::new(name.as_ref()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid interface name")
        })?;
        let result = unsafe { libc::if_nametoindex(name_cstr.as_ptr()) };
        if result == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(result as _)
        }
    }
}

#[cfg(windows)]
mod windows {
    use super::{
        AddressFilterCriteria, Interface, InterfaceFilter, InterfaceFilterCriteria, InterfaceFlags,
    };
    use std::{ffi::OsString, io, net::IpAddr, os::windows::prelude::OsStringExt};
    use windows_sys::Win32::Foundation::{
        ERROR_BUFFER_OVERFLOW, ERROR_NOT_ENOUGH_MEMORY, ERROR_NO_DATA, NO_ERROR,
    };
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        if_indextoname, if_nametoindex, ConvertInterfaceLuidToIndex, ConvertLengthToIpv4Mask,
        GetAdaptersAddresses, GetNumberOfInterfaces, IF_TYPE_IEEE80211, IP_ADAPTER_ADDRESSES_LH,
        IP_ADAPTER_UNICAST_ADDRESS_LH, MIB_IF_TYPE_LOOPBACK, MIB_IF_TYPE_PPP,
    };
    use windows_sys::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6,
    };

    // Larger than necessary
    const IF_NAMESIZE: usize = 1024;

    pub struct InterfaceIterator {
        adapters: AdaptersAddresses,
        current: *const IP_ADAPTER_ADDRESSES_LH,
        current_unicast: *const IP_ADAPTER_UNICAST_ADDRESS_LH,
        filter: InterfaceFilter,
    }

    impl InterfaceIterator {
        pub fn new(filter: InterfaceFilter) -> io::Result<Self> {
            let family = match filter.address {
                Some(AddressFilterCriteria::V4) => Family::V4,
                Some(AddressFilterCriteria::V6) => Family::V6,
                None => Family::UNSPEC,
            };
            let adapters = AdaptersAddresses::try_new(family, Flags::default())?;
            Ok(InterfaceIterator {
                adapters,
                current: std::ptr::null(),
                current_unicast: std::ptr::null(),
                filter,
            })
        }
    }
    impl Iterator for InterfaceIterator {
        type Item = Interface;

        fn next(&mut self) -> Option<Self::Item> {
            loop {
                if self.current.is_null() {
                    self.current = self.adapters.buf.ptr;
                    self.current_unicast = std::ptr::null();
                } else if self.current_unicast.is_null() {
                    self.current = unsafe { (*self.current).Next };
                    if self.current.is_null() {
                        return None;
                    }
                    self.current_unicast = unsafe { (*self.current).FirstUnicastAddress };
                } else {
                    self.current_unicast = unsafe { (*self.current_unicast).Next };
                }

                if self.current_unicast.is_null() {
                    continue;
                }

                let adapter = unsafe { &*self.current };
                let unicast_addr = unsafe { &*self.current_unicast };

                if let Some(InterfaceFilterCriteria::Loopback) = &self.filter.criteria {
                    if adapter.IfType != MIB_IF_TYPE_LOOPBACK {
                        continue;
                    }
                }

                if let Ok(interface) = convert_to_interface(adapter, unicast_addr) {
                    if let Some(InterfaceFilterCriteria::Name(name)) = &self.filter.criteria {
                        if name != &interface.name {
                            continue;
                        }
                    }
                    if let Some(InterfaceFilterCriteria::Index(index)) = &self.filter.criteria {
                        if Some(*index) != interface.index {
                            continue;
                        }
                    }

                    return Some(interface);
                }
            }
        }
    }

    struct AdaptersAddresses {
        buf: AdapterAddressBuf,
    }

    struct AdapterAddressBuf {
        ptr: *mut IP_ADAPTER_ADDRESSES_LH,
        size: usize,
    }

    impl AdapterAddressBuf {
        fn new(bytes: usize) -> io::Result<Self> {
            let layout = std::alloc::Layout::from_size_align(
                bytes,
                std::mem::align_of::<IP_ADAPTER_ADDRESSES_LH>(),
            )
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
            let ptr = unsafe { std::alloc::alloc(layout) };
            if ptr.is_null() {
                Err(io::Error::new(
                    io::ErrorKind::OutOfMemory,
                    "Failed to allocate memory",
                ))
            } else {
                Ok(Self {
                    ptr: ptr as *mut IP_ADAPTER_ADDRESSES_LH,
                    size: bytes,
                })
            }
        }
    }

    impl Drop for AdapterAddressBuf {
        fn drop(&mut self) {
            let layout = std::alloc::Layout::from_size_align(
                self.size,
                std::mem::align_of::<IP_ADAPTER_ADDRESSES_LH>(),
            )
            .unwrap();
            unsafe { std::alloc::dealloc(self.ptr as *mut u8, layout) };
        }
    }

    impl AdaptersAddresses {
        fn try_new(family: Family, flags: Flags) -> io::Result<Self> {
            let mut num_interfaces = 0u32;
            unsafe {
                if GetNumberOfInterfaces(&mut num_interfaces) != NO_ERROR {
                    num_interfaces = 16; // Estimate if GetNumberOfInterfaces fails
                } else {
                    num_interfaces = num_interfaces.max(8);
                }
            };

            let mut out_buf_len =
                num_interfaces * std::mem::size_of::<IP_ADAPTER_ADDRESSES_LH>() as u32;
            let mut adapter_addresses = Self {
                buf: AdapterAddressBuf::new(out_buf_len as usize)?,
            };

            // The recommended method of calling the GetAdaptersAddresses function is to pre-allocate
            // a 15KB working buffer pointed to by the AdapterAddresses parameter. On typical computers,
            // this dramatically reduces the chances that the GetAdaptersAddresses function returns
            // ERROR_BUFFER_OVERFLOW, which would require calling GetAdaptersAddresses function multiple
            // times.
            const MAX_MEMORY_SIZE: u32 = 128 * 1024; // 128kB
            loop {
                if out_buf_len > MAX_MEMORY_SIZE {
                    return Err(io::Error::new(
                        io::ErrorKind::OutOfMemory,
                        "Failed to allocate buffer: exceeded maximum memory size",
                    ));
                }

                match unsafe {
                    GetAdaptersAddresses(
                        family.into(),
                        flags.into(),
                        std::ptr::null_mut(),
                        adapter_addresses.buf.ptr,
                        &mut out_buf_len,
                    )
                } {
                    NO_ERROR => return Ok(adapter_addresses),
                    ERROR_BUFFER_OVERFLOW | ERROR_NOT_ENOUGH_MEMORY => {
                        if out_buf_len == MAX_MEMORY_SIZE {
                            return Err(io::Error::new(
                                io::ErrorKind::OutOfMemory,
                                "Failed to allocate buffer: exceeded maximum memory size",
                            ));
                        }
                        out_buf_len = (out_buf_len * 2).min(MAX_MEMORY_SIZE);
                        adapter_addresses.buf = AdapterAddressBuf::new(out_buf_len as usize)?;
                        continue;
                    }
                    ERROR_NO_DATA => {
                        return Err(io::Error::new(io::ErrorKind::NotFound, "No data"))
                    }
                    _ => return Err(io::Error::new(io::ErrorKind::Other, "Unknown error")),
                }
            }
        }
    }

    fn convert_to_interface(
        adapter: &IP_ADAPTER_ADDRESSES_LH,
        unicast_addr: &IP_ADAPTER_UNICAST_ADDRESS_LH,
    ) -> io::Result<Interface> {
        let description = to_os_string(adapter.FriendlyName)
            .to_string_lossy()
            .into_owned();

        let address = sockaddr_to_ipaddr(unicast_addr.Address.lpSockaddr)?;

        // Unsure if this is the right mapping here
        let mut flags = InterfaceFlags::empty();
        let raw_flags = unsafe { adapter.Anonymous2.Flags };
        if adapter.OperStatus == 1 {
            // IfOperStatusUp
            flags |= InterfaceFlags::UP | InterfaceFlags::RUNNING;
        }
        if adapter.IfType == MIB_IF_TYPE_LOOPBACK {
            flags |= InterfaceFlags::LOOPBACK;
        }
        if adapter.IfType == IF_TYPE_IEEE80211 {
            flags |= InterfaceFlags::BROADCAST | InterfaceFlags::MULTICAST;
        }
        if adapter.IfType == MIB_IF_TYPE_PPP {
            flags |= InterfaceFlags::POINTTOPOINT;
        }
        if raw_flags & (1 << 4) == 0 {
            // !NoMulticast
            flags |= InterfaceFlags::MULTICAST;
        }
        if raw_flags & (1 << 7) != 0 {
            // Ipv4Enabled
            flags |= InterfaceFlags::UP;
        }
        if raw_flags & (1 << 8) != 0 {
            // Ipv6Enabled
            flags |= InterfaceFlags::UP;
        }
        if raw_flags & (1 << 3) != 0 {
            // ReceiveOnly
            flags &= !InterfaceFlags::RUNNING;
        }

        let netmask = match address {
            IpAddr::V4(_) => {
                let mut mask: u32 = 0;
                unsafe {
                    ConvertLengthToIpv4Mask(unicast_addr.OnLinkPrefixLength as u32, &mut mask);
                }
                Some(IpAddr::V4(std::net::Ipv4Addr::from(mask.to_be())))
            }
            IpAddr::V6(_) => {
                // For IPv6, we can use the prefix length directly
                Some(IpAddr::V6(std::net::Ipv6Addr::new(
                    0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0,
                )))
            }
        };

        // Get the LUID and convert it to an index
        let luid = adapter.Luid;
        let mut if_index: u32 = 0;
        let result = unsafe { ConvertInterfaceLuidToIndex(&luid, &mut if_index) };
        let luid = unsafe { adapter.Luid.Value };
        let (name, index) = if result == NO_ERROR {
            // Call if_indextoname with the converted index
            let mut buffer = [0u8; IF_NAMESIZE];
            let result = unsafe { if_indextoname(if_index, buffer.as_mut_ptr()) };
            if !result.is_null() {
                let name = unsafe { std::ffi::CStr::from_ptr(result as *const i8) }
                    .to_string_lossy()
                    .into_owned();
                (name, Some(if_index))
            } else {
                (format!("if{:#x}", luid), Some(if_index))
            }
        } else {
            (format!("if{:#x}", luid), None)
        };

        Ok(Interface {
            name,
            description,
            address,
            netmask,
            dest_addr: None,
            flags,
            index,
        })
    }

    fn sockaddr_to_ipaddr(sock_addr: *const SOCKADDR) -> io::Result<IpAddr> {
        if sock_addr.is_null() {
            Err(io::Error::new(io::ErrorKind::InvalidInput, "Null pointer"))
        } else {
            match unsafe { (*sock_addr).sa_family } {
                AF_INET => {
                    let sock_addr4 = sock_addr as *const SOCKADDR_IN;
                    let ip_bytes = unsafe { (*sock_addr4).sin_addr.S_un.S_addr.to_ne_bytes() };
                    Ok(IpAddr::V4(ip_bytes.into()))
                }
                AF_INET6 => {
                    let sock_addr6 = sock_addr as *const SOCKADDR_IN6;
                    let ip_bytes = unsafe { (*sock_addr6).sin6_addr.u.Byte };
                    Ok(IpAddr::V6(ip_bytes.into()))
                }
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid address family",
                )),
            }
        }
    }

    fn to_os_string(p: *mut u16) -> OsString {
        if p.is_null() {
            OsString::new()
        } else {
            let mut i = 0usize;
            while unsafe { *p.add(i) } != 0 {
                i += 1;
            }
            OsString::from_wide(unsafe { std::slice::from_raw_parts(p, i) })
        }
    }

    #[derive(Copy, Clone)]
    struct Family(u32);

    impl Family {
        const UNSPEC: Self = Self(0);
        const V4: Self = Self(2);
        const V6: Self = Self(23);
    }

    impl From<Family> for u32 {
        fn from(family: Family) -> Self {
            family.0
        }
    }

    #[derive(Copy, Clone)]
    struct Flags(u32);

    impl Flags {
        fn default() -> Self {
            Self(0)
        }
    }

    impl From<Flags> for u32 {
        fn from(flags: Flags) -> Self {
            flags.0
        }
    }
    pub fn _if_indextoname(index: usize) -> io::Result<String> {
        let mut buffer = vec![0u8; IF_NAMESIZE]; // Allocate buffer for narrow string
        let result = unsafe { if_indextoname(index as u32, buffer.as_mut_ptr()) };
        if result.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(unsafe {
                std::ffi::CStr::from_ptr(result as _)
                    .to_string_lossy()
                    .into_owned()
            })
        }
    }

    pub fn _if_nametoindex(name: impl AsRef<str>) -> io::Result<u32> {
        use std::ffi::CString;
        let name_cstr = CString::new(name.as_ref())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid interface name"))?;
        let result = unsafe { if_nametoindex(name_cstr.as_ptr() as _) };
        if result == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(result as _)
        }
    }
}

/// Returns an iterator for all network interfaces on the system.
///
/// This function creates a new [`InterfaceFilter`] with default settings and uses it to retrieve
/// all network interfaces. It is equivalent to calling `InterfaceFilter::new().get()`.
///
/// # Returns
///
/// Returns a [`Result`] containing an [`Iterator`] over [`Interface`] items on success, or a [`std::io::Error`]
/// if there was a problem retrieving the network interfaces.
pub fn getifaddrs() -> std::io::Result<impl Iterator<Item = Interface>> {
    InterfaceFilter::new().get()
}

/// Converts a network interface index to its corresponding name.
///
/// This function takes a network interface index and returns the corresponding interface name.
///
/// # Arguments
///
/// * `index` - The index of the network interface.
///
/// # Returns
///
/// Returns a `Result` containing the interface name as a `String` on success, or an `io::Error`
/// if the conversion failed or the index is invalid.
///
/// # Examples
///
/// ```
/// match getifaddrs::if_indextoname(1) {
///     Ok(name) => println!("Interface name: {}", name),
///     Err(e) => eprintln!("Error: {}", e),
/// }
/// ```
pub fn if_indextoname(index: usize) -> std::io::Result<String> {
    #[cfg(unix)]
    {
        unix::_if_indextoname(index)
    }
    #[cfg(windows)]
    {
        windows::_if_indextoname(index)
    }
}

/// Converts a network interface name to its corresponding index.
///
/// This function takes a network interface name or number and returns the corresponding interface index.
///
/// # Arguments
///
/// * `name` - The name of the network interface. This can be any type that can be converted
///            to a string slice (`&str`).
///
/// # Returns
///
/// Returns a `Result` containing the interface index as a `usize` on success, or an `io::Error`
/// if the conversion failed or the name is invalid.
///
/// # Examples
///
/// ```
/// match getifaddrs::if_nametoindex("eth0") {
///     Ok(index) => println!("Interface index: {}", index),
///     Err(e) => eprintln!("Error: {}", e),
/// }
/// ```
pub fn if_nametoindex(name: impl AsRef<str>) -> std::io::Result<u32> {
    // Any index that can parse as u32 is returned as-is
    if let Ok(num) = name.as_ref().parse::<u32>() {
        return Ok(num as _);
    }

    #[cfg(unix)]
    {
        unix::_if_nametoindex(name)
    }
    #[cfg(windows)]
    {
        windows::_if_nametoindex(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_interfaces() {
        let interfaces: Vec<Interface> = getifaddrs().unwrap().collect();

        // Print interfaces for debugging
        for interface in &interfaces {
            eprintln!("{interface:#?}");
        }

        // Check for localhost interface
        let localhost = interfaces.iter().find(|i| {
            i.address == IpAddr::V4(Ipv4Addr::LOCALHOST)
                && i.flags.contains(InterfaceFlags::LOOPBACK)
        });
        assert!(localhost.is_some(), "No localhost interface found");

        // Check for at least one non-localhost interface
        let non_localhost = interfaces.iter().find(|i| {
            i.address != IpAddr::V4(Ipv4Addr::LOCALHOST)
                && !i.flags.contains(InterfaceFlags::LOOPBACK)
        });
        assert!(non_localhost.is_some(), "No non-localhost interface found");

        // Sanity check that any interface with an index matches its name
        for interface in &interfaces {
            if let Some(index) = interface.index {
                let name_from_index = if_indextoname(index as usize).unwrap_or_default();
                assert_eq!(
                    interface.name, name_from_index,
                    "Interface name mismatch for index {}",
                    index
                );

                let index_from_name = if_nametoindex(&interface.name).unwrap_or_default();
                assert_eq!(
                    index, index_from_name,
                    "Interface index mismatch for name {}",
                    interface.name
                );
            }
        }
    }

    #[test]
    fn test_filter_address_type() {
        let total = getifaddrs().unwrap().count();
        let mut v4_count = 0;
        for interface in InterfaceFilter::new().v4().get().unwrap() {
            assert!(
                interface.address.is_ipv4(),
                "Expected v4 only: {interface:#?}"
            );
            v4_count += 1;
        }
        let mut v6_count = 0;
        for interface in InterfaceFilter::new().v6().get().unwrap() {
            assert!(
                interface.address.is_ipv6(),
                "Expected v4 only: {interface:#?}"
            );
            v6_count += 1;
        }
        assert_eq!(v4_count + v6_count, total);
    }

    #[test]
    fn test_filter_name_and_index() {
        for interface in getifaddrs().unwrap() {
            // Test filtering by name
            let name = interface.name.clone();
            let v: Vec<_> = InterfaceFilter::new()
                .name(interface.name.clone())
                .get()
                .unwrap()
                .collect();
            eprintln!("Name filter {name}: {v:?}");
            assert!(!v.is_empty());
            for interface in v {
                assert_eq!(name, interface.name);
            }

            // Test filtering by index
            if let Some(index) = interface.index {
                let v: Vec<_> = InterfaceFilter::new().index(index).get().unwrap().collect();
                eprintln!("Index filter {index}: {v:?}");
                assert!(!v.is_empty());
                for interface in v {
                    assert_eq!(Some(index), interface.index);
                }
            }
        }
    }

    #[test]
    fn test_filter_loopback() {
        let loopback_interfaces: Vec<_> =
            InterfaceFilter::new().loopback().get().unwrap().collect();

        assert!(
            !loopback_interfaces.is_empty(),
            "No loopback interfaces found"
        );

        for interface in loopback_interfaces.clone() {
            assert!(
                interface.flags.contains(InterfaceFlags::LOOPBACK),
                "Interface {:?} is not marked as loopback",
                interface.name
            );
        }

        // Verify that non-loopback interfaces are not included
        let all_interfaces: Vec<_> = InterfaceFilter::new().get().unwrap().collect();
        let non_loopback_count = all_interfaces
            .iter()
            .filter(|i| !i.flags.contains(InterfaceFlags::LOOPBACK))
            .count();

        assert_eq!(
            all_interfaces.len() - loopback_interfaces.len(),
            non_loopback_count,
            "Loopback filter included non-loopback interfaces"
        );
    }
}
