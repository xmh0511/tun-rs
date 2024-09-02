// Many things will be used in the future
#![allow(unused)]

//! Module holding safe wrappers over winapi functions

use std::{io, mem, ptr};

use windows_sys::Win32::Foundation::ERROR_IO_PENDING;
use windows_sys::Win32::System::IO::GetOverlappedResult;
use windows_sys::{
    core::{GUID, PCWSTR},
    Win32::{
        Devices::DeviceAndDriverInstallation::{
            SetupDiBuildDriverInfoList, SetupDiCallClassInstaller, SetupDiClassNameFromGuidW,
            SetupDiCreateDeviceInfoList, SetupDiCreateDeviceInfoW, SetupDiDestroyDeviceInfoList,
            SetupDiDestroyDriverInfoList, SetupDiEnumDeviceInfo, SetupDiEnumDriverInfoW,
            SetupDiGetClassDevsW, SetupDiGetDeviceRegistryPropertyW, SetupDiGetDriverInfoDetailW,
            SetupDiOpenDevRegKey, SetupDiSetClassInstallParamsW, SetupDiSetDeviceRegistryPropertyW,
            SetupDiSetSelectedDevice, SetupDiSetSelectedDriverW, HDEVINFO, MAX_CLASS_NAME_LEN,
            SP_DEVINFO_DATA, SP_DRVINFO_DATA_V2_W, SP_DRVINFO_DETAIL_DATA_W,
        },
        Foundation::{
            CloseHandle, GetLastError, BOOL, ERROR_NO_MORE_ITEMS, FALSE, FILETIME, HANDLE, TRUE,
        },
        NetworkManagement::{
            IpHelper::{
                ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToAlias,
                ConvertInterfaceLuidToGuid, ConvertInterfaceLuidToIndex,
            },
            Ndis::NET_LUID_LH,
        },
        Storage::FileSystem::{
            CreateFileW, ReadFile, WriteFile, FILE_CREATION_DISPOSITION, FILE_FLAGS_AND_ATTRIBUTES,
            FILE_SHARE_MODE,
        },
        System::{
            Com::StringFromGUID2,
            Registry::{RegNotifyChangeKeyValue, HKEY},
            Threading::{CreateEventW, WaitForSingleObject},
            IO::DeviceIoControl,
        },
    },
};

fn to_pcwstr(s: &str) -> PCWSTR {
    let mut wide: Vec<u16> = s.encode_utf16().collect();
    wide.push(0);
    wide.as_ptr() as PCWSTR
}

#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
/// Custom type to handle variable size SP_DRVINFO_DETAIL_DATA_W
pub struct SP_DRVINFO_DETAIL_DATA_W2 {
    pub cbSize: u32,
    pub InfDate: FILETIME,
    pub CompatIDsOffset: u32,
    pub CompatIDsLength: u32,
    pub Reserved: usize,
    pub SectionName: [u16; 256],
    pub InfFileName: [u16; 260],
    pub DrvDescription: [u16; 256],
    pub HardwareID: [u16; 512],
}
/// Encode a string as a utf16 buffer
pub fn encode_utf16(string: &str) -> Vec<u16> {
    use std::iter::once;
    string.encode_utf16().chain(once(0)).collect()
}

pub fn decode_utf16(string: &[u16]) -> String {
    let end = string.iter().position(|b| *b == 0).unwrap_or(string.len());
    String::from_utf16_lossy(&string[..end])
}

pub fn string_from_guid(guid: &GUID) -> io::Result<String> {
    let mut string = vec![0; 39];

    match unsafe { StringFromGUID2(guid, string.as_mut_ptr(), string.len() as _) } {
        0 => Err(io::Error::last_os_error()),
        _ => Ok(decode_utf16(&string)),
    }
}

pub fn alias_to_luid(alias: &str) -> io::Result<NET_LUID_LH> {
    let alias = encode_utf16(alias);
    let mut luid = unsafe { mem::zeroed() };
    match unsafe { ConvertInterfaceAliasToLuid(alias.as_ptr(), &mut luid) } {
        0 => Ok(luid),
        err => Err(io::Error::last_os_error()),
    }
}

pub fn luid_to_index(luid: &NET_LUID_LH) -> io::Result<u32> {
    let mut index = 0;
    match unsafe { ConvertInterfaceLuidToIndex(luid, &mut index) } {
        0 => Ok(index),
        err => Err(io::Error::last_os_error()),
    }
}

pub fn luid_to_guid(luid: &NET_LUID_LH) -> io::Result<GUID> {
    let mut guid = unsafe { mem::zeroed() };
    match unsafe { ConvertInterfaceLuidToGuid(luid, &mut guid) } {
        0 => Ok(guid),
        err => Err(io::Error::last_os_error()),
    }
}

pub fn luid_to_alias(luid: &NET_LUID_LH) -> io::Result<String> {
    // IF_MAX_STRING_SIZE + 1
    let mut alias = vec![0; 257];
    match unsafe { ConvertInterfaceLuidToAlias(luid, alias.as_mut_ptr(), alias.len()) } {
        0 => Ok(decode_utf16(&alias)),
        err => Err(io::Error::last_os_error()),
    }
}

pub fn close_handle(handle: HANDLE) -> io::Result<()> {
    match unsafe { CloseHandle(handle) } {
        0 => Err(io::Error::last_os_error()),
        _ => Ok(()),
    }
}

pub fn create_file(
    file_name: &str,
    desired_access: u32,
    share_mode: FILE_SHARE_MODE,
    creation_disposition: FILE_CREATION_DISPOSITION,
    flags_and_attributes: FILE_FLAGS_AND_ATTRIBUTES,
) -> io::Result<HANDLE> {
    let file_name = encode_utf16(file_name);
    let handle = unsafe {
        CreateFileW(
            file_name.as_ptr(),
            desired_access,
            share_mode,
            ptr::null_mut(),
            creation_disposition,
            flags_and_attributes,
            ptr::null_mut(),
        )
    };
    if handle.is_null() {
        Err(io::Error::last_os_error())
    } else {
        Ok(handle)
    }
}
fn ip_overlapped() -> windows_sys::Win32::System::IO::OVERLAPPED {
    windows_sys::Win32::System::IO::OVERLAPPED {
        Internal: 0,
        InternalHigh: 0,
        Anonymous: windows_sys::Win32::System::IO::OVERLAPPED_0 {
            Anonymous: windows_sys::Win32::System::IO::OVERLAPPED_0_0 {
                Offset: 0,
                OffsetHigh: 0,
            },
        },
        hEvent: ptr::null_mut(),
    }
}
pub fn try_read_file(handle: HANDLE, buffer: &mut [u8]) -> io::Result<u32> {
    let mut ret = 0;
    //https://www.cnblogs.com/linyilong3/archive/2012/05/03/2480451.html
    unsafe {
        let mut ip_overlapped = ip_overlapped();
        if 0 == ReadFile(
            handle,
            buffer.as_mut_ptr() as _,
            buffer.len() as _,
            &mut ret,
            &mut ip_overlapped,
        ) {
            let e = io::Error::last_os_error();
            if e.raw_os_error().unwrap_or(0) == ERROR_IO_PENDING as i32 {
                windows_sys::Win32::System::IO::CancelIoEx(handle, &ip_overlapped);
                if 0 == GetOverlappedResult(handle, &ip_overlapped, &mut ret, 1) {
                    Err(io::Error::from(io::ErrorKind::WouldBlock))
                } else {
                    Ok(ret)
                }
            } else {
                Err(e)
            }
        } else {
            Ok(ret)
        }
    }
}
pub fn try_write_file(handle: HANDLE, buffer: &[u8]) -> io::Result<u32> {
    let mut ret = 0;
    let mut ip_overlapped = ip_overlapped();
    unsafe {
        if 0 == WriteFile(
            handle,
            buffer.as_ptr() as _,
            buffer.len() as _,
            &mut ret,
            &mut ip_overlapped,
        ) {
            let e = io::Error::last_os_error();
            if e.raw_os_error().unwrap_or(0) == ERROR_IO_PENDING as i32 {
                windows_sys::Win32::System::IO::CancelIoEx(handle, &ip_overlapped);
                if 0 == GetOverlappedResult(handle, &ip_overlapped, &mut ret, 1) {
                    Err(io::Error::from(io::ErrorKind::WouldBlock))
                } else {
                    Ok(ret)
                }
            } else {
                Err(e)
            }
        } else {
            Ok(ret)
        }
    }
}
pub fn read_file(handle: HANDLE, buffer: &mut [u8]) -> io::Result<u32> {
    let mut ret = 0;
    //https://www.cnblogs.com/linyilong3/archive/2012/05/03/2480451.html
    unsafe {
        let mut ip_overlapped = ip_overlapped();
        if 0 == ReadFile(
            handle,
            buffer.as_mut_ptr() as _,
            buffer.len() as _,
            &mut ret,
            &mut ip_overlapped,
        ) {
            wait_ip_overlapped(handle, &ip_overlapped)
        } else {
            Ok(ret)
        }
    }
}

pub fn write_file(handle: HANDLE, buffer: &[u8]) -> io::Result<u32> {
    let mut ret = 0;
    let mut ip_overlapped = ip_overlapped();
    unsafe {
        if 0 == WriteFile(
            handle,
            buffer.as_ptr() as _,
            buffer.len() as _,
            &mut ret,
            &mut ip_overlapped,
        ) {
            wait_ip_overlapped(handle, &ip_overlapped)
        } else {
            Ok(ret)
        }
    }
}
unsafe fn wait_ip_overlapped(
    handle: HANDLE,
    ip_overlapped: &windows_sys::Win32::System::IO::OVERLAPPED,
) -> io::Result<u32> {
    let e = io::Error::last_os_error();
    if e.raw_os_error().unwrap_or(0) == ERROR_IO_PENDING as i32 {
        let mut ret = 0;
        if 0 == GetOverlappedResult(handle, ip_overlapped, &mut ret, 1) {
            Err(e)
        } else {
            Ok(ret)
        }
    } else {
        Err(e)
    }
}

pub fn create_device_info_list(guid: &GUID) -> io::Result<HDEVINFO> {
    match unsafe { SetupDiCreateDeviceInfoList(guid, ptr::null_mut()) } {
        -1 => Err(io::Error::last_os_error()),
        devinfo => Ok(devinfo),
    }
}

pub fn get_class_devs(guid: &GUID, flags: u32) -> io::Result<HDEVINFO> {
    match unsafe { SetupDiGetClassDevsW(guid, ptr::null(), ptr::null_mut(), flags) } {
        -1 => Err(io::Error::last_os_error()),
        devinfo => Ok(devinfo),
    }
}

pub fn destroy_device_info_list(devinfo: HDEVINFO) -> io::Result<()> {
    match unsafe { SetupDiDestroyDeviceInfoList(devinfo) } {
        0 => Err(io::Error::last_os_error()),
        _ => Ok(()),
    }
}

pub fn class_name_from_guid(guid: &GUID) -> io::Result<String> {
    let mut class_name = vec![0; MAX_CLASS_NAME_LEN as usize];
    match unsafe {
        SetupDiClassNameFromGuidW(
            guid,
            class_name.as_mut_ptr(),
            class_name.len() as _,
            ptr::null_mut(),
        )
    } {
        0 => Err(io::Error::last_os_error()),
        _ => Ok(decode_utf16(&class_name)),
    }
}

pub fn create_device_info(
    devinfo: HDEVINFO,
    device_name: &str,
    guid: &GUID,
    device_description: &str,
    creation_flags: u32,
) -> io::Result<SP_DEVINFO_DATA> {
    let mut devinfo_data: SP_DEVINFO_DATA = unsafe { mem::zeroed() };
    devinfo_data.cbSize = mem::size_of_val(&devinfo_data) as _;
    let device_name = encode_utf16(device_name);
    let device_description = encode_utf16(device_description);
    match unsafe {
        SetupDiCreateDeviceInfoW(
            devinfo,
            device_name.as_ptr(),
            guid,
            device_description.as_ptr(),
            ptr::null_mut(),
            creation_flags,
            &mut devinfo_data,
        )
    } {
        0 => Err(io::Error::last_os_error()),
        _ => Ok(devinfo_data),
    }
}

pub fn set_selected_device(devinfo: HDEVINFO, devinfo_data: &SP_DEVINFO_DATA) -> io::Result<()> {
    match unsafe { SetupDiSetSelectedDevice(devinfo, devinfo_data as *const _ as _) } {
        0 => Err(io::Error::last_os_error()),
        _ => Ok(()),
    }
}

pub fn set_device_registry_property(
    devinfo: HDEVINFO,
    devinfo_data: &SP_DEVINFO_DATA,
    property: u32,
    value: &str,
) -> io::Result<()> {
    let value = encode_utf16(value);
    match unsafe {
        SetupDiSetDeviceRegistryPropertyW(
            devinfo,
            devinfo_data as *const _ as _,
            property,
            value.as_ptr() as _,
            (value.len() * 2) as _,
        )
    } {
        0 => Err(io::Error::last_os_error()),
        _ => Ok(()),
    }
}

pub fn get_device_registry_property(
    devinfo: HDEVINFO,
    devinfo_data: &SP_DEVINFO_DATA,
    property: u32,
) -> io::Result<String> {
    let mut value = vec![0; 32];

    match unsafe {
        SetupDiGetDeviceRegistryPropertyW(
            devinfo,
            devinfo_data as *const _ as _,
            property,
            ptr::null_mut(),
            value.as_mut_ptr() as _,
            (value.len() * 2) as _,
            ptr::null_mut(),
        )
    } {
        0 => Err(io::Error::last_os_error()),
        _ => Ok(decode_utf16(&value)),
    }
}

pub fn build_driver_info_list(
    devinfo: HDEVINFO,
    devinfo_data: &mut SP_DEVINFO_DATA,
    driver_type: u32,
) -> io::Result<()> {
    match unsafe { SetupDiBuildDriverInfoList(devinfo, devinfo_data as *const _ as _, driver_type) }
    {
        0 => Err(io::Error::last_os_error()),
        _ => Ok(()),
    }
}

pub fn destroy_driver_info_list(
    devinfo: HDEVINFO,
    devinfo_data: &SP_DEVINFO_DATA,
    driver_type: u32,
) -> io::Result<()> {
    match unsafe {
        SetupDiDestroyDriverInfoList(devinfo, devinfo_data as *const _ as _, driver_type)
    } {
        0 => Err(io::Error::last_os_error()),
        _ => Ok(()),
    }
}

pub fn get_driver_info_detail(
    devinfo: HDEVINFO,
    devinfo_data: &SP_DEVINFO_DATA,
    drvinfo_data: &SP_DRVINFO_DATA_V2_W,
) -> io::Result<SP_DRVINFO_DETAIL_DATA_W2> {
    let mut drvinfo_detail: SP_DRVINFO_DETAIL_DATA_W2 = unsafe { mem::zeroed() };
    drvinfo_detail.cbSize = mem::size_of::<SP_DRVINFO_DETAIL_DATA_W>() as _;

    match unsafe {
        SetupDiGetDriverInfoDetailW(
            devinfo,
            devinfo_data as *const _ as _,
            drvinfo_data as *const _ as _,
            &mut drvinfo_detail as *mut _ as _,
            mem::size_of_val(&drvinfo_detail) as _,
            ptr::null_mut(),
        )
    } {
        0 => Err(io::Error::last_os_error()),
        _ => Ok(drvinfo_detail),
    }
}

pub fn set_selected_driver(
    devinfo: HDEVINFO,
    devinfo_data: &SP_DEVINFO_DATA,
    drvinfo_data: &SP_DRVINFO_DATA_V2_W,
) -> io::Result<()> {
    match unsafe {
        SetupDiSetSelectedDriverW(
            devinfo,
            devinfo_data as *const _ as _,
            drvinfo_data as *const _ as _,
        )
    } {
        0 => Err(io::Error::last_os_error()),
        _ => Ok(()),
    }
}

pub fn set_class_install_params(
    devinfo: HDEVINFO,
    devinfo_data: &SP_DEVINFO_DATA,
    params: &impl Copy,
) -> io::Result<()> {
    match unsafe {
        SetupDiSetClassInstallParamsW(
            devinfo,
            devinfo_data as *const _ as _,
            params as *const _ as _,
            mem::size_of_val(params) as _,
        )
    } {
        0 => Err(io::Error::last_os_error()),
        _ => Ok(()),
    }
}

pub fn call_class_installer(
    devinfo: HDEVINFO,
    devinfo_data: &SP_DEVINFO_DATA,
    install_function: u32,
) -> io::Result<()> {
    match unsafe {
        SetupDiCallClassInstaller(install_function, devinfo, devinfo_data as *const _ as _)
    } {
        0 => Err(io::Error::last_os_error()),
        _ => Ok(()),
    }
}

pub fn open_dev_reg_key(
    devinfo: HDEVINFO,
    devinfo_data: &SP_DEVINFO_DATA,
    scope: u32,
    hw_profile: u32,
    key_type: u32,
    sam_desired: u32,
) -> io::Result<HKEY> {
    const INVALID_KEY_VALUE: HKEY = windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE as _;

    match unsafe {
        SetupDiOpenDevRegKey(
            devinfo,
            devinfo_data as *const _ as _,
            scope,
            hw_profile,
            key_type,
            sam_desired,
        )
    } {
        INVALID_KEY_VALUE => Err(io::Error::last_os_error()),
        key => Ok(key),
    }
}

pub fn notify_change_key_value(
    key: HKEY,
    watch_subtree: BOOL,
    notify_filter: u32,
    milliseconds: u32,
) -> io::Result<()> {
    const INVALID_HANDLE_VALUE: HKEY = windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE as _;

    let event = match unsafe { CreateEventW(ptr::null_mut(), FALSE, FALSE, ptr::null()) } {
        INVALID_HANDLE_VALUE => Err(io::Error::last_os_error()),
        event => Ok(event),
    }?;

    match unsafe { RegNotifyChangeKeyValue(key, watch_subtree, notify_filter, event, TRUE) } {
        0 => Ok(()),
        err => Err(io::Error::last_os_error()),
    }?;

    match unsafe { WaitForSingleObject(event, milliseconds) } {
        0 => Ok(()),
        0x102 => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "Registry timed out",
        )),
        _ => Err(io::Error::last_os_error()),
    }
}

pub fn enum_driver_info(
    devinfo: HDEVINFO,
    devinfo_data: &SP_DEVINFO_DATA,
    driver_type: u32,
    member_index: u32,
) -> Option<io::Result<SP_DRVINFO_DATA_V2_W>> {
    let mut drvinfo_data: SP_DRVINFO_DATA_V2_W = unsafe { mem::zeroed() };
    drvinfo_data.cbSize = mem::size_of_val(&drvinfo_data) as _;
    match unsafe {
        SetupDiEnumDriverInfoW(
            devinfo,
            devinfo_data as *const _ as _,
            driver_type,
            member_index,
            &mut drvinfo_data,
        )
    } {
        0 if unsafe { GetLastError() == ERROR_NO_MORE_ITEMS } => None,
        0 => Some(Err(io::Error::last_os_error())),
        _ => Some(Ok(drvinfo_data)),
    }
}

pub fn enum_device_info(
    devinfo: HDEVINFO,
    member_index: u32,
) -> Option<io::Result<SP_DEVINFO_DATA>> {
    let mut devinfo_data: SP_DEVINFO_DATA = unsafe { mem::zeroed() };
    devinfo_data.cbSize = mem::size_of_val(&devinfo_data) as _;

    match unsafe { SetupDiEnumDeviceInfo(devinfo, member_index, &mut devinfo_data) } {
        0 if unsafe { GetLastError() == ERROR_NO_MORE_ITEMS } => None,
        0 => Some(Err(io::Error::last_os_error())),
        _ => Some(Ok(devinfo_data)),
    }
}

pub fn device_io_control(
    handle: HANDLE,
    io_control_code: u32,
    in_buffer: &impl Copy,
    out_buffer: &mut impl Copy,
) -> io::Result<()> {
    let mut junk = 0;
    match unsafe {
        DeviceIoControl(
            handle,
            io_control_code,
            in_buffer as *const _ as _,
            mem::size_of_val(in_buffer) as _,
            out_buffer as *mut _ as _,
            mem::size_of_val(out_buffer) as _,
            &mut junk,
            ptr::null_mut(),
        )
    } {
        0 => Err(io::Error::last_os_error()),
        _ => Ok(()),
    }
}
