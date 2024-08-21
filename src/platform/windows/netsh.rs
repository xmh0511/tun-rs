use std::io;
use std::net::Ipv4Addr;
use std::os::windows::process::CommandExt;
use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;

pub fn set_interface_metric(index: u32, metric: u16) -> io::Result<()> {
    let cmd = format!(
        "netsh interface ip set interface {} metric={}",
        index, metric
    );
    exe_cmd(&cmd)
}
pub fn exe_cmd(cmd: &str) -> io::Result<()> {
    let out = std::process::Command::new("cmd")
        .creation_flags(CREATE_NO_WINDOW)
        .arg("/C")
        .arg(cmd)
        .output()?;
    if !out.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("cmd={:?},out={:?}", cmd, String::from_utf8(out.stderr)),
        ));
    }
    Ok(())
}

/// 设置网卡ip
pub fn set_interface_ip(index: u32, address: &Ipv4Addr, netmask: &Ipv4Addr) -> io::Result<()> {
    let cmd = format!(
        "netsh interface ip set address {} static {:?} {:?} ",
        index, address, netmask,
    );
    exe_cmd(&cmd)
}

pub fn set_interface_mtu(index: u32, mtu: u32) -> io::Result<()> {
    let cmd = format!(
        "netsh interface ipv4 set subinterface {}  mtu={} store=persistent",
        index, mtu
    );
    exe_cmd(&cmd)
}
