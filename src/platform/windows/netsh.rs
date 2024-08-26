use std::io;
use std::net::IpAddr;
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
pub fn set_interface_ip(
    index: u32,
    address: &IpAddr,
    netmask: &IpAddr,
    gateway: Option<&IpAddr>,
) -> io::Result<()> {
    let mut binding = std::process::Command::new("netsh");
    let mut cmd = binding
        .arg("interface")
        .arg(if address.is_ipv4() { "ipv4" } else { "ipv6" })
        .arg("set")
        .arg("address")
        .arg(index.to_string().as_str())
        .arg("source=static")
        .arg(format!("address={}", address).as_str())
        .arg(format!("mask={}", netmask).as_str());
    if let Some(gateway) = gateway {
        cmd = cmd.arg(format!("gateway={}", gateway).as_str());
    }
    let out = cmd.output()?;
    if !out.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("cmd={:?},out={:?} ", cmd, String::from_utf8(out.stderr)),
        ));
    }
    Ok(())
}

pub fn set_interface_mtu(index: u32, mtu: u32) -> io::Result<()> {
    let cmd = format!(
        "netsh interface ipv4 set subinterface {}  mtu={} store=persistent",
        index, mtu
    );
    exe_cmd(&cmd)
}
