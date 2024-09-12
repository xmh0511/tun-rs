use crate::platform::posix::Fd;
#[cfg(any(target_os = "macos", target_os = "ios"))]
use crate::PACKET_INFORMATION_LENGTH as PIL;
#[cfg(any(target_os = "macos", target_os = "ios"))]
use bytes::BufMut;
use std::io::{self, IoSlice, Read, Write};
use std::os::unix::io::{AsRawFd, IntoRawFd, RawFd};
#[cfg(any(target_os = "macos", target_os = "ios"))]
use std::sync::atomic::{AtomicBool, Ordering};

/// Infer the protocol based on the first nibble in the packet buffer.
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub(crate) fn is_ipv6(buf: &[u8]) -> std::io::Result<bool> {
    use std::io::{Error, ErrorKind::InvalidData};
    if buf.is_empty() {
        return Err(Error::new(InvalidData, "Zero-length data"));
    }
    match buf[0] >> 4 {
        4 => Ok(false),
        6 => Ok(true),
        p => Err(Error::new(InvalidData, format!("IP version {}", p))),
    }
}
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub(crate) fn generate_packet_information(_ipv6: bool) -> Option<[u8; PIL]> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    const TUN_PROTO_IP6: [u8; PIL] = (libc::ETH_P_IPV6 as u32).to_be_bytes();
    #[cfg(any(target_os = "linux", target_os = "android"))]
    const TUN_PROTO_IP4: [u8; PIL] = (libc::ETH_P_IP as u32).to_be_bytes();

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    const TUN_PROTO_IP6: [u8; PIL] = (libc::AF_INET6 as u32).to_be_bytes();
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    const TUN_PROTO_IP4: [u8; PIL] = (libc::AF_INET as u32).to_be_bytes();

    // FIXME: Currently, the FreeBSD we test (FreeBSD-14.0-RELEASE) seems to have no PI. Here just a dummy.
    #[cfg(target_os = "freebsd")]
    const TUN_PROTO_IP6: [u8; PIL] = 0x86DD_u32.to_be_bytes();
    #[cfg(target_os = "freebsd")]
    const TUN_PROTO_IP4: [u8; PIL] = 0x0800_u32.to_be_bytes();

    if _ipv6 {
        Some(TUN_PROTO_IP6)
    } else {
        Some(TUN_PROTO_IP4)
    }
}
#[cfg(any(target_os = "macos", target_os = "ios"))]
#[rustversion::since(1.79)]
macro_rules! local_buf_util {
	($e:expr,$size:expr) => {
		if $e{
			&mut vec![0u8; $size][..]
		}else{
			const STACK_BUF_LEN: usize = crate::DEFAULT_MTU as usize + PIL;
			&mut [0u8; STACK_BUF_LEN]
		}
	};
}
#[cfg(any(target_os = "macos", target_os = "ios"))]
#[rustversion::before(1.79)]
macro_rules! local_buf_util {
	($e:expr,$size:expr) =>{
		{
			#[allow(clippy::large_enum_variant)]
			pub(crate) enum OptBuf{
				Heap(Vec<u8>),
				Stack([u8;crate::DEFAULT_MTU as usize + PIL])
			}
			impl OptBuf{
				pub(crate) fn as_mut(& mut self)->& mut [u8]{
					match self{
						OptBuf::Heap(v)=>v.as_mut(),
						OptBuf::Stack(v)=>v.as_mut()
					}
				}
			}

			fn get_local_buf(cond:bool,in_buf_len:usize)-> OptBuf{
				if cond{
					OptBuf::Heap(vec![0u8; in_buf_len])
				}else{
					const STACK_BUF_LEN: usize = crate::DEFAULT_MTU as usize + PIL;
					OptBuf::Stack([0u8; STACK_BUF_LEN])
				}
			}
			get_local_buf($e,$size)
		}
	}
}
#[cfg(any(target_os = "macos", target_os = "ios"))]
#[rustversion::since(1.79)]
macro_rules! need_mut {
    ($id:ident, $e:expr) => {
        let $id = $e;
    };
}
#[cfg(any(target_os = "macos", target_os = "ios"))]
#[rustversion::before(1.79)]
macro_rules! need_mut {
    ($id:ident, $e:expr) => {
        let mut $id = $e;
    };
}

pub struct Tun {
    pub(crate) fd: Fd,
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    ignore_packet_information: AtomicBool,
}

impl Tun {
    pub(crate) fn new(fd: Fd) -> Self {
        Self {
            fd,
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            ignore_packet_information: AtomicBool::new(false),
        }
    }

    pub fn set_nonblock(&self) -> io::Result<()> {
        self.fd.set_nonblock()
    }
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    #[inline]
    pub(crate) fn send(&self, in_buf: &[u8]) -> io::Result<usize> {
        self.fd.write(in_buf)
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    pub(crate) fn send(&self, in_buf: &[u8]) -> io::Result<usize> {
        if self.ignore_packet_info() {
            let ipv6 = is_ipv6(in_buf)?;
            if let Some(header) = generate_packet_information(ipv6) {
                const STACK_BUF_LEN: usize = crate::DEFAULT_MTU as usize + PIL;
                let in_buf_len = in_buf.len() + PIL;

                // The following logic is to prevent dynamically allocating Vec on every send
                // As long as the MTU is set to value lesser than 1500, this api uses `stack_buf`
                // and avoids `Vec` allocation
                let local_buf_v0 = local_buf_util!(in_buf_len > STACK_BUF_LEN, in_buf_len);
                need_mut! {local_buf_v1,local_buf_v0};
                #[allow(clippy::useless_asref)]
                let local_buf = local_buf_v1.as_mut();

                (&mut local_buf[..PIL]).put_slice(header.as_ref());
                (&mut local_buf[PIL..in_buf_len]).put_slice(in_buf);
                let amount = self.fd.write(&local_buf[..in_buf_len])?;
                return Ok(amount - PIL);
            }
        }
        self.fd.write(in_buf)
    }
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    #[inline]
    pub(crate) fn send_vectored(&self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        self.fd.writev(bufs)
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    #[inline]
    pub(crate) fn send_vectored(&self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        if self.ignore_packet_info() {
            let buf = bufs
                .iter()
                .find(|b| !b.is_empty())
                .map_or(&[][..], |b| &**b);
            self.send(buf)
        } else {
            self.fd.writev(bufs)
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    #[inline]
    pub(crate) fn recv(&self, in_buf: &mut [u8]) -> io::Result<usize> {
        self.fd.read(in_buf)
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    pub(crate) fn recv(&self, mut in_buf: &mut [u8]) -> io::Result<usize> {
        if self.ignore_packet_info() {
            const STACK_BUF_LEN: usize = crate::DEFAULT_MTU as usize + PIL;
            let in_buf_len = in_buf.len() + PIL;

            // The following logic is to prevent dynamically allocating Vec on every recv
            // As long as the MTU is set to value lesser than 1500, this api uses `stack_buf`
            // and avoids `Vec` allocation

            let local_buf_v0 = local_buf_util!(in_buf_len > STACK_BUF_LEN, in_buf_len);
            need_mut! {local_buf_v1,local_buf_v0};
            #[allow(clippy::useless_asref)]
            let local_buf = local_buf_v1.as_mut();
            let amount = self.fd.read(local_buf)?;
            in_buf.put_slice(&local_buf[PIL..amount]);
            Ok(amount - PIL)
        } else {
            self.fd.read(in_buf)
        }
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    #[inline]
    pub(crate) fn ignore_packet_info(&self) -> bool {
        self.ignore_packet_information.load(Ordering::Relaxed)
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    pub(crate) fn set_ignore_packet_info(&self, ign: bool) {
        self.ignore_packet_information.store(ign, Ordering::Relaxed)
    }
    #[cfg(feature = "experimental")]
    pub(crate) fn shutdown(&self) -> io::Result<()> {
        self.fd.shutdown()
    }
}

impl Read for Tun {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv(buf)
    }
}

impl Write for Tun {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.send(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl AsRawFd for Tun {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl IntoRawFd for Tun {
    fn into_raw_fd(self) -> RawFd {
        self.fd.into_raw_fd()
    }
}
