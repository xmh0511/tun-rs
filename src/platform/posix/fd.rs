//            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//                    Version 2, December 2004
//
// Copyleft (ↄ) meh. <meh@schizofreni.co> | http://meh.schizofreni.co
//
// Everyone is permitted to copy and distribute verbatim or modified
// copies of this license document, and changing it is allowed as long
// as the name is changed.
//
//            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION
//
//  0. You just DO WHAT THE FUCK YOU WANT TO.

use crate::error::{Error, Result};
use libc::{self, fcntl, F_GETFL, F_SETFL, O_NONBLOCK};
#[cfg(feature = "experimental")]
use mio::unix::SourceFd;
#[cfg(feature = "experimental")]
use mio::{Events, Interest, Poll, Token, Waker};
use std::io;
use std::os::unix::io::{AsRawFd, IntoRawFd, RawFd};
#[cfg(feature = "experimental")]
use std::sync::RwLock;

#[cfg(feature = "experimental")]
const READREADY: Token = Token(1);
#[cfg(feature = "experimental")]
const SHUTDOWN: Token = Token(0);

/// POSIX file descriptor support for `io` traits.
pub(crate) struct Fd {
    pub(crate) inner: RawFd,
    close_fd_on_drop: bool,
    #[cfg(feature = "experimental")]
    poll: RwLock<Poll>,
    #[cfg(feature = "experimental")]
    shutdown: Waker,
    #[cfg(feature = "experimental")]
    is_shutdown_: RwLock<bool>,
}

impl Fd {
    pub fn new(value: RawFd, close_fd_on_drop: bool) -> Result<Self> {
        if value < 0 {
            return Err(Error::InvalidDescriptor);
        }
        #[cfg(feature = "experimental")]
        let (waker, poll) = {
            let poll = Poll::new()?;
            let waker = Waker::new(poll.registry(), SHUTDOWN)?;
            (waker, RwLock::new(poll))
        };
        Ok(Fd {
            inner: value,
            close_fd_on_drop,
            #[cfg(feature = "experimental")]
            poll,
            #[cfg(feature = "experimental")]
            shutdown: waker,
            #[cfg(feature = "experimental")]
            is_shutdown_: RwLock::new(false),
        })
    }

    /// Enable non-blocking mode
    pub fn set_nonblock(&self) -> io::Result<()> {
        match unsafe { fcntl(self.inner, F_SETFL, fcntl(self.inner, F_GETFL) | O_NONBLOCK) } {
            0 => Ok(()),
            _ => Err(io::Error::last_os_error()),
        }
    }

    #[cfg(not(feature = "experimental"))]
    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let fd = self.as_raw_fd();
        let amount = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut _, buf.len()) };
        if amount < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(amount as usize)
    }

    #[cfg(feature = "experimental")]
    fn is_shutdown(&self) -> bool {
        *self.is_shutdown_.read().unwrap()
    }

    #[cfg(feature = "experimental")]
    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        if self.is_shutdown() {
            return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "close"));
        }
        use std::sync::RwLockWriteGuard;

        struct Guard<'a>(RwLockWriteGuard<'a, Poll>, i32);
        impl Drop for Guard<'_> {
            fn drop(&mut self) {
                self.0
                    .registry()
                    .deregister(&mut SourceFd(&self.1))
                    .unwrap();
            }
        }
        let fd = self.as_raw_fd();
        let poll = self.poll.write().unwrap();
        let mut poll = Guard(poll, fd);
        poll.0
            .registry()
            .register(&mut SourceFd(&fd), READREADY, Interest::READABLE)?;
        let mut events = Events::with_capacity(128);
        #[allow(clippy::never_loop)]
        loop {
            poll.0.poll(&mut events, None)?;
            for event in events.iter() {
                match event.token() {
                    SHUTDOWN => {
                        return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "close"));
                    }
                    READREADY => {
                        let amount =
                            unsafe { libc::read(fd, buf.as_mut_ptr() as *mut _, buf.len()) };
                        if amount < 0 {
                            return Err(io::Error::last_os_error());
                        }
                        return Ok(amount as usize);
                    }
                    _ => unreachable!(),
                }
            }
        }
    }

    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        let fd = self.as_raw_fd();
        let amount = unsafe { libc::write(fd, buf.as_ptr() as *const _, buf.len()) };
        if amount < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(amount as usize)
    }
    #[cfg(feature = "experimental")]
    pub fn shutdown(&self) -> io::Result<()> {
        *self.is_shutdown_.write().unwrap() = true;
        self.shutdown.wake()
    }
}

impl AsRawFd for Fd {
    fn as_raw_fd(&self) -> RawFd {
        self.inner
    }
}

impl IntoRawFd for Fd {
    fn into_raw_fd(mut self) -> RawFd {
        let fd = self.inner;
        self.inner = -1;
        fd
    }
}

impl Drop for Fd {
    fn drop(&mut self) {
        if self.close_fd_on_drop && self.inner >= 0 {
            unsafe { libc::close(self.inner) };
        }
    }
}
