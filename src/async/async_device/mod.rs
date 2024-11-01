#[cfg(all(feature = "async_tokio", not(feature = "async_std")))]
mod tokio;
#[cfg(all(feature = "async_tokio", not(feature = "async_std")))]
pub use tokio::*;

#[cfg(all(feature = "async_std", not(feature = "async_tokio")))]
mod async_std;
#[cfg(all(feature = "async_std", not(feature = "async_tokio")))]
pub use async_std::*;

#[cfg(all(feature = "async_tokio", feature = "async_std"))]
compile_error! {"More than one asynchronous runtime is simultaneously specified in features"}

// Polyfill implementation, which is not usable and shouldn't be reachable
#[doc(hidden)]
#[cfg(all(feature = "async_tokio", feature = "async_std"))]
pub struct AsyncFd;

#[doc(hidden)]
#[cfg(all(feature = "async_tokio", feature = "async_std"))]
impl AsyncFd {
    pub fn new(_device: crate::platform::Device) -> std::io::Result<Self> {
        unreachable!()
    }
    pub async fn recv(&self, _buf: &mut [u8]) -> std::io::Result<usize> {
        unreachable!()
    }
    pub async fn send(&self, _buf: &[u8]) -> std::io::Result<usize> {
        unreachable!()
    }
    pub fn send_vectored<'a>(
        &'a self,
        _bufs: &'a [std::io::IoSlice<'_>],
    ) -> impl std::future::Future<Output = std::io::Result<usize>> {
        async { unreachable!() }
    }

    pub fn get_ref(&self) -> &crate::platform::Device {
        unreachable!()
    }
}
