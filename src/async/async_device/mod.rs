#[cfg(feature = "async_tokio")]
mod tokio;
#[cfg(feature = "async_tokio")]
pub use tokio::*;

#[cfg(feature = "async_std")]
#[cfg(not(feature = "async_tokio"))]
mod async_std;
#[cfg(feature = "async_std")]
#[cfg(not(feature = "async_tokio"))]
pub use async_std::*;
