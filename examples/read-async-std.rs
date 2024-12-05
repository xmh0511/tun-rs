#[allow(unused_imports)]
use std::sync::Arc;

#[allow(unused_imports)]
use tun_rs::{AbstractDevice, BoxError};

use async_ctrlc::CtrlC;
use async_std::prelude::FutureExt;

#[async_std::main]
async fn main() -> Result<(), BoxError> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init();

    main_entry().await?;
    Ok(())
}
#[cfg(any(target_os = "ios", target_os = "android",))]
async fn main_entry() -> Result<(), BoxError> {
    unimplemented!()
}

#[cfg(any(
    target_os = "windows",
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
))]
async fn main_entry() -> Result<(), BoxError> {
    let mut config = tun_rs::Configuration::default();

    config
        .address_with_prefix((10, 0, 0, 9), 24)
        // will add 0.0.0.0 to interface on windows platform, which route all traffic here
        //.destination((10, 0, 0, 1))
        .mtu(tun_rs::DEFAULT_MTU)
        .up();

    let dev = Arc::new(tun_rs::create_as_async(&config)?);
    let size = dev.mtu()? as usize + tun_rs::PACKET_INFORMATION_LENGTH;
    let mut buf = vec![0; size];
    let ctrlc = CtrlC::new().expect("cannot create Ctrl+C handler?");
    ctrlc
        .race(async {
            while let Ok(len) = dev.recv(&mut buf).await {
                println!("len = {len}");
                println!("pkt: {:?}", &buf[..len]);
            }
        })
        .await;
    println!("Quit...");
    Ok(())
}
