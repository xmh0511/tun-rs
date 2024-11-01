#[allow(unused_imports)]
use std::sync::Arc;

use tokio::sync::mpsc::Receiver;
#[allow(unused_imports)]
use tun_rs::{AbstractDevice, BoxError};

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init();
    let (tx, rx) = tokio::sync::mpsc::channel::<()>(1);

    ctrlc2::set_async_handler(async move {
        tx.send(()).await.expect("Signal error");
    })
    .await;

    main_entry(rx).await?;
    Ok(())
}
#[cfg(any(target_os = "ios", target_os = "android",))]
async fn main_entry(_quit: Receiver<()>) -> Result<(), BoxError> {
    unimplemented!()
}
#[cfg(any(
    target_os = "windows",
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
))]

async fn main_entry(mut quit: Receiver<()>) -> Result<(), BoxError> {
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
    loop {
        tokio::select! {
            _ = quit.recv() => {
                println!("Quit...");
                break;
            }
            len = dev.recv(&mut buf) => {
                println!("len = {len:?}");
                println!("pkt: {:?}", &buf[..len?]);
            }
        };
    }
    Ok(())
}
