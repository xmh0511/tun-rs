#[allow(unused_imports)]
use packet::{builder::Builder, icmp, ip, Packet};
use tokio::sync::mpsc::Receiver;
#[allow(unused_imports)]
use tun_rs::{self, AbstractDevice, BoxError, Configuration};

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
    log::info!("starting");
    let mut config = Configuration::default();

    config
        .address_with_prefix((10, 0, 0, 39), 24)
        // will add 0.0.0.0 to interface on windows platform, which route all traffic here
        //.destination((10, 0, 0, 1))
        .up();

    #[cfg(target_os = "windows")]
    config.platform_config(|config| {
        config.device_guid(9099482345783245345345_u128);
    });

    let dev = tun_rs::create_as_async(&config)?;
    log::info!("Successfully created tun {:?}", dev.name());
    #[cfg(target_os = "macos")]
    dev.set_ignore_packet_info(true);

    let size = dev.mtu()? as usize + tun_rs::PACKET_INFORMATION_LENGTH;
    let mut buf = vec![0; size];
    loop {
        tokio::select! {
            _ = quit.recv() => {
                log::info!("Quit...");
                break;
            }
            len = dev.recv(&mut buf) => {
                let pkt: Vec<u8> = buf[..len?].to_vec();
                match ip::Packet::new(pkt) {
                    Ok(ip::Packet::V4(pkt)) => {
                        if let Ok(icmp) = icmp::Packet::new(pkt.payload()) {
                            if let Ok(icmp) = icmp.echo() {
                                log::info!("{:?} - {:?}", icmp.sequence(), pkt.destination());
                                let reply = ip::v4::Builder::default()
                                    .id(0x42)?
                                    .ttl(64)?
                                    .source(pkt.destination())?
                                    .destination(pkt.source())?
                                    .icmp()?
                                    .echo()?
                                    .reply()?
                                    .identifier(icmp.identifier())?
                                    .sequence(icmp.sequence())?
                                    .payload(icmp.payload())?
                                    .build()?;
                                dev.send(&reply).await?;
                            }
                        }
                    }
                    Err(err) => log::info!("Received an invalid packet: {:?}", err),
                    _ => {}
                }
            }
        }
    }
    Ok(())
}
