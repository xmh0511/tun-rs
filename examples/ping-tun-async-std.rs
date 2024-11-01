#[allow(unused_imports)]
use packet::{builder::Builder, icmp, ip, Packet};

#[allow(unused_imports)]
use tun_rs::{self, AbstractDevice, BoxError, Configuration};

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
    let mut config = Configuration::default();

    config
        .address_with_prefix((10, 0, 0, 9), 24)
        // will add 0.0.0.0 to interface on windows platform, which route all traffic here
        //.destination((10, 0, 0, 1))
        .up();

    #[cfg(target_os = "windows")]
    config.platform_config(|config| {
        config.device_guid(9099482345783245345345_u128);
    });

    let dev = tun_rs::create_as_async(&config)?;
    #[cfg(target_os = "macos")]
    dev.set_ignore_packet_info(true);

    let size = dev.mtu()? as usize + tun_rs::PACKET_INFORMATION_LENGTH;
    let mut buf = vec![0; size];
    let ctrlc = CtrlC::new().expect("cannot create Ctrl+C handler?");
    ctrlc
        .race(async {
            _ = async {
                while let Ok(len) = dev.recv(&mut buf).await {
                    let pkt: Vec<u8> = buf[..len].to_vec();
                    match ip::Packet::new(pkt) {
                        Ok(ip::Packet::V4(pkt)) => {
                            if let Ok(icmp) = icmp::Packet::new(pkt.payload()) {
                                if let Ok(icmp) = icmp.echo() {
                                    println!("{:?} - {:?}", icmp.sequence(), pkt.destination());
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
                        Err(err) => println!("Received an invalid packet: {:?}", err),
                        _ => {}
                    }
                }
                Ok::<(), BoxError>(())
            }
            .await;
        })
        .await;
    println!("Quit...");
    Ok(())
}
