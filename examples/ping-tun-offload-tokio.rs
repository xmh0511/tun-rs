#[allow(unused_imports)]
use bytes::BytesMut;
#[allow(unused_imports)]
use packet::{builder::Builder, icmp, ip, Packet};
use tokio::sync::mpsc::Receiver;
#[cfg(target_os = "linux")]
use tun_rs::platform::{GROTable, IDEAL_BATCH_SIZE, VIRTIO_NET_HDR_LEN};
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
#[cfg(not(target_os = "linux"))]
async fn main_entry(_quit: Receiver<()>) -> Result<(), BoxError> {
    unimplemented!()
}
#[cfg(target_os = "linux")]
async fn main_entry(mut quit: Receiver<()>) -> Result<(), BoxError> {
    let mut config = Configuration::default();

    config
        .address_with_prefix((10, 0, 0, 9), 24)
        .platform_config(|config| {
            // After enabling the offload, you need to use recv_multiple and send_multiple to read and write data.
            config.offload(true);
        })
        .mtu(1500)
        .up();
    let dev = tun_rs::create_as_async(&config)?;
    // tunTCPOffloads were added in Linux v2.6
    // tunUDPOffloads were added in Linux v6.2.
    println!("TCP-GSO:{},UDP-GSO:{}", dev.tcp_gso(), dev.udp_gso());

    let mut original_buffer = vec![0; VIRTIO_NET_HDR_LEN + 65535];
    let mut bufs = vec![vec![0u8; 1500]; IDEAL_BATCH_SIZE];
    let mut sizes = vec![0; IDEAL_BATCH_SIZE];
    let mut gro_table = GROTable::default();
    loop {
        tokio::select! {
            _ = quit.recv() => {
                println!("Quit...");
                break;
            }
            num = dev.recv_multiple(&mut original_buffer,&mut bufs,&mut sizes,0) => {
                let num = num?;
                for i in 0..num  {
                    match ip::Packet::new(&bufs[i][..sizes[i]]) {
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
                                    let mut buf = BytesMut::with_capacity(VIRTIO_NET_HDR_LEN+1500);
                                    buf.resize(VIRTIO_NET_HDR_LEN,0);
                                    buf.extend_from_slice(&reply);
                                    let mut bufs = [&mut buf];
                                    dev.send_multiple(&mut gro_table,&mut bufs,VIRTIO_NET_HDR_LEN).await?;
                                }
                            }
                        }
                        Err(err) => println!("Received an invalid packet: {:?}", err),
                        _ => {}
                    }
                }
            }
        }
    }
    Ok(())
}
