#[allow(unused_imports)]
use bytes::BytesMut;
#[allow(unused_imports)]
use packet::{icmp, ip, Builder, Packet};
#[allow(unused_imports)]
use pnet_packet::icmp::IcmpTypes;
#[allow(unused_imports)]
use pnet_packet::ip::IpNextHeaderProtocols;
#[allow(unused_imports)]
use std::net::Ipv4Addr;
#[allow(unused_imports)]
use std::sync::Arc;
#[allow(unused_imports)]
use tun_rs::DeviceBuilder;
#[allow(unused_imports)]
use tun_rs::{AsyncDevice, SyncDevice};
#[allow(unused_imports)]
#[cfg(target_os = "linux")]
use tun_rs::{GROTable, IDEAL_BATCH_SIZE, VIRTIO_NET_HDR_LEN};

#[cfg(feature = "async_tokio")]
#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> std::io::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(1);

    ctrlc2::set_async_handler(async move {
        tx.send(()).await.expect("Signal error");
    })
    .await;

    let dev = Arc::new({
        let builder = DeviceBuilder::new().ipv4(Ipv4Addr::from([10, 0, 0, 9]), 24, None);
        #[cfg(target_os = "linux")]
        let builder = builder.offload(true);
        builder.build_async()?
    });
    println!("TCP-GSO:{},UDP-GSO:{}", dev.tcp_gso(), dev.udp_gso());
    let mut original_buffer = vec![0; VIRTIO_NET_HDR_LEN + 65535];
    let mut bufs = vec![vec![0u8; 1500]; IDEAL_BATCH_SIZE];
    let mut sizes = vec![0; IDEAL_BATCH_SIZE];
    let mut gro_table = GROTable::default();

    loop {
        tokio::select! {
            _ = rx.recv() => {
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
                                        .id(0x42).map_err(|e| std::io::Error::other(e))?
                                        .ttl(64).map_err(|e| std::io::Error::other(e))?
                                        .source(pkt.destination()).map_err(|e| std::io::Error::other(e))?
                                        .destination(pkt.source()).map_err(|e| std::io::Error::other(e))?
                                        .icmp().map_err(|e| std::io::Error::other(e))?
                                        .echo().map_err(|e| std::io::Error::other(e))?
                                        .reply().map_err(|e| std::io::Error::other(e))?
                                        .identifier(icmp.identifier()).map_err(|e| std::io::Error::other(e))?
                                        .sequence(icmp.sequence()).map_err(|e| std::io::Error::other(e))?
                                        .payload(icmp.payload()).map_err(|e| std::io::Error::other(e))?
                                        .build().map_err(|e| std::io::Error::other(e))?;
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
        };
    }
    Ok(())
}

#[cfg(feature = "async_std")]
#[cfg(target_os = "linux")]
#[async_std::main]
async fn main() -> std::io::Result<()> {
    use async_ctrlc::CtrlC;
    use async_std::prelude::FutureExt;
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init();
    let dev = Arc::new({
        let builder = DeviceBuilder::new().ipv4(Ipv4Addr::from([10, 0, 0, 9]), 24, None);
        #[cfg(target_os = "linux")]
        let builder = builder.offload(true);
        builder.build_async()?
    });
    println!("TCP-GSO:{},UDP-GSO:{}", dev.tcp_gso(), dev.udp_gso());
    let mut original_buffer = vec![0; VIRTIO_NET_HDR_LEN + 65535];
    let mut bufs = vec![vec![0u8; 1500]; IDEAL_BATCH_SIZE];
    let mut sizes = vec![0; IDEAL_BATCH_SIZE];
    let mut gro_table = GROTable::default();

    let ctrlc = CtrlC::new().expect("cannot create Ctrl+C handler?");
    ctrlc
        .race(async {
            while let Ok(num) = dev
                .recv_multiple(&mut original_buffer, &mut bufs, &mut sizes, 0)
                .await
            {
                for i in 0..num {
                    match ip::Packet::new(&bufs[i][..sizes[i]]) {
                        Ok(ip::Packet::V4(pkt)) => {
                            if let Ok(icmp) = icmp::Packet::new(pkt.payload()) {
                                if let Ok(icmp) = icmp.echo() {
                                    println!("{:?} - {:?}", icmp.sequence(), pkt.destination());
                                    let reply = ip::v4::Builder::default()
                                        .id(0x42)
                                        .map_err(|e| std::io::Error::other(e))?
                                        .ttl(64)
                                        .map_err(|e| std::io::Error::other(e))?
                                        .source(pkt.destination())
                                        .map_err(|e| std::io::Error::other(e))?
                                        .destination(pkt.source())
                                        .map_err(|e| std::io::Error::other(e))?
                                        .icmp()
                                        .map_err(|e| std::io::Error::other(e))?
                                        .echo()
                                        .map_err(|e| std::io::Error::other(e))?
                                        .reply()
                                        .map_err(|e| std::io::Error::other(e))?
                                        .identifier(icmp.identifier())
                                        .map_err(|e| std::io::Error::other(e))?
                                        .sequence(icmp.sequence())
                                        .map_err(|e| std::io::Error::other(e))?
                                        .payload(icmp.payload())
                                        .map_err(|e| std::io::Error::other(e))?
                                        .build()
                                        .map_err(|e| std::io::Error::other(e))?;
                                    let mut buf =
                                        BytesMut::with_capacity(VIRTIO_NET_HDR_LEN + 1500);
                                    buf.resize(VIRTIO_NET_HDR_LEN, 0);
                                    buf.extend_from_slice(&reply);
                                    let mut bufs = [&mut buf];
                                    dev.send_multiple(
                                        &mut gro_table,
                                        &mut bufs,
                                        VIRTIO_NET_HDR_LEN,
                                    )
                                    .await?;
                                }
                            }
                        }
                        Err(err) => println!("Received an invalid packet: {:?}", err),
                        _ => {}
                    }
                }
            }
            Ok::<(), std::io::Error>(())
        })
        .await;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::io::Result<()> {
    unimplemented!()
}
