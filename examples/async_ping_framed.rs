use bytes::BytesMut;
use futures::{SinkExt, StreamExt};
#[allow(unused_imports)]
use pnet_packet::icmp::IcmpTypes;
#[allow(unused_imports)]
use pnet_packet::ip::IpNextHeaderProtocols;
#[allow(unused_imports)]
use pnet_packet::Packet;
#[allow(unused_imports)]
use std::net::Ipv4Addr;
#[allow(unused_imports)]
use std::sync::Arc;
use tun_rs::async_framed::{BytesCodec, DeviceFramed};
#[allow(unused_imports)]
use tun_rs::DeviceBuilder;
#[allow(unused_imports)]
use tun_rs::{AsyncDevice, SyncDevice};

#[cfg(any(
    target_os = "windows",
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
))]
#[tokio::main]
async fn main() -> std::io::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(1);

    ctrlc2::set_async_handler(async move {
        tx.send(()).await.expect("Signal error");
    })
    .await;

    let dev = DeviceBuilder::new()
        .ipv4(Ipv4Addr::new(10, 0, 0, 21), 24, None)
        .build_async()?;
    let mut framed = DeviceFramed::new(dev, BytesCodec::new());
    loop {
        tokio::select! {
            _ = rx.recv() => {
                log::info!("Quit...");
                break;
            }
            next = framed.next() => {
                if let Some(rs) = next{
                    let buf = rs?;
                    handle_pkt(&buf, &mut framed).await?;
                }else{
                    break;
                }
            }
        };
    }
    Ok(())
}

#[cfg(any(target_os = "ios", target_os = "android",))]
fn main() -> std::io::Result<()> {
    unimplemented!()
}

#[allow(dead_code)]
async fn handle_pkt(pkt: &[u8], framed: &mut DeviceFramed<BytesCodec>) -> std::io::Result<()> {
    #[allow(clippy::single_match)]
    match pnet_packet::ipv4::Ipv4Packet::new(pkt) {
        Some(ip_pkt) => {
            match ip_pkt.get_next_level_protocol() {
                IpNextHeaderProtocols::Icmp => {
                    let icmp_pkt = pnet_packet::icmp::IcmpPacket::new(ip_pkt.payload()).unwrap();
                    match icmp_pkt.get_icmp_type() {
                        IcmpTypes::EchoRequest => {
                            let mut v = ip_pkt.payload().to_owned();
                            let mut pkkt =
                                pnet_packet::icmp::MutableIcmpPacket::new(&mut v[..]).unwrap();
                            pkkt.set_icmp_type(IcmpTypes::EchoReply);
                            pkkt.set_checksum(pnet_packet::icmp::checksum(&pkkt.to_immutable()));
                            //println!("{:?}",v);
                            let len = ip_pkt.packet().len();
                            let mut buf = BytesMut::zeroed(len);
                            let mut res =
                                pnet_packet::ipv4::MutableIpv4Packet::new(&mut buf).unwrap();
                            res.set_total_length(ip_pkt.get_total_length());
                            res.set_header_length(ip_pkt.get_header_length());
                            res.set_destination(ip_pkt.get_source());
                            res.set_source(ip_pkt.get_destination());
                            res.set_identification(0x42);
                            res.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
                            res.set_payload(&v);
                            res.set_ttl(64);
                            res.set_version(ip_pkt.get_version());
                            res.set_checksum(pnet_packet::ipv4::checksum(&res.to_immutable()));
                            log::info!("{:?}", buf.as_ref());
                            framed.send(buf).await?;
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }
        None => {}
    }
    Ok(())
}
