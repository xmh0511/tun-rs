#[allow(unused_imports)]
use pnet_packet::icmp::IcmpTypes;
#[allow(unused_imports)]
use pnet_packet::ip::IpNextHeaderProtocols;
#[allow(unused_imports)]
use pnet_packet::Packet;
#[allow(unused_imports)]
use std::net::Ipv4Addr;
#[allow(unused_imports)]
use std::sync::{mpsc::Receiver, Arc};
#[allow(unused_imports)]
use tun_rs::{DeviceBuilder, SyncDevice};

fn main() -> std::io::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init();
    let (tx, rx) = std::sync::mpsc::channel();

    let handle = ctrlc2::set_handler(move || {
        tx.send(()).expect("Signal error.");
        true
    })
    .expect("Error setting Ctrl-C handler");

    main_entry(rx)?;
    handle.join().unwrap();
    Ok(())
}
#[cfg(any(target_os = "ios", target_os = "android",))]
fn main_entry(_quit: Receiver<()>) -> std::io::Result<()> {
    unimplemented!()
}
#[cfg(any(
    target_os = "windows",
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
))]
fn main_entry(quit: Receiver<()>) -> std::io::Result<()> {
    let dev = Arc::new(
        DeviceBuilder::new()
            .ipv4(Ipv4Addr::from([10, 0, 0, 9]), 24, None)
            .build_sync()?,
    );

    #[cfg(target_os = "macos")]
    dev.set_ignore_packet_info(true);

    let mut buf = [0; 4096];

    #[cfg(feature = "experimental")]
    let dev2 = dev.clone();
    #[cfg(feature = "experimental")]
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(5));
        dev2.shutdown().unwrap();
    });

    std::thread::spawn(move || {
        loop {
            let amount = dev.recv(&mut buf);
            println!("amount == {amount:?}");
            let amount = amount?;
            let pkt = &buf[0..amount];
            handle_pkt(pkt, &dev).unwrap();
        }
        #[allow(unreachable_code)]
        Ok::<(), std::io::Error>(())
    });
    quit.recv().expect("Quit error.");
    Ok(())
}

#[allow(dead_code)]
fn handle_pkt(pkt: &[u8], dev: &SyncDevice) -> std::io::Result<()> {
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
                            let mut buf = vec![0u8; len];
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
                            println!("{:?}", buf);
                            dev.send(&buf)?;
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
