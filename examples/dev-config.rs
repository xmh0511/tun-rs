#[allow(unused_imports)]
use packet::{builder::Builder, icmp, ip, Packet};
use std::sync::mpsc::Receiver;
#[allow(unused_imports)]
use tun_rs::{AbstractDevice, BoxError};

fn main() -> Result<(), BoxError> {
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
fn main_entry(_quit: Receiver<()>) -> Result<(), BoxError> {
    unimplemented!()
}
#[cfg(any(
    target_os = "windows",
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
))]
fn main_entry(quit: Receiver<()>) -> Result<(), BoxError> {
    let mut config = tun_rs::Configuration::default();

    config
        .address_with_prefix((10, 0, 0, 9), 24)
        // will add 0.0.0.0 to interface on windows platform, which route all traffic here
        //.destination((10, 0, 0, 1))
        .up();

    let dev = tun_rs::create(&config)?;
    let r = dev.addresses()?;
    println!("{:?}", r);

    dev.set_network_address((10, 0, 0, 2), (255, 255, 255, 0), None)?;
    dev.set_mtu(65535)?;

    //dev.set_tun_name("tun8")?;

    //dev.set_address(std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 21)))?;

    // let r = dev.broadcast()?;
    // println!("{:?}",r);

    let mut buf = [0; 4096];

    std::thread::spawn(move || {
        loop {
            let amount = dev.recv(&mut buf)?;
            let pkt = &buf[0..amount];
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
                            let size = dev.send(&reply[..])?;
                            println!("write {size} len {}", reply.len());
                        }
                    }
                }
                Err(err) => println!("Received an invalid packet: {:?}", err),
                _ => {}
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), BoxError>(())
    });

    quit.recv().expect("Quit error.");
    Ok(())
}
