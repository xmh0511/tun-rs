#[allow(unused_imports)]
use packet::{builder::Builder, icmp, ip, Packet};
#[allow(unused_imports)]
use std::sync::{mpsc::Receiver, Arc};
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
        // .destination((10, 0, 0, 1))
        .up();

    let dev = Arc::new(tun_rs::create(&config)?);
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
            println!("pkt = {pkt:?}");
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
