use std::sync::mpsc::Receiver;
#[allow(unused_imports)]
use std::sync::Arc;
#[allow(unused_imports)]
use tun_rs::{AbstractDevice, BoxError};

#[cfg(any(target_os = "windows", target_os = "linux", target_os = "freebsd",))]
#[allow(unused_imports)]
use tun_rs::Layer;

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
    #[allow(unused_imports)]
    use std::net::IpAddr;

    let mut config = tun_rs::Configuration::default();

    // #[cfg(any(target_os = "windows", target_os = "linux", target_os = "freebsd",))]
    // config.layer(Layer::L2);

    config
        .address_with_prefix_multi(&vec![
            ("CDCD:910A:2222:5498:8475:1111:3900:2020", 64),
            ("10.0.0.2", 24u8),
        ])
        //.destination((10, 0, 0, 1))
        .up();

    let dev = Arc::new(tun_rs::create(&config)?);
    println!("if_index = {:?}", dev.if_index());
    let dev_t = dev.clone();
    let _join = std::thread::spawn(move || {
        let mut buf = [0; 4096];
        loop {
            let amount = dev.recv(&mut buf)?;
            println!("{:?}", &buf[0..amount]);
        }
        #[allow(unreachable_code)]
        Ok::<(), BoxError>(())
    });
    //dev_t.set_network_address((10, 0, 0, 88), (255, 255, 255, 0), None)?;
    // dev_t.set_network_address(
    //     "CDCD:910A:2222:5498:8475:1111:3900:2024"
    //         .parse::<IpAddr>()
    //         .unwrap(),
    //     "ffff:ffff:ffff:ffff::".parse::<IpAddr>().unwrap(),
    //     None,
    // )?;
    dev_t.add_address_v6(
        "CDCD:910A:2222:5498:8475:1111:3900:2024"
            .parse::<IpAddr>()
            .unwrap(),
        64,
    )?;
    // dev_t.add_address_v6(
    //     "CDCD:910A:2222:5498:8475:1111:3900:2020"
    //         .parse::<IpAddr>()
    //         .unwrap(),
    //     64,
    // )?;
    std::thread::sleep(std::time::Duration::from_secs(6));
    dev_t.remove_network_address(vec![(
        "CDCD:910A:2222:5498:8475:1111:3900:2024"
            .parse::<IpAddr>()
            .unwrap(),
        64,
    )])?;
    quit.recv().expect("Quit error.");
    println!("recv quit!!!!!");
    println!("{:#?}", dev_t.addresses()?);
    dev_t.enabled(false)?;
    Ok(())
}
