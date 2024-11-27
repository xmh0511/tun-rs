use std::sync::mpsc::Receiver;
#[allow(unused_imports)]
use std::sync::Arc;
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

#[cfg(not(target_os = "linux"))]
fn main_entry(_quit: Receiver<()>) -> Result<(), BoxError> {
    unimplemented!()
}

#[cfg(target_os = "linux")]
fn main_entry(quit: Receiver<()>) -> Result<(), BoxError> {
    #[allow(unused_imports)]
    use std::net::IpAddr;
    use tun_rs::platform::{IDEAL_BATCH_SIZE, VIRTIO_NET_HDR_LEN};

    let mut config = tun_rs::Configuration::default();

    config
        .address_with_prefix("10.0.0.2", 24u8)
        .platform_config(|config| {
            config.offload(true);
        })
        .mtu(1500)
        //.destination((10, 0, 0, 1))
        .up();

    let dev = Arc::new(tun_rs::create(&config)?);
    println!("if_index = {:?}", dev.if_index());
    let _join = std::thread::spawn(move || {
        let mut original_buffer = [0; VIRTIO_NET_HDR_LEN + 65535];
        let mut bufs = vec![vec![0u8; 1500]; IDEAL_BATCH_SIZE];
        let mut sizes = vec![0; IDEAL_BATCH_SIZE];
        loop {
            let amount = dev.recv_multiple(&mut original_buffer, &mut bufs, &mut sizes, 0)?;
            for i in 0..amount {
                let len = sizes[i];
                println!("index={i},len={len},data={:?}", &bufs[i][0..len]);
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), BoxError>(())
    });
    quit.recv().expect("Quit error.");
    println!("recv quit!!!!!");
    Ok(())
}
