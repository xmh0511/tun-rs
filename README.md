Tun/Tap interfaces 
==============
[![Crates.io](https://img.shields.io/crates/v/tun2.svg)](https://crates.io/crates/tun2)
![tun2](https://docs.rs/tun2/badge.svg)
![WTFPL](http://img.shields.io/badge/license-WTFPL-blue.svg)

This crate allows the creation and usage of Tun/Tap interfaces, the aim is to make this cross-platform.


Usage
-----
First, add the following to your `Cargo.toml`:

```toml
[dependencies]
tun2 = "3"
```

If you want to use the TUN interface with mio/tokio, you need to enable the `async` feature:

```toml
[dependencies]
tun2 = { version = "3", features = ["async"] }
```

Example
-------
The following example creates and configures a TUN interface and starts reading
packets from it.

```rust
use std::io::Read;

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let mut config = tun2::Configuration::default();
    config
        .address((10, 0, 0, 9))
        .netmask((255, 255, 255, 0))
        .destination((10, 0, 0, 1))
        .up();

    let dev = tun2::create(&config)?;
    let mut buf = [0; 4096];

    loop {
        let amount = dev.recv(&mut buf)?;
        println!("{:?}", &buf[0..amount]);
    }
}
```

Platforms
=========
## Supported Platforms

- [x] Windows
- [x] Linux
- [x] macOS
- [x] FreeBSD
- [x] Android
- [x] iOS


Linux
-----
You will need the `tun2` module to be loaded and root is required to create
interfaces.

macOS & FreeBSD
-----
`tun2` will automatically set up a route according to the provided configuration, which does a similar thing like this:
> sudo route -n add -net 10.0.0.0/24 10.0.0.1


iOS
----
You can pass the file descriptor of the TUN device to `tun2` to create the interface.

Here is an example to create the TUN device on iOS and pass the `fd` to `tun2`:
```swift
// Swift
class PacketTunnelProvider: NEPacketTunnelProvider {
    override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        let tunnelNetworkSettings = createTunnelSettings() // Configure TUN address, DNS, mtu, routing...
        setTunnelNetworkSettings(tunnelNetworkSettings) { [weak self] error in
            // The tunnel of this tunFd is contains `Packet Information` prifix.
            let tunFd = self?.packetFlow.value(forKeyPath: "socket.fileDescriptor") as! Int32
            DispatchQueue.global(qos: .default).async {
                start_tun(tunFd)
            }
            completionHandler(nil)
        }
    }
}
```

```rust
#[no_mangle]
pub extern "C" fn start_tun(fd: std::os::raw::c_int) {
    let mut rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mut cfg = tun2::Configuration::default();
        cfg.raw_fd(fd);
        #[cfg(target_os = "ios")]
        cfg.platform_config(|p_cfg| {
            p_cfg.packet_information(true);
        });
        let tun = tun2::create_as_async(&cfg).unwrap();
        let mut buf = [0u8;1500];
        while let Ok(packet) = tun.recv(& mut buf).await {
            ...
        }
    });
}
```

Windows
-----
You need to copy the [wintun.dll](https://wintun.net/) file which matches your architecture to 
the same directory as your executable and run your program as administrator.
