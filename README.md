Tun/Tap interfaces
==============
[![Crates.io](https://img.shields.io/crates/v/tun-rs.svg)](https://crates.io/crates/tun-rs)
![tun-rs](https://docs.rs/tun-rs/badge.svg)
![Apache-2.0](https://img.shields.io/github/license/xmh0511/tun-rs?style=flat)

This crate allows the creation and usage of Tun/Tap interfaces(**supporting both Ipv4 and ipv6**), aiming to make this
cross-platform.

## Features:

1. Supporting TUN and TAP
2. Supporting both IPv4 and IPv6
3. Supporting Synchronous and Asynchronous API
4. Supporting Tokio and async-std asynchronous runtimes
5. All platforms have consistent IP packets(macOS's 4-byte head information can be eliminated)
6. Experimentally supporting shutdown for Synchronous version
7. Supporting Offload on the Linux platform
8. Having a consistent behavior of setting up routes when creating a device

## Supported Platforms

| Platform | TUN | TAP |
|----------|-----|-----|
| Windows  | ✅   | ✅   |
| Linux    | ✅   | ✅   |
| macOS    | ✅   | ⬜   |
| FreeBSD  | ✅   | ✅   |
| Android  | ✅   | ⬜   |
| iOS      | ✅   | ⬜   |

Usage
-----
First, add the following to your `Cargo.toml`:

```toml
[dependencies]
tun-rs = "1"
```

If you want to use the TUN interface with asynchronous runtimes, you need to enable the `async`(aliased
as `async_tokio`), or `async_std` feature:

```toml
[dependencies]
# tokio
tun-rs = { version = "1", features = ["async"] }

# async-std
tun-rs = { version = "1", features = ["async_std"] }
```

Example
-------
The following example creates and configures a TUN interface and reads packets from it synchronously.

```rust
fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let mut config = tun_rs::Configuration::default();
    config
        .address_with_prefix((10, 0, 0, 9), 24u8)
        //.destination((10, 0, 0, 1))
        .up();

    let dev = tun_rs::create(&config)?;
    // let shared = Arc::new(dev);
    dev.add_address_v6(
        "CDCD:910A:2222:5498:8475:1111:3900:2024"
            .parse::<IpAddr>()
            .unwrap(),
        64
    )?;
    //dev_t.remove_network_address(vec![(ip,prefix)])?;
    let mut buf = [0; 4096];

    loop {
        let amount = dev.recv(&mut buf)?;
        println!("{:?}", &buf[0..amount]);
    }
}
```

An example of asynchronously reading packets from an interface

````rust
#[tokio::main]
async fn main(mut quit: Receiver<()>) -> Result<(), BoxError> {
    let mut config = tun_rs::Configuration::default();

    config
        .address_with_prefix((10, 0, 0, 9), 24)
        .mtu(tun_rs::DEFAULT_MTU)
        .up();

    let dev = Arc::new(tun_rs::create_as_async(&config)?);
    // ignore the head 4bytes packet information for calling `recv` and `send` on macOS
    #[cfg(target_os = "macos")]
    dev.set_ignore_packet_info(true);

    let mut buf = vec![0; 1500];
    loop {
        let len = dev.recv(&mut buf).await?;
        println!("pkt: {:?}", &buf[..len]);
        //dev.send(buf).await?;
    }
    Ok(())
}
````

**Offload** is supported on the Linux platform, enable it via the config

````rust
#[cfg(target_os = "linux")]
config
.platform_config( | config| {
config.offload(true);
});
````

1. [Synchronous example](https://github.com/xmh0511/tun-rs/blob/main/examples/read-offload.rs)
2. [Asynchronous example](https://github.com/xmh0511/tun-rs/blob/main/examples/ping-tun-offload-tokio.rs)

Linux
-----
You will need the `tun-rs` module to be loaded and root is required to create
interfaces.

macOS & FreeBSD
-----
`tun-rs` will automatically set up a route according to the provided configuration, which does a similar thing like
this:
> sudo route -n add -net 10.0.0.0/24 10.0.0.1


iOS
----
You can pass the file descriptor of the TUN device to `tun-rs` to create the interface.

Here is an example to create the TUN device on iOS and pass the `fd` to `tun-rs`:

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
        // This is safe if the provided fd is valid
        let tun = unsafe { tun_rs::AsyncDevice::from_raw_fd(fd) };
        let mut buf = [0u8; 1500];
        while let Ok(packet) = tun.recv(&mut buf).await {
            ...
        }
    });
}
```

Windows
-----

#### Tun:

You need to copy the [wintun.dll](https://wintun.net/) file which matches your architecture to
the same directory as your executable and run your program as administrator.

#### Tap:

When using the tap network interface, you need to manually
install [tap-windows](https://build.openvpn.net/downloads/releases/) that matches your architecture.
