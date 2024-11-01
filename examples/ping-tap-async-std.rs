use std::{fmt, io};

#[allow(unused_imports)]
use packet::{builder::Builder, icmp, ip, Packet};
use packet::{ether, PacketMut};

#[allow(unused_imports)]
use async_ctrlc::CtrlC;
#[allow(unused_imports)]
use async_std::prelude::FutureExt;

#[allow(unused_imports)]
use tun_rs::Layer;
#[allow(unused_imports)]
use tun_rs::{self, AbstractDevice, BoxError, Configuration};

#[async_std::main]
async fn main() -> Result<(), BoxError> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init();

    main_entry().await?;
    Ok(())
}
#[cfg(any(target_os = "ios", target_os = "android", target_os = "macos"))]
async fn main_entry() -> Result<(), BoxError> {
    unimplemented!()
}
#[cfg(any(target_os = "windows", target_os = "linux", target_os = "freebsd",))]
async fn main_entry() -> Result<(), BoxError> {
    let mut config = Configuration::default();

    config
        .address_with_prefix((10, 0, 0, 101), 24)
        .layer(Layer::L2)
        .up();

    let dev = tun_rs::create_as_async(&config)?;
    let mut buf = vec![0; 65536];
    let ctrlc = CtrlC::new().expect("cannot create Ctrl+C handler?");
    ctrlc
        .race(async {
            _ = async {
                while let Ok(len) = dev.recv(&mut buf).await {
                    let mut pkt: Vec<u8> = buf[..len].to_vec();
                    match ether::Packet::new(&mut pkt) {
                        Ok(mut packet) => match packet.protocol() {
                            ether::Protocol::Ipv4 => {
                                if ping(&mut packet)? {
                                    dev.send(packet.as_ref()).await?;
                                }
                            }
                            ether::Protocol::Arp => {
                                if arp(&mut packet)? {
                                    if pkt.len() < 60 {
                                        pkt.resize(60, 0);
                                    }
                                    dev.send(&pkt).await?;
                                }
                            }
                            protocol => {
                                println!("ignore ether protocol: {:?}", protocol)
                            }
                        },
                        Err(err) => {
                            println!("Received an invalid packet: {:?}", err)
                        }
                    }
                }
                Ok::<(), BoxError>(())
            }
            .await;
        })
        .await;
    println!("Quit...");
    Ok(())
}
pub fn ping(packet: &mut ether::Packet<&mut Vec<u8>>) -> Result<bool, BoxError> {
    let source = packet.source();
    let destination = packet.destination();

    match ip::Packet::new(packet.payload()) {
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
                    packet.payload_mut().copy_from_slice(&reply);
                    packet.set_destination(source)?;
                    packet.set_source(destination)?;
                    return Ok(true);
                }
            }
        }
        Err(err) => println!("Received an invalid packet: {:?}", err),
        _ => {}
    }
    Ok(false)
}
pub fn arp(packet: &mut ether::Packet<&mut Vec<u8>>) -> Result<bool, BoxError> {
    const MAC: [u8; 6] = [0xf, 0xf, 0xf, 0xf, 0xe, 0x9];
    let sender_h = packet.source();
    let mut arp_packet = ArpPacket::new(packet.payload_mut())?;
    println!("arp_packet={:?}", arp_packet);
    if arp_packet.op_code() != 1 {
        return Ok(false);
    }
    let sender_p: [u8; 4] = arp_packet.sender_protocol_addr().try_into().unwrap();
    let target_p: [u8; 4] = arp_packet.target_protocol_addr().try_into().unwrap();
    if target_p == [0, 0, 0, 0] || sender_p == [0, 0, 0, 0] || target_p == sender_p {
        return Ok(false);
    }
    arp_packet.set_op_code(2);
    arp_packet.set_target_hardware_addr(&sender_h.octets());
    arp_packet.set_target_protocol_addr(&sender_p);
    arp_packet.set_sender_protocol_addr(&target_p);
    arp_packet.set_sender_hardware_addr(&MAC);
    packet.set_destination(sender_h)?;
    packet.set_source(MAC.into())?;
    Ok(true)
}

/// 地址解析协议，由IP地址找到MAC地址
/// https://www.ietf.org/rfc/rfc6747.txt
/*
  0      2       4         5          6      8      10  (字节)
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 | 硬件类型|协议类型|硬件地址长度|协议地址长度|操作类型|
 |          源MAC地址                  |    源ip地址    |
 |          目的MAC地址                 |   目的ip地址   |
*/

pub struct ArpPacket<B> {
    buffer: B,
}

impl<B: AsRef<[u8]>> ArpPacket<B> {
    pub fn unchecked(buffer: B) -> Self {
        Self { buffer }
    }
    pub fn new(buffer: B) -> io::Result<Self> {
        if buffer.as_ref().len() != 28 {
            Err(io::Error::from(io::ErrorKind::InvalidData))?;
        }
        let packet = Self::unchecked(buffer);
        Ok(packet)
    }
}

impl<B: AsRef<[u8]>> ArpPacket<B> {
    /// 硬件类型 以太网类型为1
    pub fn hardware_type(&self) -> u16 {
        u16::from_be_bytes(self.buffer.as_ref()[0..2].try_into().unwrap())
    }
    /// 上层协议类型,ipv4是0x0800
    pub fn protocol_type(&self) -> u16 {
        u16::from_be_bytes(self.buffer.as_ref()[2..4].try_into().unwrap())
    }
    /// 如果是MAC地址 则长度为6
    pub fn hardware_size(&self) -> u8 {
        self.buffer.as_ref()[4]
    }
    /// 如果是IPv4 则长度为4
    pub fn protocol_size(&self) -> u8 {
        self.buffer.as_ref()[5]
    }
    /// 操作类型，请求和响应 1：ARP请求，2：ARP响应，3：RARP请求，4：RARP响应
    pub fn op_code(&self) -> u16 {
        u16::from_be_bytes(self.buffer.as_ref()[6..8].try_into().unwrap())
    }
    /// 发送端硬件地址，仅支持以太网
    pub fn sender_hardware_addr(&self) -> &[u8] {
        &self.buffer.as_ref()[8..14]
    }
    /// 发送端协议地址，仅支持IPv4
    pub fn sender_protocol_addr(&self) -> &[u8] {
        &self.buffer.as_ref()[14..18]
    }
    /// 接收端硬件地址，仅支持以太网
    pub fn target_hardware_addr(&self) -> &[u8] {
        &self.buffer.as_ref()[18..24]
    }
    /// 接收端协议地址，仅支持IPv4
    pub fn target_protocol_addr(&self) -> &[u8] {
        &self.buffer.as_ref()[24..28]
    }
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> ArpPacket<B> {
    /// 硬件类型 以太网类型为1
    pub fn set_hardware_type(&mut self, value: u16) {
        self.buffer.as_mut()[0..2].copy_from_slice(&value.to_be_bytes())
    }
    /// 上层协议类型,ipv4是0x0800
    pub fn set_protocol_type(&mut self, value: u16) {
        self.buffer.as_mut()[2..4].copy_from_slice(&value.to_be_bytes())
    }
    /// 如果是MAC地址 则长度为6
    pub fn set_hardware_size(&mut self, value: u8) {
        self.buffer.as_mut()[4] = value
    }
    /// 如果是IPv4 则长度为4
    pub fn set_protocol_size(&mut self, value: u8) {
        self.buffer.as_mut()[5] = value
    }
    /// 操作类型，请求和响应 1：ARP请求，2：ARP响应，3：RARP请求，4：RARP响应
    pub fn set_op_code(&mut self, value: u16) {
        self.buffer.as_mut()[6..8].copy_from_slice(&value.to_be_bytes())
    }
    /// 发送端硬件地址，仅支持以太网
    pub fn set_sender_hardware_addr(&mut self, buf: &[u8]) {
        self.buffer.as_mut()[8..14].copy_from_slice(buf)
    }
    /// 发送端协议地址，仅支持IPv4
    pub fn set_sender_protocol_addr(&mut self, buf: &[u8]) {
        self.buffer.as_mut()[14..18].copy_from_slice(buf)
    }
    /// 接收端硬件地址，仅支持以太网
    pub fn set_target_hardware_addr(&mut self, buf: &[u8]) {
        self.buffer.as_mut()[18..24].copy_from_slice(buf)
    }
    /// 接收端协议地址，仅支持IPv4
    pub fn set_target_protocol_addr(&mut self, buf: &[u8]) {
        self.buffer.as_mut()[24..28].copy_from_slice(buf)
    }
}

impl<B: AsRef<[u8]>> fmt::Debug for ArpPacket<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArpPacket")
            .field("hardware_type", &self.hardware_type())
            .field("protocol_type", &self.protocol_type())
            .field("hardware_size", &self.hardware_size())
            .field("protocol_size", &self.protocol_size())
            .field("op_code", &self.op_code())
            .field("sender_hardware_addr", &self.sender_hardware_addr())
            .field("sender_protocol_addr", &self.sender_protocol_addr())
            .field("target_hardware_addr", &self.target_hardware_addr())
            .field("target_protocol_addr", &self.target_protocol_addr())
            .finish()
    }
}
