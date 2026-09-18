use std::{
    fmt::Display,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops::{Deref, DerefMut},
};

use libc::{ARPHRD_ETHER, ARPOP_REQUEST, arphdr};
use thiserror::Error;

pub struct Device {
    pub ip: String,
    pub mac: MacAddress,
    pub device_type: String,
}

#[repr(C)]
pub struct icmphdr {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
    pub id: u16,
    pub seq: u16,
}

#[derive(Debug, PartialEq)]
pub struct Subnet {
    pub ip: IpAddr,
    pub mask: u8,
}

#[derive(Debug, PartialEq)]
pub struct NetworkInterface {
    pub ip: Ipv4Addr,
    pub mac: MacAddress,
    pub subnet: Subnet,
}

#[derive(Debug, PartialEq)]
pub struct MacAddress {
    pub addr: [u8; 6],
}

#[repr(C)]
#[derive(Debug)]
pub struct arpreq {
    pub arphdr: arphdr,
    pub src_mac: [u8; 6],
    pub src_ip: [u8; 4],
    pub dst_mac: [u8; 6],
    pub dst_ip: [u8; 4],
}

#[derive(Debug, Error)]
pub enum DiscoverError {
    #[error("failed to connect to socket")]
    SocketError {
        #[source]
        source: std::io::Error,
    },
    #[error("failed to find network interface")]
    NetworkInterfaceNotFound,
    #[error("failed to communicate with kernel. {details}")]
    KernelError {
        #[source]
        source: std::io::Error,
        details: String,
    },
    #[error("failed to send message over socket of type: {sock_type}")]
    SendMessageError {
        sock_type: String,
        #[source]
        source: std::io::Error,
    },
}

impl Deref for icmphdr {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        unsafe {
            std::slice::from_raw_parts(
                self as *const icmphdr as *const u8,
                std::mem::size_of::<icmphdr>(),
            )
        }
    }
}

impl DerefMut for icmphdr {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe {
            std::slice::from_raw_parts_mut(
                self as *mut icmphdr as *mut u8,
                std::mem::size_of::<icmphdr>(),
            )
        }
    }
}

impl Subnet {
    pub fn new(addr: IpAddr, mask: u8) -> Self {
        match addr {
            IpAddr::V4(addr_v4) => {
                let mut bitmask = 1;
                for _ in 0..mask {
                    bitmask = (bitmask << 1) + 1;
                }

                for _ in 0..32 - mask {
                    bitmask = bitmask << 1;
                }
                let ip = addr_v4.to_bits() & bitmask;
                Subnet {
                    ip: IpAddr::V4(Ipv4Addr::from_bits(ip)),
                    mask,
                }
            }
            IpAddr::V6(addr_v6) => {
                let mut bitmask: u128 = 1;
                for _ in 0..mask {
                    bitmask = (bitmask << 1) + 1;
                }

                for _ in 0..64 - mask {
                    bitmask = bitmask << 1;
                }
                let ip = addr_v6.to_bits() & bitmask;
                Subnet {
                    ip: IpAddr::V6(Ipv6Addr::from_bits(ip)),
                    mask,
                }
            }
        }
    }

    pub fn get_subnet_ips(&self) -> Vec<Ipv4Addr> {
        let mut res = Vec::new();
        if let IpAddr::V4(ip) = self.ip {
            let possibles_addrs = 2u32.pow((32 - self.mask) as u32);
            for i in 1..possibles_addrs - 1 {
                let addr = (ip.to_bits() + i).to_be_bytes();
                res.push(Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]));
            }
        }
        res
    }
}

impl arpreq {
    pub const PROTO_IPV4: u16 = 0x0800;

    pub fn request(src_mac: MacAddress, src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> Self {
        let hdr = arphdr {
            ar_hrd: ARPHRD_ETHER,
            ar_pro: Self::PROTO_IPV4,
            ar_hln: 6,
            ar_pln: 4,
            ar_op: ARPOP_REQUEST,
        };
        Self {
            arphdr: hdr,
            src_mac: src_mac.addr,
            src_ip: src_ip.octets(),
            dst_mac: [0u8; 6],
            dst_ip: dst_ip.octets(),
        }
    }

    pub fn to_bytes(&self) -> [u8; 28] {
        let mut out = [0u8; 28];

        out[0..2].copy_from_slice(&self.arphdr.ar_hrd.to_be_bytes());
        out[2..4].copy_from_slice(&self.arphdr.ar_pro.to_be_bytes());
        out[4] = self.arphdr.ar_hln;
        out[5] = self.arphdr.ar_pln;
        out[6..8].copy_from_slice(&self.arphdr.ar_op.to_be_bytes());
        out[8..14].copy_from_slice(&self.src_mac);
        out[14..18].copy_from_slice(&self.src_ip);
        out[18..24].copy_from_slice(&self.dst_mac);
        out[24..28].copy_from_slice(&self.dst_ip);

        out
    }
}

impl Display for Subnet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.ip, self.mask)
    }
}

impl Display for MacAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let [a, b, c, d, e, g] = self.addr;
        let mac = format!("{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}");
        match f.width() {
            Some(width) => write!(f, "{mac:<width$}"),
            None => write!(f, "{mac}"),
        }
    }
}
