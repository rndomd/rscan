use std::{
    fmt::Display,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops::{Deref, DerefMut},
};

use thiserror::Error;

pub struct Device {
    pub ip: String,
    pub mac: String,
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
    pub subnet: Subnet,
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
        details: String
    },
    #[error("failed to send message over socket of type: {sock_type}")]
    SendMessageError {
        sock_type: String,
        #[source]
        source: std::io::Error,
    },
    #[error("received invalid message. details: {details}")]
    RecvInvalidMessage{
        details: String,
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
            for i in 1..possibles_addrs-1 {
                let addr = (ip.to_bits() + i).to_be_bytes();
                res.push(Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]));
            }
        }
        res
    }
}

impl Display for Subnet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.ip, self.mask)
    }
}
