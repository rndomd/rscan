use libc::{
    AF_INET, AF_PACKET, ARPHRD_ETHER, ETH_P_ARP, IPPROTO_ICMP, SO_RCVTIMEO, SOCK_DGRAM,
    SOCK_STREAM, SOL_SOCKET, addrinfo, freeaddrinfo, freeifaddrs, getaddrinfo, gethostname,
    getifaddrs, if_nametoindex, ifaddrs, recvfrom, sa_family_t, sendto, setsockopt, sockaddr,
    sockaddr_in, sockaddr_ll, sockaddr_storage, socket, socklen_t, suseconds_t, time_t, timeval,
};
use std::{
    ffi::{CStr, CString, c_char},
    mem,
    net::{IpAddr, Ipv4Addr},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        raw::{c_int, c_void},
    },
    str::FromStr,
    time::Duration,
};

use crate::models::{DiscoverError, MacAddress, NetworkInterface, Subnet, arpreq, icmphdr};
use anyhow::{Context, Result};

pub fn get_netw_addr() -> Result<NetworkInterface> {
    let ip = getaddr().context("failed to retrieve local ipv4 address")?;
    let (mac, netmask, ifname) = getaddr_details(ip).with_context(|| {
        format!("failed to fetch netmask and mac address for network interface {ip}")
    })?;
    Ok(NetworkInterface {
        ifname,
        ip,
        mac,
        subnet: Subnet::new(IpAddr::V4(ip), netmask),
    })
}

pub fn ping_local_ip(ip: Ipv4Addr) -> Result<Option<Ipv4Addr>, anyhow::Error> {
    let sockfd: OwnedFd =
        open_socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP).context("failed to open icmp socket")?;
    let imsg = create_icmp_ping_message();
    send_ping(sockfd.as_raw_fd(), imsg, ip).context("failed to send icmp message")?;
    recv_ping(sockfd.as_raw_fd()).context("failed to retrieve ping reply")
}

fn open_socket(domain: c_int, sock_type: c_int, protocol: c_int) -> Result<OwnedFd, DiscoverError> {
    let sockfd_nl: RawFd = unsafe { socket(domain, sock_type, protocol) };
    if sockfd_nl < 0 {
        return Err(DiscoverError::SocketError {
            source: std::io::Error::last_os_error(),
        });
    }

    Ok(unsafe { OwnedFd::from_raw_fd(sockfd_nl) })
}

fn recv_ping(sockfd: RawFd) -> Result<Option<Ipv4Addr>, DiscoverError> {
    let mut buf: [u8; 65535] = unsafe { mem::zeroed() };
    let mut addr: sockaddr_storage = unsafe { mem::zeroed() };
    let mut addr_len = mem::size_of::<sockaddr_storage>() as socklen_t;
    let _ = set_sock_timeout(sockfd, Duration::from_millis(250))?;
    let buf_len = unsafe {
        recvfrom(
            sockfd,
            buf.as_mut_ptr() as *mut c_void,
            65535,
            0,
            &mut addr as *mut sockaddr_storage as *mut sockaddr,
            &mut addr_len,
        )
    };
    if buf_len < 0 {
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::WouldBlock {
            return Ok(None);
        } else {
            return Err(DiscoverError::SocketError {
                source: std::io::Error::last_os_error(),
            });
        }
    }
    if buf[0] == 0 {
        let recv_addr: &sockaddr =
            unsafe { &*(&addr as *const sockaddr_storage as *const sockaddr) };
        match recv_addr.sa_family as i32 {
            AF_INET => {
                let recv_addr: &sockaddr_in =
                    unsafe { &*(recv_addr as *const sockaddr as *const sockaddr_in) };
                let bytes = recv_addr.sin_addr.s_addr.to_ne_bytes();
                let ip = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
                return Ok(Some(ip));
            }
            _ => {}
        }
    }
    Ok(None)
}

fn send_ping(sockfd: RawFd, msg: icmphdr, ip: Ipv4Addr) -> Result<(), DiscoverError> {
    let mut dst: sockaddr_in = unsafe { mem::zeroed() };
    dst.sin_family = AF_INET as u16;
    dst.sin_addr.s_addr = u32::from_ne_bytes(ip.octets());

    let mut buf = [0u8; 8];
    buf[0] = msg.icmp_type;
    buf[1] = msg.code;
    buf[2..4].copy_from_slice(&msg.checksum.to_be_bytes());
    buf[4..6].copy_from_slice(&msg.id.to_be_bytes());
    buf[6..8].copy_from_slice(&msg.seq.to_be_bytes());

    unsafe {
        if sendto(
            sockfd,
            buf.as_ptr() as *const c_void,
            mem::size_of_val(&buf),
            0,
            &dst as *const sockaddr_in as *const sockaddr,
            mem::size_of_val(&dst) as u32,
        ) < 0
        {
            return Err(DiscoverError::SendMessageError {
                sock_type: String::from("ICMP"),
                source: std::io::Error::last_os_error(),
            });
        }
    }
    Ok(())
}

fn set_sock_timeout(fd: RawFd, timeout: Duration) -> Result<(), DiscoverError> {
    let tv = timeval {
        tv_sec: timeout.as_secs() as time_t,
        tv_usec: timeout.subsec_micros() as suseconds_t,
    };

    let ret = unsafe {
        setsockopt(
            fd,
            SOL_SOCKET,
            SO_RCVTIMEO,
            &tv as *const timeval as *const c_void,
            mem::size_of::<timeval>() as socklen_t,
        )
    };

    if ret < 0 {
        return Err(DiscoverError::SocketError {
            source: std::io::Error::last_os_error(),
        });
    }
    Ok(())
}

fn create_icmp_ping_message() -> icmphdr {
    let mut checksum: u32 = 0;
    let mut hdr = icmphdr {
        icmp_type: 8u8,
        code: 0u8,
        checksum: 0u16,
        id: 0,
        seq: 1u16,
    };

    let words = [
        u16::from_be_bytes([hdr.icmp_type, hdr.code]),
        hdr.checksum,
        hdr.id,
        hdr.seq,
    ];

    for word in words {
        checksum += word as u32;
    }
    checksum = (checksum >> 16) + (checksum & 0xffff);
    checksum = (checksum >> 16) + (checksum & 0xffff);

    hdr.checksum = !(checksum as u16);
    hdr
}

fn getaddr() -> Result<Ipv4Addr, DiscoverError> {
    let mut name = [0 as c_char; 256];
    let ret = unsafe { gethostname(name.as_mut_ptr(), name.len()) };
    if ret != 0 {
        return Err(DiscoverError::KernelError {
            source: std::io::Error::last_os_error(),
            details: String::from("gethostname error"),
        });
    }
    let mut hints: addrinfo = unsafe { mem::zeroed() };
    hints.ai_family = AF_INET; // TEST with AF_INET and AF_PACKET
    hints.ai_socktype = SOCK_STREAM;

    let mut res: *mut addrinfo = std::ptr::null_mut();
    let ret = unsafe { getaddrinfo(name.as_ptr(), std::ptr::null(), &hints, &mut res) };
    if ret != 0 {
        return Err(DiscoverError::KernelError {
            source: std::io::Error::last_os_error(),
            details: String::from("getaddrinfo error"),
        });
    }
    let mut curr = res;
    while !curr.is_null() {
        let addr_info = unsafe { &*curr };
        if let Some(ip) = parse_addr_info(addr_info.ai_addr) {
            unsafe {
                freeaddrinfo(res);
            }
            return Ok(ip);
        }
        curr = addr_info.ai_next;
    }
    unsafe {
        freeaddrinfo(res);
    }
    Err(DiscoverError::NetworkInterfaceNotFound)
}

fn getaddr_details(ip: Ipv4Addr) -> Result<(MacAddress, u8, String), DiscoverError> {
    let mut ifap: *mut ifaddrs = std::ptr::null_mut();
    let ret = unsafe { getifaddrs(&mut ifap) };
    if ret < 0 {
        return Err(DiscoverError::KernelError {
            source: std::io::Error::last_os_error(),
            details: String::from("getifaddrs error"),
        });
    }
    let mut curr = ifap;
    let mut mask: u8 = 0;
    let mut found_mask = false;
    let mut ifname: Option<String> = None;
    while !curr.is_null() {
        let addr_info = unsafe { &*curr };
        let sockaddr: *const sockaddr = addr_info.ifa_addr;
        if let Some(if_ip) = parse_addr_info(sockaddr) {
            if if_ip == ip {
                let netmask_addrin: sockaddr_in =
                    unsafe { *(addr_info.ifa_netmask as *const sockaddr_in) };
                let netmask_bits = netmask_addrin.sin_addr.s_addr;
                mask = netmask_bits.count_ones() as u8;
                found_mask = true;
                ifname = Some(unsafe {
                    CStr::from_ptr(addr_info.ifa_name)
                        .to_string_lossy()
                        .into_owned()
                });
                break;
            }
        }
        curr = addr_info.ifa_next;
    }

    let found_ifname = match ifname {
        Some(name) => name,
        None => {
            unsafe {
                freeifaddrs(ifap);
            }
            return Err(DiscoverError::NetworkInterfaceNotFound);
        }
    };

    let mut mac_bytes = [0u8; 6];
    let mut found_mac = false;

    curr = ifap;
    while !curr.is_null() {
        let addr_info = unsafe { &*curr };
        if !addr_info.ifa_name.is_null() && !addr_info.ifa_addr.is_null() {
            let curr_name = unsafe { CStr::from_ptr(addr_info.ifa_name) }.to_string_lossy();
            if curr_name == found_ifname {
                let family = unsafe { (*addr_info.ifa_addr).sa_family as i32 };
                if family == AF_PACKET {
                    let sll = unsafe { &*(addr_info.ifa_addr as *const sockaddr_ll) };
                    if sll.sll_halen == 6 {
                        mac_bytes.copy_from_slice(&sll.sll_addr[..6]);
                        found_mac = true;
                        break;
                    }
                }
            }
        }
        curr = addr_info.ifa_next;
    }

    unsafe {
        freeifaddrs(ifap);
    }
    if found_mac && found_mask {
        return Ok((MacAddress { addr: mac_bytes }, mask, found_ifname));
    }
    Err(DiscoverError::NetworkInterfaceNotFound)
}

fn parse_addr_info(sockaddr: *const sockaddr) -> Option<Ipv4Addr> {
    let family = unsafe { (*sockaddr).sa_family as i32 };
    match family {
        AF_INET => {
            let sockaddr_in: sockaddr_in = unsafe { *(sockaddr as *const sockaddr_in) };
            Some(Ipv4Addr::from_bits(u32::from_be(
                sockaddr_in.sin_addr.s_addr,
            )))
        }
        _ => None,
    }
}

pub fn arp_scan(ntw_ifa: &NetworkInterface, dst_ip: Ipv4Addr) -> Result<()> {
    let sockfd: OwnedFd =
        open_socket(AF_PACKET, SOCK_DGRAM, ETH_P_ARP).context("failed to open arp socket")?;
    let req = arpreq::request(&ntw_ifa.mac, &ntw_ifa.ip, dst_ip);
    send_arp(sockfd.as_raw_fd(), req, &ntw_ifa.ifname).context("failed to send arp message")?;
    Ok(())
}

pub fn send_arp(sockfd: RawFd, req: arpreq, ifname: &str) -> Result<(), DiscoverError> {
    let c_ifname = CString::from_str(ifname).map_err(|e| DiscoverError::InternalError {
        details: String::from("failed to convert interface name to CString"),
    })?;
    let mut dst: sockaddr_ll = unsafe { mem::zeroed() };
    dst.sll_family = AF_PACKET as sa_family_t;
    dst.sll_protocol = ETH_P_ARP as u16;
    dst.sll_ifindex = unsafe { if_nametoindex(c_ifname.as_ptr()) as c_int };
    dst.sll_hatype = ARPHRD_ETHER;
    dst.sll_halen = 6;
    dst.sll_addr[..6].copy_from_slice(&[0xff; 6]);
    let req_bytes = req.to_bytes();
    let ret = unsafe {
        sendto(
            sockfd,
            req_bytes.as_ptr() as *const c_void,
            28,
            0,
            &dst as *const sockaddr_ll as *const sockaddr,
            mem::size_of::<sockaddr_ll>() as socklen_t,
        )
    };

    if ret < 0 {
        return Err(DiscoverError::SendMessageError {
            sock_type: String::from("ARP"),
            source: std::io::Error::last_os_error(),
        });
    }
    Ok(())
}
