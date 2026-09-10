use libc::{
    AF_INET, AF_INET6, AF_NETLINK, AF_UNSPEC, IFA_LOCAL, IFNAMSIZ, IPPROTO_ICMP, NETLINK_ROUTE,
    NLM_F_DUMP, NLM_F_REQUEST, NLMSG_DONE, RTM_GETADDR, SO_RCVTIMEO, SOCK_DGRAM, SOCK_RAW,
    SOCK_STREAM, SOL_SOCKET, addrinfo, bind, freeaddrinfo, freeifaddrs, getaddrinfo, gethostname,
    getifaddrs, getpid, if_indextoname, ifaddrmsg, ifaddrs, nlmsghdr, recv, recvfrom, rtattr, send,
    sendto, setsockopt, sockaddr, sockaddr_in, sockaddr_nl, sockaddr_storage, socket, socklen_t,
    suseconds_t, time_t, timeval,
};
use std::{
    collections::HashMap,
    ffi::{CStr, c_char},
    mem,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        raw::{c_int, c_void},
    },
    time::Duration,
};

use crate::models::{DiscoverError, NetworkInterface, Subnet, icmphdr};
use anyhow::{Context, Result};

pub fn get_netw_addr() -> Result<NetworkInterface> {
    let ntwif_ip = getaddr().context("failed to retrieve local ipv4 address")?;
    let netmask = getaddr_netmask(ntwif_ip)
        .with_context(|| format!("failed to fetch netmask for address {ntwif_ip}"))?;
    println!("{ntwif_ip} {netmask}");
    Ok(NetworkInterface {
        ip: ntwif_ip,
        subnet: Subnet::new(IpAddr::V4(ntwif_ip), netmask),
    })
}

pub fn ping_local_ip(ip: Ipv4Addr) -> Result<Option<Ipv4Addr>, anyhow::Error> {
    let sockfd: OwnedFd =
        open_socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP).context("failed to open icmp socket")?;
    let imsg = create_icmp_ping_message();
    send_ping(sockfd.as_raw_fd(), imsg, ip).context("failed to send icmp message")?;
    recv_ping(sockfd.as_raw_fd()).context("failed to retrieve ping reply")
}

//fn parse_rtaattr_data(
//    addr_msg: &ifaddrmsg,
//    buf: &[u8],
//    data_offset: &mut usize,
//    msg_end: usize,
//) -> Option<NetworkInterface> {
//    let mut found: bool = false;
//    while *data_offset + mem::size_of::<rtattr>() <= msg_end {
//        let rta = unsafe { &*(buf[*data_offset..].as_ptr() as *const rtattr) };
//        let attr_len = rta.rta_len as usize;
//        if attr_len < mem::size_of::<rtattr>() || *data_offset + attr_len > msg_end {
//            break;
//        }
//        let attr_data_start = *data_offset + mem::size_of::<rtattr>();
//        let attr_data_end = *data_offset + attr_len;
//        let attr_data = &buf[attr_data_start..attr_data_end];
//
//        match rta.rta_type {
//            IFA_LOCAL => match addr_msg.ifa_family as i32 {
//                AF_INET => {
//                    let addr = IpAddr::V4(Ipv4Addr::new(
//                        attr_data[0],
//                        attr_data[1],
//                        attr_data[2],
//                        attr_data[3],
//                    ));
//                    if !addr.is_loopback() {
//                        ntw_if.add_subnet(Subnet::new(addr, addr_msg.ifa_prefixlen));
//                        found = true;
//                    }
//                }
//                AF_INET6 => {
//                    let bytes: [u8; 16] = attr_data[..16].try_into().unwrap();
//                    let addr = IpAddr::V6(Ipv6Addr::from(bytes));
//                    if !addr.is_loopback() {
//                        ntw_if.add_subnet(Subnet::new(addr, addr_msg.ifa_prefixlen));
//                        found = true;
//                    }
//                }
//                _ => {}
//            },
//            _ => {}
//        }
//        *data_offset += (attr_len + 3) & !3;
//    }
//
//    if found {
//        let ifindex = u32::from_ne_bytes(addr_msg.ifa_index.to_ne_bytes());
//        let mut name = [0 as c_char; IFNAMSIZ];
//        unsafe {
//            if_indextoname(ifindex, name.as_mut_ptr());
//        }
//        let name = unsafe { CStr::from_ptr(name.as_ptr()) };
//        ntw_if.set_name(&name.to_string_lossy());
//
//        return Some(ntw_if);
//    } else {
//        return None;
//    }
//}
//
//fn recv_rtmsg(fd: RawFd) -> Result<NetworkInterface, DiscoverError> {
//    let mut buf = [0u8; 8192];
//    loop {
//        let received = unsafe { recv(fd, buf.as_mut_ptr() as *mut c_void, buf.len(), 0) };
//        if received < 0 {
//            return Err(DiscoverError::SocketError {
//                source: std::io::Error::last_os_error(),
//            });
//        }
//        if received == 0 {
//            break;
//        }
//
//        let mut offset = 0usize;
//
//        while offset < received as usize {
//            let hdr = unsafe { &*(buf[offset..].as_ptr() as *const nlmsghdr) };
//            if hdr.nlmsg_type == NLMSG_DONE as u16 {
//                return Ok(interfaces);
//            }
//            let msg_len = hdr.nlmsg_len as usize;
//            if msg_len < mem::size_of::<nlmsghdr>() || offset + msg_len > buf.len() {
//                break;
//            }
//
//            let msg_end = offset + msg_len;
//            let attrs_offset = offset + mem::size_of::<nlmsghdr>();
//            let mut data_offset = attrs_offset + mem::size_of::<ifaddrmsg>();
//            if data_offset > msg_end {
//                break;
//            }
//            let addr_msg = unsafe { &*(buf[attrs_offset..].as_ptr() as *const ifaddrmsg) };
//            if let Some(iface) = parse_rtaattr_data(addr_msg, &buf, &mut data_offset, msg_end) {
//                return Ok(iface);
//            }
//            offset += (msg_len + 3) & !3;
//        }
//    }
//    Err(DiscoverError::NetworkInterfaceNotFound {
//        iface: "local".to_string(),
//    })
//}

fn send_rtmsg(fd: RawFd, addr_msg: ifaddrmsg, nlh: nlmsghdr) -> Result<(), DiscoverError> {
    unsafe {
        let mut buf = [0u8; size_of::<nlmsghdr>() + size_of::<ifaddrmsg>()];
        std::ptr::copy_nonoverlapping(
            &nlh as *const _ as *const u8,
            buf.as_mut_ptr(),
            size_of::<nlmsghdr>(),
        );
        std::ptr::copy_nonoverlapping(
            &addr_msg as *const _ as *const u8,
            buf.as_mut_ptr().add(mem::size_of::<nlmsghdr>()),
            size_of::<ifaddrmsg>(),
        );
        let sent = send(fd, buf.as_ptr() as *const c_void, buf.len(), 0);
        if sent < 0 {
            return Err(DiscoverError::SendMessageError {
                sock_type: String::from("RTM"),
                source: std::io::Error::last_os_error(),
            });
        }
        Ok(())
    }
}

fn build_rtm_getaddr() -> (ifaddrmsg, nlmsghdr) {
    let mut addr_msg: ifaddrmsg = unsafe { mem::zeroed() };
    addr_msg.ifa_family = AF_UNSPEC as u8;
    let mut nlh: nlmsghdr = unsafe { mem::zeroed() };
    nlh.nlmsg_len = (size_of::<nlmsghdr>() + size_of::<ifaddrmsg>()) as u32;
    nlh.nlmsg_type = RTM_GETADDR;
    nlh.nlmsg_flags = (NLM_F_REQUEST | NLM_F_DUMP) as u16;
    nlh.nlmsg_seq = 1;

    (addr_msg, nlh)
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

fn bind_socket(sockfd: RawFd, saddr: *const sockaddr) -> Result<(), DiscoverError> {
    unsafe {
        if bind(sockfd, saddr, mem::size_of::<sockaddr_nl>() as socklen_t) < 0 {
            return Err(DiscoverError::SocketError {
                source: std::io::Error::last_os_error(),
            });
        }
        Ok(())
    }
}

fn create_nl_sockaddr() -> sockaddr_nl {
    let mut saddr: sockaddr_nl = unsafe { mem::zeroed() };
    saddr.nl_pid = unsafe { getpid() as u32 };
    saddr.nl_family = AF_NETLINK as u16;
    saddr.nl_groups = 0;
    saddr
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

pub fn getaddr() -> Result<Ipv4Addr, DiscoverError> {
    let mut name = [0 as c_char; 256];
    let ret = unsafe { gethostname(name.as_mut_ptr(), name.len()) };
    if ret != 0 {
        return Err(DiscoverError::FailedToResolveHostname {
            hostname: String::from("local"),
        });
    }
    let mut hints: addrinfo = unsafe { mem::zeroed() };
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    let mut res: *mut addrinfo = std::ptr::null_mut();
    let ret = unsafe { getaddrinfo(name.as_ptr(), std::ptr::null(), &hints, &mut res) };
    if ret != 0 {
        return Err(DiscoverError::NetworkInterfaceNotFound {
            iface: unsafe { String::from(CStr::from_ptr(name.as_ptr()).to_string_lossy()) },
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
    Err(DiscoverError::NetworkInterfaceNotFound {
        iface: String::from("default"),
    })
}

fn getaddr_netmask(ip: Ipv4Addr) -> Option<u8> {
    let mut ifap: *mut ifaddrs = std::ptr::null_mut();
    let ret = unsafe { getifaddrs(&mut ifap) };
    // TODO: Error handling
    let mut curr = ifap;
    while !curr.is_null() {
        let addr_info = unsafe { &*curr };
        let sockaddr: *const sockaddr = addr_info.ifa_addr;
        if let Some(if_ip) = parse_addr_info(sockaddr) {
            if if_ip == ip {
                let netmask_addr = addr_info.ifa_netmask;
                let netmask_addrin: sockaddr_in = unsafe { *(netmask_addr as *const sockaddr_in) };
                let mut netmask_bits = netmask_addrin.sin_addr.s_addr;
                let mut mask = 0u8;
                for _ in 0..32 {
                    mask += (netmask_bits & 1) as u8;
                    netmask_bits = netmask_bits >> 1;
                }
                unsafe {
                    freeifaddrs(ifap);
                }
                return Some(mask);
            }
        }
        curr = addr_info.ifa_next;
    }
    unsafe {
        freeifaddrs(ifap);
    }
    None
}

fn parse_addr_info(sockaddr: *const sockaddr) -> Option<Ipv4Addr> {
    let family = unsafe { (*sockaddr).sa_family as i32 };
    match family {
        AF_INET => {
            let sockaddr_in: sockaddr_in = unsafe { *(sockaddr as *const sockaddr_in) };
            let ip = Ipv4Addr::from_bits(u32::from_be(sockaddr_in.sin_addr.s_addr));
            Some(ip)
        }

        _ => None,
    }
}
