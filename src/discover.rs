use crate::models::{FoundDevice, MacAddress, NetworkInterface};
use crate::network::{arp_scan, get_netw_addr, open_arp_socket};
use crate::ui::{init_scan_ui, print_found_devices};
use anyhow::{Context, Result};
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
use std::thread;

pub fn discover(_interface: &str) -> Result<()> {
    let pb = init_scan_ui();
    let (job_tx, job_rx) = channel();
    let (result_tx, result_rx) = channel();
    let job_rx = Arc::new(Mutex::new(job_rx));
    let result_tx = Arc::new(Mutex::new(result_tx));
    let sockfd = Arc::new(Mutex::new(open_arp_socket()?));
    let iface = get_netw_addr().context("failed to get routing table")?;
    let mut handles = vec![];
    for _ in 0..10 {
        let job_rx = Arc::clone(&job_rx);
        let result_tx = Arc::clone(&result_tx);
        let socket = Arc::clone(&sockfd);
        let iface = iface.clone();
        handles.push(thread::spawn(move || {
            loop {
                let job = job_rx.lock().unwrap().recv();
                let sock = socket.lock().unwrap();
                match job {
                    Ok(ip) => {
                        let res = scan_network(sock.as_raw_fd(), &iface, ip);
                        result_tx.lock().unwrap().send(res).unwrap();
                    }
                    Err(_) => break,
                }
            }
        }));
    }

    let ips = iface.subnet.get_subnet_ips();
    let subnet_size = ips.len();

    for ip in ips {
        job_tx.send(ip).unwrap();
    }
    drop(job_tx);

    for _ in 0..subnet_size {
        match result_rx.recv() {
            Ok(Some(mut found)) => {
                if found.ip == iface.ip {
                    found.hostname = "This PC".to_string();
                }
                print_found_devices(&pb, found);
            }
            Ok(None) => continue,
            Err(_) => break,
        }
    }

    for h in handles {
        h.join().unwrap();
    }

    Ok(())
}

pub fn scan_network(
    sockfd: RawFd,
    nw_iface: &NetworkInterface,
    ip: Ipv4Addr,
) -> Option<FoundDevice> {
    if let Ok(Some((req, hostname))) = arp_scan(sockfd, nw_iface, ip) {
        let found = FoundDevice {
            ip: Ipv4Addr::from_octets(req.src_ip),
            mac: MacAddress { addr: req.src_mac },
            hostname: hostname,
        };
        return Some(found);
    } else {
        None
    }
}
