use crate::models::MacAddress;
use crate::network::{arp_scan, get_netw_addr};
use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use std::net::Ipv4Addr;
use std::thread;
use std::time::Duration;

pub fn scan_network(interface: String) -> Result<()> {
    let pb = progress_bar();
    pb.println(format!(
        "{:<20} {:<20} Hostname",
        "IP address", "MAC Address"
    ));
    if &interface == "default" {
        let iface = get_netw_addr().context("failed to get routing table")?;
        let mut handles = Vec::new();

        for ip in iface.subnet.get_subnet_ips() {
            if ip == iface.ip {
                output_found_device(&pb, &iface.ip, &iface.mac, "This PC");
                continue;
            }
            let iface = iface.clone();
            let pb = pb.clone();
            handles.push(thread::spawn(move || -> Result<()> {
                let Some((found, hostname)) = arp_scan(&iface, ip)? else {
                    return Ok(());
                };

                output_found_device(
                    &pb,
                    &Ipv4Addr::from_octets(found.src_ip),
                    &MacAddress {
                        addr: found.src_mac,
                    },
                    &hostname,
                );
                Ok(())
            }));
        }
        for handle in handles {
            match handle.join() {
                Ok(res) => res.context("scan thread failed")?,
                Err(panic) => eprintln!("scan thread panicked: {panic:?}"),
            }
        }
    }
    end_progress_bar(pb);
    Ok(())
}

fn progress_bar() -> ProgressBar {
    let pb = ProgressBar::new_spinner();

    pb.set_style(
        ProgressStyle::with_template("{spinner:.green} {msg}")
            .unwrap()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
    );

    pb.enable_steady_tick(Duration::from_millis(80));
    pb.set_message("Scanning network...");
    pb
}

fn end_progress_bar(pb: ProgressBar) {
    pb.finish_and_clear();
    println!("Scan complete \x1b[32m✓\x1b[0m");
}

fn output_found_device(spinner: &ProgressBar, ip: &Ipv4Addr, mac: &MacAddress, device_type: &str) {
    spinner.println(format!("{:<20} {:<20} {}", ip, mac, device_type));
}
