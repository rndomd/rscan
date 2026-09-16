use crate::models::{Device, MacAddress};
use crate::network::{get_netw_addr, ping_local_ip};
use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use std::net::Ipv4Addr;
use std::time::Duration;

pub fn scan_network(interface: String) -> Result<()> {
    let pb = progress_bar();
    pb.println(format!(
        "{:<20} {:<20} Device Type",
        "IP address", "MAC Address"
    ));
    if &interface == "default" {
        let iface = get_netw_addr().context("failed to get routing table")?;
        for ip in iface.subnet.get_subnet_ips() {
            if ip == iface.ip {
                output_found_device(
                    &pb,
                        &iface.ip,
                        &iface.mac,
                        "This PC"
                );
            } else {
                if let Ok(Some(found)) = ping_local_ip(ip) {
                    output_found_device(&pb, &found, &MacAddress { addr: [0u8; 6] }, "unkown");
                }
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
