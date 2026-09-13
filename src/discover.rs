use crate::models::Device;
use crate::network::{get_netw_addr, ping_local_ip};
use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
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
                    &Device {
                        ip: iface.ip.to_string(),
                        mac: String::from("hidden"),
                        device_type: String::from("This PC"),
                    },
                );
            } else {
                if let Ok(Some(found)) = ping_local_ip(ip) {
                    output_found_device(
                        &pb,
                        &Device {
                            ip: found.to_string(),
                            mac: String::from("unkown"),
                            device_type: String::from("unkown"),
                        },
                    );
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

fn output_found_device(spinner: &ProgressBar, device: &Device) {
    spinner.println(format!(
        "{:<20} {:<20} {}",
        device.ip, device.mac, device.device_type
    ));
}
