use crate::models::FoundDevice;
use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;

pub fn init_scan_ui() -> ProgressBar {
    let pb = ProgressBar::new_spinner();

    pb.set_style(
        ProgressStyle::with_template("{spinner:.green} {msg}")
            .unwrap()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
    );

    pb.enable_steady_tick(Duration::from_millis(80));
    pb.set_message("Scanning network...");
    pb.println(format!(
        "{:<20} {:<20} {:<60} {:<20}",
        "IP address", "MAC Address", "Hostname", "Vendor"
    ));
    pb
}

pub fn terminate_scan_ui(pb: ProgressBar) {
    pb.finish_and_clear();
    println!("Scan complete \x1b[32m✓\x1b[0m");
}

pub fn print_found_devices(spinner: &ProgressBar, device: FoundDevice) {
    spinner.println(format!(
        "{:<20} {:<20} {:<60} {:<20}",
        device.ip, device.mac, device.hostname, device.vendor
    ));
}
