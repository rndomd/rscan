mod cli;
mod discover;
mod fingerprint;
mod models;
mod network;
mod ui;

use anyhow::{Error, Result};

fn main() -> Result<()> {
    let cmd = cli::parse();
    match cmd {
        cli::Command::Discover { interface } => {
            if let Err(error) = discover::scan_network(interface.as_str()) {
                print_error(&error);
                std::process::exit(1);
            }
        }
        cli::Command::Fingerprint { ip } => {
            if let Err(error) = fingerprint::scan_device(&ip) {
                print_error(&error);
                std::process::exit(1);
            }
        }
    }
    Ok(())
}

fn print_error(err: &Error) {
    eprintln!("Error: {}", err);

    eprintln!();
    eprintln!("Caused by:");

    for (i, cause) in err.chain().skip(1).enumerate() {
        eprintln!("    {i}: {cause}");
    }
}
