use std::{collections::HashMap, fs::read_to_string};

use anyhow::{Context, Result};

static MA_L: &str = "../db/ma-l.csv";
static MA_M: &str = "../db/ma-m.csv";
static MA_S: &str = "../db/ma-s.csv";

pub fn init() -> Result<()> {
    let mut mac_vendors: HashMap<String, Vec<String>> = HashMap::new();

    read_csv_to_db(MA_L, &mut mac_vendors).context("failed to insert into memory ma-l")?;
    read_csv_to_db(MA_M, &mut mac_vendors).context("failed to insert into memory ma-m")?;
    read_csv_to_db(MA_S, &mut mac_vendors).context("failed to insert into memory from ma-s")?;

    Ok(())
}

fn read_csv_to_db(path: &str, mac_vendors: &mut HashMap<String, Vec<String>>) -> Result<()> {
    let content = read_to_string(path).context("failed to find file")?;
    content.lines().for_each(|line: &str| {
        let parts = line.split(",").collect::<Vec<_>>();
        let addr = parts[1].trim();
        let vendor = parts[2].trim();

        mac_vendors
            .entry(addr.to_string())
            .or_insert_with(Vec::new)
            .push(vendor.to_string());
    });
    Ok(())
}
