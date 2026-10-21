use std::{collections::HashMap, fmt::Debug, fs::read_to_string};

use anyhow::{Context, Result};

use crate::models::MacAddress;

static MA_L: &str = "./db/ma-l.csv";
static MA_M: &str = "./db/ma-m.csv";
static MA_S: &str = "./db/ma-s.csv";

#[derive(Debug, Clone)]
pub struct Database {
    mac_vendors: HashMap<String, Vec<String>>,
}

impl Database {
    pub fn init() -> Result<Self> {
        let mut mac_vendors: HashMap<String, Vec<String>> = HashMap::new();

        read_csv_to_db(MA_L, &mut mac_vendors).context("failed to insert into memory from ma-l")?;
        read_csv_to_db(MA_M, &mut mac_vendors).context("failed to insert into memory from ma-m")?;
        read_csv_to_db(MA_S, &mut mac_vendors).context("failed to insert into memory from ma-s")?;

        Ok(Self { mac_vendors })
    }

    pub fn findByMacAddress(&self, addr: &MacAddress) -> Option<String> {
        let (l_key, m_key, s_key) = normalize_addr_to_keys(&addr.addr);
        if self.mac_vendors.contains_key(&l_key) {
            let vendor: String = self.mac_vendors.get(&l_key).unwrap().join("/");
            return Some(vendor);
        } else if self.mac_vendors.contains_key(&m_key) {
            let vendor: String = self.mac_vendors.get(&m_key).unwrap().join("/");
            return Some(vendor);
        } else if self.mac_vendors.contains_key(&s_key) {
            let vendor: String = self.mac_vendors.get(&s_key).unwrap().join("/");
            return Some(vendor);
        }
        None
    }
}

fn normalize_addr_to_keys(addr: &[u8]) -> (String, String, String) {
    let l_key = format!("{:02x}{:02x}{:02x}", addr[0], addr[1], addr[2]).to_uppercase();
    let m_key = format!(
        "{:02x}{:02x}{:02x}{:01x}",
        addr[0],
        addr[1],
        addr[2],
        addr[3] >> 4
    )
    .to_uppercase();
    let s_key = format!(
        "{:02x}{:02x}{:02x}{:02x}{:01x}",
        addr[0],
        addr[1],
        addr[2],
        addr[3],
        addr[4] >> 4
    )
    .to_uppercase();
    (l_key, m_key, s_key)
}

fn read_csv_to_db(path: &str, mac_vendors: &mut HashMap<String, Vec<String>>) -> Result<()> {
    let content = read_to_string(path).with_context(|| format!("failed to find file {}", path))?;
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
