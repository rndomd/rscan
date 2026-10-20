use anyhow::{Context, Result};
use rusqlite::Connection;

pub fn init() -> Result<()> {
    let conn = Connection::open_in_memory()
        .context("failed to initialize mac address vendors database")?;

    conn.execute(
        "create table if not exists mac_vendors (
                    id integer primary key,
                    addr text not null unique,
                    vendor text not null unique,
                )",
        (),
    )
    .context("failed to initialize in-memory mac address table")?;
    Ok(())
}

