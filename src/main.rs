use std::fs::{File, OpenOptions};

use tokio::sync::mpsc;

use rsdsl_ip_config::DsConfig;
use rsdsl_netlinklib::link;
use rsdsl_pppoe3::{Client, Error, Result};
use serde::{Deserialize, Serialize};
use sysinfo::{ProcessExt, Signal, System, SystemExt};

const INTERFACE: &str = "eth1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Config {
    username: String,
    password: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("[info] wait for eth1");
    link::wait_up(INTERFACE.into()).await?;
    println!("[info] startup");

    let mut config_file = File::open("/data/pppoe.conf")?;
    let config: Config = serde_json::from_reader(&mut config_file)?;

    let mut ds_config: DsConfig = {
        let mut ds_config_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(rsdsl_ip_config::LOCATION)?;

        serde_json::from_reader(&mut ds_config_file).unwrap_or_else(|_| {
            println!("[info] no valid ds config to reuse");
            DsConfig::default()
        })
    };

    let (v4_tx, mut v4_rx) = mpsc::unbounded_channel();
    let (v6_tx, mut v6_rx) = mpsc::unbounded_channel();

    let client = Client::new(
        INTERFACE.into(),
        config.username,
        config.password,
        ds_config.v4.map(|v4| v4.addr),
        ds_config
            .v6
            .map(|v6| (u128::from(v6.laddr) & 0xffffffffffffffff) as u64),
    )?;

    let mut join_handle = tokio::spawn(client.run(v4_tx.clone(), v6_tx.clone()));

    loop {
        tokio::select! {
            result = v4_rx.recv() => {
                ds_config.v4 = result.ok_or(Error::V4ChannelClosed)?;

                let mut ds_config_file = File::create(rsdsl_ip_config::LOCATION)?;
                serde_json::to_writer_pretty(&mut ds_config_file, &ds_config)?;

                inform();

                if let Some(v4) = ds_config.v4 {
                    println!("[info] <> ipv4: addr={}, dns1={}, dns2={}", v4.addr, v4.dns1, v4.dns2);
                } else {
                    println!("[info] <> ipv4: n/a");
                }
            }
            result = v6_rx.recv() => {
                ds_config.v6 = result.ok_or(Error::V6ChannelClosed)?;

                let mut ds_config_file = File::create(rsdsl_ip_config::LOCATION)?;
                serde_json::to_writer_pretty(&mut ds_config_file, &ds_config)?;

                inform();

                if let Some(v6) = ds_config.v6 {
                    println!("[info] <> ipv6: laddr={}, raddr={}", v6.laddr, v6.raddr);
                } else {
                    println!("[info] <> ipv6: n/a");
                }
            }
            result = &mut join_handle => {
                result??;

                println!("[info] <> exiting");
                return Ok(());
            }
        }
    }
}

/// Informs netlinkd of IPv4/IPv6 configuration changes.
fn inform() {
    for netlinkd in System::new_all().processes_by_exact_name("rsdsl_netlinkd") {
        netlinkd.kill_with(Signal::User1);
    }
}
