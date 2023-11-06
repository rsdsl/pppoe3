use std::fs::{File, OpenOptions};
use std::io::Seek;

use tokio::sync::mpsc;

use rsdsl_ip_config::DsConfig;
use rsdsl_pppoe3::{Client, Error, Result};
use serde::{Deserialize, Serialize};
use sysinfo::{ProcessExt, Signal, System, SystemExt};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Config {
    username: String,
    password: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("[info] init");

    let mut config_file = File::open("/data/pppoe.conf")?;
    let config: Config = serde_json::from_reader(&mut config_file)?;

    let mut ds_config_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(rsdsl_ip_config::LOCATION)?;
    let mut ds_config: DsConfig =
        serde_json::from_reader(&mut ds_config_file).unwrap_or(DsConfig::default());

    let (v4_tx, mut v4_rx) = mpsc::unbounded_channel();
    let (v6_tx, mut v6_rx) = mpsc::unbounded_channel();

    let client = Client::new(
        "eth1".into(),
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

                ds_config_file.rewind()?;
                serde_json::to_writer_pretty(&mut ds_config_file, &ds_config)?;
                ds_config_file.sync_all()?;

                inform();

                if let Some(v4) = ds_config.v4 {
                    println!("[info] <> ipv4: addr={}, dns1={}, dns2={}", v4.addr, v4.dns1, v4.dns2);
                } else {
                    println!("[info] <> ipv4: n/a");
                }
            }
            result = v6_rx.recv() => {
                ds_config.v6 = result.ok_or(Error::V6ChannelClosed)?;

                ds_config_file.rewind()?;
                serde_json::to_writer_pretty(&mut ds_config_file, &ds_config)?;
                ds_config_file.sync_all()?;

                inform();

                if let Some(v6) = ds_config.v6 {
                    println!("[info] <> ipv6: laddr={}, raddr={}", v6.laddr, v6.raddr);
                } else {
                    println!("[info] <> ipv6: n/a");
                }
            }
            result = &mut join_handle => {
                result??; // This always fails, the task never exits with an Ok(_).
                unreachable!("Client::run exited successfully")
            }
        }
    }
}

/// Informs netlinkd of IPv4/IPv6 configuration changes.
fn inform() {
    for netlinkd in System::default().processes_by_exact_name("/bin/rsdsl_netlinkd") {
        netlinkd.kill_with(Signal::User1);
    }
}
