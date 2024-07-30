use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use dirs::config_dir;
use serde_json::{json, Value};
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::time::Duration;

use reqwest::Client;
use serde::Deserialize;

fn main() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async_main());
}

async fn async_main() {
    let config = {
        let exe_config = std::env::current_exe()
            .map(|mut p| {
                p.pop();
                p.push("Config.toml");
                p
            })
            .and_then(|p| std::fs::read_to_string(p));
        let folder_config = config_dir()
            .map(|mut p| {
                p.push("elir");
                p.push("Config.toml");
                p
            })
            .context("Couldn't find config directory")
            .and_then(|p| std::fs::read_to_string(p).map_err(Into::into));

        let workingdir_config = std::fs::read_to_string("Config.toml");

        let config_file = exe_config.or(folder_config).or(workingdir_config);
        let c = config_file.expect("Could not find config file anywhere!");
        let config: Config =
            toml::from_str(&c).expect("Unable to parse configuration file for Elir!");
        config
    };

    if let Some(ttl) = config.ttl {
        if ttl > 60 * 60 * 24 || ttl < 60 {
            panic!("ttl should be 60 sec < ttl < 1 day");
        }
    }

    let api_key_loc_error = "api_key_loc should have format `env:ENVIRONMENT_VARIBLE` or `file:FILE_NAME.TXT` or `string:API_KEY`";
    let api_key = match config.api_key_loc.split_once(":") {
        Some((kind, location)) => match kind {
            "env" => std::env::var(location).expect("Environment variable did not have API key!"),
            "file" => std::fs::read_to_string(location).expect("File did not contain API key!"),
            "string" => location.to_owned(),
            _ => panic!("{api_key_loc_error}"),
        },
        None => panic!("{api_key_loc_error}"),
    };

    let (manager, id, mut ip) = {
        const EXPONENTIAL_BACKOFF_MULTIPLIER: f32 = 1.5;
        let mut delay = config.delay.unwrap_or(DEFAULT_DELAY) as f32;
        loop {
            match DnsManager::new(api_key.clone(), &config).await {
                Ok((manager, id, ip)) => break (manager, id, ip),
                Err(e) => {
                    eprintln!("Error occured: {e:#}.");
                    eprintln!("Trying again in {:?}", Duration::from_secs_f32(delay));
                    std::thread::sleep(Duration::from_secs_f32(delay));
                    delay *= EXPONENTIAL_BACKOFF_MULTIPLIER;
                    continue;
                }
            }
        }
    };

    println!("Successfully connected to DNS server!");

    let delay = || {
        std::thread::sleep(Duration::from_secs(
            config.delay.unwrap_or(DEFAULT_DELAY) as u64
        ));
    };

    let delay_time = config.delay.unwrap_or(DEFAULT_DELAY);
    loop {
        let new_ip = match manager.get_ip().await {
            Ok(ip) => ip,
            Err(e) => {
                eprintln!("Error occured file fetching IP: {e:#}. Retrying in {delay_time}");
                delay();
                continue;
            }
        };
        if ip != new_ip {
            if let Err(e) = manager.update_dns_record(new_ip, &id).await {
                eprintln!("Unable to update IP: {e:#}. Retrying in {delay_time}");
            } else {
                println!("Successfully changed ip from {ip} to {new_ip}");
                ip = new_ip;
            }
        } else {
            println!("Checked ip. No need to update.");
        }
        delay();
    }
}

#[derive(Deserialize)]
struct Config {
    name: String,
    api_key_loc: String,
    zone_id: String,
    proxied: Option<bool>,
    delay: Option<u32>,
    check_server: Option<String>,
    ttl: Option<u32>,
}

#[derive(Debug)]
struct DnsManager {
    client: Client,
    name: String,
    api_key: String,
    zone_id: String,
    proxied: bool,
    check_server: String,
    ttl: u32,
}

const DEFAULT_DELAY: u32 = 300;
const DEFAULT_TTL: u32 = 300;

impl DnsManager {
    async fn new(api_key: String, config: &Config) -> Result<(Self, String, IpAddr)> {
        let client = Client::builder()
            .local_address(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)))
            .build()
            .expect("Should not fail as no dynamic variables");

        let manager = DnsManager {
            client,
            api_key,
            zone_id: config.zone_id.clone(),
            name: config.name.clone(),
            proxied: config.proxied.unwrap_or(false),
            check_server: config
                .check_server
                .clone()
                .unwrap_or_else(|| String::from("https://ipv4.icanhazip.com")),
            ttl: config.ttl.unwrap_or(DEFAULT_TTL),
        };

        let records = manager
            .get_dns_records()
            .await
            .context("Failed to send initial dns record request")?;

        for record in records.result {
            manager
                .delete_dns_record(&record.id)
                .await
                .context("Failed to delete dns record: {record:?}")?
        }

        let ip = manager.get_ip().await.context("Failed to get initial IP")?;

        let id = manager
            .create_dns_record(ip)
            .await
            .context("Failed to initially create DNS record")?;

        return Ok((manager, id, ip));
    }

    async fn get_ip(&self) -> Result<IpAddr> {
        let resp = self
            .client
            .get(&self.check_server)
            .send()
            .await
            .context("Error when sending get req to IP server")?;
        let addr_text = resp
            .text()
            .await
            .context("Error when receiving response from IP server")?;
        let addr_text = addr_text.trim();
        let addr = addr_text
            .parse::<IpAddr>()
            .context("Failed to parse IP, invalid remote response...?")?;
        return Ok(addr);
    }

    async fn get_dns_records(&self) -> Result<GetDnsRecordResponse> {
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records",
            self.zone_id
        );
        let resp = self
            .client
            .get(&url)
            .header("Authorization", &format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .query(&[("name", &self.name)])
            .send()
            .await
            .context("Error when sending request to API")?;
        let json: GetDnsRecordResponse = resp
            .json()
            .await
            .context("Error receiving json response from API.")?;
        if !json.success {
            bail!("Api returned error: {:?}", json.errors);
        }
        Ok(json)
    }

    async fn delete_dns_record(&self, record_id: &str) -> Result<()> {
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records/{}",
            self.zone_id, record_id
        );

        let resp = self
            .client
            .delete(&url)
            .header("Authorization", &format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .send()
            .await
            .context("Error when sending request to API")?;

        let json: Value = resp
            .json()
            .await
            .context("Error converting response to JSON")?;

        if !json["success"]
            .as_bool()
            .context("Malformed remote response body...?")?
        {
            bail!("API returned error")
        }

        return Ok(());
    }

    async fn update_dns_record(&self, ip: IpAddr, id: &str) -> Result<()> {
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records/{}",
            self.zone_id, id,
        );

        let json = json!({
            "content": ip,
        });

        let resp = self
            .client
            .patch(&url)
            .header("Authorization", &format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&json)
            .send()
            .await
            .context("Error when sending request to API")?;

        let json: Value = resp
            .json()
            .await
            .context("Error converting response to JSON")?;

        if !json["success"]
            .as_bool()
            .context("Malformed remote response body...?")?
        {
            bail!("API returned error")
        }
        Ok(())
    }

    async fn create_dns_record(&self, ip: IpAddr) -> Result<String> {
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records",
            self.zone_id
        );

        let json = json!({
            "content": ip.to_string(),
            "name": self.name,
            "type": "A",
            "proxied": self.proxied,
            "ttl": self.ttl,
        });

        let resp = self
            .client
            .post(&url)
            .header("Authorization", &format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&json)
            .send()
            .await
            .context("Error when sending request to API")?;

        let json: Value = resp
            .json()
            .await
            .context("Error converting response to JSON")?;

        if !json["success"]
            .as_bool()
            .context("Malformed remote response body...?")?
        {
            bail!("API returned error")
        }
        let id = json["result"]["id"]
            .as_str()
            .context("Malformed remote response body...?")?
            .to_owned();
        Ok(id)
    }
}

#[derive(Debug, Clone, Deserialize)]
struct DnsRecord {
    #[serde(rename = "name")]
    _name: String,
    #[serde(rename = "content")]
    _content: std::net::IpAddr,
    #[serde(rename = "type")]
    _record_type: String,
    #[serde(rename = "zone_name")]
    _zone_name: String,
    id: String,
}

#[derive(Debug, Clone, Deserialize)]
struct GetDnsRecordResponse {
    errors: Vec<String>,
    #[serde(rename = "messages")]
    _messages: Vec<String>,
    result: Vec<DnsRecord>,
    success: bool,
}
