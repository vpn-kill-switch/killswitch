use anyhow::{anyhow, Result};

pub fn whoami() -> Result<String> {
    let client = reqwest::blocking::Client::builder()
        .user_agent("killswitch")
        .build()?;

    let resp = client.get("https://myip.country/ip").send()?;

    if resp.status().is_success() {
        let body = resp.text()?;
        Ok(body)
    } else {
        Err(anyhow!("Failed to get public IP: {}", resp.status()))
    }
}
