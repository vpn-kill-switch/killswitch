use anyhow::{anyhow, Result};

const MYIP_URLS: [&str; 3] = [
    "https://myip.country/ip",
    "http://trackip.net/ip",
    "https://checkip.amazonaws.com",
];

pub fn whoami() -> Result<String> {
    let client = reqwest::blocking::Client::builder()
        .user_agent("killswitch")
        .build()?;

    for url in &MYIP_URLS {
        match client.get(*url).send() {
            Ok(resp) if resp.status().is_success() => {
                let body = resp.text()?;
                return Ok(body);
            }
            Ok(_) => {
                // Continue to the next URL if the response is not successful
                continue;
            }
            Err(err) => {
                // Log the error or handle it as needed
                eprintln!("Error fetching IP from {}: {}", url, err);
                continue;
            }
        }
    }

    Err(anyhow!("Failed to get public IP from all URLs"))
}
