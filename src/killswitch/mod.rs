use anyhow::Result;

use pnet::datalink;

pub fn default() -> Result<String> {
    let all_interfaces = datalink::interfaces();
    let default_interface = all_interfaces
        .iter()
        .find(|e| e.is_up() && !e.is_loopback() && !e.ips.is_empty());

    println!("{:#?}", default_interface);

    Ok("".to_string())
}
