use std::net::IpAddr;
use std::rc::Rc;

fn wan_ip() -> Result<IpAddr, String> {
    // Get IP for ns1.google.com
    let mut query = rustdns::Message::default();
    query.add_question("ns1.google.com", rustdns::Type::A, rustdns::Class::Internet);

    use rustdns::clients::Exchanger;
    let ns1_ip = rustdns::clients::udp::Client::new("8.8.8.8:53")
        .map_err(|e| format!("Error connecting to 8.8.8.8:53\n{:?}", e))?
        .exchange(&query)
        .map_err(|e| format!("Error exchanging dns query to 8.8.8.8:53\n{:?}", e))?
        .answers
        .into_iter()
        .filter_map(|record| match record.resource {
            rustdns::Resource::A(ip) => Some(ip),
            _ => None,
        })
        .next()
        .ok_or("No A record found for ns1.google.com".to_string())?;

    // Get TXT record for 0-0.myaddr.google.com from ns1.google.com
    let mut query = rustdns::Message::default();
    query.add_question(
        "o-o.myaddr.1.google.com",
        rustdns::Type::TXT,
        rustdns::Class::Internet,
    );

    let res = rustdns::clients::udp::Client::new(format!("{}:53", ns1_ip))
        .map_err(|e| format!("Error connecting to ns1.google.com\n{:?}", e))?
        .exchange(&query)
        .map_err(|e| format!("Error exchanging dns query to ns1.google.com\n{:?}", e))?
        .answers
        .into_iter()
        .filter_map(|record| match record.resource {
            rustdns::Resource::TXT(mut txt) => {
                txt.0.pop().map(String::from_utf8).map(Result::ok).flatten()
            }
            _ => None,
        })
        .next()
        .ok_or("No TXT record found for o-o.myaddr.1.google.com".to_string())?;

    use std::str::FromStr;
    let ip = IpAddr::from_str(&res)
        .map_err(|e| format!("Error parsing ip from dig: {}\n{:#?}", res, e))?;

    return Ok(ip);
}

#[derive(serde::Deserialize, Debug)]
struct Config {
    cloudflare_api_key: Rc<str>,
    cloudflare_zone_id: Rc<str>,
    ddns_comment: Rc<str>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct CloudflareDnsRecord {
    id: Rc<str>,
    name: Rc<str>,
    comment: Option<Rc<str>>,
    content: Rc<str>,
    proxied: bool,
    ttl: u32,
    r#type: Rc<str>,
}

fn get_cloudflare_ddns_records(config: &Config) -> Result<Vec<CloudflareDnsRecord>, String> {
    #[derive(serde::Deserialize, Debug)]
    struct CloudflareRes {
        result: Vec<CloudflareDnsRecord>,
    }

    let ddns_records = ureq::get(&format!(
        "https://api.cloudflare.com/client/v4/zones/{}/dns_records",
        config.cloudflare_zone_id
    ))
    .set(
        "Authorization",
        &format!("Bearer {}", config.cloudflare_api_key),
    )
    .call()
    .map_err(|e| format!("Error querying cloudflare\n{:#?}", e))?
    .into_json::<CloudflareRes>()
    .map_err(|e| format!("Error parsing cloudflare response\n{:#?}", e))?
    .result
    .into_iter()
    // grab records with DDNS comment, e.g. "ddns record"
    .filter(|record| record.comment.as_ref() == Some(&config.ddns_comment))
    .collect::<Vec<_>>();

    Ok(ddns_records)
}

fn set_cloudflare_dns_records(
    dns_records: &Vec<CloudflareDnsRecord>,
    config: &Config,
) -> Result<(), String> {
    for record in dns_records.iter() {
        ureq::put(&format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records/{}",
            config.cloudflare_zone_id, record.id
        ))
        .set(
            "Authorization",
            &format!("Bearer {}", config.cloudflare_api_key),
        )
        .send_json(record)
        .map_err(|e| format!("Error querying cloudflare\n{:#?}", e))?
        .into_string()
        .map_err(|e| format!("Error parsing cloudflare response\n{:#?}", e))?;
    }

    Ok(())
}

/// Update Cloudflare "ddns record" entries with WAN IP
#[derive(clap::Parser, Debug)]
#[command(version, about, long_about=None)]
struct Args {
    /// Config file to read
    #[arg(long)]
    config_dir: String,
}

fn _main() -> Result<(), String> {
    use clap::Parser;
    let args = Args::parse();

    let wan_ip: Rc<str> = wan_ip()?.to_string().into();

    let wan_ip_file = format!("{}/wan_ip.cache", args.config_dir);
    if let Ok(s) = std::fs::read_to_string(wan_ip_file.clone()) {
        if *s == *wan_ip {
            println!("WAN IP unchanged {}", wan_ip);
            return Ok(());
        }
    }
    println!("Updating WAN IP {}", wan_ip);

    let config_file = format!("{}/config.json", args.config_dir);
    let config_file_reader = std::fs::File::open(config_file.clone())
        .map_err(|e| format!("error opening config file {}\n{:#?}", config_file, e))?;
    let config: Config = serde_json::from_reader(config_file_reader)
        .map_err(|e| format!("error parsing config file {}\n{:#?}", config_file, e))?;

    let mut ddns_records = get_cloudflare_ddns_records(&config)?;
    println!("\nDDNS records: {:#?}", ddns_records);

    for record in ddns_records.iter_mut() {
        record.content = wan_ip.clone()
    }

    println!("\nUpdated DDNS records: {:#?}", ddns_records);

    set_cloudflare_dns_records(&ddns_records, &config)?;

    std::fs::write(wan_ip_file.clone(), &*wan_ip).map_err(|e| {
        format!(
            "Error writing wan ip `{}` to file `{}`\n{}",
            wan_ip, wan_ip_file, e
        )
    })?;

    println!("\ndone");

    Ok(())
}

fn main() -> std::process::ExitCode {
    match _main() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(s) => {
            eprintln!("{}", s);
            std::process::ExitCode::FAILURE
        }
    }
}
