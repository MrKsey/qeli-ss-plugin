//! CLI entry point.
//!
//! Under shadowsocks (SIP003) the process is launched by `ss-local` /
//! `ss-server` with the SS_* environment; `plugin_opts` comes from
//! SS_PLUGIN_OPTIONS (or the first positional argument, which some
//! implementations pass). Standalone use — no shadowsocks at all, the plugin
//! runs from its own JSON config file:
//!
//! ```text
//! qeli-ss-plugin -genkey                          # print a server identity pair
//! qeli-ss-plugin -c plugin.json                   # standalone (own config file)
//! qeli-ss-plugin -s "key=<hex>;password=..."      # explicit role, SIP003 env
//! ```

use anyhow::{anyhow, Result};
use qeli_core::crypto::StaticKeypair;
use qeli_ss_plugin::opts::{self, Role};
use qeli_ss_plugin::{client, server};

const USAGE: &str = "\
Usage of qeli-ss-plugin:
  -c <file>
        path to a JSON config file (standalone mode, see examples/)
  -client
        run as client (default)
  -genkey
        generate a new server identity key pair and exit
  -h
        print this help and exit
  -s
        run as server
  -v
        print version and exit

Standalone config file (JSON, see examples/standalone-*.json):
  role, listen, remote (alias: forward), password, sni, serverkey, key,
  ping, timeout. listen and remote are required; IPv4 and bracketed IPv6
  addresses are accepted (\"[2001:db8::10]:8443\").

Under shadowsocks (SIP003): addresses come from the environment
(SS_LOCAL_HOST/PORT, SS_REMOTE_HOST/PORT — IPv4 and IPv6); options come
from plugin_opts (SS_PLUGIN_OPTIONS or the first positional argument,
k=v;... with \\; \\= \\\\ escapes):
  s=1             run as server
  password=<sec>  required; one password serves any number of clients
  sni=<host>      fake-TLS SNI (default www.cloudflare.com)
  serverkey=<hex> client: pin the server's static public key
  key=<hex>       server: static identity private key
  ping=<secs>     keepalive interval (default 2; dead-peer detection ≤ ping+2s)
  timeout=<secs>  connect/handshake timeout (default 10)
";

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut genkey = false;
    let mut role_flag: Option<Role> = None;
    let mut opts_arg: Option<String> = None;
    let mut config_path: Option<String> = None;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        match arg.as_str() {
            "--config" | "-c" => {
                index += 1;
                config_path = Some(
                    args.get(index)
                        .ok_or_else(|| anyhow!("--config requires a file path"))?
                        .clone(),
                );
            }
            "--genkey" | "-genkey" => genkey = true,
            "--server" | "-s" => role_flag = Some(Role::Server),
            "--client" => role_flag = Some(Role::Client),
            "--help" | "-h" => {
                print!("{USAGE}");
                return Ok(());
            }
            "--version" | "-v" | "-V" => {
                println!("{}", qeli_ss_plugin::VERSION);
                return Ok(());
            }
            other if !other.starts_with('-') => {
                if opts_arg.is_some() {
                    anyhow::bail!("unexpected extra argument: {other}");
                }
                opts_arg = Some(other.to_string());
            }
            other => anyhow::bail!("unknown flag: {other} (see --help)"),
        }
        index += 1;
    }

    if genkey {
        let kp = StaticKeypair::generate();
        println!("private key (key=...):        {}", opts::to_hex(kp.private_bytes().as_ref()));
        println!("public  key (serverkey=...):  {}", opts::to_hex(kp.public.as_bytes()));
        return Ok(());
    }

    // Standalone mode: everything (role, addresses, options) from the config
    // file; the SS_* environment and SS_PLUGIN_OPTIONS are not consulted.
    // (Startup is logged by client::run / server::run — no duplicate here.)
    if let Some(path) = config_path {
        let text = std::fs::read_to_string(&path)
            .map_err(|e| anyhow!("failed to read config {path}: {e}"))?;
        let mut cfg = opts::parse_standalone_config(&text)?;
        if let Some(role) = role_flag {
            cfg.role = role;
        }
        cfg.opts.role = cfg.role;
        let sip = opts::standalone_sip003(&cfg);
        return match cfg.role {
            Role::Client => client::run(cfg.opts, sip).await,
            Role::Server => server::run(cfg.opts, sip).await,
        };
    }

    let raw_opts = opts_arg
        .or_else(|| std::env::var("SS_PLUGIN_OPTIONS").ok())
        .unwrap_or_default();
    let mut plugin_opts = opts::parse_plugin_opts(&raw_opts)?;
    if let Some(role) = role_flag {
        plugin_opts.role = role;
    }

    let sip = opts::sip003_from_env()?;
    match plugin_opts.role {
        Role::Client => client::run(plugin_opts, sip).await,
        Role::Server => server::run(plugin_opts, sip).await,
    }
}
