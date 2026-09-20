//! SIP003 environment parsing and the `plugin_opts` string.
//!
//! SIP003 (https://shadowsocks.org/en/wiki/Plugin.html) passes everything via
//! environment variables:
//!
//! * client side (`ss-local`): the plugin **listens** on
//!   `SS_LOCAL_HOST:SS_LOCAL_PORT` and **connects** to `SS_REMOTE_HOST:SS_REMOTE_PORT`;
//! * server side (`ss-server`): the plugin **listens** on
//!   `SS_REMOTE_HOST:SS_REMOTE_PORT` and **forwards** to
//!   `SS_LOCAL_HOST:SS_LOCAL_PORT` (where ss-server itself listens on loopback).
//!
//! The role is NOT part of the environment — like yggss, the plugin takes it
//! from `plugin_opts` (`s=1` / `server=1`) or the `--server` CLI flag.
//!
//! `plugin_opts` is a `;`-separated `k=v` list. Per SIP003, `;`, `=` and `\`
//! inside values are backslash-escaped (`\;`, `\=`, `\\`).

use anyhow::{anyhow, bail};
use qeli_core::crypto::parse_pubkey_hex;
use std::net::{SocketAddr, ToSocketAddrs};

/// Which SIP003 side this process runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}

/// Options parsed from `plugin_opts` (and CLI overrides).
#[derive(Clone, Debug)]
pub struct PluginOpts {
    pub role: Role,
    /// Auth password (the shared secret — one password, any number of
    /// clients from any hosts) — required on both sides.
    pub password: String,
    /// fake-tls SNI (default `www.cloudflare.com`). Empty string omits SNI.
    pub sni: String,
    /// Client: pinned server static public key (hex, 64 chars).
    pub server_public_key: Option<[u8; 32]>,
    /// Server: static identity private key (hex, 64 chars). Generated (and
    /// logged) when absent — pin it in production with `--genkey`.
    pub server_private_key: Option<[u8; 32]>,
    /// Keepalive PING interval, seconds. 0 = off (default 2).
    ///
    /// Dead-peer detection is bounded by `ping + 2s` (the fixed PONG grace),
    /// so the default detects a silently dead tunnel within ~4s. Larger
    /// values trade keepalive chatter for slower detection.
    pub ping_secs: u32,
    /// Connect/handshake timeout, seconds (default 10).
    pub dial_timeout_secs: u64,
}

impl Default for PluginOpts {
    fn default() -> Self {
        Self {
            role: Role::Client,
            password: String::new(),
            sni: "www.cloudflare.com".to_string(),
            server_public_key: None,
            server_private_key: None,
            ping_secs: 2,
            dial_timeout_secs: 10,
        }
    }
}

/// Parse a `plugin_opts` string (`k1=v1;k2=v2;...` with SIP003 escaping).
pub fn parse_plugin_opts(raw: &str) -> anyhow::Result<PluginOpts> {
    let mut opts = PluginOpts::default();
    for (key, value) in split_entries(raw) {
        apply_entry(&mut opts, &key, &value)?;
    }
    validate_opts(&opts)?;
    Ok(opts)
}

/// Apply one `key=value` entry to `opts` (shared by `plugin_opts` parsing and
/// the standalone config file).
fn apply_entry(opts: &mut PluginOpts, key: &str, value: &str) -> anyhow::Result<()> {
    match key {
        "s" | "server" => {
            opts.role = if parse_bool(key, value)? {
                Role::Server
            } else {
                Role::Client
            };
        }
        "password" | "pass" => opts.password = value.to_string(),
        "sni" => {
            validate_sni(value)?;
            opts.sni = value.to_string();
        }
        "serverkey" | "server_key" => {
            opts.server_public_key = Some(
                parse_pubkey_hex(value)
                    .ok_or_else(|| anyhow!("serverkey must be 64 hex chars"))?,
            );
        }
        "key" => {
            opts.server_private_key = Some(
                parse_pubkey_hex(value)
                    .ok_or_else(|| anyhow!("key must be 64 hex chars"))?,
            );
        }
        "ping" | "keepalive" => {
            opts.ping_secs = value
                .parse()
                .map_err(|_| anyhow!("ping must be a non-negative integer"))?;
        }
        "timeout" => {
            opts.dial_timeout_secs = value
                .parse()
                .map_err(|_| anyhow!("timeout must be a positive integer"))?;
            if opts.dial_timeout_secs == 0 {
                bail!("timeout must be at least 1 second");
            }
        }
        other => log::warn!("unknown plugin option '{other}' ignored"),
    }
    Ok(())
}

/// Cross-option validation (shared by both config sources).
fn validate_opts(opts: &PluginOpts) -> anyhow::Result<()> {
    if opts.password.is_empty() {
        bail!("password is required: set password=... (both sides)");
    }
    if opts.role == Role::Server && opts.server_private_key.is_none() {
        log::warn!(
            "server: no static key configured (key=...); an ephemeral identity is generated \
             and logged — clients cannot pin it across restarts"
        );
    }
    Ok(())
}

/// The qeli fake-tls ClientHello builder accepts an ASCII hostname of at most
/// 253 bytes, or the special markers `""`/`!`/`~`/`@` (it asserts otherwise).
/// Validate here so a bad option is a config error, not a panic.
fn validate_sni(sni: &str) -> anyhow::Result<()> {
    if matches!(sni, "" | "!" | "~" | "@") || (sni.is_ascii() && sni.len() <= 253) {
        Ok(())
    } else {
        bail!("sni must be an ASCII hostname of at most 253 bytes (or empty to omit)")
    }
}

fn parse_bool(key: &str, value: &str) -> anyhow::Result<bool> {
    match value.trim() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" | "" => Ok(false),
        other => bail!("option '{key}' expects a boolean, got '{other}'"),
    }
}

/// Split `k=v;k=v;...` honoring SIP003 backslash escapes. Entries are trimmed;
/// empty entries are skipped.
fn split_entries(raw: &str) -> Vec<(String, String)> {
    let mut entries = Vec::new();
    let mut current = String::new();
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                if let Some(&next) = chars.peek() {
                    if matches!(next, ';' | '=' | '\\') {
                        current.push(next);
                        chars.next();
                        continue;
                    }
                }
                current.push('\\');
            }
            ';' => entries.push(std::mem::take(&mut current)),
            _ => current.push(c),
        }
    }
    entries.push(current);

    entries
        .into_iter()
        .filter_map(|entry| {
            let entry = entry.trim();
            if entry.is_empty() {
                return None;
            }
            // Split on the FIRST '=': values may legitimately contain '='.
            let (key, value) = entry.split_once('=')?;
            Some((key.trim().to_string(), value.trim().to_string()))
        })
        .collect()
}

/// The two SIP003 addresses (from the environment).
#[derive(Clone, Copy, Debug)]
pub struct Sip003 {
    /// Client: the plugin's listen address. Server: where ss-server listens.
    pub local: SocketAddr,
    /// Client: the remote (plugin server) address. Server: the plugin's listen.
    pub remote: SocketAddr,
}

/// Read and resolve the SIP003 environment.
pub fn sip003_from_env() -> anyhow::Result<Sip003> {
    let local_host = required_env("SS_LOCAL_HOST")?;
    let local_port: u16 = required_env("SS_LOCAL_PORT")?
        .parse()
        .map_err(|_| anyhow!("SS_LOCAL_PORT is not a valid port"))?;
    let remote_host = required_env("SS_REMOTE_HOST")?;
    let remote_port: u16 = required_env("SS_REMOTE_PORT")?
        .parse()
        .map_err(|_| anyhow!("SS_REMOTE_PORT is not a valid port"))?;

    let local = resolve(&local_host, local_port, "SS_LOCAL_HOST/PORT")?;
    let remote = resolve(&remote_host, remote_port, "SS_REMOTE_HOST/PORT")?;
    Ok(Sip003 { local, remote })
}

fn required_env(name: &str) -> anyhow::Result<String> {
    std::env::var(name)
        .map(|v| v.trim().to_string())
        .map_err(|_| anyhow!("missing environment variable {name} (must run under ss-local/ss-server)"))
}

// ── standalone config (JSON) ─────────────────────────────────────────────────

/// A standalone (non-SIP003) configuration: the plugin runs directly from a
/// JSON config file — no ss-local/ss-server, no SS_* environment.
#[derive(Clone, Debug)]
pub struct StandaloneConfig {
    pub role: Role,
    /// Where THIS plugin process listens.
    pub listen: SocketAddr,
    /// Client: the plugin server to dial. Server: the TCP service to forward
    /// demuxed streams to (any TCP target — ss-server, an HTTP server, sshd…).
    pub remote: SocketAddr,
    /// All the regular `plugin_opts` options (password, sni, serverkey, key,
    /// ping, timeout).
    pub opts: PluginOpts,
}

/// The JSON config file shape. Every key is optional except `listen` and
/// `remote`; the plugin-option keys are the same names as in `plugin_opts`.
/// `_comment` (string or array of strings) is allowed and ignored — JSON has
/// no comments. Unknown keys are a config ERROR (a typo must not be silently
/// ignored).
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StandaloneFile {
    /// `"client"` or `"server"` (case-insensitive; default client).
    role: Option<String>,
    /// THIS process's listener, `"host:port"` (required).
    listen: String,
    /// Client: the plugin server. Server: the forward target
    /// (`"forward"` is an alias) (required).
    #[serde(alias = "forward")]
    remote: String,
    /// Auth password (the shared secret — one password, any number of
    /// clients from any hosts). Required.
    password: Option<String>,
    sni: Option<String>,
    /// Client: pin the server's static public key (64 hex chars).
    serverkey: Option<String>,
    /// Server: static identity private key (64 hex chars).
    key: Option<String>,
    /// Keepalive interval, seconds (0 = off).
    ping: Option<u32>,
    /// Connect/handshake timeout, seconds.
    timeout: Option<u64>,
    /// Ignored documentation field (string or array of strings).
    #[serde(default, deserialize_with = "de_comment")]
    _comment: (),
}

/// Deserialize `_comment` (string or array of strings) into `()`.
fn de_comment<'de, D>(deserializer: D) -> Result<(), D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize as _;
    serde_json::Value::deserialize(deserializer).map(|_| ())
}

/// Parse a standalone JSON config file.
///
/// ```json
/// {
///   "role": "server",
///   "listen": "0.0.0.0:8443",
///   "remote": "127.0.0.1:8080",
///   "password": "secret",
///   "key": "<64 hex>",
///   "ping": 2, "timeout": 10
/// }
/// ```
///
/// `role`/`listen`/`remote` are standalone-only keys; every other key is the
/// same `plugin_opts` option with the same validation.
pub fn parse_standalone_config(text: &str) -> anyhow::Result<StandaloneConfig> {
    let file: StandaloneFile = serde_json::from_str(text)
        .map_err(|e| anyhow!("invalid standalone config: {e}"))?;

    let role = match file.role.as_deref().map(|r| r.trim().to_ascii_lowercase()) {
        None => Role::Client,
        Some(ref r) if r == "client" => Role::Client,
        Some(ref r) if r == "server" => Role::Server,
        Some(other) => bail!("role must be \"client\" or \"server\", got \"{other}\""),
    };

    let mut opts = PluginOpts::default();
    opts.role = role;
    if let Some(password) = &file.password {
        opts.password = password.clone();
    }
    if let Some(sni) = &file.sni {
        validate_sni(sni)?;
        opts.sni = sni.clone();
    }
    if let Some(hex) = &file.serverkey {
        opts.server_public_key = Some(
            parse_pubkey_hex(hex).ok_or_else(|| anyhow!("serverkey must be 64 hex chars"))?,
        );
    }
    if let Some(hex) = &file.key {
        opts.server_private_key = Some(
            parse_pubkey_hex(hex).ok_or_else(|| anyhow!("key must be 64 hex chars"))?,
        );
    }
    if let Some(ping) = file.ping {
        opts.ping_secs = ping;
    }
    if let Some(timeout) = file.timeout {
        if timeout == 0 {
            bail!("timeout must be at least 1 second");
        }
        opts.dial_timeout_secs = timeout;
    }
    validate_opts(&opts)?;

    let listen = parse_config_addr(&file.listen, "listen")?;
    let remote = parse_config_addr(&file.remote, "remote")?;
    Ok(StandaloneConfig {
        role,
        listen,
        remote,
        opts,
    })
}

/// Parse a `"host:port"` address: an IPv4 or **bracketed IPv6** literal
/// (`"127.0.0.1:8443"`, `"[2001:db8::1]:8443"`, `"[::]:8443"`) parses
/// directly; a hostname resolves via the system resolver. A bare (unbracketed)
/// IPv6 literal is rejected with a hint — it is ambiguous with the port
/// separator.
fn parse_config_addr(value: &str, what: &str) -> anyhow::Result<SocketAddr> {
    let value = value.trim();
    if let Ok(addr) = value.parse::<SocketAddr>() {
        return Ok(addr);
    }
    let (host, port) = value
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("{what} must be host:port, got '{value}'"))?;
    if host.contains(':') {
        bail!(
            "{what}: a bare IPv6 literal is ambiguous — bracket it, e.g. \
             \"[2001:db8::1]:8443\" (got '{value}')"
        );
    }
    let port: u16 = port
        .parse()
        .map_err(|_| anyhow!("{what}: invalid port '{port}'"))?;
    resolve(&host.to_string(), port, what)
}

/// Map a standalone config to the SIP003-shaped address pair the client and
/// server runners already consume:
/// * client: listens on `listen`, dials `remote`;
/// * server: listens on `listen`, forwards demuxed streams to `remote`.
pub fn standalone_sip003(cfg: &StandaloneConfig) -> Sip003 {
    match cfg.role {
        Role::Client => Sip003 {
            local: cfg.listen,
            remote: cfg.remote,
        },
        Role::Server => Sip003 {
            // server::run binds `remote` (the plugin listener) and forwards
            // to `local` (the destination) — see its doc comment.
            local: cfg.remote,
            remote: cfg.listen,
        },
    }
}

/// Resolve `host:port` (IPv4, IPv6 or a hostname) to a socket address.
///
/// IPv6 literals must be bracketed (`[2001:db8::1]:8443`) — a bare
/// `2001:db8::1:8443` is ambiguous; unbracketed IPv6 hosts from the
/// environment are bracketed automatically here.
fn resolve(host: &str, port: u16, what: &str) -> anyhow::Result<SocketAddr> {
    let host = host.trim();
    let host = if host.is_empty() {
        "127.0.0.1".to_string()
    } else if host.contains(':') && !host.starts_with('[') {
        // A bare IPv6 literal (no brackets) — bracket it for the parser.
        format!("[{host}]")
    } else {
        host.to_string()
    };
    let addr_str = format!("{host}:{port}");
    let mut addrs = addr_str
        .to_socket_addrs()
        .map_err(|e| anyhow!("failed to resolve {what} ({addr_str}): {e}"))?;
    addrs
        .next()
        .ok_or_else(|| anyhow!("no addresses for {what} ({addr_str})"))
}

/// Lowercase hex of a byte slice (identity keys in logs / --genkey output).
pub fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0F) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_option_string() {
        let opts = parse_plugin_opts(
            r"server=1;password=p@ss\=word;sni=cdn.example.com;serverkey=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff;ping=15;timeout=5",
        )
        .unwrap();
        assert_eq!(opts.role, Role::Server);
        assert_eq!(opts.password, "p@ss=word");
        assert_eq!(opts.sni, "cdn.example.com");
        assert_eq!(
            opts.server_public_key,
            Some([
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
                0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
            ])
        );
        assert_eq!(opts.ping_secs, 15);
        assert_eq!(opts.dial_timeout_secs, 5);
    }

    #[test]
    fn defaults_are_client_side() {
        let opts = parse_plugin_opts("password=x").unwrap();
        assert_eq!(opts.role, Role::Client);
        assert_eq!(opts.sni, "www.cloudflare.com");
        assert_eq!(opts.ping_secs, 2, "default keepalive must detect a dead peer in ≤5s");
    }

    #[test]
    fn password_is_required() {
        assert!(parse_plugin_opts("").is_err());
        assert!(parse_plugin_opts("sni=example.com").is_err());
    }

    #[test]
    fn escaped_semicolon_splits_entries() {
        let opts = parse_plugin_opts(r"password=a\;b;c=ignored-wrong-key").unwrap();
        assert_eq!(opts.password, "a;b");
    }

    #[test]
    fn value_may_contain_equals() {
        let opts = parse_plugin_opts(r"password=base64==").unwrap();
        assert_eq!(opts.password, "base64==");
    }

    #[test]
    fn user_option_is_no_longer_a_config_key() {
        // `user` was removed: one password serves any number of clients.
        // It now falls into unknown-option handling (warn + ignore), and a
        // config with only `user` still fails on the missing password.
        assert!(parse_plugin_opts("user=alice").is_err());
    }

    #[test]
    fn bad_hex_key_is_rejected() {
        assert!(parse_plugin_opts("password=x;serverkey=not-hex").is_err());
        assert!(parse_plugin_opts("password=x;key=1234").is_err());
    }

    #[test]
    fn bad_sni_is_rejected() {
        assert!(parse_plugin_opts("password=x;sni=не-ascii").is_err());
        let long = "a".repeat(254);
        assert!(parse_plugin_opts(&format!("password=x;sni={long}")).is_err());
        // Markers and empty SNI are allowed by the qeli hello builder.
        assert!(parse_plugin_opts("password=x;sni=").is_ok());
        assert!(parse_plugin_opts("password=x;sni=!").is_ok());
    }

    #[test]
    fn boolean_forms() {
        assert_eq!(parse_plugin_opts("s=1;password=x").unwrap().role, Role::Server);
        assert_eq!(parse_plugin_opts("s=0;password=x").unwrap().role, Role::Client);
        assert_eq!(parse_plugin_opts("server=true;password=x").unwrap().role, Role::Server);
        assert!(parse_plugin_opts("server=maybe;password=x").is_err());
    }

    #[test]
    fn unknown_options_are_ignored() {
        assert!(parse_plugin_opts("password=x;future-thing=1").is_ok());
    }

    #[test]
    fn bad_timeout_rejected() {
        assert!(parse_plugin_opts("password=x;timeout=0").is_err());
        assert!(parse_plugin_opts("password=x;timeout=abc").is_err());
    }

    #[test]
    fn to_hex_lowercase() {
        assert_eq!(to_hex(&[0x00, 0x0f, 0xff]), "000fff");
        assert_eq!(to_hex(&[]), "");
    }

    #[test]
    fn parses_full_standalone_client_config() {
        let cfg = parse_standalone_config(
            r#"{
                "_comment": ["standalone client", "all plugin options"],
                "role": "client",
                "listen": "127.0.0.1:1080",
                "remote": "203.0.113.10:8443",
                "password": "p@ss=word",
                "sni": "cdn.example.com",
                "serverkey": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
                "ping": 5,
                "timeout": 7
            }"#,
        )
        .unwrap();
        assert_eq!(cfg.role, Role::Client);
        assert_eq!(cfg.listen.to_string(), "127.0.0.1:1080");
        assert_eq!(cfg.remote.to_string(), "203.0.113.10:8443");
        assert_eq!(cfg.opts.password, "p@ss=word");
        assert_eq!(cfg.opts.sni, "cdn.example.com");
        assert!(cfg.opts.server_public_key.is_some());
        assert_eq!(cfg.opts.ping_secs, 5);
        assert_eq!(cfg.opts.dial_timeout_secs, 7);

        // Address mapping for the runners: client listens on `listen`,
        // dials `remote`.
        let sip = standalone_sip003(&cfg);
        assert_eq!(sip.local, cfg.listen);
        assert_eq!(sip.remote, cfg.remote);
    }

    #[test]
    fn standalone_ipv4_and_ipv6_addresses() {
        // IPv6 literals (bracketed) parse everywhere an IPv4 does.
        let cfg = parse_standalone_config(
            r#"{
                "role": "server",
                "listen": "[::]:8443",
                "remote": "[::1]:8080",
                "password": "x"
            }"#,
        )
        .unwrap();
        assert!(cfg.listen.is_ipv6());
        assert_eq!(cfg.listen.to_string(), "[::]:8443");
        assert!(cfg.remote.is_ipv6());
        assert_eq!(cfg.remote.to_string(), "[::1]:8080");

        let cfg = parse_standalone_config(
            r#"{
                "role": "client",
                "listen": "[::1]:1080",
                "remote": "[2001:db8::10]:8443",
                "password": "x"
            }"#,
        )
        .unwrap();
        assert!(cfg.listen.is_ipv6());
        assert!(cfg.remote.is_ipv6());

        // A bare (unbracketed) IPv6 literal is rejected with a hint.
        let err = parse_standalone_config(
            r#"{"listen": "2001:db8::1:8443", "remote": "127.0.0.1:2", "password": "x"}"#,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("bracket"),
            "the error must hint at bracketing, got: {err}"
        );
    }

    #[test]
    fn env_resolver_handles_ipv6_hosts() {
        // Bracketed and bare IPv6 hosts resolve (localhost ::1 always exists).
        assert!(resolve("[::1]", 8443, "test").is_ok());
        assert!(resolve("::1", 8443, "test").is_ok());
        assert_eq!(resolve("::1", 8443, "test").unwrap().is_ipv6(), true);
        assert!(resolve("127.0.0.1", 8443, "test").is_ok());
        assert_eq!(resolve("127.0.0.1", 8443, "test").unwrap().is_ipv4(), true);
    }

    #[test]
    fn parses_full_standalone_server_config() {
        let cfg = parse_standalone_config(
            r#"{
                "role": "server",
                "listen": "0.0.0.0:8443",
                "forward": "127.0.0.1:8080",
                "key": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
                "password": "change-me"
            }"#,
        )
        .unwrap();
        assert_eq!(cfg.role, Role::Server);
        assert_eq!(cfg.listen.to_string(), "0.0.0.0:8443");
        assert_eq!(cfg.remote.to_string(), "127.0.0.1:8080", "forward is an alias");
        assert!(cfg.opts.server_private_key.is_some());

        // Server mapping: listens on `listen`, forwards demuxed streams to
        // `remote` (server::run binds sip.remote, forwards to sip.local).
        let sip = standalone_sip003(&cfg);
        assert_eq!(sip.remote, cfg.listen);
        assert_eq!(sip.local, cfg.remote);
    }

    #[test]
    fn standalone_role_defaults_and_forms() {
        let base = r#""listen": "127.0.0.1:1", "remote": "127.0.0.1:2", "password": "x""#;
        assert_eq!(
            parse_standalone_config(&format!("{{{base}}}",)).unwrap().role,
            Role::Client,
            "default role is client"
        );
        assert_eq!(
            parse_standalone_config(&format!("{{\"role\": \"server\", {base}}}"))
                .unwrap()
                .role,
            Role::Server
        );
        assert_eq!(
            parse_standalone_config(&format!("{{\"role\": \"Client\", {base}}}",))
                .unwrap()
                .role,
            Role::Client,
            "role is case-insensitive"
        );
        let err = parse_standalone_config(&format!("{{\"role\": \"proxy\", {base}}}")).unwrap_err();
        assert!(err.to_string().contains("role"), "got: {err}");
    }

    #[test]
    fn standalone_requires_listen_and_remote() {
        let err = parse_standalone_config(
            r#"{"role": "client", "remote": "127.0.0.1:2", "password": "x"}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("listen"), "got: {err}");
        let err = parse_standalone_config(
            r#"{"role": "client", "listen": "127.0.0.1:1", "password": "x"}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("remote"), "got: {err}");
    }

    #[test]
    fn standalone_requires_password() {
        let err = parse_standalone_config(r#"{"listen": "127.0.0.1:1", "remote": "127.0.0.1:2"}"#)
            .unwrap_err();
        assert!(err.to_string().contains("password"), "got: {err}");
    }

    #[test]
    fn standalone_rejects_bad_json_and_addresses() {
        // Not JSON at all.
        let err = parse_standalone_config("garbage").unwrap_err();
        assert!(err.to_string().contains("config"), "got: {err}");
        // A bad address.
        let err = parse_standalone_config(
            r#"{"listen": "not-an-addr", "remote": "127.0.0.1:2", "password": "x"}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("listen"), "got: {err}");
        // A bad port.
        let err = parse_standalone_config(
            r#"{"listen": "127.0.0.1:99999", "remote": "127.0.0.1:2", "password": "x"}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("port"), "got: {err}");
    }

    #[test]
    fn standalone_rejects_unknown_keys_and_bad_values() {
        // A typo'd key must not be silently ignored.
        let err = parse_standalone_config(
            r#"{"listen": "127.0.0.1:1", "remote": "127.0.0.1:2", "password": "x", "pasword": "y"}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("pasword"), "got: {err}");
        // `user` was removed — it is now an unknown key (config error).
        let err = parse_standalone_config(
            r#"{"listen": "127.0.0.1:1", "remote": "127.0.0.1:2", "password": "x", "user": "alice"}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("user"), "got: {err}");
        // Bad serverkey hex must fail exactly like in plugin_opts.
        let err = parse_standalone_config(
            r#"{"listen": "127.0.0.1:1", "remote": "127.0.0.1:2", "password": "x", "serverkey": "nothex"}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("serverkey"), "got: {err}");
        // Bad SNI must fail.
        let err = parse_standalone_config(
            r#"{"listen": "127.0.0.1:1", "remote": "127.0.0.1:2", "password": "x", "sni": "не-ascii"}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("sni"), "got: {err}");
        // timeout=0 must fail.
        let err = parse_standalone_config(
            r#"{"listen": "127.0.0.1:1", "remote": "127.0.0.1:2", "password": "x", "timeout": 0}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("timeout"), "got: {err}");
    }

    #[test]
    fn standalone_accepts_comment_field() {
        let cfg = parse_standalone_config(
            r#"{"_comment": "a note", "listen": "127.0.0.1:1", "remote": "127.0.0.1:2", "password": "x"}"#,
        )
        .unwrap();
        assert_eq!(cfg.role, Role::Client);
    }
}
