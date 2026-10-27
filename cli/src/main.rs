//! `hyphae` — a small, synchronous IMS REGISTER client.
//!
//! Mock mode runs the complete initial REGISTER → 401 → AKAv1-MD5 REGISTER
//! ladder entirely in memory against `transport::MockTransport`. UDP/TCP mode
//! uses the real `std::net` transports. SIP messages are written to stdout only
//! with `--verbose`; logs and warnings always go to stderr.
//!
//! Lab-only credentials are accepted explicitly. A real client must eventually
//! obtain RES from a USIM/ISIM AKA adapter; that adapter does not exist yet.

use std::collections::HashMap;
use std::env;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use carrier::CarrierProfile;
use ims::{ImsProfile, Registration, RegistrationEvent};
use sip::{Header, Headers, Message, Response};
use transport::net::{TcpTransport, UdpTransport};
use transport::{MockTransport, Transport};

/// 3GPP TS 35.208 test set 1 RES. Public test vector; mock/lab only.
const MOCK_RES_HEX: &str = "a54211d5e3ba50bf";
/// 3GPP TS 35.208 test set 1 OPc. Public test vector; mock/lab only.
const MOCK_OPC_HEX: &str = "cd63cb71954a9f4e48a5994e37a02baf";
const MOCK_IMSI: &str = "001010000000001";
const MOCK_CONTACT: &str = "127.0.0.1:5060";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Command {
    Register,
    Deregister,
    ShowProfile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransportKind {
    Mock,
    Udp,
    Tcp,
}

impl TransportKind {
    fn parse(value: &str) -> Result<Self, String> {
        match value.to_ascii_lowercase().as_str() {
            "mock" => Ok(Self::Mock),
            "udp" => Ok(Self::Udp),
            "tcp" => Ok(Self::Tcp),
            other => Err(format!(
                "unknown transport {other:?} (expected mock|udp|tcp)"
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Mock => "mock",
            Self::Udp => "udp",
            Self::Tcp => "tcp",
        }
    }
}

#[derive(Debug, Default, Clone)]
struct RawArgs {
    profile: Option<String>,
    config: Option<String>,
    transport: Option<String>,
    local_addr: Option<String>,
    p_cscf: Option<String>,
    imsi: Option<String>,
    res_hex: Option<String>,
    opc_hex: Option<String>,
    k_hex: Option<String>,
    once: bool,
    verbose: bool,
    command: Option<Command>,
    help: bool,
}

impl RawArgs {
    fn merge(base: RawArgs, over: RawArgs) -> Self {
        Self {
            profile: over.profile.or(base.profile),
            config: over.config.or(base.config),
            transport: over.transport.or(base.transport),
            local_addr: over.local_addr.or(base.local_addr),
            p_cscf: over.p_cscf.or(base.p_cscf),
            imsi: over.imsi.or(base.imsi),
            res_hex: over.res_hex.or(base.res_hex),
            opc_hex: over.opc_hex.or(base.opc_hex),
            k_hex: over.k_hex.or(base.k_hex),
            once: base.once || over.once,
            verbose: base.verbose || over.verbose,
            command: over.command.or(base.command),
            help: base.help || over.help,
        }
    }
}

struct Options {
    carrier: CarrierProfile,
    profile_arg: String,
    transport: TransportKind,
    local_addr: Option<String>,
    p_cscf: Option<String>,
    imsi: String,
    res_hex: Option<String>,
    opc_hex: Option<String>,
    k_hex: Option<String>,
    once: bool,
    verbose: bool,
    command: Command,
}

fn main() {
    match run() {
        Ok(()) => {}
        Err(err) => {
            eprintln!("hyphae: error: {err}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_help();
        return Ok(());
    }
    let cli = parse_args(&args)?;
    let config = match &cli.config {
        Some(path) => load_config(path)?,
        None => RawArgs::default(),
    };
    let raw = RawArgs::merge(config, cli);
    let opts = build_options(raw)?;

    if opts.verbose {
        eprintln!(
            "hyphae: profile={} transport={}",
            opts.profile_arg,
            opts.transport.as_str()
        );
    }

    match opts.command {
        Command::ShowProfile => show_profile(&opts),
        Command::Register => match opts.transport {
            TransportKind::Mock => run_mock(&opts, false),
            _ => run_real(&opts, false),
        },
        Command::Deregister => match opts.transport {
            TransportKind::Mock => run_mock(&opts, true),
            _ => run_real(&opts, true),
        },
    }
}

fn build_options(raw: RawArgs) -> Result<Options, String> {
    let profile_arg = raw.profile.unwrap_or_else(|| "00101".into());
    let carrier = load_carrier(&profile_arg)?;
    let transport = TransportKind::parse(raw.transport.as_deref().unwrap_or("mock"))?;
    let command = raw.command.unwrap_or(Command::Register);

    let imsi = match raw.imsi {
        Some(imsi) => validate_imsi(&imsi)?,
        None if carrier.id == "00101" => MOCK_IMSI.into(),
        None => {
            let derived = format!("{:<15}", carrier.id).replace(' ', "0");
            if transport != TransportKind::Mock && command != Command::ShowProfile {
                return Err(format!(
                    "no --imsi for carrier {}; refusing to invent a subscriber identity on the real network",
                    carrier.id
                ));
            }
            eprintln!(
                "hyphae: warning: no --imsi; using placeholder {derived} for carrier {}",
                carrier.id
            );
            derived
        }
    };

    let res_hex = raw
        .res_hex
        .or_else(|| env_first(&["HYPPHAE_RES_HEX", "HYPHAE_RES_HEX"]));
    let opc_hex = raw
        .opc_hex
        .or_else(|| env_first(&["HYPPHAE_OPC_HEX", "HYPHAE_OPC_HEX"]));
    let k_hex = raw
        .k_hex
        .or_else(|| env_first(&["HYPPHAE_K_HEX", "HYPHAE_K_HEX"]));

    Ok(Options {
        carrier,
        profile_arg,
        transport,
        local_addr: raw.local_addr,
        p_cscf: raw.p_cscf,
        imsi,
        res_hex,
        opc_hex,
        k_hex,
        once: raw.once,
        verbose: raw.verbose,
        command,
    })
}

fn parse_args(args: &[String]) -> Result<RawArgs, String> {
    let mut raw = RawArgs::default();
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        let (key, inline) = match arg.split_once('=') {
            Some((k, v)) => (k, Some(v.to_string())),
            None => (arg.as_str(), None),
        };
        match key {
            "--profile" => raw.profile = Some(take_value(key, inline, args, &mut i)?),
            "--config" => raw.config = Some(take_value(key, inline, args, &mut i)?),
            "--transport" => raw.transport = Some(take_value(key, inline, args, &mut i)?),
            "--local-addr" => raw.local_addr = Some(take_value(key, inline, args, &mut i)?),
            "--p-cscf" => raw.p_cscf = Some(take_value(key, inline, args, &mut i)?),
            "--imsi" => raw.imsi = Some(take_value(key, inline, args, &mut i)?),
            "--res-hex" => raw.res_hex = Some(take_value(key, inline, args, &mut i)?),
            "--opc-hex" => raw.opc_hex = Some(take_value(key, inline, args, &mut i)?),
            "--k-hex" => raw.k_hex = Some(take_value(key, inline, args, &mut i)?),
            "--once" => {
                if inline.is_some() {
                    return Err("--once does not take a value".into());
                }
                raw.once = true;
            }
            "--verbose" | "-v" => raw.verbose = true,
            "register" => set_command(&mut raw, Command::Register)?,
            "deregister" => set_command(&mut raw, Command::Deregister)?,
            "show-profile" => set_command(&mut raw, Command::ShowProfile)?,
            other if other.starts_with('-') => {
                return Err(format!("unknown option {other:?}; try --help"))
            }
            other => return Err(format!("unknown command {other:?}; try --help")),
        }
        i += 1;
    }
    Ok(raw)
}

fn take_value(
    key: &str,
    inline: Option<String>,
    args: &[String],
    index: &mut usize,
) -> Result<String, String> {
    if let Some(value) = inline {
        if value.is_empty() {
            return Err(format!("{key} requires a value"));
        }
        return Ok(value);
    }
    *index += 1;
    args.get(*index)
        .cloned()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| format!("{key} requires a value"))
}

fn set_command(raw: &mut RawArgs, command: Command) -> Result<(), String> {
    if raw.command.is_some() {
        return Err("only one subcommand may be given".into());
    }
    raw.command = Some(command);
    Ok(())
}

fn load_config(path: &str) -> Result<RawArgs, String> {
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("cannot read config {path}: {e}"))?;
    let mut values = HashMap::new();
    for (lineno, raw_line) in text.lines().enumerate() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("{path}:{}: expected key = value", lineno + 1))?;
        let key = normalize_key(key);
        let value = value
            .trim()
            .trim_matches('"')
            .trim_matches('\'')
            .to_string();
        values.insert(key, value);
    }

    let mut raw = RawArgs::default();
    for (key, value) in values {
        match key.as_str() {
            "profile" => raw.profile = Some(value),
            "transport" => raw.transport = Some(value),
            "local_addr" => raw.local_addr = Some(value),
            "p_cscf" => raw.p_cscf = Some(value),
            "imsi" => raw.imsi = Some(value),
            "res_hex" => raw.res_hex = Some(value),
            "opc_hex" => raw.opc_hex = Some(value),
            "k_hex" => raw.k_hex = Some(value),
            "once" => raw.once = parse_bool(&key, &value)?,
            "verbose" => raw.verbose = parse_bool(&key, &value)?,
            other => return Err(format!("{path}: unknown config key {other:?}")),
        }
    }
    Ok(raw)
}

fn normalize_key(key: &str) -> String {
    key.trim().to_ascii_lowercase().replace('-', "_")
}

fn parse_bool(key: &str, value: &str) -> Result<bool, String> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        other => Err(format!("config {key}: expected boolean, got {other:?}")),
    }
}

fn env_first(names: &[&str]) -> Option<String> {
    names
        .iter()
        .find_map(|name| env::var(name).ok().filter(|v| !v.is_empty()))
}

fn validate_imsi(imsi: &str) -> Result<String, String> {
    let imsi = imsi.trim();
    if imsi.is_empty() || imsi.len() > 15 || !imsi.chars().all(|c| c.is_ascii_digit()) {
        return Err(format!(
            "invalid IMSI {imsi:?}: expected 1-15 decimal digits"
        ));
    }
    Ok(imsi.to_string())
}

fn load_carrier(id_or_path: &str) -> Result<CarrierProfile, String> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    let as_path = Path::new(id_or_path);
    if as_path.is_file() {
        candidates.push(as_path.to_path_buf());
    } else {
        let file = if id_or_path.ends_with(".toml") {
            id_or_path.to_string()
        } else {
            format!("{id_or_path}.toml")
        };
        candidates.push(Path::new("carrier/profiles").join(&file));
        candidates.push(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../carrier/profiles")
                .join(&file),
        );
    }

    for path in &candidates {
        if path.is_file() {
            let text = std::fs::read_to_string(path)
                .map_err(|e| format!("cannot read carrier profile {}: {e}", path.display()))?;
            return CarrierProfile::parse(&text)
                .map_err(|e| format!("carrier profile {}: {e}", path.display()));
        }
    }

    if id_or_path == "00101" {
        // Embedded copy of carrier/profiles/00101.toml, for an installed binary
        // that was built outside the source tree.
        return Ok(CarrierProfile::lab());
    }

    Err(format!(
        "carrier profile {id_or_path:?} not found (looked for {})",
        candidates
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    ))
}

fn build_ims_profile(opts: &Options) -> Result<ImsProfile, String> {
    let mut profile = ImsProfile::from_carrier(&opts.carrier, &opts.imsi);
    profile.transport = match opts.transport {
        TransportKind::Tcp => "TCP".into(),
        _ => "UDP".into(),
    };
    if let Some(p_cscf) = &opts.p_cscf {
        profile.p_cscf = vec![with_default_port(p_cscf, 5060)];
    }
    if opts.transport == TransportKind::Mock {
        let contact = opts.local_addr.as_deref().unwrap_or(MOCK_CONTACT);
        apply_contact(&mut profile, contact)?;
    } else if let Some(local) = &opts.local_addr {
        apply_contact(&mut profile, local)?;
    }
    Ok(profile)
}

fn apply_contact(profile: &mut ImsProfile, endpoint: &str) -> Result<(), String> {
    let (host, port) = parse_host_port(endpoint, 5060)
        .ok_or_else(|| format!("invalid local address {endpoint:?} (expected host:port)"))?;
    profile.contact_host = host;
    profile.contact_port = port;
    Ok(())
}

fn update_contact_from_transport(profile: &mut ImsProfile, local: &str, explicit: bool) {
    if explicit {
        return;
    }
    if let Some((mut host, port)) = parse_host_port(local, profile.contact_port) {
        if host == "0.0.0.0" || host == "[::]" {
            host = "127.0.0.1".into();
        }
        profile.contact_host = host;
        profile.contact_port = port;
    }
}

fn show_profile(opts: &Options) -> Result<(), String> {
    let profile = build_ims_profile(opts)?;
    let c = &opts.carrier;
    println!("carrier: {} — {}", c.id, c.display_name);
    println!("  operator: {}", c.operator);
    println!("  mcc/mnc: {}/{}", c.mcc, c.mnc);
    println!("  ims domain: {}", c.ims_domain());
    println!("  ims apn: {}", c.ims_apn);
    println!("  p-cscf discovery: {}", c.p_cscf_discovery.as_str());
    println!("  p-cscf: {}", c.p_cscf.join(", "));
    println!(
        "  volte/evs/sms-over-ims: {}/{}/{}",
        c.volte, c.evs, c.sms_over_ims
    );
    println!("  amr-wb modes: {:?}", c.amr_wb_modes);
    println!(
        "  timers: t1={}ms t2={}ms register={}s",
        c.timers.t1_ms, c.timers.t2_ms, c.timers.register_expires_s
    );
    println!("ims profile:");
    println!("  impi: {}", profile.private_identity);
    println!("  impu: {}", profile.public_identity);
    println!("  realm: {}", profile.realm);
    println!("  p-cscf endpoints: {}", profile.p_cscf.join(", "));
    println!("  contact: {}", profile.contact_uri());
    println!("  transport: {}", profile.transport);
    println!("  register expires: {}", profile.register_expires);
    println!(
        "  security client: {}",
        profile
            .security_clients
            .first()
            .map(|s| s.header_value())
            .unwrap_or_default()
    );
    println!("  user agent: {}", profile.user_agent);
    println!("  feature tags: {}", profile.feature_tags.join(", "));
    let offer = profile.amr_wb_offer(&profile.contact_host, true);
    if let Some(media) = offer.audio() {
        println!("  sdp amr-wb fmtp: {}", media.fmtp(116).unwrap_or(""));
    }
    Ok(())
}

fn run_mock(opts: &Options, deregister: bool) -> Result<(), String> {
    let profile = build_ims_profile(opts)?;
    let (mut client, mut server) = MockTransport::pair();
    let mut reg = Registration::new(profile);
    let timeout = Duration::from_millis(500);

    eprintln!(
        "hyphae: MOCK/LAB ONLY: using 3GPP TS 35.208 test set 1 RES={MOCK_RES_HEX} OPc={MOCK_OPC_HEX}"
    );
    eprintln!("hyphae: mock mode is in-memory; no socket, network, modem or USIM is used");

    let first = reg.register_request();
    client
        .send(&Message::Request(first.clone()))
        .map_err(transport_error)?;
    dump(
        opts.verbose,
        "== 1. client -> server: initial REGISTER ==",
        &Message::Request(first),
    );
    let received = server
        .recv(timeout)
        .map_err(transport_error)?
        .ok_or("mock server did not receive initial REGISTER")?;
    dump(opts.verbose, "== 1. server received ==", &received);

    let challenge = mock_response(
        &reg,
        401,
        "Unauthorized",
        &[
            (
                "WWW-Authenticate",
                "Digest realm=\"ims.mnc001.mcc001.3gppnetwork.org\", nonce=\"bm9uY2U=\", algorithm=AKAv1-MD5, qop=\"auth\"",
            ),
            (
                "Security-Server",
                "ipsec-3gpp;alg=hmac-md5-96;ealg=null;prot=esp;mod=trans;spi-c=20000;spi-s=20001;port-c=6062;port-s=6064",
            ),
        ],
    );
    let challenge = Message::Response(challenge);
    server.send(&challenge).map_err(transport_error)?;
    dump(
        opts.verbose,
        "== 2. server -> client: 401 challenge ==",
        &challenge,
    );
    let response = client
        .recv(timeout)
        .map_err(transport_error)?
        .ok_or("mock client did not receive 401")?;
    let Message::Response(response) = response else {
        return Err("mock client expected a response".into());
    };
    let RegistrationEvent::Challenge(c) = reg.on_response(&response) else {
        return Err("401 was not recognised as a challenge".into());
    };

    let res = parse_hex8(MOCK_RES_HEX)?;
    let auth = reg.authorize(&c, &res, "0a4f113b");
    client
        .send(&Message::Request(auth.clone()))
        .map_err(transport_error)?;
    dump(
        opts.verbose,
        "== 3. client -> server: challenged REGISTER with AKAv1-MD5 ==",
        &Message::Request(auth),
    );
    let received = server
        .recv(timeout)
        .map_err(transport_error)?
        .ok_or("mock server did not receive challenged REGISTER")?;
    if received.headers().get("authorization").is_none() {
        return Err("challenged REGISTER lacks Authorization".into());
    }
    if received.headers().get("security-verify").is_none() {
        return Err("challenged REGISTER lacks Security-Verify".into());
    }

    let ok = Message::Response(mock_response(
        &reg,
        200,
        "OK",
        &[(
            "Service-Route",
            "<sip:orig@scscf.ims.mnc001.mcc001.3gppnetwork.org;lr>",
        )],
    ));
    server.send(&ok).map_err(transport_error)?;
    dump(opts.verbose, "== 4. server -> client: 200 OK ==", &ok);
    let response = client
        .recv(timeout)
        .map_err(transport_error)?
        .ok_or("mock client did not receive 200 OK")?;
    let Message::Response(response) = response else {
        return Err("mock client expected a response".into());
    };
    match reg.on_response(&response) {
        RegistrationEvent::Registered => {}
        other => return Err(format!("expected Registered, got {other:?}")),
    }

    if deregister {
        let bye = reg.deregister_request();
        client
            .send(&Message::Request(bye.clone()))
            .map_err(transport_error)?;
        dump(
            opts.verbose,
            "== 5. client -> server: REGISTER Expires: 0 ==",
            &Message::Request(bye),
        );
        let received = server
            .recv(timeout)
            .map_err(transport_error)?
            .ok_or("mock server did not receive deregistration")?;
        if received.headers().get("expires") != Some("0") {
            return Err("deregistration did not carry Expires: 0".into());
        }
        let ok = Message::Response(mock_response(&reg, 200, "OK", &[]));
        server.send(&ok).map_err(transport_error)?;
        dump(
            opts.verbose,
            "== 6. server -> client: 200 OK (deregistered) ==",
            &ok,
        );
        let response = client
            .recv(timeout)
            .map_err(transport_error)?
            .ok_or("mock client did not receive deregistration 200")?;
        let Message::Response(response) = response else {
            return Err("mock client expected a response".into());
        };
        if !(200..300).contains(&response.status) {
            return Err(format!("deregistration failed: {}", response.status));
        }
        eprintln!("hyphae: deregistered (mock, 200 OK)");
    } else {
        eprintln!(
            "hyphae: registered (mock, 200 OK) as {}; Service-Route {}",
            reg.profile().public_identity,
            reg.profile().service_route.join(", ")
        );
    }
    Ok(())
}

fn mock_response(
    reg: &Registration,
    status: u16,
    reason: &str,
    extra: &[(&str, &str)],
) -> Response {
    let mut headers = Headers::new();
    headers.push(Header::new("Call-ID", reg.call_id()));
    headers.push(Header::new("CSeq", format!("{} REGISTER", reg.cseq())));
    headers.push(Header::new("Content-Length", "0"));
    for (name, value) in extra {
        headers.push(Header::new(*name, *value));
    }
    Response {
        status,
        reason: reason.into(),
        headers,
        body: Vec::new(),
    }
}

fn run_real(opts: &Options, deregister: bool) -> Result<(), String> {
    let mut profile = build_ims_profile(opts)?;
    if profile.p_cscf.is_empty() {
        return Err("no P-CSCF configured; pass --p-cscf host:port".into());
    }
    let endpoint = with_default_port(&profile.p_cscf[0], 5060);
    let timeout = Duration::from_millis(10_000);

    eprintln!(
        "hyphae: LAB ONLY: AKA RES/OPc credentials are being supplied by flag/env; a USIM adapter is not implemented yet"
    );
    if opts.res_hex.is_none() {
        if opts.k_hex.is_some() && opts.opc_hex.is_some() {
            eprintln!("hyphae: will derive RES from a lab RAND/AUTN nonce using --k-hex/--opc-hex");
        } else if opts.opc_hex.is_some() {
            eprintln!(
                "hyphae: warning: --opc-hex alone cannot produce RES; pass --res-hex or --k-hex too"
            );
        } else {
            eprintln!(
                "hyphae: warning: no RES supplied; a challenge will fail unless --res-hex (or env HYPPHAE_RES_HEX) is set"
            );
        }
    }

    let mut transport: Box<dyn Transport> = match opts.transport {
        TransportKind::Udp => {
            let bind = opts.local_addr.as_deref().unwrap_or("0.0.0.0:0");
            Box::new(
                UdpTransport::connect(bind, &endpoint)
                    .map_err(|e| format!("UDP transport: {e}"))?,
            )
        }
        TransportKind::Tcp => Box::new(
            TcpTransport::connect(&endpoint, Duration::from_secs(5))
                .map_err(|e| format!("TCP transport: {e}"))?,
        ),
        TransportKind::Mock => unreachable!("mock handled separately"),
    };
    update_contact_from_transport(
        &mut profile,
        transport.local_addr(),
        opts.local_addr.is_some(),
    );

    eprintln!(
        "hyphae: {} to {} from {} (contact {})",
        if deregister {
            "deregistering"
        } else {
            "registering"
        },
        endpoint,
        transport.local_addr(),
        profile.contact_uri()
    );

    let mut reg = Registration::new(profile);
    let max_attempts = if opts.once { 1 } else { 3 };
    for attempt in 1..=max_attempts {
        let request = if deregister {
            reg.deregister_request()
        } else {
            reg.register_request()
        };
        transport
            .send(&Message::Request(request.clone()))
            .map_err(transport_error)?;
        dump(
            opts.verbose,
            if deregister {
                "== client -> server: REGISTER Expires: 0 =="
            } else {
                "== client -> server: initial REGISTER =="
            },
            &Message::Request(request),
        );

        let response = match recv_final(transport.as_mut(), timeout) {
            Ok(response) => response,
            Err(err) if !opts.once && attempt < max_attempts => {
                eprintln!("hyphae: attempt {attempt}: {err}; retrying");
                continue;
            }
            Err(err) => return Err(err),
        };
        dump(
            opts.verbose,
            &format!("== server -> client: {} ==", response.status),
            &Message::Response(response.clone()),
        );

        match reg.on_response(&response) {
            RegistrationEvent::Registered => {
                if deregister {
                    eprintln!("hyphae: deregistered (200 OK)");
                } else {
                    eprintln!(
                        "hyphae: registered (200 OK) as {}; Service-Route {}",
                        reg.profile().public_identity,
                        reg.profile().service_route.join(", ")
                    );
                }
                return Ok(());
            }
            RegistrationEvent::Failed(status) => {
                return Err(format!("REGISTER failed with {status}"));
            }
            RegistrationEvent::Challenge(challenge) => {
                let res = resolve_res(opts, &response)?;
                let cnonce = generate_cnonce();
                let authorized = if deregister {
                    reg.authorize_deregister(&challenge, &res, &cnonce)
                } else {
                    reg.authorize(&challenge, &res, &cnonce)
                };
                transport
                    .send(&Message::Request(authorized.clone()))
                    .map_err(transport_error)?;
                dump(
                    opts.verbose,
                    "== client -> server: challenged REGISTER (AKAv1-MD5) ==",
                    &Message::Request(authorized),
                );
                let response = recv_final(transport.as_mut(), timeout)?;
                dump(
                    opts.verbose,
                    &format!("== server -> client: {} ==", response.status),
                    &Message::Response(response.clone()),
                );
                match reg.on_response(&response) {
                    RegistrationEvent::Registered => {
                        if deregister {
                            eprintln!("hyphae: deregistered (200 OK)");
                        } else {
                            eprintln!(
                                "hyphae: registered (200 OK) as {}; Service-Route {}",
                                reg.profile().public_identity,
                                reg.profile().service_route.join(", ")
                            );
                        }
                        return Ok(());
                    }
                    RegistrationEvent::Failed(status) => {
                        return Err(format!("challenged REGISTER failed with {status}"))
                    }
                    RegistrationEvent::Challenge(_) => {
                        return Err("server re-challenged the authorized REGISTER".into())
                    }
                }
            }
        }
    }

    Err("registration timed out".into())
}

fn recv_final(transport: &mut dyn Transport, timeout: Duration) -> Result<Response, String> {
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("timed out waiting for a final SIP response".into());
        }
        match transport.recv(remaining).map_err(transport_error)? {
            Some(Message::Response(response)) if response.status < 200 => continue,
            Some(Message::Response(response)) => return Ok(response),
            Some(Message::Request(_)) => continue,
            None => return Err("timed out waiting for a final SIP response".into()),
        }
    }
}

fn resolve_res(opts: &Options, response: &Response) -> Result<[u8; 8], String> {
    if let Some(hex) = &opts.res_hex {
        return parse_hex8(hex);
    }
    if let (Some(k_hex), Some(opc_hex)) = (&opts.k_hex, &opts.opc_hex) {
        let k = aka::parse_hex16(k_hex).map_err(|e| format!("--k-hex: {e}"))?;
        let opc = aka::parse_hex16(opc_hex).map_err(|e| format!("--opc-hex: {e}"))?;
        let (rand, autn) = Registration::rand_autn_from_response(response)
            .ok_or("cannot derive RES: challenge nonce is not a lab RAND||AUTN value")?;
        let milenage = aka::Milenage::new_with_opc(k, opc);
        let check = aka::verify_autn(&milenage, &rand, &autn);
        if !check.mac_valid {
            return Err("AUTN MAC-A verification failed; check K/OPc and RAND".into());
        }
        let mut amf = [0u8; 2];
        amf.copy_from_slice(&autn[6..8]);
        let out = milenage.compute(&rand, &check.sqn, &amf);
        return Ok(out.res);
    }
    Err(
        "no lab RES available: pass --res-hex (or env HYPPHAE_RES_HEX), or --k-hex and --opc-hex"
            .into(),
    )
}

fn generate_cnonce() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{nanos:x}{:x}", std::process::id())
}

fn parse_hex8(hex: &str) -> Result<[u8; 8], String> {
    let hex = hex.trim();
    if hex.len() != 16 {
        return Err(format!(
            "RES must be 16 hex chars (8 bytes), got {}",
            hex.len()
        ));
    }
    let mut out = [0u8; 8];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| format!("RES contains a non-hex character: {hex:?}"))?;
    }
    Ok(out)
}

/// Append a default port to `host` unless one is already present.
fn with_default_port(host: &str, default_port: u16) -> String {
    match parse_host_port(host, default_port) {
        Some((h, p)) if p == default_port && !has_explicit_port(host) => format!("{h}:{p}"),
        _ => host.to_string(),
    }
}

fn has_explicit_port(endpoint: &str) -> bool {
    if endpoint.starts_with('[') {
        return endpoint
            .rsplit_once(']')
            .map(|(_, tail)| tail.starts_with(':'))
            .unwrap_or(false);
    }
    match endpoint.rsplit_once(':') {
        Some((host, port)) => {
            !host.contains(':') && !port.is_empty() && port.chars().all(|c| c.is_ascii_digit())
        }
        None => false,
    }
}

/// Parse `host:port`, `[v6]:port` or a bare host with `default_port`.
fn parse_host_port(endpoint: &str, default_port: u16) -> Option<(String, u16)> {
    let endpoint = endpoint.trim();
    if endpoint.is_empty() {
        return None;
    }
    if let Some(rest) = endpoint.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port = match tail.strip_prefix(':') {
            Some(p) if !p.is_empty() => p.parse().ok()?,
            Some(_) => default_port,
            None if tail.is_empty() => default_port,
            None => return None,
        };
        return Some((format!("[{host}]"), port));
    }
    match endpoint.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => {
            if port.is_empty() {
                Some((host.to_string(), default_port))
            } else {
                Some((host.to_string(), port.parse().ok()?))
            }
        }
        Some(_) => Some((endpoint.to_string(), default_port)),
        None => Some((endpoint.to_string(), default_port)),
    }
}

fn transport_error(err: transport::TransportError) -> String {
    err.to_string()
}

fn dump(verbose: bool, label: &str, message: &Message) {
    if !verbose {
        return;
    }
    println!("{label}");
    let text = message.to_text().replace("\r\n", "\n");
    print!("{text}");
    if !text.ends_with('\n') {
        println!();
    }
    println!();
}

fn print_help() {
    println!(
        "\
hyphae — standalone IMS/VoLTE REGISTER client

USAGE:
    hyphae [OPTIONS] [register|deregister|show-profile]

OPTIONS:
    --profile <id|path>   Carrier profile id (e.g. 00101) or TOML path [default: 00101]
    --config <path>       Key=value config file (CLI flags override it)
    --transport <kind>    mock | udp | tcp [default: mock]
    --local-addr <addr>   Local bind/contact endpoint, e.g. 192.0.2.10:5060
    --p-cscf <host:port>  Override the carrier P-CSCF endpoint
    --imsi <digits>       Subscriber IMSI used in IMPI/IMPU
    --res-hex <hex>       LAB ONLY: 8-byte AKA RES (16 hex chars)
    --opc-hex <hex>       LAB ONLY: OPc for RAND/AUTN derivation with --k-hex
    --k-hex <hex>         LAB ONLY: K for RAND/AUTN derivation with --opc-hex
    --once                One attempt; do not retry a timed-out REGISTER
    --verbose, -v         Print the SIP ladder to stdout
    --help, -h            This help

ENVIRONMENT:
    HYPPHAE_RES_HEX       LAB ONLY fallback for --res-hex
    HYPPHAE_OPC_HEX       LAB ONLY fallback for --opc-hex
    HYPPHAE_K_HEX         LAB ONLY fallback for --k-hex

EXIT STATUS:
    0 on a 2xx registration/deregistration or successful show-profile
    1 on transport, authentication or SIP failure

Mock mode uses the public 3GPP TS 35.208 test-set RES/OPc and prints a warning.
UDP/TCP mode is lab-only until a USIM/ISIM AKA adapter exists.
"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_flags_and_subcommand_in_any_order() {
        let args = vec![
            "--transport=tcp".to_string(),
            "show-profile".to_string(),
            "--profile".to_string(),
            "00101".to_string(),
            "--verbose".to_string(),
        ];
        let raw = parse_args(&args).unwrap();
        assert_eq!(raw.transport.as_deref(), Some("tcp"));
        assert_eq!(raw.profile.as_deref(), Some("00101"));
        assert_eq!(raw.command, Some(Command::ShowProfile));
        assert!(raw.verbose);
    }

    #[test]
    fn config_is_overridden_by_cli() {
        let base = RawArgs {
            profile: Some("00101".into()),
            transport: Some("mock".into()),
            ..RawArgs::default()
        };
        let over = RawArgs {
            transport: Some("udp".into()),
            ..RawArgs::default()
        };
        let merged = RawArgs::merge(base, over);
        assert_eq!(merged.profile.as_deref(), Some("00101"));
        assert_eq!(merged.transport.as_deref(), Some("udp"));
    }

    #[test]
    fn parses_res_hex() {
        assert_eq!(parse_hex8(MOCK_RES_HEX).unwrap()[0], 0xa5);
        assert!(parse_hex8("xyz").is_err());
    }

    #[test]
    fn host_port_defaults_and_explicit_ports() {
        assert_eq!(
            parse_host_port("pcscf.example", 5060),
            Some(("pcscf.example".into(), 5060))
        );
        assert_eq!(
            parse_host_port("pcscf.example:5070", 5060),
            Some(("pcscf.example".into(), 5070))
        );
        assert_eq!(
            parse_host_port("[2001:db8::1]:5062", 5060),
            Some(("[2001:db8::1]".into(), 5062))
        );
        assert_eq!(
            with_default_port("pcscf.example", 5060),
            "pcscf.example:5060"
        );
        assert_eq!(
            with_default_port("pcscf.example:5070", 5060),
            "pcscf.example:5070"
        );
    }

    #[test]
    fn mock_ladder_reaches_registered_state() {
        let opts = Options {
            carrier: CarrierProfile::lab(),
            profile_arg: "00101".into(),
            transport: TransportKind::Mock,
            local_addr: None,
            p_cscf: None,
            imsi: MOCK_IMSI.into(),
            res_hex: None,
            opc_hex: None,
            k_hex: None,
            once: true,
            verbose: false,
            command: Command::Register,
        };
        run_mock(&opts, false).unwrap();
        run_mock(&opts, true).unwrap();
    }
}
