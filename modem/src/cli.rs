//! The `hyphae-modem` command line: arguments and usage text, nothing else.
//!
//! Kept separate from the runner so the parsing is testable on any host, even
//! where `modem-qmi` is not compiled.

use std::time::Duration;

/// Board default: the TX pipe from the device tree
/// (`dmas = <&bam_dmux_dma 4>, <&bam_dmux_dma 5>` named `tx`, `rx`).
pub const DEFAULT_TX_ID: u32 = 4;
/// Board default: the RX pipe from the same device tree entry.
pub const DEFAULT_RX_ID: u32 = 5;
/// The interface a QMI data call is exposed on.
pub const DEFAULT_IFACE: &str = "wwan0";

/// What the binary should do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    /// Ask the QRTR name service and exit. Sends no QMI request.
    Lookup,
    /// Bring a bearer up, then down again.
    BringUp {
        /// Run the QMI sequence but leave the interface alone.
        dry_run: bool,
    },
    /// Print the usage and exit.
    Help,
}

/// Parsed arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    /// What to do.
    pub mode: Mode,
    /// APN to start the call with; required unless [`Mode::Lookup`] or
    /// [`Mode::Help`].
    pub apn: Option<String>,
    /// Interface to configure.
    pub iface: String,
    /// BAM DMUX TX pipe id.
    pub tx_id: u32,
    /// BAM DMUX RX pipe id.
    pub rx_id: u32,
    /// How long to keep the bearer up once it is configured.
    pub hold: Duration,
}

/// The usage text, printed on `--help` and on a parse error.
pub fn usage() -> &'static str {
    "hyphae-modem — bring up an LTE bearer on a QMI-over-QRTR modem

usage:
  hyphae-modem --apn <apn> [--iface wwan0] [--tx-id 4] [--rx-id 5] [--hold SECS] [--dry-run]
  hyphae-modem --lookup

  --apn <apn>   APN for the SIM in the modem (required unless --lookup)
  --iface       interface to configure (default wwan0)
  --tx-id       BAM DMUX TX pipe from the device tree (default 4)
  --rx-id       BAM DMUX RX pipe from the device tree (default 5)
  --hold SECS   keep the bearer up for SECS after configuring it (default 0)
  --dry-run     run the whole QMI sequence and print what the modem reported,
                then stop the call: the interface is not touched
  --lookup      ask the QRTR name service for the WDS and DPM services and
                exit (read-only: no QMI request is sent)

Requires CAP_NET_ADMIN for anything but --lookup.
"
}

/// Parse the arguments after the program name.
pub fn parse<I>(argv: I) -> Result<Args, String>
where
    I: IntoIterator<Item = String>,
{
    let mut argv = argv.into_iter();
    let mut mode = Mode::BringUp { dry_run: false };
    let mut apn = None;
    let mut iface = DEFAULT_IFACE.to_string();
    let mut tx_id = DEFAULT_TX_ID;
    let mut rx_id = DEFAULT_RX_ID;
    let mut hold = Duration::ZERO;

    while let Some(argument) = argv.next() {
        let (flag, inline) = match argument.split_once('=') {
            Some((flag, value)) => (flag.to_string(), Some(value.to_string())),
            None => (argument, None),
        };
        match flag.as_str() {
            "--apn" => apn = Some(value(inline, &mut argv, "--apn")?),
            "--iface" => iface = value(inline, &mut argv, "--iface")?,
            "--tx-id" => tx_id = number(inline, &mut argv, "--tx-id")?,
            "--rx-id" => rx_id = number(inline, &mut argv, "--rx-id")?,
            "--hold" => hold = Duration::from_secs(u64::from(number(inline, &mut argv, "--hold")?)),
            "--dry-run" => mode = Mode::BringUp { dry_run: true },
            "--lookup" => mode = Mode::Lookup,
            "-h" | "--help" => mode = Mode::Help,
            other => return Err(format!("unknown argument {other}")),
        }
    }

    if matches!(mode, Mode::BringUp { .. }) {
        match apn.as_deref() {
            Some(apn) if !apn.is_empty() => {}
            _ => {
                return Err(
                    "--apn is required: pass the APN the SIM's network expects, e.g. --apn fast.t-mobile.com"
                        .to_string(),
                )
            }
        }
    }

    Ok(Args {
        mode,
        apn,
        iface,
        tx_id,
        rx_id,
        hold,
    })
}

fn value(
    inline: Option<String>,
    argv: &mut impl Iterator<Item = String>,
    flag: &str,
) -> Result<String, String> {
    match inline {
        Some(value) => Ok(value),
        None => argv.next().ok_or_else(|| format!("{flag} needs a value")),
    }
}

fn number(
    inline: Option<String>,
    argv: &mut impl Iterator<Item = String>,
    flag: &str,
) -> Result<u32, String> {
    let raw = value(inline, argv, flag)?;
    raw.parse()
        .map_err(|_| format!("{flag} needs a number, got {raw:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_args(args: &[&str]) -> Result<Args, String> {
        parse(args.iter().map(|arg| arg.to_string()))
    }

    #[test]
    fn defaults_and_the_apn() {
        let args = parse_args(&["--apn", "fast.t-mobile.com"]).unwrap();
        assert_eq!(args.mode, Mode::BringUp { dry_run: false });
        assert_eq!(args.apn.as_deref(), Some("fast.t-mobile.com"));
        assert_eq!(args.iface, DEFAULT_IFACE);
        assert_eq!((args.tx_id, args.rx_id), (DEFAULT_TX_ID, DEFAULT_RX_ID));
        assert_eq!(args.hold, Duration::ZERO);
    }

    #[test]
    fn flag_equals_value_is_accepted() {
        let args = parse_args(&[
            "--apn=fast.t-mobile.com",
            "--iface=wwan1",
            "--tx-id=1",
            "--rx-id=2",
            "--hold=60",
        ])
        .unwrap();
        assert_eq!(args.apn.as_deref(), Some("fast.t-mobile.com"));
        assert_eq!(args.iface, "wwan1");
        assert_eq!((args.tx_id, args.rx_id), (1, 2));
        assert_eq!(args.hold, Duration::from_secs(60));
    }

    #[test]
    fn dry_run_and_hold() {
        let args = parse_args(&["--apn", "x", "--dry-run", "--hold", "5"]).unwrap();
        assert_eq!(args.mode, Mode::BringUp { dry_run: true });
        assert_eq!(args.hold, Duration::from_secs(5));
    }

    #[test]
    fn lookup_needs_no_apn() {
        let args = parse_args(&["--lookup"]).unwrap();
        assert_eq!(args.mode, Mode::Lookup);
        assert_eq!(args.apn, None);
    }

    #[test]
    fn bring_up_requires_an_apn() {
        let error = parse_args(&[]).unwrap_err();
        assert!(error.contains("--apn is required"), "{error}");
        assert!(parse_args(&["--apn", ""]).is_err());
    }

    #[test]
    fn help_wins_over_validation() {
        let args = parse_args(&["--help"]).unwrap();
        assert_eq!(args.mode, Mode::Help);
        assert!(usage().contains("--dry-run"));
    }

    #[test]
    fn bad_arguments_are_named() {
        let cases = [
            (["--nope"].as_slice(), "unknown argument --nope"),
            (["--apn"].as_slice(), "--apn needs a value"),
            (
                ["--apn", "x", "--tx-id"].as_slice(),
                "--tx-id needs a value",
            ),
            (
                ["--apn", "x", "--rx-id", "five"].as_slice(),
                "--rx-id needs a number",
            ),
        ];
        for (argv, expected) in cases {
            let error = parse_args(argv).unwrap_err();
            assert!(error.contains(expected), "{argv:?}: {error}");
        }
    }
}
