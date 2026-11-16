//! The binary's runner: argument dispatch and the loop that drives the bearer
//! supervisor.
//!
//! Everything interesting lives in the library; this file is the policy of a
//! command-line tool — how long to wait, how many attempts before giving up,
//! and what to print.

use std::time::{Duration, Instant};

use hyphae_modem::bearer::{self, Backoff, LossReason, State, Supervisor};
use hyphae_modem::cli::{Args, Mode};
use hyphae_modem::wds::{self, BearerConfig};
use hyphae_modem::{dpm, link, netlink, Error};

/// How many failed attempts a one-shot run tolerates before giving up.
///
/// The supervisor retries forever; a tool a human runs should not.
const MAX_ATTEMPTS: u32 = 3;

/// Run the requested mode; returns the process exit code.
///
/// `--help` and usage errors were already handled where the arguments were
/// parsed.
pub fn main(args: Args) -> i32 {
    match &args.mode {
        Mode::Lookup => lookup(),
        Mode::BringUp { dry_run } => bring_up(&args, *dry_run),
        Mode::Help => 0,
    }
}

/// Name-service lookup only: one packet per service, no modem state touched.
fn lookup() -> i32 {
    let mut ok = true;
    for (name, service) in [("WDS", wds::SERVICE), ("DPM", dpm::SERVICE)] {
        match link::lookup_service(service, link::DEFAULT_TIMEOUT) {
            Ok(addr) => println!("{name}: service {service} at QRTR {addr}"),
            Err(error) => {
                eprintln!("{name}: {error}");
                ok = false;
            }
        }
    }
    i32::from(!ok)
}

fn bring_up(args: &Args, dry_run: bool) -> i32 {
    let Some(apn) = args.apn.clone() else {
        eprintln!("hyphae-modem: --apn is required");
        return 2;
    };
    let modem = link::QrtrModem::new(
        dpm::PortConfig::bam_dmux(args.tx_id, args.rx_id),
        wds::MuxEndpoint::bam_dmux(0),
    );

    if dry_run {
        let mut supervisor = Supervisor::new(modem, DryRun, apn, Backoff::default());
        return drive(&mut supervisor, args);
    }

    let interface = match netlink::Interface::new(&args.iface) {
        Ok(interface) => interface,
        Err(error) => {
            eprintln!("{}: {error}", args.iface);
            return 1;
        }
    };
    let mut supervisor = Supervisor::new(modem, interface, apn, Backoff::default());
    drive(&mut supervisor, args)
}

/// Step the supervisor, print every transition, hold, then tear down.
fn drive<N: bearer::NetworkConfig>(
    supervisor: &mut Supervisor<link::QrtrModem, N>,
    args: &Args,
) -> i32 {
    let mut last: Option<State> = None;
    let mut connected_at: Option<Instant> = None;
    let mut attempts = 0u32;

    loop {
        let state = supervisor.step(Instant::now()).clone();
        // A state that has not changed is not new information: only print and
        // count attempts on a transition.
        let entered = last.as_ref() != Some(&state);
        if entered {
            println!("{state}");
            last = Some(state.clone());
        }

        match &state {
            State::Connected(_) => {
                // The hold window starts at each successful bring-up, so a
                // bearer that was re-established still gets its full window.
                if entered {
                    connected_at = Some(Instant::now());
                }
                let since = connected_at.unwrap_or_else(Instant::now);
                if since.elapsed() >= args.hold {
                    break;
                }
                std::thread::sleep(Duration::from_millis(250));
            }
            State::Lost(LossReason::Shutdown) => return 0,
            State::Lost(_) => {
                if entered {
                    attempts += 1;
                    if attempts >= MAX_ATTEMPTS {
                        eprintln!("hyphae-modem: giving up after {attempts} attempts");
                        return 1;
                    }
                }
                let wait = supervisor
                    .retry_in(Instant::now())
                    .unwrap_or(Duration::from_secs(1));
                std::thread::sleep(wait.max(Duration::from_millis(50)));
            }
            State::Unbound | State::PortOpen | State::Bound => {}
        }
    }

    supervisor.shutdown();
    println!("{}", supervisor.state());
    0
}

/// A configurator that only prints: `--dry-run` runs the real QMI sequence but
/// leaves the interface alone.
struct DryRun;

impl bearer::NetworkConfig for DryRun {
    fn configure(&self, config: &BearerConfig) -> Result<(), Error> {
        println!("dry run: would configure the interface with {config}");
        Ok(())
    }

    fn clear(&self) -> Result<(), Error> {
        println!("dry run: would clear the interface");
        Ok(())
    }
}
