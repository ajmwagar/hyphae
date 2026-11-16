//! `hyphae-modem`: bring up an LTE bearer on a QMI-over-QRTR modem.
//!
//! The binary is a shell around the library: [`run`] owns the loop and the
//! printing, `hyphae_modem::cli` owns the arguments. Parsing happens here, not
//! in [`run`], so `--help` and a usage error are answered the same way whatever
//! the platform or feature set — and can be tested on a host with no modem.

use hyphae_modem::cli::{self, Mode};

#[cfg(all(feature = "modem-qmi", target_os = "linux"))]
mod run;

fn main() {
    let args = match cli::parse(std::env::args().skip(1)) {
        Ok(args) => args,
        Err(message) => {
            eprintln!("hyphae-modem: {message}\n\n{}", cli::usage());
            std::process::exit(2);
        }
    };

    if args.mode == Mode::Help {
        print!("{}", cli::usage());
        return;
    }

    #[cfg(all(feature = "modem-qmi", target_os = "linux"))]
    {
        let code = run::main(args);
        // stdout is block-buffered when it is a pipe or a log file, and
        // `process::exit` does not flush it. A run that failed at the last
        // step therefore looked like a run that printed nothing at all.
        let _ = std::io::Write::flush(&mut std::io::stdout());
        std::process::exit(code);
    }

    #[cfg(not(all(feature = "modem-qmi", target_os = "linux")))]
    {
        eprintln!(
            "hyphae-modem has no QMI backend in this build: \
             it needs --features modem-qmi on Linux"
        );
        std::process::exit(2);
    }
}
