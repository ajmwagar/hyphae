//! `hyphae-modem`: bring up an LTE bearer on a QMI-over-QRTR modem.
//!
//! The binary is a shell around the library: [`run`] owns the loop and the
//! printing, `hyphae_modem::cli` owns the arguments.

#[cfg(all(feature = "modem-qmi", target_os = "linux"))]
mod run;

fn main() {
    #[cfg(all(feature = "modem-qmi", target_os = "linux"))]
    std::process::exit(run::main());

    #[cfg(not(all(feature = "modem-qmi", target_os = "linux")))]
    {
        eprintln!(
            "hyphae-modem has no QMI backend in this build: \
             it needs --features modem-qmi on Linux"
        );
        std::process::exit(2);
    }
}
