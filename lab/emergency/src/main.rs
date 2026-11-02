//! Print what the stand-in E-CSCF would answer, without a socket.
//!
//! Kept deliberately inert: this is a diagnostic for reading the messages, not
//! a server. The other end of an emergency call is a PSAP.

fn main() {
    eprintln!(
        "emergency-lab: stand-in E-CSCF, used by tests and by `cargo test -p emergency-lab`.\n\
         It answers over loopback only; it never originates a request."
    );
    print!("{}", emergency_lab::anonymous_emergency_xml());
}
