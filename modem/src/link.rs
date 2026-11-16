//! The hardware link: [`bearer::Modem`] over a QRTR socket and QMI.
//!
//! One [`QrtrModem`] owns at most two QMI clients:
//!
//! ```text
//!   DPM socket ──▶ Open Port ──▶ (starts the BAM DMUX power-control handshake)
//!   WDS socket ──▶ Bind Mux Data Port ──▶ Start Network ──▶ Get Current Settings
//!                                                                 │
//!                                    Stop Network ◀──────────────┘ (on teardown)
//! ```
//!
//! The WDS socket *is* the client: the modem keys a client on the QRTR port it
//! receives messages from, so as long as this socket lives, the bind stays
//! applied to the client that started the call. [`bearer::Modem::release`]
//! drops it, which is what makes a retry start from a clean client.
//!
//! ## What happens on a modem reset
//!
//! The QRTR ports are re-discovered on every [`bearer::Modem::open_port`]
//! (they can change when the modem restarts), the DPM port is opened again
//! (that is what restarts the BAM DMUX handshake), and a new WDS socket is
//! created. Nothing from the previous generation is reused.
//!
//! ## Node selection
//!
//! The modem's node id is whatever the name service reports for the service —
//! node 0 on the CAT S22. The lookup is the source of truth, so there is no
//! node override in the configuration; a second modem on the same bus would be
//! a different problem (two matching entries).

use std::time::{Duration, Instant};

use crate::bearer;
use crate::dpm;
use crate::qmi::{Client, Transport};
use crate::qrtr::{Addr, Socket};
use crate::wds;
use crate::Error;

/// Timeout for one QMI exchange, or one name-service lookup.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(20);

/// A QMI transport: one bound QRTR socket pointed at one service port.
struct ServiceTransport {
    socket: Socket,
    target: Addr,
}

impl Transport for ServiceTransport {
    fn send(&mut self, frame: &[u8]) -> Result<(), Error> {
        self.socket.send_to(self.target, frame)
    }

    fn recv(&mut self, timeout: Duration) -> Result<Option<Vec<u8>>, Error> {
        let deadline = Instant::now() + timeout;
        let mut buf = [0u8; 4096];
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            let Some((from, len)) = self.socket.recv_from(&mut buf, remaining)? else {
                return Ok(None);
            };
            // A lookup can leave its terminator queued on this socket; only
            // datagrams from the service port are QMI frames.
            if from != self.target {
                continue;
            }
            return Ok(Some(buf[..len].to_vec()));
        }
    }
}

/// Open one service: a fresh socket, a name-service lookup, and a client.
fn connect(service: u16, timeout: Duration) -> Result<Client<ServiceTransport>, Error> {
    let socket = Socket::connect()?;
    let target = socket.lookup(service, timeout)?;
    Ok(Client::new(ServiceTransport { socket, target }, timeout))
}

/// Look a service up on the QRTR name service without sending any QMI.
///
/// This is the read-only path `hyphae-modem --lookup` uses: one lookup packet,
/// no modem state touched.
pub fn lookup_service(service: u16, timeout: Duration) -> Result<Addr, Error> {
    let socket = Socket::connect()?;
    socket.lookup(service, timeout)
}

/// The QRTR/QMI implementation of [`bearer::Modem`].
pub struct QrtrModem {
    port: dpm::PortConfig,
    mux: wds::MuxEndpoint,
    timeout: Duration,
    dpm: Option<Client<ServiceTransport>>,
    wds: Option<Client<ServiceTransport>>,
    handle: Option<u32>,
}

impl QrtrModem {
    /// A modem that opens `port` and binds `mux` before starting a call.
    pub fn new(port: dpm::PortConfig, mux: wds::MuxEndpoint) -> Self {
        Self {
            port,
            mux,
            timeout: DEFAULT_TIMEOUT,
            dpm: None,
            wds: None,
            handle: None,
        }
    }

    /// Override the per-exchange timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// The packet data handle of the call that is up, if any.
    pub fn handle(&self) -> Option<u32> {
        self.handle
    }
}

impl bearer::Modem for QrtrModem {
    fn open_port(&mut self) -> Result<(), Error> {
        // Start from nothing: a previous generation's clients are not reused.
        self.dpm = None;
        self.wds = None;
        self.handle = None;

        let mut dpm = connect(dpm::SERVICE, self.timeout)?;
        dpm.call(dpm::OPEN_PORT, &self.port.open_port_tlvs()?)?;
        self.dpm = Some(dpm);

        self.wds = Some(connect(wds::SERVICE, self.timeout)?);
        Ok(())
    }

    fn bind_mux_data_port(&mut self) -> Result<(), Error> {
        let wds = self.wds.as_mut().ok_or(Error::NoClient)?;
        wds.call(wds::BIND_MUX_DATA_PORT, &self.mux.bind_tlvs())?;
        Ok(())
    }

    fn start_network(&mut self, apn: &str) -> Result<u32, Error> {
        let wds = self.wds.as_mut().ok_or(Error::NoClient)?;
        let response = wds.call(wds::START_NETWORK, &wds::start_network_tlvs(apn)?)?;
        let handle = wds::packet_data_handle(&response)?;
        self.handle = Some(handle);
        Ok(handle)
    }

    fn current_settings(&mut self) -> Result<wds::BearerConfig, Error> {
        let wds = self.wds.as_mut().ok_or(Error::NoClient)?;
        let response = wds.call(wds::GET_CURRENT_SETTINGS, &wds::current_settings_tlvs())?;
        wds::BearerConfig::from_current_settings(&response)
    }

    fn stop_network(&mut self, handle: u32) -> Result<(), Error> {
        let wds = self.wds.as_mut().ok_or(Error::NoClient)?;
        wds.call(wds::STOP_NETWORK, &wds::stop_network_tlvs(handle))?;
        self.handle = None;
        Ok(())
    }

    fn release(&mut self) {
        // Dropping the clients closes their QRTR sockets; the modem forgets
        // the client, and with it the bind.
        self.dpm = None;
        self.wds = None;
        self.handle = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bearer::Modem;

    #[test]
    fn a_released_modem_has_no_clients() {
        // Release is the whole teardown contract; it must be idempotent.
        let mut modem = QrtrModem::new(
            dpm::PortConfig::bam_dmux(4, 5),
            wds::MuxEndpoint::bam_dmux(0),
        );
        assert_eq!(modem.handle(), None);
        modem.release();
        modem.release();
        assert_eq!(
            modem.stop_network(1),
            Err(Error::NoClient),
            "a released modem must not pretend to stop a call"
        );
    }
}
