//! Bearer supervision: one explicit state machine around one data call.
//!
//! ```text
//!   Unbound ──open_port──▶ PortOpen ──bind──▶ Bound ──start + settings──▶ Connected
//!      ▲                                                                     │
//!      │                                          transport loss, modem reset │
//!      │                                                                     ▼
//!      └──────────────── backoff ───────────────────────────────────────── Lost
//! ```
//!
//! The order is not a preference. `WDS Bind Mux Data Port` only applies to the
//! client that sent it, so the bind has to land on the same WDS client that
//! sends `WDS Start Network`; a bind on a different client is answered
//! `INVALID_OPERATION` (70). The supervisor therefore keeps [`Modem`] alive
//! for the whole bearer and only calls [`Modem::release`] when the bearer is
//! being torn down ([`Modem::release`] is what drops the client's socket).
//!
//! ## Why it is shaped like this
//!
//! * The state machine owns *policy*: the sequence, the retry, the backoff.
//! * [`Modem`] owns the QMI conversation and [`NetworkConfig`] owns the
//!   interface; neither knows about the other. The real implementations are
//!   `crate::link` and `crate::netlink`; tests use a scripted modem and a
//!   recording configurator.
//! * Time is an argument ([`Supervisor::step`] takes `now`), so a test can
//!   drive a reset and a retry without sleeping.
//! * Nothing here retries on its own: a step does one transition, and the
//!   caller decides when to step again. That keeps the loop deterministic and
//!   the log readable.
//!
//! ## Loss and teardown
//!
//! The supervisor cannot see a QRTR node disappear — only the transport can.
//! Whoever drives the loop reports it with [`Supervisor::note_loss`], naming
//! the reason; the same path handles a failed step. Teardown stops the call,
//! clears the interface and releases the client, in that order, and is best
//! effort: a modem that has just reset will refuse the stop, and the retry
//! re-establishes everything from `Unbound` anyway. `configure` is idempotent
//! (it flushes addresses first), so a failed `clear` is corrected by the next
//! successful `configure`.

use std::fmt;
use std::time::{Duration, Instant};

use crate::wds::BearerConfig;
use crate::Error;

/// The modem boundary: the QMI conversation, in the order the hardware needs.
pub trait Modem {
    /// Open the data port and (re)create the WDS client.
    ///
    /// On a reset the QRTR ports change, so this is also where the name
    /// service is consulted again. After it returns, the WDS client exists but
    /// is not bound to a mux port.
    fn open_port(&mut self) -> Result<(), Error>;

    /// Bind the mux data port **on the client that will start the call**.
    fn bind_mux_data_port(&mut self) -> Result<(), Error>;

    /// Start the call and return its packet data handle.
    fn start_network(&mut self, apn: &str) -> Result<u32, Error>;

    /// Read back the settings of the call that was just started.
    fn current_settings(&mut self) -> Result<BearerConfig, Error>;

    /// Stop the call. Best effort: the modem may already be gone.
    fn stop_network(&mut self, handle: u32) -> Result<(), Error>;

    /// Drop the WDS client (its QRTR socket). The next `open_port` makes a new
    /// one, which is exactly what the modem requires after a reset.
    fn release(&mut self);
}

/// The interface boundary: apply and remove a bearer's addressing.
pub trait NetworkConfig {
    /// Bring the interface up, flush stale addresses, add the bearer address
    /// and route the default gateway through it.
    ///
    /// Must be idempotent: a retry calls it again with the same or a new
    /// config, and a previous partial `configure` must not accumulate.
    fn configure(&self, config: &BearerConfig) -> Result<(), Error>;

    /// Remove what [`Self::configure`] installed.
    fn clear(&self) -> Result<(), Error>;
}

/// Deterministic exponential backoff between bearer attempts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Backoff {
    base: Duration,
    max: Duration,
    attempt: u32,
}

impl Backoff {
    /// Backoff starting at `base`, doubling, capped at `max`.
    pub fn new(base: Duration, max: Duration) -> Self {
        Self {
            base,
            max,
            attempt: 0,
        }
    }

    /// The next delay, and count the attempt.
    pub fn next_delay(&mut self) -> Duration {
        // 2^16 seconds is already far past any sane cap; clamp the shift so a
        // long outage cannot overflow the multiplication.
        let factor = 1u32 << self.attempt.min(16);
        self.attempt = self.attempt.saturating_add(1);
        self.base.saturating_mul(factor).min(self.max)
    }

    /// Forget the outage: the next failure waits `base` again.
    pub fn reset(&mut self) {
        self.attempt = 0;
    }

    /// How many delays have been handed out since the last reset.
    pub fn attempt(&self) -> u32 {
        self.attempt
    }
}

impl Default for Backoff {
    fn default() -> Self {
        Self::new(Duration::from_secs(1), Duration::from_secs(30))
    }
}

/// Why a bearer is down.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LossReason {
    /// A step was rejected or failed before the call was up.
    Modem(Error),
    /// The call was up but could not be applied to the interface.
    Interface(Error),
    /// The caller saw the QRTR node or the data call go away.
    ModemGone,
    /// The caller asked to stop; no retry follows.
    Shutdown,
}

impl fmt::Display for LossReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LossReason::Modem(error) => {
                write!(f, "{error}")?;
                if is_missing_bind(error) {
                    write!(
                        f,
                        " — WDS Bind Mux Data Port did not reach the client that started the call"
                    )?;
                }
                Ok(())
            }
            LossReason::Interface(error) => write!(f, "interface configuration failed: {error}"),
            LossReason::ModemGone => f.write_str("the modem went away"),
            LossReason::Shutdown => f.write_str("shutdown requested"),
        }
    }
}

/// `INVALID_OPERATION` on `Start Network` is the signature of a lost bind.
fn is_missing_bind(error: &Error) -> bool {
    matches!(
        error,
        Error::Modem { op, error }
            if *op == crate::wds::START_NETWORK && error.is_invalid_operation()
    )
}

/// Where the bearer is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    /// Nothing is open yet.
    Unbound,
    /// The data port is open and the WDS client exists.
    PortOpen,
    /// The WDS client is bound to its mux port: the next step starts the call.
    Bound,
    /// The call is up and the interface carries it.
    Connected(BearerConfig),
    /// Down, waiting for the retry timer.
    Lost(LossReason),
}

impl State {
    /// True while the interface carries a live bearer.
    pub fn is_connected(&self) -> bool {
        matches!(self, State::Connected(_))
    }
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            State::Unbound => f.write_str("unbound"),
            State::PortOpen => f.write_str("data port open"),
            State::Bound => f.write_str("bound to the mux port"),
            State::Connected(config) => write!(f, "connected: {config}"),
            State::Lost(reason) => write!(f, "lost: {reason}"),
        }
    }
}

/// Drives one bearer: the modem, the interface, and the retry policy.
pub struct Supervisor<M: Modem, N: NetworkConfig> {
    modem: M,
    network: N,
    apn: String,
    state: State,
    backoff: Backoff,
    retry_at: Option<Instant>,
    handle: Option<u32>,
    applied: bool,
}

impl<M: Modem, N: NetworkConfig> Supervisor<M, N> {
    /// A supervisor that has not opened anything yet.
    pub fn new(modem: M, network: N, apn: impl Into<String>, backoff: Backoff) -> Self {
        Self {
            modem,
            network,
            apn: apn.into(),
            state: State::Unbound,
            backoff,
            retry_at: None,
            handle: None,
            applied: false,
        }
    }

    /// The current state.
    pub fn state(&self) -> &State {
        &self.state
    }

    /// The modem boundary, for inspection.
    pub fn modem(&self) -> &M {
        &self.modem
    }

    /// The interface boundary, for inspection.
    pub fn network(&self) -> &N {
        &self.network
    }

    /// Advance one transition. `now` only drives the retry timer.
    ///
    /// `Unbound → PortOpen`, `PortOpen → Bound` and `Bound → Connected` each
    /// perform their hardware step immediately; `Connected` is a steady state
    /// and changes only through [`Self::note_loss`]; `Lost` returns to
    /// `Unbound` once the backoff has elapsed.
    pub fn step(&mut self, now: Instant) -> &State {
        match self.state.clone() {
            State::Unbound => match self.modem.open_port() {
                Ok(()) => self.state = State::PortOpen,
                Err(error) => self.lose(LossReason::Modem(error), now),
            },
            State::PortOpen => match self.modem.bind_mux_data_port() {
                Ok(()) => self.state = State::Bound,
                Err(error) => self.lose(LossReason::Modem(error), now),
            },
            State::Bound => match self.start_and_apply() {
                Ok(config) => {
                    self.backoff.reset();
                    self.state = State::Connected(config);
                }
                Err(reason) => self.lose(reason, now),
            },
            State::Connected(_) => {}
            State::Lost(_) => {
                if self.retry_at.is_some_and(|at| now >= at) {
                    self.retry_at = None;
                    self.state = State::Unbound;
                }
            }
        }
        &self.state
    }

    /// Report that the modem or the call went away while connected.
    ///
    /// The transport is the only thing that can notice a QRTR node removal, so
    /// the driver of this loop calls this when a request fails with `ENODEV`,
    /// the node disappears from the bus, or the call is dropped.
    pub fn note_loss(&mut self, reason: LossReason, now: Instant) {
        if matches!(self.state, State::Lost(_)) {
            return;
        }
        self.teardown();
        self.schedule_retry(now);
        self.state = State::Lost(reason);
    }

    /// Stop the bearer and stay down.
    pub fn shutdown(&mut self) {
        self.teardown();
        self.retry_at = None;
        self.backoff.reset();
        self.state = State::Lost(LossReason::Shutdown);
    }

    /// How long until the next attempt, if a retry is scheduled.
    pub fn retry_in(&self, now: Instant) -> Option<Duration> {
        self.retry_at.map(|at| at.saturating_duration_since(now))
    }

    /// Start the call and apply it. Stops the call if either half fails.
    fn start_and_apply(&mut self) -> Result<BearerConfig, LossReason> {
        let handle = match self.modem.start_network(&self.apn) {
            Ok(handle) => handle,
            Err(error) => return Err(LossReason::Modem(error)),
        };
        self.handle = Some(handle);

        let config = match self.modem.current_settings() {
            Ok(config) => config,
            Err(error) => {
                // The call exists but cannot be described: do not leave it up.
                self.stop_call();
                return Err(LossReason::Modem(error));
            }
        };

        match self.network.configure(&config) {
            Ok(()) => {
                self.applied = true;
                Ok(config)
            }
            Err(error) => {
                // `configure` can fail half-way; clear what may be left over.
                let _ = self.network.clear();
                self.stop_call();
                Err(LossReason::Interface(error))
            }
        }
    }

    fn lose(&mut self, reason: LossReason, now: Instant) {
        self.teardown();
        self.schedule_retry(now);
        self.state = State::Lost(reason);
    }

    fn schedule_retry(&mut self, now: Instant) {
        let delay = self.backoff.next_delay();
        self.retry_at = Some(now + delay);
    }

    fn teardown(&mut self) {
        self.stop_call();
        if self.applied {
            // Best effort: the next `configure` flushes whatever survives.
            let _ = self.network.clear();
            self.applied = false;
        }
        self.modem.release();
    }

    fn stop_call(&mut self) {
        if let Some(handle) = self.handle.take() {
            // Best effort: a modem that just reset will refuse this.
            let _ = self.modem.stop_network(handle);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wds;
    use crate::ProtocolError;
    use std::cell::RefCell;
    use std::net::Ipv4Addr;

    const APN: &str = "fast.t-mobile.com";

    fn config() -> BearerConfig {
        BearerConfig {
            address: Ipv4Addr::new(192, 0, 0, 2),
            gateway: Ipv4Addr::new(192, 0, 0, 1),
            dns: [Some(Ipv4Addr::new(192, 0, 0, 1)), None],
            mtu: 1472,
        }
    }

    /// One recorded call on the modem boundary, in order.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Call {
        OpenPort,
        Bind,
        Start,
        Settings,
        Stop,
        Release,
    }

    /// A modem that behaves like the hardware does: a bind only counts for the
    /// client that sent it, and a new client starts unbound.
    #[derive(Default)]
    struct MockModem {
        generation: u32,
        bound: Option<u32>,
        skip_bind: bool,
        settings_error: Option<Error>,
        handle: u32,
        calls: Vec<Call>,
    }

    impl Modem for MockModem {
        fn open_port(&mut self) -> Result<(), Error> {
            self.calls.push(Call::OpenPort);
            self.generation += 1;
            self.bound = None;
            Ok(())
        }

        fn bind_mux_data_port(&mut self) -> Result<(), Error> {
            self.calls.push(Call::Bind);
            if !self.skip_bind {
                self.bound = Some(self.generation);
            }
            Ok(())
        }

        fn start_network(&mut self, apn: &str) -> Result<u32, Error> {
            self.calls.push(Call::Start);
            assert_eq!(apn, APN, "the supervisor must use the configured APN");
            if self.bound != Some(self.generation) {
                return Err(Error::Modem {
                    op: wds::START_NETWORK,
                    error: ProtocolError::INVALID_OPERATION,
                });
            }
            self.handle += 1;
            Ok(self.handle)
        }

        fn current_settings(&mut self) -> Result<BearerConfig, Error> {
            self.calls.push(Call::Settings);
            match &self.settings_error {
                Some(error) => Err(error.clone()),
                None => Ok(config()),
            }
        }

        fn stop_network(&mut self, handle: u32) -> Result<(), Error> {
            self.calls.push(Call::Stop);
            assert_eq!(handle, self.handle);
            Ok(())
        }

        fn release(&mut self) {
            self.calls.push(Call::Release);
            self.bound = None;
        }
    }

    /// A configurator that records what it was asked to do.
    #[derive(Default)]
    struct Recorder {
        state: RefCell<Recorded>,
    }

    #[derive(Default)]
    struct Recorded {
        configured: Vec<BearerConfig>,
        cleared: usize,
        fail: bool,
    }

    impl NetworkConfig for Recorder {
        fn configure(&self, config: &BearerConfig) -> Result<(), Error> {
            let mut state = self.state.borrow_mut();
            if state.fail {
                return Err(Error::Netlink {
                    op: "RTM_NEWROUTE",
                    errno: 22,
                });
            }
            state.configured.push(*config);
            Ok(())
        }

        fn clear(&self) -> Result<(), Error> {
            self.state.borrow_mut().cleared += 1;
            Ok(())
        }
    }

    fn supervisor(modem: MockModem, network: Recorder) -> Supervisor<MockModem, Recorder> {
        Supervisor::new(
            modem,
            network,
            APN,
            Backoff::new(Duration::from_secs(1), Duration::from_secs(8)),
        )
    }

    /// Step until `Connected`, returning the instant the loop started.
    fn connect(supervisor: &mut Supervisor<MockModem, Recorder>, now: Instant) {
        for _ in 0..4 {
            supervisor.step(now);
        }
    }

    #[test]
    fn happy_path_connects_with_the_modems_settings() {
        let mut sup = supervisor(MockModem::default(), Recorder::default());
        let now = Instant::now();

        assert_eq!(sup.state(), &State::Unbound);
        assert_eq!(sup.step(now), &State::PortOpen);
        assert_eq!(sup.step(now), &State::Bound);
        assert_eq!(sup.step(now), &State::Connected(config()));

        // Bind before start, on the same client: this order is the reason the
        // crate exists.
        assert_eq!(
            sup.modem().calls,
            vec![Call::OpenPort, Call::Bind, Call::Start, Call::Settings]
        );
        assert_eq!(sup.network().state.borrow().configured, vec![config()]);

        // Connected is a steady state.
        assert_eq!(sup.step(now), &State::Connected(config()));
        assert!(sup.state().is_connected());
    }

    #[test]
    fn a_client_that_starts_without_a_bind_is_rejected() {
        // The mock reproduces the hardware's rule, which is what makes the
        // next test meaningful.
        let mut modem = MockModem::default();
        modem.open_port().unwrap();
        assert_eq!(
            modem.start_network(APN),
            Err(Error::Modem {
                op: wds::START_NETWORK,
                error: ProtocolError::INVALID_OPERATION,
            })
        );
    }

    #[test]
    fn invalid_operation_on_start_surfaces_as_a_clear_error() {
        // A modem boundary that lost the bind: the modem answers the start with
        // INVALID_OPERATION, exactly as it did when qmicli split the two
        // requests across invocations.
        let modem = MockModem {
            skip_bind: true,
            ..MockModem::default()
        };
        let mut sup = supervisor(modem, Recorder::default());
        let now = Instant::now();

        sup.step(now); // Unbound -> PortOpen
        sup.step(now); // PortOpen -> Bound
        let state = sup.step(now).clone(); // start is rejected

        let State::Lost(reason) = &state else {
            panic!("expected a loss, got {state:?}");
        };
        assert_eq!(
            reason,
            &LossReason::Modem(Error::Modem {
                op: wds::START_NETWORK,
                error: ProtocolError::INVALID_OPERATION,
            })
        );
        let message = reason.to_string();
        assert!(message.contains("WDS Start Network"), "{message}");
        assert!(message.contains("INVALID_OPERATION"), "{message}");
        assert!(message.contains("Bind Mux Data Port"), "{message}");

        // Nothing was applied and nothing was left running.
        assert!(sup.network().state.borrow().configured.is_empty());
        assert_eq!(sup.network().state.borrow().cleared, 0);
        assert!(!sup.modem().calls.contains(&Call::Stop));

        // The retry is scheduled, and it is a full retry, not a resumed one.
        assert_eq!(sup.retry_in(now), Some(Duration::from_secs(1)));
        assert_eq!(
            sup.step(now + Duration::from_millis(999)),
            &state,
            "the retry must wait for the backoff"
        );
        assert_eq!(sup.step(now + Duration::from_secs(1)), &State::Unbound);
    }

    #[test]
    fn modem_reset_tears_down_and_brings_a_new_client_up() {
        let mut sup = supervisor(MockModem::default(), Recorder::default());
        let now = Instant::now();
        connect(&mut sup, now);
        assert!(sup.state().is_connected());
        let before = sup.modem().calls.len();

        sup.note_loss(LossReason::ModemGone, now);

        // The call was stopped, the interface cleared, the client released —
        // in that order.
        assert_eq!(
            sup.modem().calls[before..].to_vec(),
            vec![Call::Stop, Call::Release],
            "a loss must tear the call down before retrying"
        );
        assert_eq!(sup.network().state.borrow().cleared, 1);
        assert_eq!(sup.state(), &State::Lost(LossReason::ModemGone));
        assert_eq!(sup.retry_in(now), Some(Duration::from_secs(1)));

        // After the backoff the whole sequence runs again on a fresh client,
        // and that includes the bind.
        let later = now + Duration::from_secs(1);
        assert_eq!(sup.step(later), &State::Unbound);
        assert_eq!(sup.step(later), &State::PortOpen);
        assert_eq!(sup.step(later), &State::Bound);
        assert_eq!(sup.step(later), &State::Connected(config()));
        assert_eq!(
            sup.modem().calls[before..].to_vec(),
            vec![
                Call::Stop,
                Call::Release,
                Call::OpenPort,
                Call::Bind,
                Call::Start,
                Call::Settings
            ]
        );
        assert_eq!(sup.network().state.borrow().configured.len(), 2);
    }

    #[test]
    fn a_failed_interface_configure_is_reported_and_undone() {
        let network = Recorder::default();
        network.state.borrow_mut().fail = true;
        let mut sup = supervisor(MockModem::default(), network);
        let now = Instant::now();

        sup.step(now);
        sup.step(now);
        let state = sup.step(now).clone();

        let State::Lost(LossReason::Interface(error)) = &state else {
            panic!("expected an interface loss, got {state:?}");
        };
        assert!(matches!(
            error,
            Error::Netlink {
                op: "RTM_NEWROUTE",
                ..
            }
        ));
        assert!(sup.network().state.borrow().configured.is_empty());
        assert_eq!(
            sup.network().state.borrow().cleared,
            1,
            "a half-applied config must be cleared"
        );
        assert_eq!(
            sup.modem().calls,
            vec![
                Call::OpenPort,
                Call::Bind,
                Call::Start,
                Call::Settings,
                Call::Stop,
                Call::Release
            ],
            "the call must be stopped and the client released"
        );
    }

    #[test]
    fn a_settings_failure_stops_the_call() {
        let modem = MockModem {
            settings_error: Some(Error::Timeout {
                op: wds::GET_CURRENT_SETTINGS,
            }),
            ..MockModem::default()
        };
        let mut sup = supervisor(modem, Recorder::default());
        let now = Instant::now();

        sup.step(now);
        sup.step(now);
        let state = sup.step(now).clone();
        assert_eq!(
            state,
            State::Lost(LossReason::Modem(Error::Timeout {
                op: wds::GET_CURRENT_SETTINGS
            }))
        );
        assert_eq!(
            sup.modem().calls,
            vec![
                Call::OpenPort,
                Call::Bind,
                Call::Start,
                Call::Settings,
                Call::Stop,
                Call::Release
            ]
        );
        assert!(sup.network().state.borrow().configured.is_empty());
    }

    #[test]
    fn shutdown_tears_down_once_and_never_retries() {
        let mut sup = supervisor(MockModem::default(), Recorder::default());
        let now = Instant::now();
        connect(&mut sup, now);

        sup.shutdown();
        assert_eq!(sup.state(), &State::Lost(LossReason::Shutdown));
        assert_eq!(sup.retry_in(now), None);
        assert!(sup.modem().calls.contains(&Call::Stop));
        assert!(sup.modem().calls.contains(&Call::Release));
        assert_eq!(sup.network().state.borrow().cleared, 1);

        // A lost bearer with no retry stays lost, even long after.
        assert_eq!(
            sup.step(now + Duration::from_secs(3600)),
            &State::Lost(LossReason::Shutdown)
        );
    }

    #[test]
    fn backoff_doubles_and_caps() {
        let mut backoff = Backoff::new(Duration::from_secs(1), Duration::from_secs(5));
        let delays: Vec<u64> = (0..5).map(|_| backoff.next_delay().as_secs()).collect();
        assert_eq!(delays, vec![1, 2, 4, 5, 5]);
        assert_eq!(backoff.attempt(), 5);

        // Success resets the ladder.
        backoff.reset();
        assert_eq!(backoff.next_delay(), Duration::from_secs(1));
    }

    #[test]
    fn repeated_loss_reports_do_not_reschedule() {
        let mut sup = supervisor(MockModem::default(), Recorder::default());
        let now = Instant::now();
        connect(&mut sup, now);

        sup.note_loss(LossReason::ModemGone, now);
        let after_first = sup.modem().calls.len();
        sup.note_loss(LossReason::ModemGone, now + Duration::from_millis(10));
        assert_eq!(
            sup.modem().calls.len(),
            after_first,
            "a second loss report must not tear down again"
        );
        assert_eq!(sup.retry_in(now), Some(Duration::from_secs(1)));
    }
}
