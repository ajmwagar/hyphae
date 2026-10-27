//! RFC 3261 §17 transaction state machines, without timers or sockets.
//!
//! The caller owns the clock and the wire. Feeding a parsed response (client)
//! or request (server) advances the state and tells the caller which side
//! effect is owed. Retransmission is expressed as a [`Timer`] event.

use crate::Message;

/// RFC 3261 §17.1.1.1 default retransmission interval T1 = 500 ms.
pub const T1_MS: u64 = 500;
/// §17.1.1.1 Timer B / Timer F = 64*T1.
pub const TIMER_B_MS: u64 = 64 * T1_MS;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Timer {
    /// INVITE retransmit (UDP), §17.1.1.2.
    A,
    /// INVITE transaction timeout, §17.1.1.2.
    B,
    /// non-INVITE retransmit (UDP), §17.1.2.2.
    E,
    /// non-INVITE transaction timeout, §17.1.2.2.
    F,
    /// Completed-state keepalive, §17.1.2.2.
    K,
}

impl Timer {
    pub fn millis(self) -> u64 {
        match self {
            Timer::A | Timer::E => T1_MS,
            Timer::B | Timer::F => TIMER_B_MS,
            Timer::K => 5_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TransactionKey {
    pub branch: String,
    pub method: crate::Method,
    /// Via sent-by, so two dialogs on one branch namespace stay distinct.
    pub sent_by: String,
}

impl std::fmt::Display for TransactionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {} {}", self.branch, self.method, self.sent_by)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientTransactionState {
    Calling,
    Proceeding,
    Completed,
    Terminated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientEvent {
    /// Send/retransmit the request.
    SendRequest,
    /// A provisional response arrived.
    Provisional(u16),
    /// A final response arrived; ACK is owed for a non-2xx INVITE.
    Final(u16),
    /// Transaction consumed without further wire action (e.g. 2xx INVITE ACKed
    /// by the dialog, or Timer K expiry).
    Done,
    /// No response before Timer B/F; retransmissions stop.
    Timeout(Timer),
}

#[derive(Debug, Clone)]
pub struct ClientTransaction {
    pub key: TransactionKey,
    pub state: ClientTransactionState,
    /// Whether the request was sent over an unreliable transport.
    pub unreliable: bool,
    pub retransmits: u32,
    pub last_status: Option<u16>,
}

impl ClientTransaction {
    pub fn new(key: TransactionKey, unreliable: bool) -> Self {
        Self {
            key,
            state: ClientTransactionState::Calling,
            unreliable,
            retransmits: 0,
            last_status: None,
        }
    }

    pub fn on_response(&mut self, status: u16) -> ClientEvent {
        self.last_status = Some(status);
        match self.state {
            ClientTransactionState::Terminated => ClientEvent::Done,
            _ if (100..200).contains(&status) => {
                self.state = ClientTransactionState::Proceeding;
                ClientEvent::Provisional(status)
            }
            _ => {
                self.state = ClientTransactionState::Completed;
                ClientEvent::Final(status)
            }
        }
    }

    /// Called after the final response has been acted on (ACK sent / dialog owns it).
    pub fn complete(&mut self) -> ClientEvent {
        self.state = ClientTransactionState::Terminated;
        ClientEvent::Done
    }

    /// Fire the appropriate retransmission or timeout timer.
    pub fn on_timeout(&mut self, timer: Timer) -> ClientEvent {
        match timer {
            Timer::A | Timer::E => {
                if self.unreliable && self.state == ClientTransactionState::Calling {
                    self.retransmits += 1;
                    ClientEvent::SendRequest
                } else {
                    ClientEvent::Done
                }
            }
            Timer::B | Timer::F => {
                self.state = ClientTransactionState::Terminated;
                ClientEvent::Timeout(timer)
            }
            Timer::K => {
                self.state = ClientTransactionState::Terminated;
                ClientEvent::Done
            }
        }
    }

    pub fn timer_for_method(&self) -> Timer {
        if self.key.method == crate::Method::Invite {
            if self.state == ClientTransactionState::Completed {
                Timer::B
            } else {
                Timer::A
            }
        } else if self.state == ClientTransactionState::Completed {
            Timer::K
        } else {
            Timer::E
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerTransactionState {
    Trying,
    Proceeding,
    Completed,
    Confirmed,
    Terminated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerEvent {
    /// Send a provisional response.
    SendProvisional(u16),
    /// Send the final response, then retransmit until ACK (INVITE) / Timer J.
    SendFinal(u16),
    /// A retransmission of the original request arrived; replay last response.
    Retransmit,
    /// Transaction done; drop state.
    Done,
}

#[derive(Debug, Clone)]
pub struct ServerTransaction {
    pub state: ServerTransactionState,
    pub last_response: Option<Vec<u8>>,
}

impl ServerTransaction {
    pub fn new() -> Self {
        Self {
            state: ServerTransactionState::Trying,
            last_response: None,
        }
    }

    pub fn on_request(&mut self, retransmission: bool) -> ServerEvent {
        if retransmission {
            return if let Some(bytes) = &self.last_response {
                let _ = bytes;
                ServerEvent::Retransmit
            } else {
                ServerEvent::Done
            };
        }
        ServerEvent::SendProvisional(100)
    }

    pub fn on_provisional(&mut self, status: u16) -> ServerEvent {
        self.state = ServerTransactionState::Proceeding;
        ServerEvent::SendProvisional(status)
    }

    pub fn on_final(&mut self, status: u16, bytes: Vec<u8>, is_invite: bool) -> ServerEvent {
        self.state = if is_invite && !(200..300).contains(&status) {
            ServerTransactionState::Completed
        } else {
            ServerTransactionState::Terminated
        };
        self.last_response = Some(bytes);
        ServerEvent::SendFinal(status)
    }

    pub fn on_ack(&mut self) -> ServerEvent {
        if self.state == ServerTransactionState::Completed {
            self.state = ServerTransactionState::Confirmed;
            ServerEvent::Done
        } else {
            ServerEvent::Done
        }
    }
}

impl Default for ServerTransaction {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience for matching an incoming message to a transaction.
pub fn key_from_message(msg: &Message) -> Option<TransactionKey> {
    let headers = msg.headers();
    let via = headers.via()?;
    let method = match msg {
        Message::Request(r) => r.method.clone(),
        Message::Response(_) => headers.cseq()?.method,
    };
    Some(TransactionKey {
        branch: via.branch()?.to_string(),
        method,
        sent_by: via.sent_by,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Method;

    fn key(method: Method) -> TransactionKey {
        TransactionKey {
            branch: "z9hG4bK-1".into(),
            method,
            sent_by: "192.0.2.10:5060".into(),
        }
    }

    #[test]
    fn invite_client_hits_proceeding_then_completed() {
        let mut tx = ClientTransaction::new(key(Method::Invite), true);
        assert_eq!(tx.on_response(180), ClientEvent::Provisional(180));
        assert_eq!(tx.state, ClientTransactionState::Proceeding);
        assert_eq!(tx.on_response(486), ClientEvent::Final(486));
        assert_eq!(tx.state, ClientTransactionState::Completed);
        assert_eq!(tx.complete(), ClientEvent::Done);
    }

    #[test]
    fn unreliable_calling_retransmits_only_while_calling() {
        let mut tx = ClientTransaction::new(key(Method::Register), true);
        assert_eq!(tx.on_timeout(Timer::E), ClientEvent::SendRequest);
        assert_eq!(tx.retransmits, 1);
        tx.on_response(401);
        assert_eq!(tx.on_timeout(Timer::E), ClientEvent::Done);
    }

    #[test]
    fn timer_b_terminates() {
        let mut tx = ClientTransaction::new(key(Method::Invite), true);
        assert_eq!(tx.on_timeout(Timer::B), ClientEvent::Timeout(Timer::B));
        assert_eq!(tx.state, ClientTransactionState::Terminated);
    }

    #[test]
    fn server_replays_final_on_request_retransmission() {
        let mut tx = ServerTransaction::new();
        assert_eq!(tx.on_request(false), ServerEvent::SendProvisional(100));
        assert_eq!(
            tx.on_final(486, b"response".to_vec(), true),
            ServerEvent::SendFinal(486)
        );
        assert_eq!(tx.on_request(true), ServerEvent::Retransmit);
        assert_eq!(tx.on_ack(), ServerEvent::Done);
    }
}
