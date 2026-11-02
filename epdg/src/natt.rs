//! NAT traversal for IKEv2 (RFC 7296 §2.23, RFC 3948).
//!
//! Most Wi-Fi calling happens behind a home router, so the tunnel has to work
//! through NAT or it does not work at all. Two independent mechanisms:
//!
//! * **Detection.** Both sides put `NAT_DETECTION_SOURCE_IP` and
//!   `NAT_DETECTION_DESTINATION_IP` notifies in IKE_SA_INIT. Each carries a
//!   SHA-1 digest of `SPIi | SPIr | IP | port` (RFC 7296 §2.23). If the peer's
//!   source hash does not match the address we actually see, there is a NAT on
//!   the path; if its destination hash does not match our own address, we are
//!   behind one.
//! * **Encapsulation.** Once port 4500 is in use, IKE messages are prefixed
//!   with a 4-octet non-ESP marker of zeros so they can be told apart from ESP
//!   (RFC 3948 §2.2), and an idle peer sends a single `0xFF` octet to keep the
//!   mapping alive (RFC 3948 §2.3).
//!
//! The notify numbers are from the IANA IKEv2 registry, not from the RFC text.

#![forbid(unsafe_code)]

/// `NAT_DETECTION_SOURCE_IP` (IANA IKEv2 notify registry).
pub const NAT_DETECTION_SOURCE_IP: u16 = 16388;
/// `NAT_DETECTION_DESTINATION_IP` (IANA IKEv2 notify registry).
pub const NAT_DETECTION_DESTINATION_IP: u16 = 16389;

/// The 4-octet marker that separates IKE from ESP on port 4500
/// (RFC 3948 §2.2).
pub const NON_ESP_MARKER: [u8; 4] = [0x00, 0x00, 0x00, 0x00];

/// The one-octet NAT-keepalive payload (RFC 3948 §2.3).
pub const NAT_KEEPALIVE: [u8; 1] = [0xFF];

/// Default idle interval before a keepalive is sent (RFC 3948 §4, `M`).
pub const NAT_KEEPALIVE_IDLE_SECS: u64 = 20;
/// Default period after the last SA for which keepalives may still be sent
/// (RFC 3948 §4, `N`).
pub const NAT_KEEPALIVE_LINGER_SECS: u64 = 300;

/// The digest a nat-detection notify carries (RFC 7296 §2.23).
///
/// `address` is the raw address octets — 4 for IPv4, 16 for IPv6 — and `port`
/// is the UDP port, big-endian. The SPIs are in wire order.
pub fn nat_detection_hash(spi_i: [u8; 8], spi_r: [u8; 8], address: &[u8], port: u16) -> [u8; 20] {
    use sha1::Digest;
    let mut hasher = sha1::Sha1::new();
    hasher.update(spi_i);
    hasher.update(spi_r);
    hasher.update(address);
    hasher.update(port.to_be_bytes());
    hasher.finalize().into()
}

/// One end of the UDP path, as the NAT-detection digest needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    /// Raw address octets: 4 for IPv4, 16 for IPv6.
    pub address: Vec<u8>,
    pub port: u16,
}

impl Endpoint {
    /// An IPv4 endpoint.
    pub fn v4(address: [u8; 4], port: u16) -> Self {
        Self {
            address: address.to_vec(),
            port,
        }
    }

    /// An endpoint from raw address octets.
    pub fn new(address: impl Into<Vec<u8>>, port: u16) -> Self {
        Self {
            address: address.into(),
            port,
        }
    }

    /// Address and port as the digest functions want them.
    pub fn parts(&self) -> (&[u8], u16) {
        (&self.address, self.port)
    }
}

/// What the detection notifies say about the path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NatVerdict {
    /// The peer's source hash did not match the address we see it coming from:
    /// there is a NAT between us.
    pub peer_behind_nat: bool,
    /// The peer's destination hash did not match our own address: we are
    /// behind a NAT.
    pub we_are_behind_nat: bool,
}

impl NatVerdict {
    /// Whether the tunnel must be encapsulated on port 4500.
    ///
    /// Either side being behind a NAT is enough: the probe only works if both
    /// ends speak UDP-ESP.
    pub fn needs_encapsulation(&self) -> bool {
        self.peer_behind_nat || self.we_are_behind_nat
    }

    /// Whether *we* must send NAT keepalives (RFC 7296 §2.23: the side that
    /// sees a mismatching destination hash keeps the mapping alive).
    pub fn needs_keepalive(&self) -> bool {
        self.we_are_behind_nat
    }
}

/// One side's view of a NAT-detection exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NatDetector {
    spi_i: [u8; 8],
    spi_r: [u8; 8],
}

impl NatDetector {
    /// Bind the detector to one IKE SA.
    pub fn new(spi_i: [u8; 8], spi_r: [u8; 8]) -> Self {
        Self { spi_i, spi_r }
    }

    /// The hash we put in `NAT_DETECTION_SOURCE_IP`: our address and port as we
    /// believe the peer will see them.
    pub fn source_hash(&self, address: &[u8], port: u16) -> [u8; 20] {
        nat_detection_hash(self.spi_i, self.spi_r, address, port)
    }

    /// The hash we put in `NAT_DETECTION_DESTINATION_IP`: the peer's address and
    /// port as we believe them to be.
    pub fn destination_hash(&self, address: &[u8], port: u16) -> [u8; 20] {
        nat_detection_hash(self.spi_i, self.spi_r, address, port)
    }

    /// Compare the peer's notifies with what we actually observe.
    ///
    /// `observed_peer` is the address/port the peer's packet really came from;
    /// `local` is our own address/port as we know it. A peer may send several
    /// source hashes when it has several attachments (RFC 7296 §2.23), so all
    /// of them are accepted.
    pub fn evaluate(
        &self,
        peer_source_hashes: &[[u8; 20]],
        peer_destination_hash: Option<&[u8; 20]>,
        observed_peer: (&[u8], u16),
        local: (&[u8], u16),
    ) -> NatVerdict {
        let expected_source = self.source_hash(observed_peer.0, observed_peer.1);
        let peer_behind_nat =
            !peer_source_hashes.is_empty() && !peer_source_hashes.contains(&expected_source);

        let expected_destination = self.destination_hash(local.0, local.1);
        let we_are_behind_nat = peer_destination_hash
            .map(|hash| hash != &expected_destination)
            .unwrap_or(false);

        NatVerdict {
            peer_behind_nat,
            we_are_behind_nat,
        }
    }
}

/// The two notifies a side puts in IKE_SA_INIT (RFC 7296 §2.23).
///
/// `local` is our own address and port, `peer` the peer's. The responder SPI is
/// zero in the request, which is what both sides hash at that point.
pub fn nat_detection_notifies(
    spi_i: [u8; 8],
    spi_r: [u8; 8],
    local: (&[u8], u16),
    peer: (&[u8], u16),
) -> [crate::ikev2::Notify; 2] {
    let source = nat_detection_hash(spi_i, spi_r, local.0, local.1);
    let destination = nat_detection_hash(spi_i, spi_r, peer.0, peer.1);
    [
        crate::ikev2::Notify {
            protocol_id: 0,
            notify_type: NAT_DETECTION_SOURCE_IP,
            spi: Vec::new(),
            data: source.to_vec(),
        },
        crate::ikev2::Notify {
            protocol_id: 0,
            notify_type: NAT_DETECTION_DESTINATION_IP,
            spi: Vec::new(),
            data: destination.to_vec(),
        },
    ]
}

/// Prefix an IKE message with the non-ESP marker for port 4500.
pub fn encapsulate(message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(NON_ESP_MARKER.len() + message.len());
    out.extend_from_slice(&NON_ESP_MARKER);
    out.extend_from_slice(message);
    out
}

/// Strip the non-ESP marker from a port-4500 datagram.
///
/// Returns `None` when the datagram does not start with the marker — that is,
/// when it is ESP or a keepalive, not IKE.
pub fn decapsulate(packet: &[u8]) -> Option<&[u8]> {
    if packet.len() > NON_ESP_MARKER.len() && packet.starts_with(&NON_ESP_MARKER) {
        Some(&packet[NON_ESP_MARKER.len()..])
    } else {
        None
    }
}

/// Whether a datagram is a NAT keepalive.
pub fn is_nat_keepalive(packet: &[u8]) -> bool {
    packet == NAT_KEEPALIVE
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPI_I: [u8; 8] = [0x11; 8];
    const SPI_R: [u8; 8] = [0x22; 8];

    #[test]
    fn the_digest_matches_an_independent_computation() {
        // SHA-1 over 11*8 | 22*8 | c0 00 02 01 (192.0.2.1) | 01 f4 (port 500),
        // computed with OpenSSL rather than by this code.
        let hash = nat_detection_hash(SPI_I, SPI_R, &[192, 0, 2, 1], 500);
        assert_eq!(
            hash,
            [
                0xd5, 0x63, 0xe5, 0x8a, 0x48, 0x04, 0x0d, 0x97, 0x9c, 0xa9, 0x0e, 0x6e, 0xc0, 0x5d,
                0x12, 0x6b, 0x22, 0x9f, 0x8b, 0xc1
            ]
        );
    }

    #[test]
    fn the_digest_covers_spis_address_and_port() {
        let base = nat_detection_hash(SPI_I, SPI_R, &[192, 0, 2, 1], 500);
        assert_ne!(
            base,
            nat_detection_hash([0x12; 8], SPI_R, &[192, 0, 2, 1], 500)
        );
        assert_ne!(
            base,
            nat_detection_hash(SPI_I, [0x23; 8], &[192, 0, 2, 1], 500)
        );
        assert_ne!(base, nat_detection_hash(SPI_I, SPI_R, &[192, 0, 2, 2], 500));
        assert_ne!(base, nat_detection_hash(SPI_I, SPI_R, &[192, 0, 2, 1], 501));
    }

    #[test]
    fn no_nat_when_both_hashes_match() {
        let detector = NatDetector::new(SPI_I, SPI_R);
        let peer: (&[u8], u16) = (&[192, 0, 2, 1], 500);
        let local: (&[u8], u16) = (&[192, 0, 2, 10], 500);

        // The peer says "my source is peer" and "your address is local"; we
        // agree on both, so there is no NAT anywhere.
        let peer_source = detector.source_hash(peer.0, peer.1);
        let peer_destination = detector.source_hash(local.0, local.1);
        let verdict = detector.evaluate(&[peer_source], Some(&peer_destination), peer, local);
        assert_eq!(
            verdict,
            NatVerdict {
                peer_behind_nat: false,
                we_are_behind_nat: false
            }
        );
        assert!(!verdict.needs_encapsulation());
        assert!(!verdict.needs_keepalive());
    }

    #[test]
    fn a_mismatched_source_hash_means_a_nat_on_the_path() {
        let detector = NatDetector::new(SPI_I, SPI_R);
        // The peer hashed 10.0.0.1:4500, but we see it arriving from
        // 192.0.2.1:500 — a NAT rewrote the packet.
        let claimed = detector.source_hash(&[10, 0, 0, 1], 4500);
        let local: (&[u8], u16) = (&[192, 0, 2, 10], 500);
        let peer_destination = detector.source_hash(&[192, 0, 2, 10], 500);
        let verdict = detector.evaluate(
            &[claimed],
            Some(&peer_destination),
            (&[192, 0, 2, 1], 500),
            local,
        );
        assert!(verdict.peer_behind_nat);
        assert!(verdict.needs_encapsulation());
        assert!(
            !verdict.needs_keepalive(),
            "the peer keeps the mapping alive"
        );
    }

    #[test]
    fn a_mismatched_destination_hash_means_we_are_behind_a_nat() {
        let detector = NatDetector::new(SPI_I, SPI_R);
        let peer: (&[u8], u16) = (&[192, 0, 2, 1], 500);
        // The peer hashed our address as 203.0.113.5, but we think we are
        // 192.0.2.10 — so our router is rewriting us.
        let peer_destination = detector.destination_hash(&[203, 0, 113, 5], 4500);
        let peer_source = detector.source_hash(&[192, 0, 2, 1], 500);
        let verdict = detector.evaluate(
            &[peer_source],
            Some(&peer_destination),
            peer,
            (&[192, 0, 2, 10], 500),
        );
        assert!(verdict.we_are_behind_nat);
        assert!(verdict.needs_encapsulation());
        assert!(verdict.needs_keepalive());
    }

    #[test]
    fn several_source_hashes_are_all_accepted() {
        // A peer with two attachments sends two source hashes; the one that
        // matches the observed path is enough (RFC 7296 §2.23).
        let detector = NatDetector::new(SPI_I, SPI_R);
        let peer: (&[u8], u16) = (&[192, 0, 2, 1], 500);
        let local: (&[u8], u16) = (&[192, 0, 2, 10], 500);
        let other = detector.source_hash(&[10, 9, 9, 9], 4500);
        let matching = detector.source_hash(peer.0, peer.1);
        let peer_destination = detector.source_hash(local.0, local.1);
        let verdict = detector.evaluate(&[other, matching], Some(&peer_destination), peer, local);
        assert!(!verdict.peer_behind_nat);
    }

    #[test]
    fn encapsulation_adds_and_strips_the_non_esp_marker() {
        let message = vec![0x20, 0x20, 0x23, 0x08];
        let packet = encapsulate(&message);
        assert_eq!(packet, vec![0x00, 0x00, 0x00, 0x00, 0x20, 0x20, 0x23, 0x08]);
        assert_eq!(decapsulate(&packet), Some(&message[..]));
    }

    #[test]
    fn an_esp_packet_is_not_mistaken_for_ike() {
        // An ESP packet's SPI is non-zero, so it never starts with the marker.
        assert_eq!(
            decapsulate(&[0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01]),
            None
        );
        // Nor is a keepalive, nor a runt packet.
        assert_eq!(decapsulate(&NAT_KEEPALIVE), None);
        assert_eq!(decapsulate(&[0, 0, 0, 0]), None);
    }

    #[test]
    fn a_keepalive_is_a_single_ff_octet() {
        assert!(is_nat_keepalive(&[0xFF]));
        assert!(!is_nat_keepalive(&[0xFF, 0x00]));
        assert!(!is_nat_keepalive(&NON_ESP_MARKER));
    }

    #[test]
    fn the_notifies_carry_the_two_hashes() {
        let notifies = nat_detection_notifies(
            SPI_I,
            [0u8; 8],
            (&[192, 0, 2, 10], 500),
            (&[192, 0, 2, 1], 500),
        );
        assert_eq!(notifies[0].notify_type, NAT_DETECTION_SOURCE_IP);
        assert_eq!(notifies[1].notify_type, NAT_DETECTION_DESTINATION_IP);
        assert_eq!(
            notifies[0].data,
            nat_detection_hash(SPI_I, [0u8; 8], &[192, 0, 2, 10], 500).to_vec()
        );
        assert_eq!(
            notifies[1].data,
            nat_detection_hash(SPI_I, [0u8; 8], &[192, 0, 2, 1], 500).to_vec()
        );
        // They survive the payload codec unchanged.
        for notify in notifies {
            let encoded = notify.encode();
            assert_eq!(crate::ikev2::Notify::decode(&encoded).unwrap(), notify);
        }
    }

    #[test]
    fn notify_numbers_are_the_iana_assignments() {
        assert_eq!(NAT_DETECTION_SOURCE_IP, 16388);
        assert_eq!(NAT_DETECTION_DESTINATION_IP, 16389);
    }
}
