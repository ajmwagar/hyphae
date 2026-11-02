//! A UDP driver and a stand-in ePDG for the Wi-Fi calling path.
//!
//! The protocol crates contain no sockets on purpose, so this is where the
//! network lives. It exists to answer one question end to end: does the
//! exchange the crates describe actually complete against a peer that derives
//! its keys independently?
//!
//! * [`client`] — the UE: IKE_SA_INIT, then EAP-only IKE_AUTH, holding `K`/`OPc`
//!   and running Milenage as a USIM would.
//! * [`responder`] — a stand-in ePDG: picks the RAND, derives `CK'`/`IK'`, issues
//!   the AKA' challenge, verifies `AT_RES` and the client's AUTH, and answers
//!   with a child SA and a `CFG_REPLY`.
//!
//! Both halves share only the subscriber key, so a completed exchange means the
//! whole key chain agreed rather than a shared fixture.
//!
//! This is lab code: no rekeying, no liveness, no NAT-T, and a fixed RAND.

#![forbid(unsafe_code)]

pub mod client;
pub mod responder;

pub use client::{ClientError, Established, UeClient};
pub use responder::{Reply, ResponderError, StandInEpdg};

/// The public 3GPP Milenage test-set-1 key (TS 35.208 §4.1).
pub const TEST_K: [u8; 16] = [
    0x46, 0x5b, 0x5c, 0xe8, 0xb1, 0x99, 0xb4, 0x9f, 0xaa, 0x5f, 0x0a, 0x2e, 0xe2, 0x38, 0xa6, 0xbc,
];
/// The matching OPc for test set 1.
pub const TEST_OPC: [u8; 16] = [
    0xcd, 0x63, 0xcb, 0x71, 0x95, 0x4a, 0x9f, 0x4e, 0x48, 0xa5, 0x99, 0x4e, 0x37, 0xa0, 0x2b, 0xaf,
];
/// A lab access-network name.
pub const TEST_NETWORK: &str = "WLAN";
/// A lab IMS identity.
pub const TEST_IDENTITY: &str = "234150999999999@ims.mnc015.mcc234.3gppnetwork.org";

#[cfg(test)]
mod tests {
    use super::*;

    /// The full exchange, message by message, without a socket. This is the
    /// same sequence the UDP test drives; keeping it here makes a failure
    /// readable without a network in the way.
    #[test]
    fn the_exchange_completes_and_both_sides_agree() {
        let group = 14;
        let mut client = UeClient::new(
            TEST_NETWORK,
            TEST_IDENTITY,
            TEST_K,
            TEST_OPC,
            [0x11; 8],
            &[0x22; 32],
            vec![0x33; 32],
            group,
            [0x00, 0x00, 0x10, 0x01],
        )
        .unwrap();
        let mut responder = StandInEpdg::new(
            TEST_NETWORK,
            TEST_K,
            TEST_OPC,
            group,
            vec![0x55; 32],
            [0x44; 8],
            vec![0x66; 32],
            [0x00, 0x00, 0x10, 0x00],
            [10, 32, 0, 7],
            [10, 32, 0, 1],
        );

        let sa_init = client.sa_init_request();
        let sa_init_response = responder.on_sa_init(&sa_init).unwrap();
        let first_auth = client.on_sa_init_response(&sa_init_response).unwrap();

        // Challenge.
        let challenge = responder.on_ike_auth(&first_auth, &[0x11; 16]).unwrap();
        let Reply::Send(challenge) = challenge else {
            panic!("expected a challenge");
        };
        let (eap_response, _) = client.on_ike_auth(&challenge).unwrap();
        let eap_response = eap_response.expect("the client answers the challenge");

        // Success.
        let success = responder.on_ike_auth(&eap_response, &[0x22; 16]).unwrap();
        let Reply::Send(success) = success else {
            panic!("expected EAP success");
        };
        let (client_auth, _) = client.on_ike_auth(&success).unwrap();
        let client_auth = client_auth.expect("the client sends AUTH after success");

        // Final responder message.
        let done = responder.on_ike_auth(&client_auth, &[0x33; 16]).unwrap();
        let Reply::Established {
            bytes,
            child: responder_child,
            ims_address,
        } = done
        else {
            panic!("expected the exchange to complete");
        };
        let (_, established) = client.on_ike_auth(&bytes).unwrap();
        let established = established.expect("the client finished");

        // The two halves agree on the tunnel.
        assert_eq!(established.ims_address, Some(ims_address));
        assert_eq!(established.dns, vec![[10, 32, 0, 1]]);
        assert_eq!(established.child.outbound.spi, 0x1000);
        assert_eq!(established.child.inbound.spi, 0x1001);
        assert_eq!(
            established.child.outbound.encryption.key(),
            responder_child.outbound.encryption.key()
        );
        assert_eq!(
            established.child.inbound.integrity.key(),
            responder_child.inbound.integrity.key()
        );
        assert_eq!(established.child_keys.len(), 128);
    }

    #[test]
    fn a_usim_backed_client_completes_the_exchange() {
        use usim::{LoopbackChannel, SoftwareUsim, UsimCard};

        let group = 14;
        // The stand-in responder uses SQN 1; a card with the same SQN accepts
        // the challenge. This is the same boundary a PC/SC card uses.
        let usim = SoftwareUsim::with_opc(TEST_K, TEST_OPC, [0, 0, 0, 0, 0, 1]);
        let card = UsimCard::new(LoopbackChannel::new(usim));
        let mut client = UeClient::with_usim(
            TEST_NETWORK,
            TEST_IDENTITY,
            Box::new(card),
            [0x11; 8],
            &[0x22; 32],
            vec![0x33; 32],
            group,
            [0x00, 0x00, 0x10, 0x01],
        )
        .unwrap();
        let mut responder = StandInEpdg::new(
            TEST_NETWORK,
            TEST_K,
            TEST_OPC,
            group,
            vec![0x55; 32],
            [0x44; 8],
            vec![0x66; 32],
            [0x00, 0x00, 0x10, 0x00],
            [10, 32, 0, 7],
            [10, 32, 0, 1],
        );

        let sa_init = client.sa_init_request();
        let sa_init_response = responder.on_sa_init(&sa_init).unwrap();
        let first_auth = client.on_sa_init_response(&sa_init_response).unwrap();
        let challenge = responder.on_ike_auth(&first_auth, &[0x11; 16]).unwrap();
        let Reply::Send(challenge) = challenge else {
            panic!("expected a challenge");
        };
        let (eap_response, _) = client.on_ike_auth(&challenge).unwrap();
        let eap_response = eap_response.expect("the USIM answers the challenge");
        let success = responder.on_ike_auth(&eap_response, &[0x22; 16]).unwrap();
        let Reply::Send(success) = success else {
            panic!("expected EAP success");
        };
        let (client_auth, _) = client.on_ike_auth(&success).unwrap();
        let client_auth = client_auth.expect("the client sends AUTH after success");
        let done = responder.on_ike_auth(&client_auth, &[0x33; 16]).unwrap();
        let Reply::Established {
            bytes, ims_address, ..
        } = done
        else {
            panic!("expected the exchange to complete");
        };
        let (_, established) = client.on_ike_auth(&bytes).unwrap();
        let established = established.expect("the USIM-backed client finished");
        assert_eq!(established.ims_address, Some(ims_address));
        assert_eq!(established.child_keys.len(), 128);
    }

    #[test]
    fn a_wrong_subscriber_key_is_rejected() {
        let group = 14;
        let mut client = UeClient::new(
            TEST_NETWORK,
            TEST_IDENTITY,
            [0x00; 16], // not the network's key
            TEST_OPC,
            [0x11; 8],
            &[0x22; 32],
            vec![0x33; 32],
            group,
            [0x00, 0x00, 0x10, 0x01],
        )
        .unwrap();
        let mut responder = StandInEpdg::new(
            TEST_NETWORK,
            TEST_K,
            TEST_OPC,
            group,
            vec![0x55; 32],
            [0x44; 8],
            vec![0x66; 32],
            [0x00, 0x00, 0x10, 0x00],
            [10, 32, 0, 7],
            [10, 32, 0, 1],
        );
        let sa_init = client.sa_init_request();
        let sa_init_response = responder.on_sa_init(&sa_init).unwrap();
        let first_auth = client.on_sa_init_response(&sa_init_response).unwrap();
        let challenge = responder.on_ike_auth(&first_auth, &[0x11; 16]).unwrap();
        let Reply::Send(challenge) = challenge else {
            panic!()
        };
        // A USIM with the wrong K cannot verify AUTN, so it never answers.
        assert_eq!(
            client.on_ike_auth(&challenge).unwrap_err(),
            ClientError::AutnRejected
        );
    }
}
