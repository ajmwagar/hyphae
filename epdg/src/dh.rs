//! Diffie-Hellman for the IKEv2 SA_INIT exchange (RFC 7296 §2.12, RFC 3526).
//!
//! IKEv2 derives the shared secret `g^ir` from a MODP group. This module
//! implements the groups an ePDG realistically negotiates and nothing else:
//!
//! * **group 14** — 2048-bit MODP (RFC 3526 §3), the group IKEv2 requires
//!   implementations to support;
//! * **group 15** — 3072-bit MODP (RFC 3526 §4);
//! * **group 16** — 4096-bit MODP (RFC 3526 §5).
//!
//! Elliptic-curve groups (19, 20, 21) are not implemented and are reported as
//! unsupported rather than guessed at. The private exponent is supplied by the
//! caller, so this module needs no RNG dependency.

#![forbid(unsafe_code)]

use num_bigint::BigUint;

/// MODP 2048-bit group (RFC 3526 §3).
pub const GROUP_MODP_2048: u16 = 14;
/// MODP 3072-bit group (RFC 3526 §4).
pub const GROUP_MODP_3072: u16 = 15;
/// MODP 4096-bit group (RFC 3526 §5).
pub const GROUP_MODP_4096: u16 = 16;

/// Errors from the DH exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DhError {
    /// The group is not implemented here.
    UnsupportedGroup(u16),
    /// The private exponent was zero.
    ZeroPrivate,
    /// The peer's public value was outside `[2, p-2]`.
    BadPeerPublic,
    /// A group prime constant failed to parse (a build-time invariant).
    BadPrime,
}

impl core::fmt::Display for DhError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DhError::UnsupportedGroup(g) => write!(f, "unsupported DH group {g}"),
            DhError::ZeroPrivate => f.write_str("DH private exponent is zero"),
            DhError::BadPeerPublic => f.write_str("peer DH public value is out of range"),
            DhError::BadPrime => f.write_str("DH group prime is malformed"),
        }
    }
}

impl std::error::Error for DhError {}

/// The RFC 3526 §3 prime (2048 bits).
const PRIME_2048: &str = "\
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74\
020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437\
4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05\
98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB\
9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B\
E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718\
3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";

/// The RFC 3526 §4 prime (3072 bits).
const PRIME_3072: &str = "\
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74\
020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437\
4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05\
98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB\
9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B\
E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718\
3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33\
A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7\
ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864\
D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2\
08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";
const PRIME_4096: &str = "\
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74\
020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437\
4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05\
98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB\
9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B\
E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718\
3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33\
A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7\
ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864\
D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2\
08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7\
88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8\
DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2\
233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9\
93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF";

/// The group prime and generator for an implemented DH group.
pub fn group_parameters(group: u16) -> Result<(BigUint, u8), DhError> {
    let hex = match group {
        GROUP_MODP_2048 => PRIME_2048,
        GROUP_MODP_3072 => PRIME_3072,
        GROUP_MODP_4096 => PRIME_4096,
        other => return Err(DhError::UnsupportedGroup(other)),
    };
    let prime = BigUint::parse_bytes(hex.as_bytes(), 16).ok_or(DhError::BadPrime)?;
    Ok((prime, 2))
}

/// A DH key pair bound to one group.
#[derive(Debug, Clone)]
pub struct DhKeyPair {
    group: u16,
    private: BigUint,
    public: BigUint,
    prime: BigUint,
}

impl DhKeyPair {
    /// Build a key pair from a caller-supplied private exponent.
    ///
    /// The exponent must be non-zero and should carry at least 256 bits of
    /// entropy; this module does not generate randomness.
    pub fn from_private(group: u16, private_bytes: &[u8]) -> Result<Self, DhError> {
        let (prime, generator) = group_parameters(group)?;
        let private = BigUint::from_bytes_be(private_bytes);
        if private == BigUint::from(0u8) {
            return Err(DhError::ZeroPrivate);
        }
        let public = BigUint::from(generator).modpow(&private, &prime);
        Ok(Self {
            group,
            private,
            public,
            prime,
        })
    }

    pub fn group(&self) -> u16 {
        self.group
    }

    /// The public value as `KEi` octets, left-padded to the modulus length.
    pub fn public_bytes(&self) -> Vec<u8> {
        left_pad(&self.public, self.modulus_len())
    }

    /// The shared secret `g^ir`, left-padded to the modulus length.
    pub fn agree(&self, peer_public: &[u8]) -> Result<Vec<u8>, DhError> {
        let peer = BigUint::from_bytes_be(peer_public);
        let one = BigUint::from(1u8);
        // RFC 7296 §2.12: reject values outside [2, p-2].
        if peer < BigUint::from(2u8) || peer >= &self.prime - &one {
            return Err(DhError::BadPeerPublic);
        }
        let shared = peer.modpow(&self.private, &self.prime);
        Ok(left_pad(&shared, self.modulus_len()))
    }

    fn modulus_len(&self) -> usize {
        (self.prime.bits() as usize).div_ceil(8)
    }
}

fn left_pad(value: &BigUint, len: usize) -> Vec<u8> {
    let mut bytes = value.to_bytes_be();
    if bytes.len() < len {
        let mut padded = vec![0u8; len - bytes.len()];
        padded.append(&mut bytes);
        return padded;
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_primes_have_the_rfc_bit_lengths() {
        for (group, bits) in [(14u16, 2048usize), (15, 3072), (16, 4096)] {
            let (prime, generator) = group_parameters(group).unwrap();
            assert_eq!(prime.bits() as usize, bits, "group {group}");
            assert_eq!(generator, 2);
        }
        assert_eq!(
            group_parameters(19).unwrap_err(),
            DhError::UnsupportedGroup(19)
        );
    }

    #[test]
    fn two_parties_agree_on_the_same_secret() {
        let alice = DhKeyPair::from_private(14, &[0x11; 32]).unwrap();
        let bob = DhKeyPair::from_private(14, &[0x22; 32]).unwrap();
        let a_shared = alice.agree(&bob.public_bytes()).unwrap();
        let b_shared = bob.agree(&alice.public_bytes()).unwrap();
        assert_eq!(a_shared, b_shared);
        // The public and shared values are modulus-length padded.
        assert_eq!(alice.public_bytes().len(), 256);
        assert_eq!(a_shared.len(), 256);
        // The shared secret is not one of the public values.
        assert_ne!(a_shared, alice.public_bytes());
    }

    #[test]
    fn dh_is_algebraically_consistent() {
        // (g^a)^b == g^(a*b) == (g^b)^a, checked through the module.
        let (prime, generator) = group_parameters(14).unwrap();
        let a = BigUint::from_bytes_be(&[0x03; 16]);
        let b = BigUint::from_bytes_be(&[0x05; 16]);
        let g = BigUint::from(generator);
        let left = g.modpow(&a, &prime).modpow(&b, &prime);
        let right = g.modpow(&b, &prime).modpow(&a, &prime);
        assert_eq!(left, right);
    }

    #[test]
    fn bad_inputs_are_rejected() {
        assert_eq!(
            DhKeyPair::from_private(14, &[0x00; 32]).unwrap_err(),
            DhError::ZeroPrivate
        );
        let key = DhKeyPair::from_private(14, &[0x11; 32]).unwrap();
        // 0, 1 and p-1 are all outside [2, p-2].
        assert_eq!(key.agree(&[0x00]), Err(DhError::BadPeerPublic));
        assert_eq!(key.agree(&[0x01]), Err(DhError::BadPeerPublic));
        let (prime, _) = group_parameters(14).unwrap();
        let p_minus_1 = (&prime - BigUint::from(1u8)).to_bytes_be();
        assert_eq!(key.agree(&p_minus_1), Err(DhError::BadPeerPublic));
    }
}
