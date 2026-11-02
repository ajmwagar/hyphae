//! Where an emergency fix comes from.
//!
//! The IMS signalling can only *convey* a location (E911-003, E911-005). Where
//! it comes from — GNSS, a civic address, a carrier location service, the
//! access point's identity mapped by the network — is a device concern, so it
//! sits behind a trait exactly like `Usim`, `AtChannel` and `HttpChannel` do.
//! Nothing in this crate performs I/O, and a `LocationSource` implementation
//! that does lives outside the protocol crates.
//!
//! ## Staleness is the source's problem
//!
//! TS 24.229 §5.1.6.8.3 NOTE 3: *"If the location information is old or
//! inaccurate, the UE does not consider location information to be available."*
//! Only the source knows how old its fix is, so [`LocationSource::current`]
//! returns `None` for a fix it would not stand behind. The emergency code will
//! then omit the `Geolocation` header (§5.1.6.8.3 item 9) or publish a PIDF with
//! no location object (§5.1.6.12.3 NOTE) — both of which are correct and
//! harmless, whereas a stale fix may dispatch help to the wrong place.

#![forbid(unsafe_code)]

use crate::emergency::{Geolocation, Location};

/// A source of the UE's current location.
pub trait LocationSource {
    /// The current fix, or `None` when there is no usable one.
    ///
    /// Returning `None` is always safe. Returning a stale or invented fix is
    /// not: an emergency service will act on it.
    fn current(&mut self) -> Option<Location>;
}

/// A source that always reports the same answer.
///
/// This is for tests and for callers that already hold a fix from somewhere
/// else (for example the access point's position, configured by hand).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct FixedLocation(pub Option<Location>);

impl FixedLocation {
    /// A source with a geodetic fix.
    pub fn at(location: Geolocation) -> Self {
        Self(Some(Location::Geodetic(location)))
    }

    /// A source with a civic address (RFC 5139).
    pub fn civic(address: crate::emergency::CivicAddress) -> Self {
        Self(Some(Location::civic(address)))
    }

    /// A source with no fix — the honest answer when nothing has been acquired.
    pub fn unavailable() -> Self {
        Self(None)
    }
}

impl LocationSource for FixedLocation {
    fn current(&mut self) -> Option<Location> {
        self.0.clone()
    }
}

impl<T: LocationSource + ?Sized> LocationSource for &mut T {
    fn current(&mut self) -> Option<Location> {
        (**self).current()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fixed_source_reports_what_it_was_given() {
        let location = Geolocation::new(51.5, -0.12).unwrap();
        let mut source = FixedLocation::at(location);
        assert_eq!(source.current(), Some(Location::Geodetic(location)));

        let mut none = FixedLocation::unavailable();
        assert_eq!(none.current(), None);
    }

    #[test]
    fn a_mutable_reference_is_a_source_too() {
        let location = Geolocation::new(0.0, 0.0).unwrap();
        let mut inner = FixedLocation::at(location);
        let mut by_ref = &mut inner;
        assert_eq!(
            LocationSource::current(&mut by_ref),
            Some(Location::Geodetic(location))
        );
    }
}
