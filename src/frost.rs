use std::collections::BTreeMap;

use crate::schnorr;

/// A participant in the FROST protocol
pub struct FrostSigner<const T: usize> {
    /// The client's identifier.
    id: u64,
    /// The coefficient of the polynomial used to generate the signing key.
    signing_key: [decaf377::Fr; T],
    /// A public commitment to the coefficients of the polynomial
    /// used to generate the signing key.
    fingerprint: [decaf377::Element; T],
    peer_commitments: BTreeMap<u64, PeerCommitment<T>>,
}

pub struct PeerCommitment<const T: usize> {
    /// The signer's identifier.
    pub id: u64,
    /// A public commitment to the coefficients of that signer's key.
    pub signing_key: [decaf377::Element; T],
    ///
    pub sig: schnorr::Signature,
}
