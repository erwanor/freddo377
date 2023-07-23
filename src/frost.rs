use ark_ff::{UniformRand, Zero};
use rand_core::{CryptoRng, RngCore};

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
    peer_commitments: [PeerCommitment<T>; T],
}

pub struct PeerCommitment<const T: usize> {
    /// The signer's identifier.
    pub id: u64,
    /// A public commitment to the coefficients of that signer's key.
    pub signing_key: [decaf377::Element; T],
    ///
    pub sig: schnorr::Signature,
}

impl<const T: usize> Default for PeerCommitment<T> {
    fn default() -> Self {
        Self {
            id: 0,
            signing_key: [decaf377::Element::zero(); T],
            sig: schnorr::Signature::default(),
        }
    }
}

impl<const T: usize> FrostSigner<T> {
    pub fn new<R: CryptoRng + RngCore>(id: u64, mut rng: R) -> Self {
        let signing_key: [decaf377::Fr; T] = [decaf377::Fr::rand(&mut rng); T];
        let fingerprint = [decaf377::Element::rand(&mut rng); T];
        let peer_commitments = core::array::from_fn(|_| PeerCommitment::default());
        Self {
            id,
            signing_key,
            fingerprint,
            peer_commitments,
        }
    }
}
