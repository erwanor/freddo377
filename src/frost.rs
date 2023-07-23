use ark_ff::{UniformRand, Zero};
use rand_core::{CryptoRng, RngCore};

use crate::schnorr;


/*

    Imagining what the usage of this library might look like:

    We have a set of signers, each of which has a unique identifier, that form a committee.

    Signer_1: 
        - initializes a FrostSigner with a unique identifier
        - generates its signing key, and a public commitment to that key
        - software glue code sends the public commitment to the other signers
        - software glue code receives the public commitments from the other signers
    
    During that process, it's possible that:
        - a committee member is malicious and sends a bad public commitment
        - a committee member is malicious and drops out of the protocol
        - a committee member is malicious and spoofs the id of another committee member

    So, we need to be able to have two representations of the protocol:
    - one data structure that models the local signer, and the view that the local signer has of the committee.
    - one data structure that models the committee, and the view that the committee has of the local signer.
    - a splittable data structure that contains both, we should be able to delegate processing of the committee to a separate process.


        ```rust

        let mut committee = FrostCommittee::new();
        let mut local_signer = FrostSigner::new();

        p2p.broadcast(local_signer.public_commitment);
        for peer_commitment in p2p.receive() {
            committee.add_signer(peer_commitment);
        }


*/



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
