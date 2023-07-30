use ark_ff::{PrimeField, UniformRand, Zero};
use decaf377::Fr;
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

        ```

        In this setup, the work of verifying the peer commitments is done by the committee, and the local signer doesn't need to do any work.


    Entry: July 30th,

    I'm going to first implement all the different bits of logic of the protocol (e.g. evaluating the committed polynomial at a specific point), and then
    i'll go about re-architecting the whole into a more modular design with hopefully not footguns.


*/

pub struct FrostCommittee {
    /// The number of signers in the committee.
    pub n: usize,
    /// The number of signers required to produce a signature.
    pub t: usize,
    /// The set of signers in the committee.
    pub signers: Vec<PeerCommitment>,
}

impl FrostCommittee {
    pub fn new(n: usize, t: usize) -> Self {
        Self {
            n,
            t,
            signers: Vec::new(),
        }
    }

    pub fn add_signer(&mut self, peer_commitment: PeerCommitment) {
        self.signers.push(peer_commitment);
    }

    pub fn threshold(&self) -> usize {
        self.t
    }

    pub fn committee_size(&self) -> usize {
        self.n
    }
}

/// A participant in the FROST protocol
pub struct FrostSigner {
    /// The client's identifier.
    id: u64,
    /// The coefficient of the polynomial used to generate the signing key.
    /// TODO(erwan): newtype this or something.
    pub signing_key: Vec<decaf377::Fr>,
    /// This participant's blinding factor.
    pub nonce: decaf377::Fr,
    /// A public commitment to the coefficients of the polynomial
    /// used to generate the signing key.
    pub commitment: Vec<decaf377::Element>,
}

pub struct PeerCommitment {
    /// The signer's identifier.
    pub id: u64,
    /// A public commitment to the coefficients of that signer's key.
    pub commitment: Vec<decaf377::Element>,
    /// A proof of knowledge of the constant term of the polynomial.
    pub sig: schnorr::Signature,
}

impl Default for PeerCommitment {
    fn default() -> Self {
        Self {
            id: 0,
            commitment: Vec::new(),
            sig: schnorr::Signature::default(),
        }
    }
}

impl FrostSigner {
    /// TODO(erwan): this signature is confusing
    pub fn new<R: CryptoRng + RngCore>(
        id: u64,
        _committee_size: usize,
        threshold: usize,
        mut rng: R,
    ) -> Self {
        let signing_key: Vec<decaf377::Fr> = (0..threshold)
            .map(|_| decaf377::Fr::rand(&mut rng))
            .collect::<Vec<_>>();

        let generator = decaf377::basepoint();

        let commitment: Vec<decaf377::Element> = signing_key
            .iter()
            .map(|k| k * generator)
            .collect::<Vec<_>>();

        let nonce = decaf377::Fr::rand(&mut rng);

        Self {
            id,
            signing_key,
            commitment,
            nonce,
        }
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn public_commitment(&self) -> Vec<decaf377::Element> {
        self.commitment.clone()
    }

    fn signing_key_evaluate<T: Into<decaf377::Fr>>(&self, point: T) -> decaf377::Fr {
        let point: decaf377::Fr = point.into();
        let mut result = decaf377::Fr::zero();

        for coefficient in self.signing_key.iter().rev() {
            result = result * point + coefficient;
        }

        result
    }

    /// TODO: specify the transcript protocol in a trait, and implement it for specific
    /// FrostSigner<T: State> types.
    pub fn keygen_proof(&self) -> (schnorr::Signature, merlin::Transcript) {
        let nonce_commitment = self.nonce * decaf377::basepoint();
        let (challenge, transcript) =
            FrostSigner::keygen_challenge(self.id(), self.commitment[0], nonce_commitment);

        let sig = schnorr::Signature {
            commitment: nonce_commitment,
            challenge_response: self.nonce + challenge * self.signing_key[0],
        };

        (sig, transcript)
    }

    pub fn keygen_challenge(
        id: u64,
        constant_term_commitment: decaf377::Element,
        nonce_commitment: decaf377::Element,
    ) -> (decaf377::Fr, merlin::Transcript) {
        let mut transcript =
            FrostSigner::keygen_transcript(id, constant_term_commitment, nonce_commitment);
        let mut challenge_raw: [u8; 32] = [0u8; 32];
        transcript.challenge_bytes(b"schnorr-sig-challenge", &mut challenge_raw);
        let challenge_scalar = decaf377::Fr::from_le_bytes_mod_order(&challenge_raw);
        (challenge_scalar, transcript)
    }

    pub fn keygen_transcript(
        id: u64,
        constant_term_commitment: decaf377::Element,
        nonce_commitment: decaf377::Element,
    ) -> merlin::Transcript {
        let mut transcript = merlin::Transcript::new(b"freddo377-key-gen");
        transcript.append_u64(b"signer-identifier", id);
        transcript.append_message(
            b"constant-term-commitment",
            constant_term_commitment.vartime_compress().0.as_ref(),
        );

        transcript.append_message(
            b"nonce-commitment",
            nonce_commitment.vartime_compress().0.as_ref(),
        );
        transcript
    }

    pub fn keygen_verify_proof(
        id: u64,
        constant_term_commitment: decaf377::Element,
        nonce_commitment: decaf377::Element,
        sig: schnorr::Signature,
    ) -> bool {
        let (challenge, _) =
            FrostSigner::keygen_challenge(id, constant_term_commitment, nonce_commitment);

        let candidate_commitment =
            sig.challenge_response * decaf377::basepoint() - challenge * constant_term_commitment;
        candidate_commitment.vartime_compress().0 == sig.commitment.vartime_compress().0
    }

    pub fn nonce_commitment(&self) -> decaf377::Element {
        self.nonce * decaf377::basepoint()
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::*;

    #[test]
    /// Check that a signer can verify its own proof.
    pub fn generate_proof_and_verify() {
        let mut rng = OsRng;
        let signer = FrostSigner::new(1, 3, 2, &mut rng);
        let (sig, _transcript) = signer.keygen_proof();
        assert!(FrostSigner::keygen_verify_proof(
            signer.id(),
            signer.commitment[0],
            signer.nonce_commitment(),
            sig
        ));
    }

    #[test]
    /// Check that challenges are generated deterministically.
    pub fn transcript_consistency() {
        let mut rng = OsRng;
        let signer = FrostSigner::new(1, 3, 2, &mut rng);
        let (challenge1, _) = FrostSigner::keygen_challenge(
            signer.id(),
            signer.commitment[0],
            signer.nonce_commitment(),
        );

        let (challenge2, _) = FrostSigner::keygen_challenge(
            signer.id(),
            signer.commitment[0],
            signer.nonce_commitment(),
        );

        assert_eq!(challenge1, challenge2);
    }
}
/*

What if we abstracted the protocol implemetnation into a trait?
    DKG: SchnorrSig

    PreProcessing: DKG

    etc.

*/
