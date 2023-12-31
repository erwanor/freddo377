use ark_ff::PrimeField;
mod frost;
pub use frost::FrostSigner;

mod schnorr;
pub use schnorr::Signature;

mod signing_key;

mod keygen;
mod participant;

struct ParticipantIndex(pub u64);

impl ParticipantIndex {
    pub fn new(x: u64) -> Self {
        // TODO: use thiserror
        assert_ne!(x, 0, "ParticipantIndex must be nonzero");
        Self(x)
    }
}
