use ark_ff::Zero;
use decaf377::{Element, Fr};

pub struct Signature {
    /// A public commitment to a random scalar.
    pub commitment: Element,
    /// \mu := k + a0*H(...)
    pub challenge_response: Fr,
}

impl Signature {}

impl Default for Signature {
    fn default() -> Self {
        Self {
            commitment: Element::zero(),
            challenge_response: Fr::zero(),
        }
    }
}
