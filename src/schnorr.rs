use decaf377::{Element, Fr};

pub struct Signature {
    /// A public commitment to a random scalar.
    pub commitment: Element,
    /// \mu := k + a0*H(...)
    pub challenge_response: Fr,
}
