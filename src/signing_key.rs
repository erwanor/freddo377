use ark_ff::{PrimeField, UniformRand, Zero};

pub struct VerificationKey {
    pub coefficients: Vec<decaf377::Element>,
}

impl VerificationKey {}

pub struct SigningKey {
    pub coefficients: Vec<decaf377::Fr>,
}

impl SigningKey {
    pub fn to_public_signing_key(&self) -> VerificationKey {
        VerificationKey {
            coefficients: self
                .coefficients
                .iter()
                .map(|k| k * decaf377::basepoint())
                .collect::<Vec<_>>(),
        }
    }

    /// Evaluate the polynomial at the given point using Horner's method.
    /// TODO: the clashing nomenclature (signing key and polynomial) is awkward.
    fn evaluate<T: Into<decaf377::Fr>>(&self, point: T) -> decaf377::Fr {
        let point: decaf377::Fr = point.into();
        let mut result = decaf377::Fr::zero();

        for coefficient in self.coefficients.iter().rev() {
            result = result * point + coefficient;
        }

        result
    }
}
