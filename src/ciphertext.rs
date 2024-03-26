use bls12_381::{G1Affine, G1Projective};
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt::{Debug, Display, Formatter, Result as NullResult};

#[derive(Clone, PartialEq, Eq, Copy)]
pub struct Ciphertext(pub G1Projective, pub G1Projective);

impl Serialize for Ciphertext {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let bytes_c1 = G1Affine::from(self.0).to_compressed();
        let bytes_c2 = G1Affine::from(self.1).to_compressed();

        let mut bytes = bytes_c1.to_vec();
        bytes.extend_from_slice(bytes_c2.as_slice());

        serializer.serialize_bytes(&bytes[..])
    }
}

impl<'de> Deserialize<'de> for Ciphertext {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;

        let mut buf = [0u8; 48];
        buf.copy_from_slice(&bytes[0..48]);
        let c1 = G1Projective::from(G1Affine::from_compressed(&buf).unwrap());

        let mut buf = [0u8; 48];
        buf.copy_from_slice(&bytes[48..]);
        let c2 = G1Projective::from(G1Affine::from_compressed(&buf).unwrap());

        Ok(Ciphertext(c1, c2))
    }
}

impl Debug for Ciphertext {
    fn fmt(&self, f: &mut Formatter) -> NullResult {
        write!(f, "(\n\t{:?}, \n\t{:?}\n)", self.0, self.1)
    }
}

impl Display for Ciphertext {
    fn fmt(&self, f: &mut Formatter) -> NullResult {
        write!(f, "(\n\t{:?}, \n\t{:?}\n)", self.0, self.1)
    }
}
