use bls12_381::{G1Affine, G1Projective, Scalar};
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt::{Debug, Display, Formatter, Result as NullResult};

#[derive(Clone, PartialEq, Eq, Copy)]
pub struct EGPublicKey(pub G1Projective);

impl Debug for EGPublicKey {
    fn fmt(&self, f: &mut Formatter) -> NullResult {
        write!(f, "{:?}", self.0)
    }
}

impl Display for EGPublicKey {
    fn fmt(&self, f: &mut Formatter) -> NullResult {
        write!(f, "{:?}", self.0)
    }
}

#[derive(Clone, PartialEq, Eq, Copy)]
pub struct EGSecretKey(pub Scalar);

impl Debug for EGSecretKey {
    fn fmt(&self, f: &mut Formatter) -> NullResult {
        write!(f, "{:?}", self.0)
    }
}

impl Display for EGSecretKey {
    fn fmt(&self, f: &mut Formatter) -> NullResult {
        write!(f, "{:?}", self.0)
    }
}

impl EGPublicKey {
    pub fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> Self {
        let bytes = bytes.as_ref();
        if bytes.len() != 48 {
            panic!("Invalid length");
        }
        let mut buf = [0u8; 48];
        buf.copy_from_slice(bytes);
        let g1 = G1Projective::from(G1Affine::from_compressed(&buf).unwrap());
        EGPublicKey(g1)
    }

    pub fn to_bytes(&self) -> [u8; 48] {
        G1Affine::from(self.0).to_compressed()
    }
}

impl Serialize for EGPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

impl<'de> Deserialize<'de> for EGPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        Ok(EGPublicKey::from_bytes(&bytes[..]))
    }
}

impl EGSecretKey {
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> Self {
        let bytes = bytes.as_ref();
        if bytes.len() != 32 {
            panic!("Invalid length");
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(bytes);
        Self(Scalar::from_bytes(&buf).unwrap())
    }
}

impl Serialize for EGSecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0.to_bytes())
    }
}

impl<'de> Deserialize<'de> for EGSecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        Ok(EGSecretKey::from_bytes(&bytes[..]))
    }
}
