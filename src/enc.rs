use bls12_381::{G1Projective, Scalar};
use ff::Field;

use bbs::{ciphersuite::Bls12381Sha256, prelude::Message, Bbs};
use rand::Rng;

use crate::{ciphertext::Ciphertext, key::EGPublicKey, EGSecretKey};

pub fn keygen_impl<R: Rng>(rng: &mut R) -> (EGPublicKey, EGSecretKey) {
    let sk = EGSecretKey(<Scalar as Field>::random(rng));
    let pk = EGPublicKey(G1Projective::generator() * sk.0);
    (pk, sk)
}

pub fn sample_randomness_impl<R: Rng>(rng: &mut R) -> Message {
    Message(<Scalar as Field>::random(rng))
}

pub fn encrypt_impl(pk: &EGPublicKey, message: &Message, r: &Message) -> Ciphertext {
    Ciphertext(
        r.0 * G1Projective::generator(),
        r.0 * pk.0 + G1Projective::generator() * message.0,
    )
}

pub fn decrypt_impl(
    sk: &EGSecretKey,
    ciphertext: &Ciphertext,
    message_set: &[String],
) -> Result<String, &'static str> {
    let bbs = Bbs::<Bls12381Sha256>::default();
    let plaintext_in_group = ciphertext.1 - sk.0 * ciphertext.0;
    let result = message_set
        .iter()
        .find(|msg| G1Projective::generator() * bbs.message(msg).0 == plaintext_in_group)
        .ok_or("Decryption failed")?;
    Ok(String::from(result))
}
