#![allow(unused_mut)] // @TODO Check if needed

use crate::ciphertext::Ciphertext;
use crate::key::{EGPublicKey, EGSecretKey};
use bbs::encoding::Message;
use rand::Rng;

mod ciphertext;
mod enc;
mod key;

pub fn keygen<R: Rng>(rng: &mut R) -> (EGPublicKey, EGSecretKey) {
    enc::keygen_impl(rng)
}

pub fn sample_randomness<R: Rng>(rng: &mut R) -> Message {
    enc::sample_randomness_impl(rng)
}

pub fn encrypt(pk: &EGPublicKey, message: &Message, r: &Message) -> Ciphertext {
    enc::encrypt_impl(pk, message, r)
}

pub fn decrypt(
    sk: &EGSecretKey,
    ciphertext: &Ciphertext,
    message_set: &[String],
) -> Result<String, &'static str> {
    enc::decrypt_impl(sk, ciphertext, message_set)
}

#[cfg(test)]
mod test {

    use crate::{decrypt, encrypt, keygen};
    use bbs::prelude::*;
    use rand::SeedableRng;

    #[test]
    fn elgamal_demo_ok() {
        let bbs = Bbs::<Bls12381Sha256>::default();
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([0u8; 32]);
        let (pk, sk) = keygen(&mut rng);
        let data = bbs.message("This ElGamal thingy works.");
        let r = sample_randomness(&mut rng);
        let c = encrypt(&pk, &data, &r);
        let msg_set = [String::from("This ElGamal thingy works.")];
        let dm = decrypt(&sk, &c, &msg_set);
        println!("Decrypted message: {:?}", dm);
    }

    #[test]
    fn elgamal_demo_should_fail() {
        let bbs = Bbs::<Bls12381Sha256>::default();
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([0u8; 32]);
        let (pk, sk) = keygen(&mut rng);
        let data = bbs.message("This ElGamal thingy does not work.");
        let r = sample_randomness(&mut rng);
        let c = encrypt(&pk, &data, &r);
        let msg_set = [String::from("This ElGamal thingy works.")];
        assert!(decrypt(&sk, &c, &msg_set).is_err());
    }
}
