//! Contains the implementations of AES encryptors
pub mod hardware;
pub mod software;

/// Represents the counter used by the AES block cipher to generate a set of values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct AesCtr(pub u128);

/// Represents a key used in the AES ciphertext.
#[derive(Clone, Copy)]
pub struct AesKey(pub u128);

/// A trait for batched AES encryptors.
///
/// Batched encryptors, are encryptors that encrypts 128 bytes at a time.
pub trait AesBatchedEncryptor: Clone {
    /// Tries to instantiate a new generator from a secret key.
    fn try_new(key: AesKey) -> Result<Self, crate::Error>;

    /// Generates the batch corresponding to the given counter.
    fn encrypt_batch(&mut self, ctr: AesCtr) -> [u8; 128];
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
pub enum FirmAesEncryptor {
    #[doc(hidden)]
    Software(software::Encryptor),
    #[doc(hidden)]
    Hardware(hardware::Encryptor),
}

impl AesBatchedEncryptor for FirmAesEncryptor {
    fn try_new(aes_key: AesKey) -> Result<Self, crate::Error> {
        Ok(Self::new(aes_key))
    }

    fn encrypt_batch(&mut self, ctr: AesCtr) -> [u8; 128] {
        match self {
            Self::Software(soft) => soft.encrypt_batch(ctr),
            Self::Hardware(hard) => hard.encrypt_batch(ctr),
        }
    }
}

impl FirmAesEncryptor {
    pub fn new_software(key: AesKey) -> Self {
        Self::Software(software::Encryptor::new(key))
    }

    pub fn new_hardware(key: AesKey) -> Result<Self, crate::Error> {
        hardware::Encryptor::try_new(key).map(Self::Hardware)
    }

    pub fn new(key: AesKey) -> Self {
        match Self::new_hardware(key) {
            Ok(encryptor) => encryptor,
            Err(error) => {
                if cfg!(not(test)) {
                    eprintln!("Could not create hardware-based AES encryptor, generation will be slower. \
                    error: {}", error);
                }
                Self::new_software(key)
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::aes::encryptors::AesBatchedEncryptor;

    use super::*;

    pub(super) const CIPHER_KEY: u128 = u128::from_be(0x000102030405060708090a0b0c0d0e0f);
    #[cfg(all(target_feature = "aes", target_feature = "sse2"))]
    pub(super) const KEY_SCHEDULE: [u128; 11] = [
        u128::from_be(0x000102030405060708090a0b0c0d0e0f),
        u128::from_be(0xd6aa74fdd2af72fadaa678f1d6ab76fe),
        u128::from_be(0xb692cf0b643dbdf1be9bc5006830b3fe),
        u128::from_be(0xb6ff744ed2c2c9bf6c590cbf0469bf41),
        u128::from_be(0x47f7f7bc95353e03f96c32bcfd058dfd),
        u128::from_be(0x3caaa3e8a99f9deb50f3af57adf622aa),
        u128::from_be(0x5e390f7df7a69296a7553dc10aa31f6b),
        u128::from_be(0x14f9701ae35fe28c440adf4d4ea9c026),
        u128::from_be(0x47438735a41c65b9e016baf4aebf7ad2),
        u128::from_be(0x549932d1f08557681093ed9cbe2c974e),
        u128::from_be(0x13111d7fe3944a17f307a78b4d2b30c5),
    ];
    pub(super) const PLAINTEXT: u128 = u128::from_be(0x00112233445566778899aabbccddeeff);
    pub(super) const CIPHERTEXT: u128 = u128::from_be(0x69c4e0d86a7b0430d8cdb78070b4c55a);

    pub(super) fn test_uniformity<Encryptor: AesBatchedEncryptor>(aes_key: AesKey) {
        // Checks that the PRNG generates uniform numbers
        let precision = 10f64.powi(-4);
        let n_samples = 10_000_000_usize;
        let mut generator = Encryptor::try_new(aes_key).unwrap();
        let mut counts = [0usize; 256];
        let expected_prob: f64 = 1. / 256.;
        for counter in 0..n_samples {
            let generated = generator.encrypt_batch(AesCtr(counter as u128));
            for i in 0..128 {
                counts[generated[i] as usize] += 1;
            }
        }
        counts
            .iter()
            .map(|a| (*a as f64) / ((n_samples * 128) as f64))
            .for_each(|a| assert!((a - expected_prob) < precision))
    }
}
