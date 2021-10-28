use crate::utils::RawUnsignedIntegers;
use concrete_commons::dispersion::Variance;
use concrete_commons::parameters::{CiphertextCount, LweDimension};
use concrete_core::specification::engines::{
    CleartextCreationEngine, LweCiphertextCleartextAssignedMultiplicationEngine,
    LweCiphertextDecryptionEngine, LweCiphertextEncryptionEngine,
    LweCiphertextZeroEncryptionEngine, LweSecretKeyGenerationEngine, PlaintextCreationEngine,
    PlaintextRetrievalEngine,
};
use concrete_core::specification::entities::{
    CleartextEntity, LweCiphertextEntity, LweSecretKeyEntity, PlaintextEntity,
};

// The variance used to encrypt everything in the test (log std = -20)
const VARIANCE: Variance = Variance(0.0000000000009094947017729282);

// The parameters the test is executed against.
const PARAMETERS: [(LweDimension, CiphertextCount); 1] = [(LweDimension(600), CiphertextCount(10))];

/// A generic function testing the assigned lwe cleartext multiplication operation.
///
/// # Note:
///
/// Type parameters prefixed with `Util` are not used in the test, but are needed to generate
/// the entities that the operation will execute on.
pub fn test<
    Engine,        // The tested engine, implementing the multiplication trait.
    Ciphertext,    // The lwe ciphertext type.
    Cleartext,     // The cleartext type.
    UtilEngine,    // The util engine used to generate all operator inputs.
    UtilRaw,       // A raw numeric type used to generate the cleartexts.
    UtilSecretKey, // A util secret key used to generate the ciphertext.
    UtilPlaintext, // A util plaintext used to encode ciphertexts.
>()
where
    Engine: LweCiphertextCleartextAssignedMultiplicationEngine<Ciphertext, Cleartext>,
    Ciphertext: LweCiphertextEntity,
    Cleartext: CleartextEntity<Representation = Ciphertext::Representation>,
    UtilEngine: LweSecretKeyGenerationEngine<UtilSecretKey>
        + LweCiphertextEncryptionEngine<UtilSecretKey, UtilPlaintext, Ciphertext>
        + LweCiphertextDecryptionEngine<UtilSecretKey, Ciphertext, UtilPlaintext>
        + CleartextCreationEngine<UtilRaw, Cleartext>
        + PlaintextCreationEngine<UtilRaw, UtilPlaintext>
        + PlaintextRetrievalEngine<UtilPlaintext, UtilRaw>,
    UtilRaw: RawUnsignedIntegers,
    UtilSecretKey: LweSecretKeyEntity<
        KeyFlavor = Ciphertext::KeyFlavor,
        Representation = Ciphertext::Representation,
    >,
    UtilPlaintext: PlaintextEntity<Representation = Ciphertext::Representation>,
{
    let mut engine = Engine::new().unwrap();
    let mut util_engine = UtilEngine::new().unwrap();

    for (lwe_dimension, ciphertext_count) in PARAMETERS {
        let mut expected = UtilRaw::zero_vec(ciphertext_count.0);
        let mut obtained = UtilRaw::zero_vec(ciphertext_count.0);
        // generate the secret key
        let sk = util_engine.generate_lwe_secret_key(lwe_dimension).unwrap();

        for ith in 0..ciphertext_count.0 {
            // generate random messages
            let raw_message = UtilRaw::uniform();
            let message = util_engine.create_plaintext(&raw_message).unwrap();

            // encryption
            let mut ciphertext = util_engine
                .encrypt_lwe_ciphertext(&sk, &message, VARIANCE)
                .unwrap();

            // generate a random signed weight vector represented as Torus elements
            let raw_weight = UtilRaw::uniform_weight();
            let weight = util_engine.create_cleartext(&raw_weight).unwrap();

            // We store the expected result
            expected[ith] = raw_message.wrapping_mul(raw_weight);

            // scalar mul
            engine
                .assign_mul_lwe_ciphertext_cleartext(&mut ciphertext, &weight)
                .unwrap();

            // decryption
            let decryption = util_engine
                .decrypt_lwe_ciphertext(&sk, &ciphertext)
                .unwrap();
            let raw_decryption = util_engine.retrieve_plaintext(&decryption).unwrap();

            // We store the obtained result
            obtained[ith] = raw_decryption;
        }

        // test
        let output_variance: f64 =
            <T as npe::LWE>::single_scalar_mul(f64::powi(noise.0, 2), weight.0);

        assert_noise_distribution(
            &messages_mul,
            &decryptions,
            Variance::from_variance(output_variance),
        );
    }
}
