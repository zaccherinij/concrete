use super::*;
use crate::generator::RandomBytesGenerator;

#[test]
fn test_soft_hard_eq() {
    // Checks that both the software and hardware prng outputs the same values.

    let aes_key = AesKey(0);

    let mut soft = SoftAesCtrGenerator::try_new(aes_key).unwrap();
    let mut hard = HardAesCtrGenerator::try_new(aes_key).unwrap();
    for _ in 0..1000 {
        assert_eq!(soft.generate_next(), hard.generate_next());
    }
}
