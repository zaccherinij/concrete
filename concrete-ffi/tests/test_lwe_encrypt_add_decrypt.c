#include "concrete-ffi.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <tgmath.h>

#define NO_ERR(s) s; assert(ERR==0);

const int PRECISION = 4;
const int SHIFT = 64 - (PRECISION+1);

int main(void)
{
    int ERR = 0;

    // We generate the random sources
    SecretRandomGenerator * secret_gen = NO_ERR(allocate_secret_generator(&ERR, 0, 0));
    EncryptionRandomGenerator *enc_gen = NO_ERR(allocate_encryption_generator(&ERR, 0, 0));
    Variance variance = { 0.000000001 };

    // We generate the secret key
    LweSize lwe_size = { 10 };
    LweSecretKey_u64 *sk = NO_ERR(allocate_lwe_secret_key_u64(&ERR, lwe_size));
    NO_ERR(fill_lwe_secret_key_u64(&ERR, sk, secret_gen));

    // We generate the texts
    LweCiphertext_u64 *input_ct_1 = NO_ERR(allocate_lwe_ciphertext_u64(&ERR, lwe_size));
    LweCiphertext_u64 *input_ct_2 = NO_ERR(allocate_lwe_ciphertext_u64(&ERR, lwe_size));
    LweCiphertext_u64 *output_ct = NO_ERR(allocate_lwe_ciphertext_u64(&ERR, lwe_size));
    Plaintext_u64 plaintext_1 = { ((uint64_t) 1) << SHIFT };
    Plaintext_u64 plaintext_2 = { ((uint64_t) 2) << SHIFT };
    Plaintext_u64 output = { 0 };

    // We encrypt the plaintext
    NO_ERR(encrypt_lwe_u64(&ERR, sk, input_ct_1, plaintext_1, enc_gen, variance));
    NO_ERR(encrypt_lwe_u64(&ERR, sk, input_ct_2, plaintext_2, enc_gen, variance));

    // We add the plaintext
    NO_ERR(add_lwe_ciphertexts_u64(&ERR, output_ct, input_ct_1, input_ct_2));

    // We decrypt the plaintext
    NO_ERR(decrypt_lwe_u64(&ERR, sk, output_ct, &output));

    // We check that the output are the same
    double expected = ((double)plaintext_2._0 + (double)plaintext_1._0) / pow(2, SHIFT);
    double obtained = (double) output._0 / pow(2, SHIFT);
    printf("Comparing output. Expected %f, Obtained %f\n", expected, obtained);
    double abs_diff = abs(obtained - expected);
    double rel_error = abs_diff / fmax(expected, obtained);
    assert(rel_error < 0.002);

    // We deallocate the objects
    NO_ERR(free_secret_generator(&ERR, secret_gen));
    NO_ERR(free_encryption_generator(&ERR, enc_gen));
    NO_ERR(free_lwe_secret_key_u64(&ERR, sk));
    NO_ERR(free_lwe_ciphertext_u64(&ERR, input_ct_1));
    NO_ERR(free_lwe_ciphertext_u64(&ERR, input_ct_2));
    NO_ERR(free_lwe_ciphertext_u64(&ERR, output_ct));
}