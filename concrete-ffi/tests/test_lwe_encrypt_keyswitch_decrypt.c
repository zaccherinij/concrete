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

    // We generate the keys
    LweSize input_lwe_size = { 10 };
    LweSize output_lwe_size = { 20 };
    DecompositionLevelCount level = { 10 };
    DecompositionBaseLog base_log = { 3 };
    LweSecretKey_u64 *input_sk = NO_ERR(allocate_lwe_secret_key_u64(&ERR, input_lwe_size));
    LweSecretKey_u64 *output_sk = NO_ERR(allocate_lwe_secret_key_u64(&ERR, output_lwe_size)) ;
    NO_ERR(fill_lwe_secret_key_u64(&ERR, input_sk, secret_gen));
    NO_ERR(fill_lwe_secret_key_u64(&ERR, output_sk, secret_gen));
    LweKeyswitchKey_u64 *ksk = NO_ERR(allocate_lwe_keyswitch_key_u64(&ERR,
                                                                     level,
                                                                     base_log,
                                                                     input_lwe_size,
                                                                     output_lwe_size));
    NO_ERR(fill_lwe_keyswitch_key_u64(&ERR, ksk, input_sk, output_sk, enc_gen, variance));

    // We generate the texts
    LweCiphertext_u64 *input_ct = NO_ERR(allocate_lwe_ciphertext_u64(&ERR, input_lwe_size));
    LweCiphertext_u64 *output_ct = NO_ERR(allocate_lwe_ciphertext_u64(&ERR, output_lwe_size));
    Plaintext_u64 plaintext = { ((uint64_t) 1) << SHIFT };
    Plaintext_u64 output = { 0 };

    // We encrypt the plaintext
    NO_ERR(encrypt_lwe_u64(&ERR, input_sk, input_ct, plaintext, enc_gen, variance));

    // We generate the keyswitch key and keyswitch
    NO_ERR(keyswitch_lwe_u64(&ERR, ksk, output_ct, input_ct));

    // We decrypt the plaintext
    NO_ERR(decrypt_lwe_u64(&ERR, output_sk, output_ct, &output));

    // We check that the output are the same
    double expected = (double)plaintext._0/pow(2, SHIFT);
    double obtained = (double)output._0/ pow(2,SHIFT);
    printf("Comparing output. Expected %f, Obtained %f\n", expected, obtained);
    double abs_diff = abs(obtained - expected);
    double rel_error = abs_diff / fmax(expected, obtained);
    assert(rel_error < 0.01);

    // We deallocate the objects
    NO_ERR(free_secret_generator(&ERR, secret_gen));
    NO_ERR(free_encryption_generator(&ERR, enc_gen));
    NO_ERR(free_lwe_secret_key_u64(&ERR, input_sk));
    NO_ERR(free_lwe_secret_key_u64(&ERR, output_sk));
    NO_ERR(free_lwe_keyswitch_key_u64(&ERR, ksk));
    NO_ERR(free_lwe_ciphertext_u64(&ERR, input_ct));
    NO_ERR(free_lwe_ciphertext_u64(&ERR, output_ct));

}
