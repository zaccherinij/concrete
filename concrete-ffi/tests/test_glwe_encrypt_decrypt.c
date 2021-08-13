#include "concrete-ffi.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <tgmath.h>

#define NO_ERR(s) s; assert(ERR==0);

const int PRECISION = 4;
const int SHIFT = 64 - (PRECISION + 1);

int main(void)
{
    int ERR = 0;

    // We generate the random sources
    SecretRandomGenerator * secret_gen = NO_ERR(allocate_secret_generator(&ERR, 0, 0));
    EncryptionRandomGenerator *enc_gen = NO_ERR(allocate_encryption_generator(&ERR, 0, 0));
    Variance variance = { 0.000000001 };

    // We generate the key
    GlweSize glwe_size = { 10 };
    PolynomialSize poly_size = { 3 };
    GlweSecretKey_u64 *sk = NO_ERR(allocate_glwe_secret_key_u64(&ERR, glwe_size, poly_size));
    NO_ERR(fill_glwe_secret_key_u64(&ERR, sk, secret_gen));

    // We generate the texts
    GlweCiphertext_u64 *ciphertext = NO_ERR(allocate_glwe_ciphertext_u64(&ERR, glwe_size,
                                                                         poly_size));
    PlaintextCount count = {3};
    PlaintextList_u64 *plaintext_list =NO_ERR(allocate_plaintext_list_u64(&ERR, count));
    NO_ERR(set_plaintext_list_element_u64(&ERR, plaintext_list, 0, ((uint64_t) 1) << SHIFT));
    NO_ERR(set_plaintext_list_element_u64(&ERR, plaintext_list, 1, ((uint64_t) 2) << SHIFT));
    NO_ERR(set_plaintext_list_element_u64(&ERR, plaintext_list, 2, ((uint64_t) 3) << SHIFT));
    PlaintextList_u64 *output_list =NO_ERR(allocate_plaintext_list_u64(&ERR, count));

    // We encrypt the plaintext
    NO_ERR(encrypt_glwe_u64(&ERR, sk, ciphertext, plaintext_list, enc_gen, variance));

    // We decrypt the plaintext
    NO_ERR(decrypt_glwe_u64(&ERR, sk, output_list, ciphertext));

    // We check that the output are the same as the plaintexts
    for (int i = 0; i < 3; ++i) {
        uint64_t plaintext = NO_ERR(get_plaintext_list_element_u64(&ERR,plaintext_list,i));
        uint64_t output = NO_ERR(get_plaintext_list_element_u64(&ERR,output_list,i));
        double expected = (double)plaintext / pow(2, SHIFT);
        double obtained = (double)output / pow(2, SHIFT);
        printf("Comparing %i-th component. Expected %f, Obtained %f\n", i, expected, obtained);
        double abs_diff = abs(obtained - expected);
        double rel_error = abs_diff / fmax(expected, obtained);
        assert(rel_error < 0.001);
    }

    // We deallocate the objects
    NO_ERR(free_secret_generator(&ERR, secret_gen));
    NO_ERR(free_encryption_generator(&ERR, enc_gen));
    NO_ERR(free_glwe_secret_key_u64(&ERR, sk));
    NO_ERR(free_glwe_ciphertext_u64(&ERR, ciphertext));
    NO_ERR(free_plaintext_list_u64(&ERR, plaintext_list));
    NO_ERR(free_plaintext_list_u64(&ERR, output_list));
}