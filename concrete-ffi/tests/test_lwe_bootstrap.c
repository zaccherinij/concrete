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

    // We generate the keys
    LweSize input_lwe_size = {600};
    LweSecretKey_u64 *input_lwe_sk = NO_ERR(allocate_lwe_secret_key_u64(&ERR, input_lwe_size));
    GlweSize glwe_size = { 2 };
    PolynomialSize poly_size = { 1024 };
    GlweSecretKey_u64 *glwe_sk = NO_ERR(allocate_glwe_secret_key_u64(&ERR, glwe_size, poly_size));
    DecompositionLevelCount level = {4 };
    DecompositionBaseLog base_log = {7 };
    LweBootstrapKey_u64 *bsk = NO_ERR(allocate_lwe_bootstrap_key_u64(
            &ERR,
            level,
            base_log,
            glwe_size,
            input_lwe_size,
            poly_size));
    NO_ERR(fill_lwe_bootstrap_key_u64(&ERR, bsk, input_lwe_sk, glwe_sk, enc_gen, variance));
    LweSize output_lwe_size = { (glwe_size._0 -1) * poly_size._0 + 1};
    LweSecretKey_u64 *output_lwe_sk = NO_ERR(allocate_lwe_secret_key_u64(&ERR, output_lwe_size));
    NO_ERR(fill_lwe_secret_key_with_glwe_secret_key_u64(&ERR, output_lwe_sk, glwe_sk));

    // We generate the ciphertexts
    LweCiphertext_u64 *input_ct = NO_ERR(allocate_lwe_ciphertext_u64(&ERR, input_lwe_size));
    LweCiphertext_u64 *output_ct = NO_ERR(allocate_lwe_ciphertext_u64(&ERR, output_lwe_size));
    Plaintext_u64 plaintext = { ((uint64_t) 4) << SHIFT };
    NO_ERR(encrypt_lwe_u64(&ERR, input_lwe_sk, input_ct, plaintext, enc_gen, variance));

    // We generate the accumulator
    GlweCiphertext_u64 *accumulator = NO_ERR(allocate_glwe_ciphertext_u64(
            &ERR,
            glwe_size,
            poly_size));
    GlweCiphertext_u64 *_accumulator = NO_ERR(allocate_glwe_ciphertext_u64(
            &ERR,
            glwe_size,
            poly_size));
    PlaintextCount count = {poly_size._0};
    PlaintextList_u64 *plaintext_list = NO_ERR(allocate_plaintext_list_u64(&ERR, count));
    int tabulation_length = 1 << PRECISION;
    uint64_t *tabulated_function_array = malloc(sizeof(uint64_t) * tabulation_length);
    for (int i = 0; i<tabulation_length; i++){
        tabulated_function_array[i] = ((uint64_t) i) << SHIFT;
    }
    ForeignPlaintextList_u64 *tabulated_function = NO_ERR(foreign_plaintext_list_u64(
            &ERR,
            tabulated_function_array,
            tabulation_length));
    NO_ERR(fill_plaintext_list_with_expansion_u64(&ERR, plaintext_list, tabulated_function));
    NO_ERR(add_plaintext_list_glwe_ciphertext_u64(&ERR, accumulator, _accumulator, plaintext_list));

    // We perform the bootstrap
    NO_ERR(bootstrap_lwe_u64(&ERR, bsk, output_ct, input_ct, accumulator));
    Plaintext_u64 output = { 0 };
    NO_ERR(decrypt_lwe_u64(&ERR, output_lwe_sk, output_ct, &output));

    // We check that the output are the same
    double expected = (double)(plaintext._0) / pow(2, SHIFT);
    double obtained = (double)(output._0) / pow(2, SHIFT);
    printf("Expected: %f, Obtained: %f\n", expected, obtained);
    double abs_diff = abs(obtained - expected);
    double rel_error = abs_diff / fmax(expected, obtained);
//    assert(rel_error < 0.001);

    // We deallocate the objects
    NO_ERR(free_secret_generator(&ERR, secret_gen));
    NO_ERR(free_encryption_generator(&ERR, enc_gen));
    NO_ERR(free_glwe_secret_key_u64(&ERR, glwe_sk));
    NO_ERR(free_lwe_secret_key_u64(&ERR, input_lwe_sk));
    NO_ERR(free_lwe_secret_key_u64(&ERR, output_lwe_sk));
    NO_ERR(free_lwe_bootstrap_key_u64(&ERR, bsk))
    NO_ERR(free_glwe_ciphertext_u64(&ERR, accumulator));
    NO_ERR(free_lwe_ciphertext_u64(&ERR, input_ct));
    NO_ERR(free_lwe_ciphertext_u64(&ERR, output_ct));
    NO_ERR(free_plaintext_list_u64(&ERR, plaintext_list));
}