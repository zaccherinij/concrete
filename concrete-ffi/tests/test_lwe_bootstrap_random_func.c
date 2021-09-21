#include "concrete-ffi.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <tgmath.h>

#define NO_ERR(s) \
        s;        \
        assert(ERR == 0);

const int PRECISION = 7;
const int SHIFT = 64 - (PRECISION + 1);
const uint64_t TABLE_INDEX = 5;

int main(void)
{
        int ERR = 0;

        // We generate the random sources
        SecretRandomGenerator *secret_gen = NO_ERR(allocate_secret_generator(&ERR, 0, 0));
        EncryptionRandomGenerator *enc_gen = NO_ERR(allocate_encryption_generator(&ERR, 0, 0));
        Variance variance = {0.00000000000000000};

        // We generate the keys for BS
        LweSize input_bs_lwe_size = {818};
        LweSecretKey_u64 *input_bs_lwe_sk = NO_ERR(allocate_lwe_secret_key_u64(&ERR, input_bs_lwe_size));
        GlweSize glwe_size = {1};
        PolynomialSize poly_size = {1 << 12};
        GlweSecretKey_u64 *glwe_sk = NO_ERR(allocate_glwe_secret_key_u64(&ERR, glwe_size, poly_size));
        DecompositionLevelCount bs_level = {2};
        DecompositionBaseLog bs_base_log = {15};
        LweBootstrapKey_u64 *bsk = NO_ERR(allocate_lwe_bootstrap_key_u64(
            &ERR,
            bs_level,
            bs_base_log,
            glwe_size,
            input_bs_lwe_size,
            poly_size));
        NO_ERR(fill_lwe_bootstrap_key_u64(&ERR, bsk, input_bs_lwe_sk, glwe_sk, enc_gen, variance));
        LweSize output_lwe_size = {(glwe_size._0 - 1) * poly_size._0 + 1};
        LweSecretKey_u64 *output_lwe_sk = NO_ERR(allocate_lwe_secret_key_u64(&ERR, output_lwe_size));
        NO_ERR(fill_lwe_secret_key_with_glwe_secret_key_u64(&ERR, output_lwe_sk, glwe_sk));

        // We generate the keys for KS
        LweSize input_ks_lwe_size = {4096};
        LweSize output_ks_lwe_size = {818};
        DecompositionLevelCount ks_level = {5};
        DecompositionBaseLog ks_base_log = {3};
        LweSecretKey_u64 *input_ks_sk = NO_ERR(allocate_lwe_secret_key_u64(&ERR, input_ks_lwe_size));
        NO_ERR(fill_lwe_secret_key_u64(&ERR, input_ks_sk, secret_gen));
        LweKeyswitchKey_u64 *ksk = NO_ERR(allocate_lwe_keyswitch_key_u64(&ERR,
                                                                         ks_level,
                                                                         ks_base_log,
                                                                         input_ks_lwe_size,
                                                                         output_ks_lwe_size));
        NO_ERR(fill_lwe_keyswitch_key_u64(&ERR, ksk, input_ks_sk, input_bs_lwe_sk, enc_gen, variance));

        // We generate the ciphertexts
        LweCiphertext_u64 *input_ks_ct = NO_ERR(allocate_lwe_ciphertext_u64(&ERR, input_ks_lwe_size));
        LweCiphertext_u64 *output_ks_ct = NO_ERR(allocate_lwe_ciphertext_u64(&ERR, output_ks_lwe_size));
        LweCiphertext_u64 *output_bs_ct = NO_ERR(allocate_lwe_ciphertext_u64(&ERR, output_lwe_size));
        Plaintext_u64 plaintext = {((uint64_t)TABLE_INDEX) << SHIFT};
        NO_ERR(encrypt_lwe_u64(&ERR, input_ks_sk, input_ks_ct, plaintext, enc_gen, variance));

        // We Keyswitch
        NO_ERR(keyswitch_lwe_u64(&ERR, ksk, output_ks_ct, input_ks_ct));

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
        assert(tabulation_length == 128);
        uint64_t tabulated_function_array[128] = {13, 58, 38, 58, 15, 15, 77, 86, 80, 94, 108, 27, 126, 60, 65, 95, 50, 79, 22, 97, 38,
                                                  60, 25, 48, 73, 112, 27, 45, 88, 20, 67, 17, 16, 6, 71, 60, 77, 43, 93, 40, 41, 31, 99,
                                                  122, 120, 40, 94, 13, 111, 44, 96, 62, 108, 91, 34, 90, 103, 58, 3, 103, 19, 69, 55,
                                                  108, 0, 111, 113, 0, 0, 73, 22, 52, 81, 2, 88, 76, 36, 121, 97, 121, 123, 79, 82, 120,
                                                  12, 65, 54, 101, 90, 52, 84, 106, 23, 15, 110, 79, 85, 101, 30, 61, 104, 35, 81, 30,
                                                  98, 44, 111, 32, 68, 18, 45, 123, 84, 80, 68, 27, 31, 38, 126, 61, 51, 7, 49, 37, 63,
                                                  114, 22, 18};
        for (int i = 0; i < tabulation_length; i++)
        {
                tabulated_function_array[i] = tabulated_function_array[i] << SHIFT;
        }
        ForeignPlaintextList_u64 *tabulated_function = NO_ERR(foreign_plaintext_list_u64(
            &ERR,
            tabulated_function_array,
            tabulation_length));
        NO_ERR(fill_plaintext_list_with_expansion_u64(&ERR, plaintext_list, tabulated_function));
        NO_ERR(add_plaintext_list_glwe_ciphertext_u64(&ERR, accumulator, _accumulator, plaintext_list));

        // We perform the bootstrap
        NO_ERR(bootstrap_lwe_u64(&ERR, bsk, output_bs_ct, output_ks_ct, accumulator));
        Plaintext_u64 output = {0};
        NO_ERR(decrypt_lwe_u64(&ERR, output_lwe_sk, output_bs_ct, &output));

        // We check that the output are the same
        double expected = (double)(tabulated_function_array[plaintext._0 >> SHIFT]) / pow(2, SHIFT);
        double obtained = (double)(output._0) / pow(2, SHIFT);
        printf("Expected: %f, Obtained: %f\n", expected, obtained);
        double abs_diff = abs(obtained - expected);
        double rel_error = abs_diff / fmax(expected, obtained);
        assert(rel_error < 0.001);

        // We deallocate the objects
        NO_ERR(free_secret_generator(&ERR, secret_gen));
        NO_ERR(free_encryption_generator(&ERR, enc_gen));
        NO_ERR(free_glwe_secret_key_u64(&ERR, glwe_sk));
        NO_ERR(free_lwe_secret_key_u64(&ERR, input_bs_lwe_sk));
        NO_ERR(free_lwe_secret_key_u64(&ERR, output_lwe_sk));
        NO_ERR(free_lwe_bootstrap_key_u64(&ERR, bsk))
        NO_ERR(free_glwe_ciphertext_u64(&ERR, accumulator));
        NO_ERR(free_lwe_ciphertext_u64(&ERR, input_ks_ct));
        NO_ERR(free_lwe_ciphertext_u64(&ERR, output_ks_ct));
        NO_ERR(free_lwe_ciphertext_u64(&ERR, output_bs_ct));
        NO_ERR(free_plaintext_list_u64(&ERR, plaintext_list));
}