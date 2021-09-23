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

        // default v0 parameters
        GlweSize k = {1};
        PolynomialSize polynomialSize = {1 << 12};
        LweSize nBig = {k._0 * polynomialSize._0};
        LweSize nSmall = {818};
        DecompositionLevelCount brLevel = {2};
        DecompositionBaseLog brBaseLog = {15};
        DecompositionLevelCount ksLevel = {5};
        DecompositionBaseLog ksBaseLog = {3};
        //GlweSize k = {2};
        //PolynomialSize polynomialSize = {1024};
        //LweSize nBig = {k._0 * polynomialSize._0};
        //LweSize nSmall = {600};
        //DecompositionLevelCount brLevel = {4};
        //DecompositionBaseLog brBaseLog = {7};
        //DecompositionLevelCount ksLevel = {5};
        //DecompositionBaseLog ksBaseLog = {3};
        Variance variance = {0.};

        // We generate the random sources
        SecretRandomGenerator *secret_gen = NO_ERR(allocate_secret_generator(&ERR, 0, 0));
        EncryptionRandomGenerator *enc_gen = NO_ERR(allocate_encryption_generator(&ERR, 0, 0));

        // We generate the lwe SK
        LweSecretKey_u64 *nBigSK = NO_ERR(allocate_lwe_secret_key_u64(&ERR, nBig));
        NO_ERR(fill_lwe_secret_key_u64(&ERR, nBigSK, secret_gen));

        LweSecretKey_u64 *nSmallSK = NO_ERR(allocate_lwe_secret_key_u64(&ERR, nSmall));
        NO_ERR(fill_lwe_secret_key_u64(&ERR, nSmallSK, secret_gen));

        // We generate the keys for KS
        LweKeyswitchKey_u64 *ksk = NO_ERR(allocate_lwe_keyswitch_key_u64(&ERR,
                                                                         ksLevel,
                                                                         ksBaseLog,
                                                                         nBig,
                                                                         nSmall));
        NO_ERR(fill_lwe_keyswitch_key_u64(&ERR, ksk, nBigSK, nSmallSK, enc_gen, variance));

        // We generate the keys for BS

        GlweSecretKey_u64 *glwe_sk = NO_ERR(allocate_glwe_secret_key_u64(&ERR, k, polynomialSize));

        LweBootstrapKey_u64 *bsk = NO_ERR(allocate_lwe_bootstrap_key_u64(
            &ERR,
            brLevel,
            brBaseLog,
            k,
            nSmall,
            polynomialSize));
        NO_ERR(fill_lwe_bootstrap_key_u64(&ERR, bsk, nSmallSK, glwe_sk, enc_gen, variance));
        LweSize output_lwe_size = {(k._0 - 1) * polynomialSize._0 + 1};
        LweSecretKey_u64 *output_lwe_sk = NO_ERR(allocate_lwe_secret_key_u64(&ERR, output_lwe_size));
        NO_ERR(fill_lwe_secret_key_with_glwe_secret_key_u64(&ERR, output_lwe_sk, glwe_sk));



        for (size_t i = 0; i < 10000; i++) {

            // We generate the ciphertexts
            LweCiphertext_u64 *input_ks_ct = NO_ERR(allocate_lwe_ciphertext_u64(&ERR, nBig));
            LweCiphertext_u64 *output_ks_ct = NO_ERR(allocate_lwe_ciphertext_u64(&ERR, nSmall));
            LweCiphertext_u64 *output_bs_ct = NO_ERR(allocate_lwe_ciphertext_u64(&ERR, output_lwe_size));
            Plaintext_u64 plaintext = {((uint64_t)TABLE_INDEX) << SHIFT};

           /* {
                // WITH KEYSWITCH
                NO_ERR(encrypt_lwe_u64(&ERR, nBigSK, input_ks_ct, plaintext, enc_gen, variance));

                // We Keyswitch
                NO_ERR(keyswitch_lwe_u64(&ERR, ksk, output_ks_ct, input_ks_ct));

                // Check the keyswitched ct
                Plaintext_u64 tmp = {0};
                NO_ERR(decrypt_lwe_u64(&ERR, nSmallSK, output_ks_ct, &tmp));
                uint64_t tmpDecoded = tmp._0 >> (64 - PRECISION - 2);
                size_t tmpCarry = tmpDecoded % 2;
                tmpDecoded = ((tmpDecoded >> 1)+ tmpCarry) % (1 << (PRECISION + 1));
                printf("TMP Obtained: %lu, Iteration:%d\n", tmpDecoded, i);
            }*/

           {
               // WITH NO KEYSWITCH 
                NO_ERR(encrypt_lwe_u64(&ERR, nSmallSK, output_ks_ct, plaintext, enc_gen, variance));
           }

            // We generate the accumulator
            GlweCiphertext_u64 *accumulator = NO_ERR(allocate_glwe_ciphertext_u64(
                &ERR,
                k,
                polynomialSize));
            GlweCiphertext_u64 *_accumulator = NO_ERR(allocate_glwe_ciphertext_u64(
                &ERR,
                k,
                polynomialSize));
            PlaintextCount count = {polynomialSize._0};
            PlaintextList_u64 *plaintext_list = NO_ERR(allocate_plaintext_list_u64(&ERR, count));
            int tabulation_length = 1 << PRECISION;
            assert(tabulation_length == 128);
            uint64_t tabulated_function_array[128];// = {16, 91, 16, 83, 80, 74, 21, 96, 1, 63, 49, 122, 76, 89, 74, 55, 109, 110, 103, 54, 105, 14, 66, 47, 52, 89, 7, 10, 73, 44, 119, 92, 25, 104, 123, 100, 108, 86, 29, 121, 118, 52, 107, 48, 34, 37, 13, 122, 107, 48, 74, 59, 96, 36, 50, 55, 120, 72, 27, 45, 12, 5, 96, 12, 24, 90, 112, 121, 68, 125, 72, 36, 0, 13, 66, 64, 18, 3, 55, 102, 116, 100, 116, 59, 94, 12, 12, 41, 3, 120, 89, 69, 71, 125, 105, 113, 4, 11, 72, 38, 88, 54, 80, 84, 64, 23, 16, 13, 36, 50, 76, 55, 115, 115, 96, 37, 60, 96, 44, 31, 111, 78, 0, 5, 23, 41, 127, 6};
            for (int i = 0; i < tabulation_length; i++)
            {
                    tabulated_function_array[i] = ((uint64_t) i) << SHIFT;
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
            uint64_t expected = tabulated_function_array[plaintext._0 >> SHIFT] >> SHIFT;
            //uint64_t obtained = output._0 >> SHIFT;
            // Decode
            uint64_t obtained = output._0 >> (64 - PRECISION - 2);
            size_t carry = obtained % 2;
            obtained = ((obtained >> 1)+ carry) % (1 << (PRECISION + 1));
            printf("Expected: %lu, Obtained: %lu, Iteration:%d\n", expected, obtained, i);
            assert(expected == obtained);
        }
        // We deallocate the objects
        //NO_ERR(free_secret_generator(&ERR, secret_gen));
        //NO_ERR(free_encryption_generator(&ERR, enc_gen));
        //NO_ERR(free_glwe_secret_key_u64(&ERR, glwe_sk));
        //NO_ERR(free_lwe_secret_key_u64(&ERR, nSmallSK));
        //NO_ERR(free_lwe_secret_key_u64(&ERR, output_lwe_sk));
        //NO_ERR(free_lwe_bootstrap_key_u64(&ERR, bsk))
        //NO_ERR(free_glwe_ciphertext_u64(&ERR, accumulator));
        //NO_ERR(free_lwe_ciphertext_u64(&ERR, input_ks_ct));
        //NO_ERR(free_lwe_ciphertext_u64(&ERR, output_ks_ct));
        //NO_ERR(free_lwe_ciphertext_u64(&ERR, output_bs_ct));
        //NO_ERR(free_plaintext_list_u64(&ERR, plaintext_list));
}