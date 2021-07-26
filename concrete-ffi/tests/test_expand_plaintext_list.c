#include "concrete-ffi.h"
#include <stdlib.h>
#include <assert.h>

#define NO_ERR(s) s; assert(ERR==0);

int main(void)
{
    int ERR = 0;

    // We initialize the plaintexts
    u_int64_t plaintext_list_array[5] = {1, 2, 3, 4, 5};
    ForeignPlaintextList_u64 *plaintext_list =NO_ERR(foreign_plaintext_list_u64(&ERR, plaintext_list_array, 5));
    PlaintextCount count = {10};
    PlaintextList_u64 *expanded_plaintext_list =NO_ERR(allocate_plaintext_list_u64(&ERR, count));

    // We expand the foreign plaintext
    NO_ERR(fill_plaintext_list_with_expansion_u64(&ERR, expanded_plaintext_list, plaintext_list));

    // We check the values
    int val = 0;
    val = NO_ERR(get_plaintext_list_element_u64(&ERR, expanded_plaintext_list, 0));
    assert(val == 1);
    val = NO_ERR(get_plaintext_list_element_u64(&ERR, expanded_plaintext_list, 1));
    assert(val == 2);
    val = NO_ERR(get_plaintext_list_element_u64(&ERR, expanded_plaintext_list, 2));
    assert(val == 2);
    val = NO_ERR(get_plaintext_list_element_u64(&ERR, expanded_plaintext_list, 3));
    assert(val == 3);
    val = NO_ERR(get_plaintext_list_element_u64(&ERR, expanded_plaintext_list, 4));
    assert(val == 3);
    val = NO_ERR(get_plaintext_list_element_u64(&ERR, expanded_plaintext_list, 5));
    assert(val == 4);
    val = NO_ERR(get_plaintext_list_element_u64(&ERR, expanded_plaintext_list, 6));
    assert(val == 4);
    val = NO_ERR(get_plaintext_list_element_u64(&ERR, expanded_plaintext_list, 7));
    assert(val == 5);
    val = NO_ERR(get_plaintext_list_element_u64(&ERR, expanded_plaintext_list, 8));
    assert(val == 5);
    val = NO_ERR(get_plaintext_list_element_u64(&ERR, expanded_plaintext_list, 9));
    assert(val == -1);

    // We deallocate the objects
    NO_ERR(free_plaintext_list_u64(&ERR, expanded_plaintext_list));
}