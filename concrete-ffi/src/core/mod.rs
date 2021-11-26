#![allow(clippy::missing_safety_doc)]
use concrete_commons::dispersion::Variance;
use concrete_commons::key_kinds::BinaryKeyKind;
use concrete_commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweSize, PlaintextCount,
    PolynomialSize,
};
use concrete_core::crypto::bootstrap::{
    Bootstrap, FourierBootstrapKey as CoreFourierBootstrapKey,
    StandardBootstrapKey as CoreStandardBootstrapKey,
};
use concrete_core::crypto::encoding::{Cleartext, Plaintext, PlaintextList as CorePlaintextList};
use concrete_core::crypto::glwe::GlweCiphertext as CoreGlweCiphertext;
use concrete_core::crypto::lwe::{
    LweCiphertext as CoreLweCiphertext, LweKeyswitchKey as CoreLweKeyswitchKey,
};
use concrete_core::crypto::secret::generators::{
    EncryptionRandomGenerator as CoreEncryptionRandomGenerator,
    SecretRandomGenerator as CoreSecretRandomGenerator,
};
use concrete_core::crypto::secret::{
    GlweSecretKey as CoreGlweSecretKey, LweSecretKey as CoreLweSecretKey,
};
use concrete_core::math::fft::{AlignedVec, Complex64};
use concrete_core::math::polynomial::{MonomialDegree, Polynomial};
use concrete_core::math::tensor::{AsMutSlice, AsMutTensor, AsRefSlice, AsRefTensor};
use concrete_core::math::torus::UnsignedTorus;
use std::os::raw::c_int;
use std::sync::Arc;

////////////////////////////////////////////////////////////////////////////////////////////////////

macro_rules! set_err {
    ($err: ident, $val: ident) => {
        $err.as_mut().map(|e| *e = $val);
    };
}

macro_rules! boxmut {
    ($val: ident) => {
        Box::into_raw(Box::new($val))
    };
}

macro_rules! free {
    ($val: ident) => {{
        let _ = Box::from_raw($val);
    }};
}

macro_rules! pointers_null{
    ($($ptr: ident),*) => {
        $($ptr.is_null())||*
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////

pub const ERR_NO_ERR: c_int = 0;
pub const ERR_NULL_POINTER: c_int = -1;
pub const ERR_SIZE_MISMATCH: c_int = -2;
pub const ERR_INDEX_OUT_OF_BOUND: c_int = -3;

////////////////////////////////////////////////////////////////////////////////////////////////////

// This type does this and that.
pub struct LweCiphertext<T: UnsignedTorus>(CoreLweCiphertext<Vec<T>>);

unsafe fn allocate_lwe_ciphertext<T: UnsignedTorus>(
    err: *mut c_int,
    size: LweSize,
) -> *mut LweCiphertext<T> {
    let ciphertext = LweCiphertext(CoreLweCiphertext::allocate(T::ZERO, size));
    set_err!(err, ERR_NO_ERR);
    boxmut!(ciphertext)
}

#[no_mangle]
pub unsafe extern "C" fn allocate_lwe_ciphertext_u64(
    err: *mut c_int,
    size: LweSize,
) -> *mut LweCiphertext<u64> {
    allocate_lwe_ciphertext(err, size)
}

#[no_mangle]
pub unsafe extern "C" fn allocate_lwe_ciphertext_u32(
    err: *mut c_int,
    size: LweSize,
) -> *mut LweCiphertext<u32> {
    allocate_lwe_ciphertext(err, size)
}

#[no_mangle]
pub unsafe extern "C" fn free_lwe_ciphertext_u64(
    err: *mut c_int,
    ciphertext: *mut LweCiphertext<u64>,
) {
    if pointers_null!(ciphertext) {
        set_err!(err, ERR_NULL_POINTER);
        return;
    }
    free!(ciphertext);
    set_err!(err, ERR_NO_ERR);
}

#[no_mangle]
pub unsafe extern "C" fn free_lwe_ciphertext_u32(
    err: *mut c_int,
    ciphertext: *mut LweCiphertext<u32>,
) {
    if pointers_null!(ciphertext) {
        set_err!(err, ERR_NULL_POINTER);
        return;
    }
    free!(ciphertext);
    set_err!(err, ERR_NO_ERR);
}

unsafe fn negate_lwe_ciphertext<T: UnsignedTorus>(
    err: *mut c_int,
    output_ciphertext: *mut LweCiphertext<T>,
    input_ciphertext: *const LweCiphertext<T>,
) {
    if pointers_null!(output_ciphertext, input_ciphertext) {
        set_err!(err, ERR_NULL_POINTER);
        return;
    }
    let output_ciphertext = output_ciphertext.as_mut().unwrap();
    let input_ciphertext = input_ciphertext.as_ref().unwrap();
    output_ciphertext.0.fill_with_neg(&input_ciphertext.0);
    set_err!(err, ERR_NO_ERR);
}

#[no_mangle]
pub unsafe extern "C" fn negate_lwe_ciphertext_u32(
    err: *mut c_int,
    output_ciphertext: *mut LweCiphertext<u32>,
    input_ciphertext: *const LweCiphertext<u32>,
) {
    negate_lwe_ciphertext(err, output_ciphertext, input_ciphertext);
}

#[no_mangle]
pub unsafe extern "C" fn negate_lwe_ciphertext_u64(
    err: *mut c_int,
    output_ciphertext: *mut LweCiphertext<u64>,
    input_ciphertext: *const LweCiphertext<u64>,
) {
    negate_lwe_ciphertext(err, output_ciphertext, input_ciphertext);
}

unsafe fn add_plaintext_lwe_ciphertext<T: UnsignedTorus>(
    err: *mut c_int,
    output_ciphertext: *mut LweCiphertext<T>,
    input_ciphertext: *const LweCiphertext<T>,
    plaintext: Plaintext<T>,
) {
    if pointers_null!(output_ciphertext, input_ciphertext) {
        set_err!(err, ERR_NULL_POINTER);
        return;
    }
    let output_ciphertext = output_ciphertext.as_mut().unwrap();
    let input_ciphertext = input_ciphertext.as_ref().unwrap();
    output_ciphertext
        .0
        .fill_with_scalar_add(&input_ciphertext.0, &plaintext);
    set_err!(err, ERR_NO_ERR);
}

#[no_mangle]
pub unsafe extern "C" fn add_plaintext_lwe_ciphertext_u32(
    err: *mut c_int,
    output_ciphertext: *mut LweCiphertext<u32>,
    input_ciphertext: *const LweCiphertext<u32>,
    plaintext: Plaintext<u32>,
) {
    add_plaintext_lwe_ciphertext(err, output_ciphertext, input_ciphertext, plaintext)
}

#[no_mangle]
pub unsafe extern "C" fn add_plaintext_lwe_ciphertext_u64(
    err: *mut c_int,
    output_ciphertext: *mut LweCiphertext<u64>,
    input_ciphertext: *const LweCiphertext<u64>,
    plaintext: Plaintext<u64>,
) {
    add_plaintext_lwe_ciphertext(err, output_ciphertext, input_ciphertext, plaintext)
}

unsafe fn mul_cleartext_lwe_ciphertext<T: UnsignedTorus>(
    err: *mut c_int,
    output_ciphertext: *mut LweCiphertext<T>,
    input_ciphertext: *const LweCiphertext<T>,
    cleartext: Cleartext<T>,
) {
    if pointers_null!(output_ciphertext, input_ciphertext) {
        set_err!(err, ERR_NULL_POINTER);
        return;
    }
    let output_ciphertext = output_ciphertext.as_mut().unwrap();
    let input_ciphertext = input_ciphertext.as_ref().unwrap();
    output_ciphertext
        .0
        .fill_with_scalar_mul(&input_ciphertext.0, &cleartext);
    set_err!(err, ERR_NO_ERR);
}

#[no_mangle]
pub unsafe extern "C" fn mul_cleartext_lwe_ciphertext_u32(
    err: *mut c_int,
    output_ciphertext: *mut LweCiphertext<u32>,
    input_ciphertext: *const LweCiphertext<u32>,
    cleartext: Cleartext<u32>,
) {
    mul_cleartext_lwe_ciphertext(err, output_ciphertext, input_ciphertext, cleartext)
}

#[no_mangle]
pub unsafe extern "C" fn mul_cleartext_lwe_ciphertext_u64(
    err: *mut c_int,
    output_ciphertext: *mut LweCiphertext<u64>,
    input_ciphertext: *const LweCiphertext<u64>,
    cleartext: Cleartext<u64>,
) {
    mul_cleartext_lwe_ciphertext(err, output_ciphertext, input_ciphertext, cleartext)
}

unsafe fn add_lwe_ciphertexts<T: UnsignedTorus>(
    err: *mut c_int,
    output_ciphertext: *mut LweCiphertext<T>,
    input_ciphertext_1: *const LweCiphertext<T>,
    input_ciphertext_2: *const LweCiphertext<T>,
) {
    if pointers_null!(output_ciphertext, input_ciphertext_1, input_ciphertext_2) {
        set_err!(err, ERR_NULL_POINTER);
        return;
    }
    let output_ciphertext = output_ciphertext.as_mut().unwrap();
    let input_ciphertext_1 = input_ciphertext_1.as_ref().unwrap();
    let input_ciphertext_2 = input_ciphertext_2.as_ref().unwrap();
    output_ciphertext
        .0
        .fill_with_add(&input_ciphertext_1.0, &input_ciphertext_2.0);
    set_err!(err, ERR_NO_ERR);
}

#[no_mangle]
pub unsafe extern "C" fn add_lwe_ciphertexts_u32(
    err: *mut c_int,
    output_ciphertext: *mut LweCiphertext<u32>,
    input_ciphertext_1: *const LweCiphertext<u32>,
    input_ciphertext_2: *const LweCiphertext<u32>,
) {
    add_lwe_ciphertexts(
        err,
        output_ciphertext,
        input_ciphertext_1,
        input_ciphertext_2,
    )
}

#[no_mangle]
pub unsafe extern "C" fn add_lwe_ciphertexts_u64(
    err: *mut c_int,
    output_ciphertext: *mut LweCiphertext<u64>,
    input_ciphertext_1: *const LweCiphertext<u64>,
    input_ciphertext_2: *const LweCiphertext<u64>,
) {
    add_lwe_ciphertexts(
        err,
        output_ciphertext,
        input_ciphertext_1,
        input_ciphertext_2,
    )
}

////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct GlweCiphertext<T: UnsignedTorus>(CoreGlweCiphertext<Vec<T>>);

unsafe fn allocate_glwe_ciphertext<T: UnsignedTorus>(
    err: *mut c_int,
    size: GlweSize,
    poly_size: PolynomialSize,
) -> *mut GlweCiphertext<T> {
    let ciphertext = GlweCiphertext(CoreGlweCiphertext::allocate(T::ZERO, poly_size, size));
    set_err!(err, ERR_NO_ERR);
    boxmut!(ciphertext)
}

#[no_mangle]
pub unsafe extern "C" fn allocate_glwe_ciphertext_u64(
    err: *mut c_int,
    size: GlweSize,
    poly_size: PolynomialSize,
) -> *mut GlweCiphertext<u64> {
    allocate_glwe_ciphertext(err, size, poly_size)
}

#[no_mangle]
pub unsafe extern "C" fn allocate_glwe_ciphertext_u32(
    err: *mut c_int,
    size: GlweSize,
    poly_size: PolynomialSize,
) -> *mut GlweCiphertext<u32> {
    allocate_glwe_ciphertext(err, size, poly_size)
}

unsafe fn add_plaintext_list_glwe_ciphertext<T: UnsignedTorus>(
    err: *mut c_int,
    output_ciphertext: *mut GlweCiphertext<T>,
    input_ciphertext: *const GlweCiphertext<T>,
    plaintext_list: *const PlaintextList<T>,
) {
    if pointers_null!(output_ciphertext, input_ciphertext, plaintext_list) {
        set_err!(err, ERR_NULL_POINTER);
        return;
    }
    let output_ciphertext = output_ciphertext.as_mut().unwrap();
    let input_ciphertext = input_ciphertext.as_ref().unwrap();
    let plaintext_list = plaintext_list.as_ref().unwrap();
    output_ciphertext
        .0
        .fill_with_plaintext_list_add(&input_ciphertext.0, &plaintext_list.0);
    set_err!(err, ERR_NO_ERR);
}

#[no_mangle]
pub unsafe extern "C" fn add_plaintext_list_glwe_ciphertext_u32(
    err: *mut c_int,
    output_ciphertext: *mut GlweCiphertext<u32>,
    input_ciphertext: *const GlweCiphertext<u32>,
    plaintext_list: *const PlaintextList<u32>,
) {
    add_plaintext_list_glwe_ciphertext(err, output_ciphertext, input_ciphertext, plaintext_list)
}

#[no_mangle]
pub unsafe extern "C" fn add_plaintext_list_glwe_ciphertext_u64(
    err: *mut c_int,
    output_ciphertext: *mut GlweCiphertext<u64>,
    input_ciphertext: *const GlweCiphertext<u64>,
    plaintext_list: *const PlaintextList<u64>,
) {
    add_plaintext_list_glwe_ciphertext(err, output_ciphertext, input_ciphertext, plaintext_list)
}

#[no_mangle]
pub unsafe extern "C" fn free_glwe_ciphertext_u64(
    err: *mut c_int,
    ciphertext: *mut GlweCiphertext<u64>,
) {
    if pointers_null!(ciphertext) {
        set_err!(err, ERR_NULL_POINTER);
        return;
    }
    free!(ciphertext);
    set_err!(err, ERR_NO_ERR);
}

#[no_mangle]
pub unsafe extern "C" fn free_glwe_ciphertext_u32(
    err: *mut c_int,
    ciphertext: *mut GlweCiphertext<u32>,
) {
    if pointers_null!(ciphertext) {
        set_err!(err, ERR_NULL_POINTER);
        return;
    }
    free!(ciphertext);
    set_err!(err, ERR_NO_ERR);
}

////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct EncryptionRandomGenerator(CoreEncryptionRandomGenerator);

#[no_mangle]
pub unsafe extern "C" fn allocate_encryption_generator(
    err: *mut c_int,
    seed_msb: u64,
    seed_lsb: u64,
) -> *mut EncryptionRandomGenerator {
    let generator = if seed_msb == 0 && seed_lsb == 0 {
        CoreEncryptionRandomGenerator::new(None)
    } else {
        let seed = ((seed_msb as u128) << 64) + (seed_lsb as u128);
        CoreEncryptionRandomGenerator::new(Some(seed))
    };
    set_err!(err, ERR_NO_ERR);
    let output = EncryptionRandomGenerator(generator);
    boxmut!(output)
}

#[no_mangle]
pub unsafe extern "C" fn free_encryption_generator(
    err: *mut c_int,
    gen: *mut EncryptionRandomGenerator,
) {
    if pointers_null!(gen) {
        set_err!(err, ERR_NULL_POINTER);
        return;
    }
    free!(gen);
    set_err!(err, ERR_NO_ERR);
}

////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct SecretRandomGenerator(CoreSecretRandomGenerator);

#[no_mangle]
pub unsafe extern "C" fn allocate_secret_generator(
    err: *mut c_int,
    seed_msb: u64,
    seed_lsb: u64,
) -> *mut SecretRandomGenerator {
    let generator = if seed_msb == 0 && seed_lsb == 0 {
        CoreSecretRandomGenerator::new(None)
    } else {
        let seed = ((seed_msb as u128) << 64) + (seed_lsb as u128);
        CoreSecretRandomGenerator::new(Some(seed))
    };
    set_err!(err, ERR_NO_ERR);
    let output = SecretRandomGenerator(generator);
    boxmut!(output)
}

#[no_mangle]
pub unsafe extern "C" fn free_secret_generator(
    err: *mut c_int,
    generator: *mut SecretRandomGenerator,
) {
    if pointers_null!(generator) {
        set_err!(err, ERR_NULL_POINTER);
        return;
    }
    free!(generator);
    set_err!(err, ERR_NO_ERR);
}

////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct LweSecretKey<T: UnsignedTorus>(CoreLweSecretKey<BinaryKeyKind, Vec<T>>);

unsafe fn allocate_lwe_secret_key<T: UnsignedTorus>(
    err: *mut c_int,
    size: LweSize,
) -> *mut LweSecretKey<T> {
    let secret_key = CoreLweSecretKey::allocate(T::ZERO, size.to_lwe_dimension());
    set_err!(err, ERR_NO_ERR);
    let output = LweSecretKey(secret_key);
    boxmut!(output)
}

#[no_mangle]
pub unsafe extern "C" fn allocate_lwe_secret_key_u64(
    err: *mut c_int,
    size: LweSize,
) -> *mut LweSecretKey<u64> {
    allocate_lwe_secret_key(err, size)
}

#[no_mangle]
pub unsafe extern "C" fn allocate_lwe_secret_key_u32(
    err: *mut c_int,
    size: LweSize,
) -> *mut LweSecretKey<u32> {
    allocate_lwe_secret_key(err, size)
}

unsafe fn fill_lwe_secret_key<T: UnsignedTorus>(
    err: *mut c_int,
    secret_key: *mut LweSecretKey<T>,
    generator: *mut SecretRandomGenerator,
) {
    if pointers_null!(secret_key, generator) {
        set_err!(err, ERR_NULL_POINTER);
        return;
    }
    let secret_key = secret_key.as_mut().unwrap();
    let generator = generator.as_mut().unwrap();
    secret_key.0.fill_with_binary(&mut generator.0);
    set_err!(err, ERR_NO_ERR);
}

#[no_mangle]
pub unsafe extern "C" fn fill_lwe_secret_key_u64(
    err: *mut c_int,
    secret_key: *mut LweSecretKey<u64>,
    generator: *mut SecretRandomGenerator,
) {
    fill_lwe_secret_key(err, secret_key, generator);
}

#[no_mangle]
pub unsafe extern "C" fn fill_lwe_secret_key_u32(
    err: *mut c_int,
    secret_key: *mut LweSecretKey<u32>,
    generator: *mut SecretRandomGenerator,
) {
    fill_lwe_secret_key(err, secret_key, generator);
}

#[no_mangle]
pub unsafe extern "C" fn free_lwe_secret_key_u64(
    err: *mut c_int,
    secret_key: *mut LweSecretKey<u64>,
) {
    if pointers_null!(secret_key) {
        set_err!(err, ERR_NULL_POINTER);
        return;
    }
    free!(secret_key);
    set_err!(err, ERR_NO_ERR);
}

#[no_mangle]
pub unsafe extern "C" fn free_lwe_secret_key_u32(
    err: *mut c_int,
    secret_key: *mut LweSecretKey<u32>,
) {
    if pointers_null!(secret_key) {
        set_err!(err, ERR_NULL_POINTER);
        return;
    }
    free!(secret_key);
    set_err!(err, ERR_NO_ERR);
}

unsafe fn encrypt_lwe<T: UnsignedTorus>(
    err: *mut c_int,
    secret_key: *const LweSecretKey<T>,
    ciphertext: *mut LweCiphertext<T>,
    input: Plaintext<T>,
    generator: *mut EncryptionRandomGenerator,
    noise: Variance,
) {
    if pointers_null!(secret_key, ciphertext, generator) {
        set_err!(err, ERR_NULL_POINTER);
        return;
    }
    let secret_key = secret_key.as_ref().unwrap();
    let ciphertext = ciphertext.as_mut().unwrap();
    let generator = generator.as_mut().unwrap();

    assert_eq!(
        secret_key.0.as_tensor().len() + 1,
        ciphertext.0.as_tensor().len()
    );

    secret_key
        .0
        .encrypt_lwe(&mut ciphertext.0, &input, noise, &mut generator.0);
    set_err!(err, ERR_NO_ERR);
}

#[no_mangle]
pub unsafe extern "C" fn encrypt_lwe_u64(
    err: *mut c_int,
    secret_key: *const LweSecretKey<u64>,
    ciphertext: *mut LweCiphertext<u64>,
    input: Plaintext<u64>,
    generator: *mut EncryptionRandomGenerator,
    noise: Variance,
) {
    encrypt_lwe(err, secret_key, ciphertext, input, generator, noise);
}

#[no_mangle]
pub unsafe extern "C" fn encrypt_lwe_u32(
    err: *mut c_int,
    secret_key: *const LweSecretKey<u32>,
    ciphertext: *mut LweCiphertext<u32>,
    input: Plaintext<u32>,
    generator: *mut EncryptionRandomGenerator,
    noise: Variance,
) {
    encrypt_lwe(err, secret_key, ciphertext, input, generator, noise)
}

unsafe fn decrypt_lwe<T: UnsignedTorus>(
    err: *mut c_int,
    secret_key: *const LweSecretKey<T>,
    ciphertext: *const LweCiphertext<T>,
    output: *mut Plaintext<T>,
) {
    if pointers_null!(secret_key, ciphertext, output) {
        set_err!(err, ERR_NULL_POINTER);
        return;
    }
    let secret_key = secret_key.as_ref().unwrap();
    let ciphertext = ciphertext.as_ref().unwrap();
    let output = output.as_mut().unwrap();

    assert_eq!(
        secret_key.0.as_tensor().len() + 1,
        ciphertext.0.as_tensor().len()
    );

    secret_key.0.decrypt_lwe(output, &ciphertext.0);
    set_err!(err, ERR_NO_ERR);
}

#[no_mangle]
pub unsafe extern "C" fn decrypt_lwe_u64(
    err: *mut c_int,
    secret_key: *const LweSecretKey<u64>,
    ciphertext: *const LweCiphertext<u64>,
    output: *mut Plaintext<u64>,
) {
    decrypt_lwe(err, secret_key, ciphertext, output)
}

#[no_mangle]
pub unsafe extern "C" fn decrypt_lwe_u32(
    err: *mut c_int,
    secret_key: *const LweSecretKey<u32>,
    ciphertext: *const LweCiphertext<u32>,
    output: *mut Plaintext<u32>,
) {
    decrypt_lwe(err, secret_key, ciphertext, output)
}

////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct GlweSecretKey<T: UnsignedTorus>(CoreGlweSecretKey<BinaryKeyKind, Vec<T>>);

unsafe fn allocate_glwe_secret_key<T: UnsignedTorus>(
    err: *mut c_int,
    size: GlweSize,
    poly_size: PolynomialSize,
) -> *mut GlweSecretKey<T> {
    let secret_key = CoreGlweSecretKey::allocate(T::ZERO, size.to_glwe_dimension(), poly_size);
    set_err!(err, ERR_NO_ERR);
    let output = GlweSecretKey(secret_key);
    boxmut!(output)
}

#[no_mangle]
pub unsafe extern "C" fn allocate_glwe_secret_key_u64(
    err: *mut c_int,
    size: GlweSize,
    poly_size: PolynomialSize,
) -> *mut GlweSecretKey<u64> {
    allocate_glwe_secret_key(err, size, poly_size)
}

#[no_mangle]
pub unsafe extern "C" fn allocate_glwe_secret_key_u32(
    err: *mut c_int,
    size: GlweSize,
    poly_size: PolynomialSize,
) -> *mut GlweSecretKey<u32> {
    allocate_glwe_secret_key(err, size, poly_size)
}

unsafe fn fill_glwe_secret_key<T: UnsignedTorus>(
    err: *mut c_int,
    secret_key: *mut GlweSecretKey<T>,
    generator: *mut SecretRandomGenerator,
) {
    if pointers_null!(secret_key, generator) {
        set_err!(err, ERR_NULL_POINTER);
        return;
    }
    let secret_key = secret_key.as_mut().unwrap();
    let generator = generator.as_mut().unwrap();
    secret_key.0.fill_with_binary(&mut generator.0);
    set_err!(err, ERR_NO_ERR);
}

#[no_mangle]
pub unsafe extern "C" fn fill_glwe_secret_key_u64(
    err: *mut c_int,
    secret_key: *mut GlweSecretKey<u64>,
    generator: *mut SecretRandomGenerator,
) {
    fill_glwe_secret_key(err, secret_key, generator);
}

#[no_mangle]
pub unsafe extern "C" fn fill_glwe_secret_key_u32(
    err: *mut c_int,
    secret_key: *mut GlweSecretKey<u32>,
    generator: *mut SecretRandomGenerator,
) {
    fill_glwe_secret_key(err, secret_key, generator);
}

unsafe fn encrypt_glwe<T: UnsignedTorus>(
    err: *mut c_int,
    secret_key: *const GlweSecretKey<T>,
    ciphertext: *mut GlweCiphertext<T>,
    plaintext: *const PlaintextList<T>,
    generator: *mut EncryptionRandomGenerator,
    noise: Variance,
) {
    if pointers_null!(secret_key, ciphertext, plaintext) {
        set_err!(err, ERR_NULL_POINTER);
        return;
    }
    let secret_key = secret_key.as_ref().unwrap();
    let ciphertext = ciphertext.as_mut().unwrap();
    let plaintext = plaintext.as_ref().unwrap();
    let generator = generator.as_mut().unwrap();
    secret_key
        .0
        .encrypt_glwe(&mut ciphertext.0, &plaintext.0, noise, &mut generator.0);
    set_err!(err, ERR_NO_ERR);
}

#[no_mangle]
pub unsafe extern "C" fn encrypt_glwe_u32(
    err: *mut c_int,
    secret_key: *const GlweSecretKey<u32>,
    ciphertext: *mut GlweCiphertext<u32>,
    plaintext: *const PlaintextList<u32>,
    generator: *mut EncryptionRandomGenerator,
    noise: Variance,
) {
    encrypt_glwe(err, secret_key, ciphertext, plaintext, generator, noise)
}

#[no_mangle]
pub unsafe extern "C" fn encrypt_glwe_u64(
    err: *mut c_int,
    secret_key: *const GlweSecretKey<u64>,
    ciphertext: *mut GlweCiphertext<u64>,
    plaintext: *const PlaintextList<u64>,
    generator: *mut EncryptionRandomGenerator,
    noise: Variance,
) {
    encrypt_glwe(err, secret_key, ciphertext, plaintext, generator, noise)
}

unsafe fn decrypt_glwe<T: UnsignedTorus>(
    err: *mut c_int,
    secret_key: *const GlweSecretKey<T>,
    plaintext: *mut PlaintextList<T>,
    ciphertext: *const GlweCiphertext<T>,
) {
    if pointers_null!(secret_key, ciphertext, plaintext) {
        set_err!(err, ERR_NULL_POINTER);
        return;
    }
    let secret_key = secret_key.as_ref().unwrap();
    let ciphertext = ciphertext.as_ref().unwrap();
    let plaintext = plaintext.as_mut().unwrap();
    secret_key.0.decrypt_glwe(&mut plaintext.0, &ciphertext.0);
    set_err!(err, ERR_NO_ERR);
}

#[no_mangle]
pub unsafe extern "C" fn decrypt_glwe_u32(
    err: *mut c_int,
    secret_key: *const GlweSecretKey<u32>,
    plaintext: *mut PlaintextList<u32>,
    ciphertext: *const GlweCiphertext<u32>,
) {
    decrypt_glwe(err, secret_key, plaintext, ciphertext);
}

#[no_mangle]
pub unsafe extern "C" fn decrypt_glwe_u64(
    err: *mut c_int,
    secret_key: *const GlweSecretKey<u64>,
    plaintext: *mut PlaintextList<u64>,
    ciphertext: *const GlweCiphertext<u64>,
) {
    decrypt_glwe(err, secret_key, plaintext, ciphertext);
}

#[no_mangle]
pub unsafe extern "C" fn free_glwe_secret_key_u64(
    err: *mut c_int,
    secret_key: *mut GlweSecretKey<u64>,
) {
    if pointers_null!(secret_key) {
        set_err!(err, ERR_NULL_POINTER);
        return;
    }
    free!(secret_key);
    set_err!(err, ERR_NO_ERR);
}

#[no_mangle]
pub unsafe extern "C" fn free_glwe_secret_key_u32(
    err: *mut c_int,
    secret_key: *mut GlweSecretKey<u32>,
) {
    if pointers_null!(secret_key) {
        set_err!(err, ERR_NULL_POINTER);
        return;
    }
    free!(secret_key);
    set_err!(err, ERR_NO_ERR);
}

unsafe fn fill_lwe_secret_key_with_glwe_secret_key<T: UnsignedTorus>(
    err: *mut c_int,
    lwe_sk: *mut LweSecretKey<T>,
    glwe_sk: *const GlweSecretKey<T>,
) {
    if pointers_null!(lwe_sk, glwe_sk) {
        set_err!(err, ERR_NULL_POINTER);
        return;
    }
    let glwe_sk = glwe_sk.as_ref().unwrap();
    let lwe_sk = lwe_sk.as_mut().unwrap();
    if glwe_sk.0.as_tensor().len() != lwe_sk.0.as_tensor().len() {
        set_err!(err, ERR_SIZE_MISMATCH);
        return;
    }
    lwe_sk
        .0
        .as_mut_tensor()
        .as_mut_slice()
        .copy_from_slice(glwe_sk.0.as_tensor().as_slice());
    set_err!(err, ERR_NO_ERR);
}

#[no_mangle]
pub unsafe extern "C" fn fill_lwe_secret_key_with_glwe_secret_key_u32(
    err: *mut c_int,
    lwe_sk: *mut LweSecretKey<u32>,
    glwe_sk: *const GlweSecretKey<u32>,
) {
    fill_lwe_secret_key_with_glwe_secret_key(err, lwe_sk, glwe_sk);
}

#[no_mangle]
pub unsafe extern "C" fn fill_lwe_secret_key_with_glwe_secret_key_u64(
    err: *mut c_int,
    lwe_sk: *mut LweSecretKey<u64>,
    glwe_sk: *const GlweSecretKey<u64>,
) {
    fill_lwe_secret_key_with_glwe_secret_key(err, lwe_sk, glwe_sk);
}

unsafe fn fill_glwe_secret_key_with_lwe_secret_key<T: UnsignedTorus>(
    err: *mut c_int,
    glwe_sk: *mut GlweSecretKey<T>,
    lwe_sk: *const LweSecretKey<T>,
) {
    if pointers_null!(lwe_sk, glwe_sk) {
        set_err!(err, ERR_NULL_POINTER);
        return;
    }
    let glwe_sk = glwe_sk.as_mut().unwrap();
    let lwe_sk = lwe_sk.as_ref().unwrap();
    if glwe_sk.0.as_tensor().len() != lwe_sk.0.as_tensor().len() {
        set_err!(err, ERR_SIZE_MISMATCH);
        return;
    }
    glwe_sk
        .0
        .as_mut_tensor()
        .as_mut_slice()
        .copy_from_slice(lwe_sk.0.as_tensor().as_slice());

    set_err!(err, ERR_NO_ERR);
}

#[no_mangle]
pub unsafe extern "C" fn fill_glwe_secret_key_with_lwe_secret_key_u32(
    err: *mut c_int,
    glwe_sk: *mut GlweSecretKey<u32>,
    lwe_sk: *const LweSecretKey<u32>,
) {
    fill_glwe_secret_key_with_lwe_secret_key(err, glwe_sk, lwe_sk);
}

#[no_mangle]
pub unsafe extern "C" fn fill_glwe_secret_key_with_lwe_secret_key_u64(
    err: *mut c_int,
    glwe_sk: *mut GlweSecretKey<u64>,
    lwe_sk: *const LweSecretKey<u64>,
) {
    fill_glwe_secret_key_with_lwe_secret_key(err, glwe_sk, lwe_sk);
}

////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct LweKeyswitchKey<T: UnsignedTorus>(CoreLweKeyswitchKey<Vec<T>>);

unsafe fn allocate_lwe_keyswitch_key<T: UnsignedTorus>(
    err: *mut c_int,
    decomp_size: DecompositionLevelCount,
    decomp_base_log: DecompositionBaseLog,
    input_size: LweSize,
    output_size: LweSize,
) -> *mut LweKeyswitchKey<T> {
    let key = CoreLweKeyswitchKey::allocate(
        T::ZERO,
        decomp_size,
        decomp_base_log,
        input_size.to_lwe_dimension(),
        output_size.to_lwe_dimension(),
    );
    set_err!(err, ERR_NO_ERR);
    let output = LweKeyswitchKey(key);
    boxmut!(output)
}

#[no_mangle]
pub unsafe extern "C" fn allocate_lwe_keyswitch_key_u64(
    err: *mut c_int,
    decomp_size: DecompositionLevelCount,
    decomp_base_log: DecompositionBaseLog,
    input_size: LweSize,
    output_size: LweSize,
) -> *mut LweKeyswitchKey<u64> {
    allocate_lwe_keyswitch_key(err, decomp_size, decomp_base_log, input_size, output_size)
}

#[no_mangle]
pub unsafe extern "C" fn allocate_lwe_keyswitch_key_u32(
    err: *mut c_int,
    decomp_size: DecompositionLevelCount,
    decomp_base_log: DecompositionBaseLog,
    input_size: LweSize,
    output_size: LweSize,
) -> *mut LweKeyswitchKey<u32> {
    allocate_lwe_keyswitch_key(err, decomp_size, decomp_base_log, input_size, output_size)
}

unsafe fn fill_lwe_keyswitch_key<T: UnsignedTorus>(
    err: *mut c_int,
    keyswitch_key: *mut LweKeyswitchKey<T>,
    input_key: *const LweSecretKey<T>,
    output_key: *const LweSecretKey<T>,
    generator: *mut EncryptionRandomGenerator,
    noise: Variance,
) {
    if pointers_null!(keyswitch_key, input_key, output_key, generator) {
        set_err!(err, ERR_NULL_POINTER);
        return;
    }
    let keyswitch_key = keyswitch_key.as_mut().unwrap();
    let input_key = input_key.as_ref().unwrap();
    let output_key = output_key.as_ref().unwrap();
    let generator = generator.as_mut().unwrap();
    keyswitch_key
        .0
        .fill_with_keyswitch_key(&input_key.0, &output_key.0, noise, &mut generator.0);
    set_err!(err, ERR_NO_ERR);
}

#[no_mangle]
pub unsafe extern "C" fn fill_lwe_keyswitch_key_u32(
    err: *mut c_int,
    keyswitch_key: *mut LweKeyswitchKey<u32>,
    input_key: *const LweSecretKey<u32>,
    output_key: *const LweSecretKey<u32>,
    generator: *mut EncryptionRandomGenerator,
    noise: Variance,
) {
    fill_lwe_keyswitch_key(err, keyswitch_key, input_key, output_key, generator, noise)
}

#[no_mangle]
pub unsafe extern "C" fn fill_lwe_keyswitch_key_u64(
    err: *mut c_int,
    keyswitch_key: *mut LweKeyswitchKey<u64>,
    input_key: *const LweSecretKey<u64>,
    output_key: *const LweSecretKey<u64>,
    generator: *mut EncryptionRandomGenerator,
    noise: Variance,
) {
    fill_lwe_keyswitch_key(err, keyswitch_key, input_key, output_key, generator, noise)
}

unsafe fn keyswitch_lwe<T: UnsignedTorus>(
    err: *mut c_int,
    keyswitch_key: *const LweKeyswitchKey<T>,
    output_ciphertext: *mut LweCiphertext<T>,
    input_ciphertext: *const LweCiphertext<T>,
) {
    if pointers_null!(keyswitch_key, output_ciphertext, input_ciphertext) {
        set_err!(err, ERR_NULL_POINTER);
        return;
    }
    let keyswitch_key = keyswitch_key.as_ref().unwrap();
    let output_ciphertext = output_ciphertext.as_mut().unwrap();
    let input_ciphertext = input_ciphertext.as_ref().unwrap();
    keyswitch_key
        .0
        .keyswitch_ciphertext(&mut output_ciphertext.0, &input_ciphertext.0);
    set_err!(err, ERR_NO_ERR);
}

#[no_mangle]
pub unsafe extern "C" fn keyswitch_lwe_u32(
    err: *mut c_int,
    keyswitch_key: *const LweKeyswitchKey<u32>,
    output_ciphertext: *mut LweCiphertext<u32>,
    input_ciphertext: *const LweCiphertext<u32>,
) {
    keyswitch_lwe(err, keyswitch_key, output_ciphertext, input_ciphertext)
}

#[no_mangle]
pub unsafe extern "C" fn keyswitch_lwe_u64(
    err: *mut c_int,
    keyswitch_key: *const LweKeyswitchKey<u64>,
    output_ciphertext: *mut LweCiphertext<u64>,
    input_ciphertext: *const LweCiphertext<u64>,
) {
    keyswitch_lwe(err, keyswitch_key, output_ciphertext, input_ciphertext)
}

#[no_mangle]
pub unsafe extern "C" fn free_lwe_keyswitch_key_u32(
    err: *mut c_int,
    keyswitch_key: *mut LweKeyswitchKey<u32>,
) {
    if pointers_null!(keyswitch_key) {
        set_err!(err, ERR_NULL_POINTER);
        return;
    }
    free!(keyswitch_key);
    set_err!(err, ERR_NO_ERR);
}

#[no_mangle]
pub unsafe extern "C" fn free_lwe_keyswitch_key_u64(
    err: *mut c_int,
    keyswitch_key: *mut LweKeyswitchKey<u64>,
) {
    if pointers_null!(keyswitch_key) {
        set_err!(err, ERR_NULL_POINTER);
        return;
    }
    free!(keyswitch_key);
    set_err!(err, ERR_NO_ERR);
}

////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct LweBootstrapKey<T: UnsignedTorus>(CoreFourierBootstrapKey<Arc<AlignedVec<Complex64>>, T>);

unsafe fn allocate_lwe_bootstrap_key<T: UnsignedTorus>(
    err: *mut c_int,
    decomp_size: DecompositionLevelCount,
    decomp_base_log: DecompositionBaseLog,
    glwe_size: GlweSize,
    lwe_size: LweSize,
    poly_size: PolynomialSize,
) -> *mut LweBootstrapKey<T> {
    let key = CoreFourierBootstrapKey::allocate(
        Complex64::new(0., 0.),
        glwe_size,
        poly_size,
        decomp_size,
        decomp_base_log,
        lwe_size.to_lwe_dimension(),
    );
    set_err!(err, ERR_NO_ERR);
    let output = LweBootstrapKey(key);
    boxmut!(output)
}

#[no_mangle]
pub unsafe extern "C" fn allocate_lwe_bootstrap_key_u64(
    err: *mut c_int,
    decomp_size: DecompositionLevelCount,
    decomp_base_log: DecompositionBaseLog,
    glwe_size: GlweSize,
    lwe_size: LweSize,
    poly_size: PolynomialSize,
) -> *mut LweBootstrapKey<u64> {
    allocate_lwe_bootstrap_key(
        err,
        decomp_size,
        decomp_base_log,
        glwe_size,
        lwe_size,
        poly_size,
    )
}

#[no_mangle]
pub unsafe extern "C" fn allocate_lwe_bootstrap_key_u32(
    err: *mut c_int,
    decomp_size: DecompositionLevelCount,
    decomp_base_log: DecompositionBaseLog,
    glwe_size: GlweSize,
    lwe_size: LweSize,
    poly_size: PolynomialSize,
) -> *mut LweBootstrapKey<u32> {
    allocate_lwe_bootstrap_key(
        err,
        decomp_size,
        decomp_base_log,
        glwe_size,
        lwe_size,
        poly_size,
    )
}

unsafe fn clone_lwe_bootstrap_key<T: UnsignedTorus>(
    err: *mut c_int,
    input: *const LweBootstrapKey<T>,
) -> *mut LweBootstrapKey<T> {
    if pointers_null!(input) {
        set_err!(err, ERR_NULL_POINTER);
        return std::ptr::null_mut();
    }
    let input = input.as_ref().unwrap();
    set_err!(err, ERR_NO_ERR);
    let output = LweBootstrapKey(input.0.to_owned());
    boxmut!(output)
}

#[no_mangle]
pub unsafe extern "C" fn clone_lwe_bootstrap_key_u32(
    err: *mut c_int,
    input: *const LweBootstrapKey<u32>,
) -> *mut LweBootstrapKey<u32> {
    clone_lwe_bootstrap_key(err, input)
}

#[no_mangle]
pub unsafe extern "C" fn clone_lwe_bootstrap_key_u64(
    err: *mut c_int,
    input: *const LweBootstrapKey<u64>,
) -> *mut LweBootstrapKey<u64> {
    clone_lwe_bootstrap_key(err, input)
}

unsafe fn copy_lwe_bootstrap_key<T: UnsignedTorus>(
    err: *mut c_int,
    output: *mut LweBootstrapKey<T>,
    input: *const LweBootstrapKey<T>,
) {
    if pointers_null!(input, output) {
        set_err!(err, ERR_NULL_POINTER);
        return;
    }
    let input = input.as_ref().unwrap();
    let output = output.as_mut().unwrap();
    if input.0.as_tensor().len() != output.0.as_tensor().len() {
        set_err!(err, ERR_SIZE_MISMATCH);
        return;
    }
    output.0.as_mut_tensor().fill_with_copy(input.0.as_tensor());
    set_err!(err, ERR_NO_ERR);
}

#[no_mangle]
pub unsafe extern "C" fn copy_lwe_bootstrap_key_u64(
    err: *mut c_int,
    output: *mut LweBootstrapKey<u64>,
    input: *const LweBootstrapKey<u64>,
) {
    copy_lwe_bootstrap_key(err, output, input);
}

#[no_mangle]
pub unsafe extern "C" fn copy_lwe_bootstrap_key_u32(
    err: *mut c_int,
    output: *mut LweBootstrapKey<u32>,
    input: *const LweBootstrapKey<u32>,
) {
    copy_lwe_bootstrap_key(err, output, input);
}

unsafe fn fill_lwe_bootstrap_key<T: UnsignedTorus>(
    err: *mut c_int,
    bootstrap_key: *mut LweBootstrapKey<T>,
    lwe_key: *const LweSecretKey<T>,
    glwe_key: *const GlweSecretKey<T>,
    generator: *mut EncryptionRandomGenerator,
    noise: Variance,
) {
    if pointers_null!(bootstrap_key, lwe_key, glwe_key, generator) {
        set_err!(err, ERR_NULL_POINTER);
        return;
    }
    let fourier_bootstrap_key = bootstrap_key.as_mut().unwrap();
    let lwe_key = lwe_key.as_ref().unwrap();
    let glwe_key = glwe_key.as_ref().unwrap();
    let generator = generator.as_mut().unwrap();

    assert_eq!(
        glwe_key.0.key_size().to_glwe_size(),
        fourier_bootstrap_key.0.glwe_size()
    );

    assert_eq!(
        glwe_key.0.polynomial_size(),
        fourier_bootstrap_key.0.polynomial_size()
    );

    assert_eq!(lwe_key.0.key_size(), fourier_bootstrap_key.0.key_size());

    let mut standard_bootstrap_key = CoreStandardBootstrapKey::allocate(
        T::ZERO,
        fourier_bootstrap_key.0.glwe_size(),
        fourier_bootstrap_key.0.polynomial_size(),
        fourier_bootstrap_key.0.level_count(),
        fourier_bootstrap_key.0.base_log(),
        fourier_bootstrap_key.0.key_size(),
    );
    standard_bootstrap_key.fill_with_new_key(&lwe_key.0, &glwe_key.0, noise, &mut generator.0);
    fourier_bootstrap_key
        .0
        .fill_with_forward_fourier(&standard_bootstrap_key);
    set_err!(err, ERR_NO_ERR);
}

#[no_mangle]
pub unsafe extern "C" fn fill_lwe_bootstrap_key_u32(
    err: *mut c_int,
    bootstrap_key: *mut LweBootstrapKey<u32>,
    lwe_key: *const LweSecretKey<u32>,
    glwe_key: *const GlweSecretKey<u32>,
    generator: *mut EncryptionRandomGenerator,
    noise: Variance,
) {
    fill_lwe_bootstrap_key(err, bootstrap_key, lwe_key, glwe_key, generator, noise)
}

#[no_mangle]
pub unsafe extern "C" fn fill_lwe_bootstrap_key_u64(
    err: *mut c_int,
    bootstrap_key: *mut LweBootstrapKey<u64>,
    lwe_key: *const LweSecretKey<u64>,
    glwe_key: *const GlweSecretKey<u64>,
    generator: *mut EncryptionRandomGenerator,
    noise: Variance,
) {
    fill_lwe_bootstrap_key(err, bootstrap_key, lwe_key, glwe_key, generator, noise)
}

unsafe fn bootstrap_lwe<T: UnsignedTorus>(
    err: *mut c_int,
    bootstrap_key: *const LweBootstrapKey<T>,
    output_ciphertext: *mut LweCiphertext<T>,
    input_ciphertext: *const LweCiphertext<T>,
    accumulator: *mut GlweCiphertext<T>,
) {
    if pointers_null!(
        bootstrap_key,
        output_ciphertext,
        input_ciphertext,
        accumulator
    ) {
        set_err!(err, ERR_NULL_POINTER);
        return;
    }
    let bootstrap_key = bootstrap_key.as_ref().unwrap();
    let output_ciphertext = output_ciphertext.as_mut().unwrap();
    let input_ciphertext = input_ciphertext.as_ref().unwrap();
    let accumulator = accumulator.as_mut().unwrap();

    assert_eq!(bootstrap_key.0.glwe_size(), accumulator.0.size());

    bootstrap_key.0.bootstrap(
        &mut output_ciphertext.0,
        &input_ciphertext.0,
        &accumulator.0,
    );
    set_err!(err, ERR_NO_ERR);
}

#[no_mangle]
pub unsafe extern "C" fn bootstrap_lwe_u32(
    err: *mut c_int,
    bootstrap_key: *const LweBootstrapKey<u32>,
    output_ciphertext: *mut LweCiphertext<u32>,
    input_ciphertext: *const LweCiphertext<u32>,
    accumulator: *mut GlweCiphertext<u32>,
) {
    bootstrap_lwe(
        err,
        bootstrap_key,
        output_ciphertext,
        input_ciphertext,
        accumulator,
    )
}

#[no_mangle]
pub unsafe extern "C" fn bootstrap_lwe_u64(
    err: *mut c_int,
    bootstrap_key: *const LweBootstrapKey<u64>,
    output_ciphertext: *mut LweCiphertext<u64>,
    input_ciphertext: *const LweCiphertext<u64>,
    accumulator: *mut GlweCiphertext<u64>,
) {
    bootstrap_lwe(
        err,
        bootstrap_key,
        output_ciphertext,
        input_ciphertext,
        accumulator,
    )
}

#[no_mangle]
pub unsafe extern "C" fn free_lwe_bootstrap_key_u32(
    err: *mut c_int,
    bootstrap_key: *mut LweBootstrapKey<u32>,
) {
    if pointers_null!(bootstrap_key) {
        set_err!(err, ERR_NULL_POINTER);
        return;
    }
    free!(bootstrap_key);
    set_err!(err, ERR_NO_ERR);
}

#[no_mangle]
pub unsafe extern "C" fn free_lwe_bootstrap_key_u64(
    err: *mut c_int,
    bootstrap_key: *mut LweBootstrapKey<u64>,
) {
    if pointers_null!(bootstrap_key) {
        set_err!(err, ERR_NULL_POINTER);
        return;
    }
    free!(bootstrap_key);
    set_err!(err, ERR_NO_ERR);
}

////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct PlaintextList<T: UnsignedTorus>(CorePlaintextList<Vec<T>>);

unsafe fn allocate_plaintext_list<T: UnsignedTorus>(
    err: *mut c_int,
    size: PlaintextCount,
) -> *mut PlaintextList<T> {
    let list = CorePlaintextList::allocate(T::ZERO, size);
    set_err!(err, ERR_NO_ERR);
    let output = PlaintextList(list);
    boxmut!(output)
}

#[no_mangle]
pub unsafe extern "C" fn allocate_plaintext_list_u32(
    err: *mut c_int,
    size: PlaintextCount,
) -> *mut PlaintextList<u32> {
    allocate_plaintext_list(err, size)
}

#[no_mangle]
pub unsafe extern "C" fn allocate_plaintext_list_u64(
    err: *mut c_int,
    size: PlaintextCount,
) -> *mut PlaintextList<u64> {
    allocate_plaintext_list(err, size)
}

unsafe fn fill_plaintext_list_with_expansion<T: UnsignedTorus>(
    err: *mut c_int,
    output: *mut PlaintextList<T>,
    input: *const ForeignPlaintextList<T>,
) {
    if pointers_null!(output, input) {
        set_err!(err, ERR_NULL_POINTER);
        return;
    }
    let output = output.as_mut().unwrap();
    let input = input.as_ref().unwrap();
    let output_ln = output.0.as_tensor().len();
    let input_ln = input.0.as_tensor().len();
    if output_ln < input_ln || (output_ln % input_ln) != 0 {
        set_err!(err, ERR_SIZE_MISMATCH);
        return;
    }
    let box_size = output_ln / input_ln;
    if box_size % 2 != 0 {
        set_err!(err, ERR_SIZE_MISMATCH);
        return;
    }
    input
        .0
        .as_tensor()
        .iter()
        .zip(output.0.as_mut_tensor().subtensor_iter_mut(box_size))
        .for_each(|(i, mut o)| {
            o.fill_with_element(*i);
        });
    let mut polynomial = Polynomial::from_container(output.0.as_mut_tensor().as_mut_slice());
    polynomial.update_with_wrapping_unit_monomial_div(MonomialDegree(box_size / 2));
    set_err!(err, ERR_NO_ERR);
}

#[no_mangle]
pub unsafe extern "C" fn fill_plaintext_list_with_expansion_u32(
    err: *mut c_int,
    output: *mut PlaintextList<u32>,
    input: *const ForeignPlaintextList<u32>,
) {
    fill_plaintext_list_with_expansion(err, output, input);
}

#[no_mangle]
pub unsafe extern "C" fn fill_plaintext_list_with_expansion_u64(
    err: *mut c_int,
    output: *mut PlaintextList<u64>,
    input: *const ForeignPlaintextList<u64>,
) {
    fill_plaintext_list_with_expansion(err, output, input)
}

unsafe fn get_plaintext_list_element<T: UnsignedTorus>(
    err: *mut c_int,
    list: *const PlaintextList<T>,
    i: usize,
) -> T {
    if pointers_null!(list) {
        set_err!(err, ERR_NULL_POINTER);
        return T::ZERO;
    }
    let list = list.as_ref().unwrap();
    if i >= list.0.count().0 {
        set_err!(err, ERR_INDEX_OUT_OF_BOUND);
        return T::ZERO;
    }
    set_err!(err, ERR_NO_ERR);
    *list.0.as_tensor().get_element(i)
}

#[no_mangle]
pub unsafe extern "C" fn get_plaintext_list_element_u32(
    err: *mut c_int,
    list: *const PlaintextList<u32>,
    i: usize,
) -> u32 {
    get_plaintext_list_element(err, list, i)
}

#[no_mangle]
pub unsafe extern "C" fn get_plaintext_list_element_u64(
    err: *mut c_int,
    list: *const PlaintextList<u64>,
    i: usize,
) -> u64 {
    get_plaintext_list_element(err, list, i)
}

unsafe fn set_plaintext_list_element<T: UnsignedTorus>(
    err: *mut c_int,
    list: *mut PlaintextList<T>,
    i: usize,
    val: T,
) {
    if pointers_null!(list) {
        set_err!(err, ERR_NULL_POINTER);
        return;
    }
    let list = list.as_mut().unwrap();
    if i >= list.0.count().0 {
        set_err!(err, ERR_INDEX_OUT_OF_BOUND);
        return;
    }
    set_err!(err, ERR_NO_ERR);
    *list.0.as_mut_tensor().get_element_mut(i) = val;
}

#[no_mangle]
pub unsafe extern "C" fn set_plaintext_list_element_u32(
    err: *mut c_int,
    list: *mut PlaintextList<u32>,
    i: usize,
    val: u32,
) {
    set_plaintext_list_element(err, list, i, val);
}

#[no_mangle]
pub unsafe extern "C" fn set_plaintext_list_element_u64(
    err: *mut c_int,
    list: *mut PlaintextList<u64>,
    i: usize,
    val: u64,
) {
    set_plaintext_list_element(err, list, i, val);
}

#[no_mangle]
pub unsafe extern "C" fn free_plaintext_list_u32(err: *mut c_int, list: *mut PlaintextList<u32>) {
    if pointers_null!(list) {
        set_err!(err, ERR_NULL_POINTER);
        return;
    }
    free!(list);
    set_err!(err, ERR_NO_ERR);
}

#[no_mangle]
pub unsafe extern "C" fn free_plaintext_list_u64(err: *mut c_int, list: *mut PlaintextList<u64>) {
    if pointers_null!(list) {
        set_err!(err, ERR_NULL_POINTER);
        return;
    }
    free!(list);
    set_err!(err, ERR_NO_ERR);
}

////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct ForeignPlaintextList<T: UnsignedTorus + 'static>(CorePlaintextList<&'static [T]>);

unsafe fn foreign_plaintext_list<T: UnsignedTorus + 'static>(
    err: *mut c_int,
    ptr: *const T,
    size: usize,
) -> *mut ForeignPlaintextList<T> {
    if pointers_null!(ptr) {
        set_err!(err, ERR_NULL_POINTER);
        return std::ptr::null_mut();
    }
    let slice = std::slice::from_raw_parts(ptr, size);
    let output = ForeignPlaintextList(CorePlaintextList::from_container(slice));
    boxmut!(output)
}

#[no_mangle]
pub unsafe extern "C" fn foreign_plaintext_list_u32(
    err: *mut c_int,
    ptr: *const u32,
    size: usize,
) -> *mut ForeignPlaintextList<u32> {
    foreign_plaintext_list(err, ptr, size)
}

#[no_mangle]
pub unsafe extern "C" fn foreign_plaintext_list_u64(
    err: *mut c_int,
    ptr: *const u64,
    size: usize,
) -> *mut ForeignPlaintextList<u64> {
    foreign_plaintext_list(err, ptr, size)
}
