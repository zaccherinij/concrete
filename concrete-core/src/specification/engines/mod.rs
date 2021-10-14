//! A module containing specifications of the concrete fhe engines.
//!
//! In essence, __engines__ are types which can be used to perform operations on fhe entities. Those
//! engines contain all the necessary side-resources needed to execute the operations they declare.
//! An engine must implement at least the [`AbstractEngine`] super-trait, and can implement any
//! number of `*Engine` traits.
//!
//! Every fhe operation is defined by a `*Engine` operation trait. Those operation traits always
//! expose two entry points:
//!
//! + A safe entry point, returning a result, with an operation-dedicated error. When using this
//! entry point, the user relies on the backend to check that the necessary preconditions are
//! verified by the inputs, at the cost of a small overhead.
//! + An unsafe entry point, returning the raw result if any. When using this entry point, it is the
//! user responsibility to ensure that the necessary preconditions are verified by the inputs.
//! Breaking one of those preconditions will result in either a panic, or an FHE UB.
//!
//! # Engine errors
//!
//! Implementing the [`AbstractEngine`] trait for a given type implies specifying an associated
//! [`EngineError`](`AbstractEngine::EngineError`) which should be able to represent all the
//! possible error cases specific to this engine.
//!
//! Each `*Engine` ([example](`LweCiphertextInplaceKeyswitchEngine`)) trait is associated with a
//! specialized `*Error<E>` ([example](`LweCiphertextInplaceKeyswitchError`)) type, which contains:
//!
//! + Multiple __general__ error variants which can be potentially produced by any backend
//! ([example](`LweCiphertextInplaceKeyswitchError::InputLweDimensionMismatch`))
//! + One __specific__ variant which encapsulate the generic argument error `E`
//! ([example](`LweCiphertextInplaceKeyswitchError::Engine`))
//!
//! When implementing a particular `*Engine` trait, this `E` argument will be forced to be the
//! [`EngineError`](`AbstractEngine::EngineError`) from the [`AbstractEngine`] super-trait, by the
//! signature of the operation entry point
//! ([example](`LweCiphertextInplaceKeyswitchEngine::inplace_keyswitch_lwe_ciphertext`)).
//!
//! This trick makes it possible for each operation, to match the error exhaustively against both
//! general error variants, and backend-related error variants.
//!
//! # Operation semantics
//!
//! For each operation possible, we try to support the three following semantics:
//!
//! + __Pure__ operations: those operations take their inputs as arguments, allocate an object
//! holding the result, and return it (example: [`LweCiphertextEncryptionEngine`]). They usually
//! require more resources than other, because of the allocation.
//! + __Inplace__ operations: those operations take both their inputs and outputs as arguments
//! (example: [`LweCiphertextInplaceAdditionEngine`]). In those operations, the data originally
//! available in the outputs is not used for the computation. They are usually the fastest ones.
//! + __Assigned__ operations: those operations take both their inputs and outputs as arguments
//! (example: [`LweCiphertextAssignedAdditionEngine`]). In those operations though, the data
//! originally contained in the output is used for computation.

// This makes it impossible for types outside concrete to implement operations.
pub(crate) mod sealed {
    pub trait AbstractEngineSeal {}
}

/// A top-level abstraction for engines of the concrete scheme.
///
/// An `AbstractEngine` is nothing more than a type with an associated error type
/// [`EngineError`](`AbstractEngine::EngineError`) and a default constructor.
///
/// The associated error type is expected to encode all the failure cases which can occur while
/// using an engine.
pub trait AbstractEngine: sealed::AbstractEngineSeal {
    // # Why putting the error type in an abstract super trait ?
    //
    // This error is supposed to be reduced to only engine related errors, and not ones related to
    // the operations. For this reason, it is better for an engine to only have one error shared
    // among all the operations. If a variant of this error can only be triggered for a single
    // operation implemented by the engine, then it should probably be moved upstream, in the
    // operation-dedicated error.

    /// The error associated to the engine.
    type EngineError: std::error::Error;

    /// A constructor for the engine.
    fn new() -> Result<Self, Self::EngineError>
    where
        Self: Sized;
}

macro_rules! engine_error{
    ($name:ident for $trait:ident @ $($variants:ident => $messages:literal),*) =>{
        #[doc="An error used with the [`"]
        #[doc=stringify!($trait)]
        #[doc="`] trait."]
        #[non_exhaustive]
        #[derive(Debug, Clone, Eq, PartialEq)]
        pub enum $name<EngineError: std::error::Error> {
            $(
                #[doc="_Generic_ error:"]
                #[doc=$messages]
                $variants,
            )*
            #[doc="_Specific_ error to the implementing engine."]
            Engine(EngineError),
        }
        impl<EngineError: std::error::Error> std::fmt::Display for $name<EngineError>{
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    $(
                        Self::$variants => write!(f, $messages),
                    )*
                    Self::Engine(error) => write!(f, "Error occurred in the engine: {}", error),
                }
            }
        }
        impl<EngineError: std::error::Error> std::error::Error for $name<EngineError>{}
    }
}
pub(crate) use engine_error;

mod cleartext_conversion;
mod cleartext_creation;
mod cleartext_encoding;
mod cleartext_inplace_conversion;
mod cleartext_inplace_retrieval;
mod cleartext_retrieval;
mod cleartext_vector_conversion;
mod cleartext_vector_creation;
mod cleartext_vector_encoding;
mod cleartext_vector_inplace_conversion;
mod cleartext_vector_inplace_retrieval;
mod cleartext_vector_retrieval;
mod destruction;
mod glwe_ciphertext_conversion;
mod glwe_ciphertext_decryption;
mod glwe_ciphertext_encryption;
mod glwe_ciphertext_inplace_conversion;
mod glwe_ciphertext_inplace_decryption;
mod glwe_ciphertext_inplace_encryption;
mod glwe_ciphertext_vector_conversion;
mod glwe_ciphertext_vector_decryption;
mod glwe_ciphertext_vector_encryption;
mod glwe_ciphertext_vector_inplace_conversion;
mod glwe_ciphertext_vector_inplace_decryption;
mod glwe_ciphertext_vector_inplace_encryption;
mod glwe_ciphertext_vector_zero_encryption;
mod glwe_ciphertext_zero_encryption;
mod glwe_secret_key_conversion;
mod glwe_secret_key_generation;
mod glwe_secret_key_inplace_conversion;
mod lwe_bootstrap_key_conversion;
mod lwe_bootstrap_key_generation;
mod lwe_bootstrap_key_inplace_conversion;
mod lwe_ciphertext_assigned_addition;
mod lwe_ciphertext_assigned_negation;
mod lwe_ciphertext_cleartext_assigned_multiplication;
mod lwe_ciphertext_cleartext_inplace_multiplication;
mod lwe_ciphertext_conversion;
mod lwe_ciphertext_decryption;
mod lwe_ciphertext_encryption;
mod lwe_ciphertext_inplace_addition;
mod lwe_ciphertext_inplace_affine_transformation;
mod lwe_ciphertext_inplace_bootstrap;
mod lwe_ciphertext_inplace_conversion;
mod lwe_ciphertext_inplace_decryption;
mod lwe_ciphertext_inplace_encryption;
mod lwe_ciphertext_inplace_extraction;
mod lwe_ciphertext_inplace_keyswitch;
mod lwe_ciphertext_inplace_loading;
mod lwe_ciphertext_inplace_negation;
mod lwe_ciphertext_inplace_storing;
mod lwe_ciphertext_loading;
mod lwe_ciphertext_plaintext_assigned_addition;
mod lwe_ciphertext_plaintext_inplace_addition;
mod lwe_ciphertext_vector_assigned_addition;
mod lwe_ciphertext_vector_assigned_negation;
mod lwe_ciphertext_vector_conversion;
mod lwe_ciphertext_vector_decryption;
mod lwe_ciphertext_vector_encryption;
mod lwe_ciphertext_vector_inplace_addition;
mod lwe_ciphertext_vector_inplace_bootstrap;
mod lwe_ciphertext_vector_inplace_conversion;
mod lwe_ciphertext_vector_inplace_decryption;
mod lwe_ciphertext_vector_inplace_encryption;
mod lwe_ciphertext_vector_inplace_keyswitch;
mod lwe_ciphertext_vector_inplace_loading;
mod lwe_ciphertext_vector_inplace_negation;
mod lwe_ciphertext_vector_loading;
mod lwe_ciphertext_vector_zero_encryption;
mod lwe_ciphertext_zero_encryption;
mod lwe_keyswitch_key_conversion;
mod lwe_keyswitch_key_generation;
mod lwe_keyswitch_key_inplace_conversion;
mod lwe_secret_key_conversion;
mod lwe_secret_key_generation;
mod lwe_secret_key_inplace_conversion;
mod plaintext_conversion;
mod plaintext_creation;
mod plaintext_decoding;
mod plaintext_inplace_conversion;
mod plaintext_inplace_retrieval;
mod plaintext_retrieval;
mod plaintext_vector_conversion;
mod plaintext_vector_creation;
mod plaintext_vector_decoding;
mod plaintext_vector_inplace_conversion;
mod plaintext_vector_inplace_retrieval;
mod plaintext_vector_retrieval;

pub use cleartext_conversion::*;
pub use cleartext_creation::*;
pub use cleartext_encoding::*;
pub use cleartext_inplace_conversion::*;
pub use cleartext_inplace_retrieval::*;
pub use cleartext_retrieval::*;
pub use cleartext_vector_conversion::*;
pub use cleartext_vector_creation::*;
pub use cleartext_vector_encoding::*;
pub use cleartext_vector_inplace_conversion::*;
pub use cleartext_vector_inplace_retrieval::*;
pub use cleartext_vector_retrieval::*;
pub use destruction::*;
pub use glwe_ciphertext_conversion::*;
pub use glwe_ciphertext_decryption::*;
pub use glwe_ciphertext_encryption::*;
pub use glwe_ciphertext_inplace_conversion::*;
pub use glwe_ciphertext_inplace_decryption::*;
pub use glwe_ciphertext_inplace_encryption::*;
pub use glwe_ciphertext_vector_conversion::*;
pub use glwe_ciphertext_vector_decryption::*;
pub use glwe_ciphertext_vector_encryption::*;
pub use glwe_ciphertext_vector_inplace_conversion::*;
pub use glwe_ciphertext_vector_inplace_decryption::*;
pub use glwe_ciphertext_vector_inplace_encryption::*;
pub use glwe_ciphertext_vector_zero_encryption::*;
pub use glwe_ciphertext_zero_encryption::*;
pub use glwe_secret_key_conversion::*;
pub use glwe_secret_key_generation::*;
pub use glwe_secret_key_inplace_conversion::*;
pub use lwe_bootstrap_key_conversion::*;
pub use lwe_bootstrap_key_generation::*;
pub use lwe_bootstrap_key_inplace_conversion::*;
pub use lwe_ciphertext_assigned_addition::*;
pub use lwe_ciphertext_assigned_negation::*;
pub use lwe_ciphertext_cleartext_assigned_multiplication::*;
pub use lwe_ciphertext_cleartext_inplace_multiplication::*;
pub use lwe_ciphertext_conversion::*;
pub use lwe_ciphertext_decryption::*;
pub use lwe_ciphertext_encryption::*;
pub use lwe_ciphertext_inplace_addition::*;
pub use lwe_ciphertext_inplace_affine_transformation::*;
pub use lwe_ciphertext_inplace_bootstrap::*;
pub use lwe_ciphertext_inplace_conversion::*;
pub use lwe_ciphertext_inplace_decryption::*;
pub use lwe_ciphertext_inplace_encryption::*;
pub use lwe_ciphertext_inplace_extraction::*;
pub use lwe_ciphertext_inplace_keyswitch::*;
pub use lwe_ciphertext_inplace_loading::*;
pub use lwe_ciphertext_inplace_negation::*;
pub use lwe_ciphertext_inplace_storing::*;
pub use lwe_ciphertext_loading::*;
pub use lwe_ciphertext_plaintext_assigned_addition::*;
pub use lwe_ciphertext_plaintext_inplace_addition::*;
pub use lwe_ciphertext_vector_assigned_addition::*;
pub use lwe_ciphertext_vector_assigned_negation::*;
pub use lwe_ciphertext_vector_conversion::*;
pub use lwe_ciphertext_vector_decryption::*;
pub use lwe_ciphertext_vector_encryption::*;
pub use lwe_ciphertext_vector_inplace_addition::*;
pub use lwe_ciphertext_vector_inplace_bootstrap::*;
pub use lwe_ciphertext_vector_inplace_conversion::*;
pub use lwe_ciphertext_vector_inplace_decryption::*;
pub use lwe_ciphertext_vector_inplace_encryption::*;
pub use lwe_ciphertext_vector_inplace_keyswitch::*;
pub use lwe_ciphertext_vector_inplace_loading::*;
pub use lwe_ciphertext_vector_inplace_negation::*;
pub use lwe_ciphertext_vector_loading::*;
pub use lwe_ciphertext_vector_zero_encryption::*;
pub use lwe_ciphertext_zero_encryption::*;
pub use lwe_keyswitch_key_conversion::*;
pub use lwe_keyswitch_key_generation::*;
pub use lwe_keyswitch_key_inplace_conversion::*;
pub use lwe_secret_key_conversion::*;
pub use lwe_secret_key_generation::*;
pub use lwe_secret_key_inplace_conversion::*;
pub use plaintext_conversion::*;
pub use plaintext_creation::*;
pub use plaintext_decoding::*;
pub use plaintext_inplace_conversion::*;
pub use plaintext_inplace_retrieval::*;
pub use plaintext_retrieval::*;
pub use plaintext_vector_conversion::*;
pub use plaintext_vector_creation::*;
pub use plaintext_vector_decoding::*;
pub use plaintext_vector_inplace_conversion::*;
pub use plaintext_vector_inplace_retrieval::*;
pub use plaintext_vector_retrieval::*;
