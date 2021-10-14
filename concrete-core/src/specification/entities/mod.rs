//! A module containing specifications of the concrete fhe entities.
//!
//! In essence, an entity, as represented in the type system, is the union of two markers
//! types conveying different meanings:
//!
//! + The __'what'__: A __kind__ marker, which encodes the abstract nature of the fhe object this
//! type impersonate (is it a plaintext, a ciphertext, a secret key, ...).
//! + The __'how'__: A __representation__ marker, which encodes the practical representation of the
//! object in the software/hardware executing the program (is it in the cpu or gpu memory, what
//! precision does it uses, what domain is it expressed in, ...).
//!
//! In practice, __Entities__ are types which implement:
//!
//! + The [`AbstractEntity`] super-trait, which allows to specify the two marker types
//! aforementioned
//! + One of the `*Entity` traits.

pub mod markers;

use markers::*;
use std::fmt::Debug;

/// A top-level abstraction for entities of the concrete scheme.
///
/// An `AbstractEntity` type is nothing more but a type with two associated markers:
///
/// + One [`Kind`](`AbstractEntity::Kind`) type, implementing the [`EntityKindMarker`] trait,
/// which encodes in the type system, the _kind_ of the entity (the _what_, the abstract
/// nature of the object).
/// + One [`Representation`](`AbstractEntity::Representation`) type, implementing the
/// [`EntityRepresentationMarker`] trait, which encodes in the type system, the
/// _representation_ of the entity (the _how_, the practical software/hardware
/// nature of the object).
///
/// This trait is used to ensure at compile-time that you operate on compatible entities.
pub trait AbstractEntity: Debug + PartialEq {
    // # Why associated types and not generic parameters ?
    //
    // With generic parameter you can have one type implement a variety of abstract entity. With
    // associated types, a type can only implement one abstract entity. Hence, using generic
    // parameter, would encourage broadly generic types representing various entities (say an array)
    // while using associated types encourages narrowly defined types representing a single entity.
    // We think it is preferable for the user if the backends expose narrowly defined types, as it
    // makes the api cleaner and the signatures leaner. The downside is probably a bit more
    // boilerplate though.
    //
    // Also, this prevents a single type to implement different downstream traits (a type being both
    // a ggsw ciphertext vector and an lwe bootstrap key). Again, I think this is for the best, as
    // it will help us design better backend-level apis.

    /// The _kind_ of the entity.
    type Kind: EntityKindMarker;
    /// The _representation_ this entity embodies.
    type Representation: EntityRepresentationMarker;
}

mod cleartext;
mod cleartext_vector;
mod encoder;
mod encoder_vector;
mod ggsw_ciphertext;
mod ggsw_ciphertext_vector;
mod glwe_ciphertext;
mod glwe_ciphertext_vector;
mod glwe_secret_key;
mod gsw_ciphertext;
mod gsw_ciphertext_vector;
mod lwe_bootstrap_key;
mod lwe_ciphertext;
mod lwe_ciphertext_vector;
mod lwe_keyswitch_key;
mod lwe_secret_key;
mod plaintext;
mod plaintext_vector;

pub use cleartext::*;
pub use cleartext_vector::*;
pub use encoder::*;
pub use encoder_vector::*;
pub use ggsw_ciphertext::*;
pub use ggsw_ciphertext_vector::*;
pub use glwe_ciphertext::*;
pub use glwe_ciphertext_vector::*;
pub use glwe_secret_key::*;
pub use gsw_ciphertext::*;
pub use gsw_ciphertext_vector::*;
pub use lwe_bootstrap_key::*;
pub use lwe_ciphertext::*;
pub use lwe_ciphertext_vector::*;
pub use lwe_keyswitch_key::*;
pub use lwe_secret_key::*;
pub use plaintext::*;
pub use plaintext_vector::*;
