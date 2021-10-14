//! A module containing various marker traits used for entities.
use std::fmt::Debug;

/// A trait implemented by marker types encoding the __kind__ of an fhe entity in
/// the type system.
///
/// By _kind_ here, we mean the _what_, the abstract nature of an fhe entity.
///
/// # Note
///
/// [`EntityKindMarker`] types are only defined in the specification part of the library, and
/// can not be defined by a backend.
pub trait EntityKindMarker: seal::EntityKindMarkerSealed {}
macro_rules! entity_kind_marker {
        (@ $name: ident => $doc: literal)=>{
            #[doc=$doc]
            #[derive(Debug, Clone, Copy)]
            pub struct $name{}
            impl seal::EntityKindMarkerSealed for $name{}
            impl EntityKindMarker for $name{}
        };
        ($($name: ident => $doc: literal),+) =>{
            $(
                entity_kind_marker!(@ $name => $doc);
            )+
        }
}
entity_kind_marker! {
        PlaintextKind
            => "An empty type representing the plaintext kind in the type system.",
        PlaintextVectorKind
            => "An empty type representing the plaintext vector kind in the type system",
        CleartextKind
            => "An empty type representing the cleartext kind in the type system.",
        CleartextVectorKind
            => "An empty type representing the cleartext vector kind in the type system.",
        LweCiphertextKind
            => "An empty type representing the lwe ciphertext kind in the type system.",
        LweCiphertextVectorKind
            => "An empty type representing the lwe ciphertext vector kind in the type system.",
        GlweCiphertextKind
            => "An empty type representing the glwe ciphertext kind in the type system.",
        GlweCiphertextVectorKind
            => "An empty type representing the glwe ciphertext vector kind in the type system.",
        GgswCiphertextKind
            => "An empty type representing the ggsw ciphertext kind in the type system.",
        GgswCiphertextVectorKind
            => "An empty type representing the ggsw ciphertext vector kind in the type system.",
        GswCiphertextKind
            => "An empty type representing the gsw ciphertext kind in the type system.",
        GswCiphertextVectorKind
            => "An empty type representing the gsw ciphertext vector kind in the type system.",
        LweSecretKeyKind
            => "An empty type representing the lwe secret key kind in the type system.",
        GlweSecretKeyKind
            => "An empty type representing the glwe secret key kind in the type system.",
        LweKeyswitchKeyKind
            => "An empty type representing the lwe keyswitch key kind in the type system.",
        LweBootstrapKeyKind
            => "An empty type representing the lwe bootstrap key kind in the type system.",
        EncoderKind
            => "An empty type representing the encoder kind in the type system.",
        EncoderVectorKind
            => "An empty type representing the encoder vector kind in the type system"
}

/// A trait implemented by marker types encoding the __representation__ on an fhe entity in
/// the type system.
///
/// By _representation_ here, we mean the _how_, the concrete software/hardware nature of an fhe
/// entity.
///
/// A type implementing this trait should contain every informations needed to completely
/// make sense of a piece of data. Among other things, this can include:
///
/// + The location of the object: Is it in the cpu or the gpu memory ?
/// + The domain the object is represented in: Is it in the fourier, the ntt, or the standard
/// domain?
/// + The precision used to represent the object: Is it 16, 32, 64, 128 bits ?
///
/// # Note
///
/// No [`EntityRepresentationMarker`] types are defined in the specification. It is really up to
/// the backends to specify the informations relevant to their implementation.
pub trait EntityRepresentationMarker: seal::EntityRepresentationMarkerSealed {}

/// A trait implemented by marker types encoding a _flavor_ of secret key in the type system.
///
/// By _flavor_ here, we mean the different types of secret key that can exist such as binary,
/// ternary, uniform or gaussian key.
///
/// # Note
///
/// [`KeyFlavorMarker`] types are only defined in the specification part of the library, and
/// can not be defined by a backend.
pub trait KeyFlavorMarker: seal::KeyFlavorMarkerSealed {}
macro_rules! key_flavor_marker {
        (@ $name: ident => $doc: literal)=>{
            #[doc=$doc]
            #[derive(Debug, Clone, Copy)]
            pub struct $name{}
            impl seal::KeyFlavorMarkerSealed for $name{}
            impl KeyFlavorMarker for $name{}
        };
        ($($name: ident => $doc: literal),+) =>{
            $(
                key_flavor_marker!(@ $name => $doc);
            )+
        }
    }
key_flavor_marker! {
    BinaryKeyFlavor => "An empty type encoding the binary key flavor in the type system.",
    TernaryKeyFlavor => "An empty type encoding the ternary key flavor in the type system.",
    GaussianKeyFlavor => "An empty type encoding the gaussian key flavor in the type system."
}

pub(crate) mod seal {
    pub trait EntityRepresentationMarkerSealed {}
    pub trait EntityKindMarkerSealed {}
    pub trait KeyFlavorMarkerSealed {}
}
