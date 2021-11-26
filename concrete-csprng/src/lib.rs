//! # Cryptographically Secure Pseudo Random Number Generator (CSPRNG).
//!
//! Welcome to the `concrete-csprng` documentation.
//!
//! This crates exposes two traits: [Seeder] and [RandomBytesGenerator].
//!
//! - [Seeders] generate random number or AES keys.
//! - [RandomBytesGenerators] securely generates random bytes.
//!
//! Currently the only `RandomBytesGenerator` implemented in this crate is
//! a reasonably fast cryptographically secure pseudo-random number generator for which
//! its implementation is based on the AES block cipher used in counter (CTR) mode,
//! as presented in the ISO/IEC 18033-4 document.
//!
//! [Seeders]: crate::Seeder#implementors
//! [RandomBytesGenerators]: crate::RandomBytesGenerator#implementors
//!
//! # Example
//!
//! ```
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use concrete_csprng::{seeders, Automatic, RandomBytesGenerator, RandomGenerator, Seeder};
//!
//! let aes_key = seeders::default().and_then(|mut s| s.seed_key())?;
//! let mut generator = RandomGenerator::<Automatic>::try_new(aes_key)?;
//!
//! let mut random_bytes = [0u8; 32];
//! generator.generate_bytes_exact(&mut random_bytes)?;
//!
//! # Ok(())
//! # }
//! ```
//!
//! # Hardware requirements
//!
//! For speed and security reasons, some of the implementation of  `RandomBytesGenerator`
//! and `Seeder` use special CPU instructions which may not be available on your CPU.
//!
//! ## `x86_64` architecture:
//! - The hardware-based seeder requires the `rdseed` CPU feature.
//! - The hardware-based generator requires `sse2` and `aes` features.
//!
//! Other architectures are not supported.
//!
//! # Listing CPU features
//!
//! ## Linux
//!
//! On Linux, you can list the features that your CPU supports by using
//! `lscpu` or `cat /proc/cpuinfo`.
//!
//! ## macOS
//!
//! On macOS, you can list the features that your CPU supports by using `sysctl hw.optional`.

#[cfg(feature = "multithread")]
use rayon::iter::plumbing::{Consumer, ProducerCallback, UnindexedConsumer};
#[cfg(feature = "multithread")]
use rayon::iter::{IndexedParallelIterator, ParallelIterator};
use std::fmt::{Debug, Display, Formatter};

use crate::aes::counter::AesCtrGenerator;
#[cfg(feature = "multithread")]
use crate::generator::ParForkableGenerator;
use aes::counter::{FirmAesCtrGenerator, HardAesCtrGenerator, SoftAesCtrGenerator};
pub use aes::encryptors::AesKey;
pub use generator::{BytesPerChild, ChildCount, ForkableGenerator, RandomBytesGenerator};
pub use seeders::software::DevRandom;
pub use seeders::Seeder;

mod aes;
mod generator;
pub mod seeders;

/// The possible errors that can happen using this lib.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The CPU does not support some required features
    UnsupportedCpuFeatures {
        /// Name of the feature(s) that were required
        // Example values for features: "seed", "sse2;aes"
        features: &'static str,
    },
    /// The generator's bounds were reached
    GeneratorBoundsReached,
    /// An error that does not fall under any other error kind.
    Other { error: Box<dyn std::error::Error> },
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::UnsupportedCpuFeatures { features } => {
                write!(
                    f,
                    "This CPU does not support the required '{}' feature(s)",
                    features
                )
            }
            Error::Other { error } => {
                write!(f, "The operation could not completed due to '{}'", error)
            }
            Error::GeneratorBoundsReached => {
                write!(f, "Tried to generate a byte outside the generator bound.")
            }
        }
    }
}

impl std::error::Error for Error {}

macro_rules! newtype_generator {
    (
        $(#[$outer:meta])*
        $newtype_name:ident => {
            inner: $inner_type:ty,
            fork_iterator_name: $forkiter_name:ident,
            par_fork_iterator_name: $parforkiter_name:ident,
        }
    ) => {
        $(#[$outer])*
        #[derive(Clone, Debug)]
        pub struct $newtype_name($inner_type);

        impl RandomBytesGenerator for $newtype_name {
            fn generate_next(&mut self) -> Option<u8> {
                self.0.generate_next()
            }

            fn is_bounded(&self) -> bool {
                self.0.is_bounded()
            }

            fn remaining_bytes(&self) -> Option<usize> {
                self.0.remaining_bytes()
            }
        }

        #[doc(hidden)]
        pub struct $forkiter_name {
            iter: <$inner_type as ForkableGenerator>::ForkIterator,
        }

        impl Iterator for $forkiter_name {
            type Item = $newtype_name;

            fn next(&mut self) -> Option<Self::Item> {
                let generator = self.iter.next()?;
                Some($newtype_name(generator))
            }
        }

        impl ForkableGenerator for $newtype_name {
            type ForkIterator = $forkiter_name;

            fn try_fork(
                &mut self,
                n_child: ChildCount,
                child_bytes: BytesPerChild,
            ) -> Option<Self::ForkIterator> {
                let fork_iter = self.0.try_fork(n_child, child_bytes)?;
                Some($forkiter_name { iter: fork_iter })
            }
        }

        #[cfg(feature = "multithread")]
        #[doc(hidden)]
        pub struct $parforkiter_name {
            part_iter: <$inner_type as ParForkableGenerator>::ParForkIterator,
        }

        #[cfg(feature = "multithread")]
        impl ParallelIterator for $parforkiter_name {
            type Item = $newtype_name;

            fn drive_unindexed<C>(self, consumer: C) -> C::Result
            where
                C: UnindexedConsumer<Self::Item>,
            {
                self.part_iter
                    .map(|generator: $inner_type| $newtype_name(generator))
                    .drive_unindexed(consumer)
            }
        }

        #[cfg(feature = "multithread")]
        impl IndexedParallelIterator for $parforkiter_name {
            fn len(&self) -> usize {
                self.part_iter.len()
            }

            fn drive<C>(self, consumer: C) -> C::Result
            where
                C: Consumer<Self::Item>,
            {
                self.part_iter
                    .map(|generator: $inner_type| $newtype_name(generator))
                    .drive(consumer)
            }

            fn with_producer<CB: ProducerCallback<Self::Item>>(self, callback: CB) -> CB::Output {
                self.part_iter
                    .map(|generator: $inner_type| $newtype_name(generator))
                    .with_producer(callback)
            }
        }

        #[cfg(feature = "multithread")]
        impl ParForkableGenerator for $newtype_name {
            type ParForkIterator = $parforkiter_name;

            fn par_try_fork(
                &mut self,
                n_child: ChildCount,
                child_bytes: BytesPerChild,
            ) -> Option<Self::ParForkIterator> {
                let internal_iter = self.0.par_try_fork(n_child, child_bytes)?;
                Some($parforkiter_name {
                    part_iter: internal_iter,
                })
            }
        }
    };
}

newtype_generator!(
    /// This implementation uses a software version of the AES CTR Generator
    SoftwareRandomGenerator =>  {
        inner: SoftAesCtrGenerator,
        fork_iterator_name: SofwareForkIterator,
        par_fork_iterator_name: SofwareParForkIterator,
    }
);

newtype_generator!(
    /// This implementation uses an AES CTR generator with intel's aesni
    /// instructions
    AesniRandomGenerator =>  {
        inner: HardAesCtrGenerator,
        fork_iterator_name: HardForkIterator,
        par_fork_iterator_name: HardParForkIterator,
    }
);

newtype_generator!(
    /// This implementation tries to use the a hardware version of the AES CTR Generator,
    /// if it is not supported by the CPU, it falls back to using the software version.
    AutomaticRandomGenerator =>  {
        inner: FirmAesCtrGenerator,
        fork_iterator_name: AutomaticForkIterator,
        par_fork_iterator_name: AutomaticParForkIterator,
    }
);

// TODO Sealed
pub trait Implementation {
    #[doc(hidden)]
    type Generator: RandomBytesGenerator + Send + Sync;

    #[doc(hidden)]
    fn generator(aes_key: AesKey) -> Result<Self::Generator, crate::Error>;
}

macro_rules! add_implementation {
    (
        $(#[$outer:meta])*
        $name:ident => $generator:ty
    ) => {
        $(#[$outer])*
        #[derive(Debug)]
        pub struct $name;

        impl Implementation for $name {
            #[doc(hidden)]
            type Generator = $generator;

            #[doc(hidden)]
            fn generator(aes_key: AesKey) -> Result<Self::Generator, crate::Error> {
                Self::Generator::try_new(aes_key)
            }
        }
    };
}

#[cfg(target_arch = "x86_64")]
add_implementation!(
    /// This implementation uses an AES CTR generator with intel's aesni
    /// instructions
    Aesni => AesCtrGenerator<aes::encryptors::hardware::x86_64::Encryptor>
);

add_implementation!(
    /// This implementation uses a software version of the AES CTR Generator
    Software => AesCtrGenerator<aes::encryptors::software::Encryptor>
);

add_implementation!(
    /// This implementation tries to use the a hardware version of the AES CTR Generator,
    /// if it is not supported by the CPU, it falls back to using the software version.
    Automatic => AesCtrGenerator<aes::encryptors::FirmAesEncryptor>
);

pub type AesniRandomGenerator2 = RandomGenerator<Aesni>;

#[cfg(target_arch = "x86_64")]
pub struct Hardware;

#[cfg(target_arch = "x86_64")]
impl Implementation for Hardware {
    #[doc(hidden)]
    type Generator = <Aesni as Implementation>::Generator;

    fn generator(aes_key: AesKey) -> Result<Self::Generator, Error> {
        <Aesni as Implementation>::generator(aes_key)
    }
}

/// A random number generator using one of the available
/// [implementations].
///
/// See [Self::try_new] to create an instance.
///
/// [implementations]: Implementation#implementors
#[derive(Clone, Debug)]
pub struct RandomGenerator<I: Implementation> {
    _marker: std::marker::PhantomData<I>,
    generator: I::Generator,
}

impl<I: Implementation> RandomGenerator<I> {
    /// Creates a new generator that uses the implementation of your choice:
    ///
    /// # Example
    /// ```
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use concrete_csprng::{seeders, Automatic, RandomBytesGenerator, RandomGenerator};
    ///
    /// let key = seeders::default().and_then(|mut s| s.seed_key())?;
    /// let generator = RandomGenerator::<Automatic>::try_new(key)?;
    ///
    /// assert_eq!(generator.is_bounded(), false);
    /// # Ok(())
    /// # }
    /// ```
    pub fn try_new(aes_key: AesKey) -> Result<Self, crate::Error> {
        let generator = I::generator(aes_key)?;
        Ok(Self {
            _marker: Default::default(),
            generator,
        })
    }
}

impl<I: Implementation> RandomBytesGenerator for RandomGenerator<I> {
    fn generate_next(&mut self) -> Option<u8> {
        self.generator.generate_next()
    }

    fn is_bounded(&self) -> bool {
        self.generator.is_bounded()
    }

    fn remaining_bytes(&self) -> Option<usize> {
        self.generator.remaining_bytes()
    }
}

#[doc(hidden)]
pub struct RandomGeneratorForkIterator<I>
where
    I: Implementation,
    I::Generator: ForkableGenerator,
{
    iter: <I::Generator as ForkableGenerator>::ForkIterator,
}

impl<I> Iterator for RandomGeneratorForkIterator<I>
where
    I: Implementation,
    I::Generator: ForkableGenerator,
{
    type Item = RandomGenerator<I>;

    fn next(&mut self) -> Option<Self::Item> {
        let new_generator = self.iter.next()?;
        Some(Self::Item {
            _marker: Default::default(),
            generator: new_generator,
        })
    }
}

impl<I> ForkableGenerator for RandomGenerator<I>
where
    I: Implementation,
    I::Generator: ForkableGenerator,
{
    type ForkIterator = RandomGeneratorForkIterator<I>;

    fn try_fork(
        &mut self,
        n_child: ChildCount,
        child_bytes: BytesPerChild,
    ) -> Option<Self::ForkIterator> {
        let fork_iter = self.generator.try_fork(n_child, child_bytes)?;
        Some(RandomGeneratorForkIterator { iter: fork_iter })
    }
}

#[cfg(feature = "multithread")]
impl<I> ParForkableGenerator for RandomGenerator<I>
where
    I: Implementation + Send + Sync,
    I::Generator: ParForkableGenerator,
    RandomGenerator<I>: ForkableGenerator,
{
    type ParForkIterator = RandomGeneratorParForkIterator<I>;

    fn par_try_fork(
        &mut self,
        n_child: ChildCount,
        child_bytes: BytesPerChild,
    ) -> Option<Self::ParForkIterator> {
        let internal_iter = self.generator.par_try_fork(n_child, child_bytes)?;
        Some(RandomGeneratorParForkIterator {
            part_iter: internal_iter,
        })
    }
}

#[cfg(feature = "multithread")]
pub struct RandomGeneratorParForkIterator<I>
where
    I: Implementation,
    I::Generator: ParForkableGenerator,
{
    part_iter: <I::Generator as ParForkableGenerator>::ParForkIterator,
}

#[cfg(feature = "multithread")]
impl<I> ParallelIterator for RandomGeneratorParForkIterator<I>
where
    I: Implementation + Send + Sync,
    I::Generator: ParForkableGenerator,
{
    type Item = RandomGenerator<I>;

    fn drive_unindexed<C>(self, consumer: C) -> C::Result
    where
        C: UnindexedConsumer<Self::Item>,
    {
        self.part_iter
            .map(|generator: I::Generator| Self::Item {
                _marker: Default::default(),
                generator,
            })
            .drive_unindexed(consumer)
    }
}

#[cfg(feature = "multithread")]
impl<I> IndexedParallelIterator for RandomGeneratorParForkIterator<I>
where
    I: Implementation + Send + Sync,
    I::Generator: ParForkableGenerator,
{
    fn len(&self) -> usize {
        self.part_iter.len()
    }

    fn drive<C>(self, consumer: C) -> C::Result
    where
        C: Consumer<Self::Item>,
    {
        self.part_iter
            .map(|generator: I::Generator| Self::Item {
                _marker: Default::default(),
                generator,
            })
            .drive(consumer)
    }

    fn with_producer<CB: ProducerCallback<Self::Item>>(self, callback: CB) -> CB::Output {
        self.part_iter
            .map(|generator: I::Generator| Self::Item {
                _marker: Default::default(),
                generator,
            })
            .with_producer(callback)
    }
}

#[cfg(test)]
mod test {
    use crate::generator::{ForkableGenerator, RandomBytesGenerator};
    use crate::seeders::Seeder;

    use super::*;

    #[test]
    fn test_uniformity() {
        // Checks that the PRNG generates uniform numbers
        let precision = 10f64.powi(-4);
        let n_samples = 10_000_000_usize;
        let aes_key = DevRandom::try_new(None)
            .and_then(|mut s| s.seed_key())
            .unwrap();
        let mut generator = crate::FirmAesCtrGenerator::try_new(aes_key).unwrap();
        let mut counts = [0usize; 256];
        let expected_prob: f64 = 1. / 256.;
        for _ in 0..n_samples {
            counts[generator.generate_next().unwrap() as usize] += 1;
        }
        counts
            .iter()
            .map(|a| (*a as f64) / (n_samples as f64))
            .for_each(|a| assert!((a - expected_prob) < precision))
    }

    #[test]
    fn test_generator_determinism() {
        // checks that given a state and a key, the prng is determinist.
        for _ in 0..100 {
            let aes_key = DevRandom::try_new(None)
                .and_then(|mut s| s.seed_key())
                .unwrap();
            let mut first_generator = crate::FirmAesCtrGenerator::try_new(aes_key).unwrap();
            let mut second_generator = crate::FirmAesCtrGenerator::try_new(aes_key).unwrap();
            for _ in 0..128 {
                assert_eq!(
                    first_generator.generate_next(),
                    second_generator.generate_next()
                );
            }
        }
    }

    #[test]
    fn test_fork() {
        // checks that forks returns a bounded child, and that the proper number of bytes can
        // generated.
        let aes_key = DevRandom::try_new(None)
            .and_then(|mut s| s.seed_key())
            .unwrap();
        let mut gen = crate::FirmAesCtrGenerator::try_new(aes_key).unwrap();
        let mut bounded = gen
            .try_fork(ChildCount(1), BytesPerChild(10))
            .unwrap()
            .next()
            .unwrap();
        assert!(bounded.is_bounded());
        assert!(!gen.is_bounded());
        for _ in 0..10 {
            bounded.generate_next();
        }
    }

    #[test]
    fn test_bounded_returns_none() {
        // checks that a bounded prng panics when exceeding the allowed number of bytes.
        let aes_key = DevRandom::try_new(None)
            .and_then(|mut s| s.seed_key())
            .unwrap();
        let mut gen = crate::FirmAesCtrGenerator::try_new(aes_key).unwrap();
        let mut bounded = gen
            .try_fork(ChildCount(1), BytesPerChild(10))
            .unwrap()
            .next()
            .unwrap();
        assert!(bounded.is_bounded());
        assert!(!gen.is_bounded());
        for _ in 0..10 {
            assert!(bounded.generate_next().is_some());
        }
        assert!(bounded.generate_next().is_none());
    }
}
