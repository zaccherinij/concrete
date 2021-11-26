#[cfg(feature = "multithread")]
use rayon::iter::plumbing::{Consumer, ProducerCallback, UnindexedConsumer};
#[cfg(feature = "multithread")]
use rayon::{iter::IndexedParallelIterator, prelude::*};

use crate::aes::encryptors::{hardware, software, AesBatchedEncryptor, FirmAesEncryptor};
#[cfg(feature = "multithread")]
use crate::generator::ParForkableGenerator;
use crate::generator::{BytesPerChild, ChildCount, ForkableGenerator};
use crate::{AesKey, RandomBytesGenerator};

#[cfg(test)]
mod test;

#[cfg(all(
    test,
    target_arch = "x86_64",
    target_feature = "aes",
    target_feature = "sse2",
    target_feature = "rdseed"
))]
mod test_aes;

mod state;

use state::{ShouldGenerateBatch, State};

/// A generator that uses the hardware implementation.
pub(crate) type HardAesCtrGenerator = AesCtrGenerator<hardware::Encryptor>;

/// A generator that uses the software implementation.
pub(crate) type SoftAesCtrGenerator = AesCtrGenerator<software::Encryptor>;

impl SoftAesCtrGenerator {
    pub fn new(aes_key: AesKey) -> Self {
        Self::try_new(aes_key)
            .expect("Internal Error, unexpectedly failed to create software AES generator")
    }
}

/// A generator that can be either software or hardware
/// prioritizing hardware and falling back to software if the required instructions are not
/// available
pub type FirmAesCtrGenerator = AesCtrGenerator<FirmAesEncryptor>;

/// A csprng which operates in batch mode.
#[derive(Clone, Debug)]
pub struct AesCtrGenerator<E: AesBatchedEncryptor> {
    encryptor: E,
    state: State,
    bound: Option<State>,
    batch: [u8; 128],
}

impl<E: AesBatchedEncryptor> AesCtrGenerator<E> {
    pub fn try_new(key: AesKey) -> Result<Self, crate::Error> {
        let state = State::default();
        Self::try_with_state(key, state, None)
    }

    fn try_with_state(
        key: AesKey,
        state: State,
        bound: Option<State>,
    ) -> Result<Self, crate::Error> {
        let mut generator = E::try_new(key)?;
        if let Some(ref actual_bound) = bound {
            debug_assert!(state <= *actual_bound);
        }
        let batch = generator.encrypt_batch(state.aes_ctr);
        Ok(AesCtrGenerator {
            encryptor: generator,
            state,
            bound,
            batch,
        })
    }

    /// Returns the state of the current generator.
    #[cfg(test)]
    pub(crate) fn get_state(&self) -> &State {
        &self.state
    }

    /// Returns the bound of the generator if any.
    #[cfg(test)]
    pub(crate) fn get_bound(&self) -> Option<&State> {
        self.bound.as_ref()
    }

    /// Returns whether the generator is bounded.
    pub fn is_bounded(&self) -> bool {
        self.bound.is_some()
    }

    fn regenerate_batch(&mut self, n_child: ChildCount, child_bytes: BytesPerChild) {
        let generate = self.state.shift(child_bytes.0 * n_child.0);
        if let ShouldGenerateBatch::GenerateBatch = generate {
            self.batch = self.encryptor.encrypt_batch(self.state.get_aes_counter());
        }
    }

    fn is_fork_in_bound(&self, n_child: ChildCount, child_bytes: BytesPerChild) -> bool {
        if let Some(ref actual_bound) = self.bound {
            let mut end = self.state;
            end.shift(n_child.0 * child_bytes.0);
            if end > *actual_bound {
                return false;
            }
        }
        true
    }
}

impl<E: AesBatchedEncryptor> RandomBytesGenerator for AesCtrGenerator<E> {
    fn generate_next(&mut self) -> Option<u8> {
        // TODO check perf when using previous way of checking
        let reached_bound = self.bound.map_or(false, |bound| {
            self.state.aes_ctr == bound.aes_ctr && self.state.byte_ctr == bound.byte_ctr
        });
        if reached_bound {
            return None;
        }

        let output = self.batch[self.state.get_batch_index()];
        if let ShouldGenerateBatch::GenerateBatch = self.state.increment() {
            self.batch = self.encryptor.encrypt_batch(self.state.get_aes_counter());
        }
        Some(output)
    }

    fn is_bounded(&self) -> bool {
        self.bound.is_some()
    }

    fn remaining_bytes(&self) -> Option<usize> {
        self.bound.as_ref().map(|bound| {
            let res = ((bound.aes_ctr.0 - self.state.aes_ctr.0) as i128) * 16
                + (bound.byte_ctr.0 as i128 - self.state.byte_ctr.0 as i128);
            res as usize
        })
    }
}

impl<E: AesBatchedEncryptor> ForkableGenerator for AesCtrGenerator<E> {
    type ForkIterator = ForkIterator<E>;

    fn try_fork(
        &mut self,
        n_child: ChildCount,
        child_bytes: BytesPerChild,
    ) -> Option<Self::ForkIterator> {
        if !self.is_fork_in_bound(n_child, child_bytes) {
            return None;
        }
        let iterator = ForkIterator {
            range_iter: (0..n_child.0),
            closure: ForkClosure::new(self, child_bytes),
        };

        self.regenerate_batch(n_child, child_bytes);
        Some(iterator)
    }
}

#[cfg(feature = "multithread")]
impl<E: AesBatchedEncryptor + Send + Sync> ParForkableGenerator for AesCtrGenerator<E> {
    type ParForkIterator = ParForkIterator<E>;

    #[cfg(feature = "multithread")]
    fn par_try_fork(
        &mut self,
        n_child: ChildCount,
        child_bytes: BytesPerChild,
    ) -> Option<Self::ParForkIterator> {
        if !self.is_fork_in_bound(n_child, child_bytes) {
            return None;
        }
        let output = ParForkIterator {
            range_iter: (0..n_child.0).into_par_iter(),
            closure: ForkClosure::new(self, child_bytes),
        };
        self.regenerate_batch(n_child, child_bytes);
        Some(output)
    }
}

/// A closure-like struct.
///
/// This struct returns a new bounded generator each time its [Self::call] is called.
///
/// It id done this way, as Rust does not allow opaque type
///(eg: `struct { field: impl Fn(usize) -> AesCtrGenerator<G>}`)
/// as a type member, and Map<Range<usize>, Fn(usize) -> ...> is not possible either
#[derive(Clone)]
struct ForkClosure<G: AesBatchedEncryptor> {
    state: State,
    encryptor: G,
    child_bytes: BytesPerChild,
}

impl<G: AesBatchedEncryptor> ForkClosure<G> {
    fn new(generator: &AesCtrGenerator<G>, child_bytes: BytesPerChild) -> Self {
        Self {
            state: generator.state,
            encryptor: generator.encryptor.clone(),
            child_bytes,
        }
    }
}

// Implementing `Fn(usize) -> AesCtrGenerator<G>` is not possible
// in stable Rust
impl<G: AesBatchedEncryptor> ForkClosure<G> {
    fn call(&self, i: usize) -> AesCtrGenerator<G> {
        let mut new_state = self.state;
        new_state.shift(self.child_bytes.0 * i);

        let mut new_bound = new_state;
        new_bound.shift(self.child_bytes.0);
        new_bound.normalize_with(&new_state);

        let mut new_generator = self.encryptor.clone();
        let batch = new_generator.encrypt_batch(new_state.aes_ctr);

        AesCtrGenerator {
            encryptor: new_generator,
            state: new_state,
            bound: Some(new_bound),
            batch,
        }
    }
}

/// Iterator that calls a [ForkClosure] on a range
#[derive(Clone)]
pub struct ForkIterator<G: AesBatchedEncryptor> {
    range_iter: std::ops::Range<usize>,
    closure: ForkClosure<G>,
}

impl<G: AesBatchedEncryptor> Iterator for ForkIterator<G> {
    type Item = AesCtrGenerator<G>;

    fn next(&mut self) -> Option<Self::Item> {
        self.range_iter.next().map(|i| self.closure.call(i))
    }
}

/// Parallelized version of [ForkIterator]
#[cfg(feature = "multithread")]
pub struct ParForkIterator<G: AesBatchedEncryptor> {
    range_iter: rayon::range::Iter<usize>,
    closure: ForkClosure<G>,
}

#[cfg(feature = "multithread")]
impl<G: AesBatchedEncryptor + Send + Sync> ParallelIterator for ParForkIterator<G> {
    type Item = AesCtrGenerator<G>;

    fn drive_unindexed<C>(self, consumer: C) -> C::Result
    where
        C: UnindexedConsumer<Self::Item>,
    {
        let closure = self.closure.clone();
        self.range_iter
            .map(|i| closure.call(i))
            .drive_unindexed(consumer)
    }
}

#[cfg(feature = "multithread")]
impl<G: AesBatchedEncryptor + Send + Sync> IndexedParallelIterator for ParForkIterator<G> {
    fn len(&self) -> usize {
        self.range_iter.len()
    }

    fn drive<C: Consumer<Self::Item>>(self, consumer: C) -> C::Result {
        let closure = self.closure.clone();
        self.range_iter.map(|i| closure.call(i)).drive(consumer)
    }

    fn with_producer<CB: ProducerCallback<Self::Item>>(self, callback: CB) -> CB::Output {
        let closure = self.closure.clone();
        self.range_iter
            .map(|i| closure.call(i))
            .with_producer(callback)
    }
}
