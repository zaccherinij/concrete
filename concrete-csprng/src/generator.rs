#[cfg(feature = "multithread")]
use rayon::iter::IndexedParallelIterator;

/// The number of children created when a generator is forked.
#[derive(Debug, Copy, Clone)]
pub struct ChildCount(pub usize);

/// The number of bytes each children can generate, when a generator is forked.
#[derive(Debug, Copy, Clone)]
pub struct BytesPerChild(pub usize);

/// The `RandomBytesGenerator` allows for generating secure random bytes.
pub trait RandomBytesGenerator: Sized {
    /// Yields the next random byte.
    ///
    /// May return `None` if the generator `is_bounded`
    /// and bounds were reached
    fn generate_next(&mut self) -> Option<u8>;

    /// Returns whether the generator is bounded.
    fn is_bounded(&self) -> bool;

    /// Returns how many bytes the `generate_next` method can return.
    ///
    /// If the generator is not bounded, `None` is returned.
    fn remaining_bytes(&self) -> Option<usize>;

    /// Completely fills the `bytes` buffer with random_bytes.
    ///
    /// If the generator is bounded and its bound were reached before being able
    /// to __fully__ fill the buffer, an `Err` is returned.
    fn generate_bytes_exact(&mut self, bytes: &mut [u8]) -> Result<(), crate::Error> {
        let mut num_bytes_generated = 0usize;
        for byte in bytes.iter_mut() {
            match self.generate_next() {
                None => break,
                Some(value) => *byte = value,
            }
            num_bytes_generated += 1;
        }

        if num_bytes_generated != bytes.len() {
            Err(crate::Error::GeneratorBoundsReached)
        } else {
            Ok(())
        }
    }
}

pub trait ForkableGenerator: RandomBytesGenerator {
    /// The type of the iterator returned when forking.
    type ForkIterator: Iterator<Item = Self>;

    /// Tries to fork the current generator into `n_child` generators each able to yield
    /// `child_bytes` random bytes.
    ///
    /// If the total number of bytes to be generated exceeds the bound of the current generator,
    /// `None` is returned. Otherwise, we return an iterator over the children generators.
    fn try_fork(
        &mut self,
        n_child: ChildCount,
        child_bytes: BytesPerChild,
    ) -> Option<Self::ForkIterator>;
}

#[cfg(feature = "multithread")]
pub trait ParForkableGenerator: ForkableGenerator {
    type ParForkIterator: IndexedParallelIterator<Item = Self>;

    /// Tries to fork the current generator into `n_child` generators each able to yield
    /// `child_bytes` random bytes as a parallel iterator.
    ///
    /// If the total number of bytes to be generated exceeds the bound of the current generator,
    /// `None` is returned. Otherwise, we return a parallel iterator over the children generators.
    ///
    /// # Notes
    ///
    /// This method necessitate the "multithread" feature.
    fn par_try_fork(
        &mut self,
        n_child: ChildCount,
        child_bytes: BytesPerChild,
    ) -> Option<Self::ParForkIterator>;
}
