//! This module contains different `seeders` possible
use crate::AesKey;
use software::DevRandom;

/// Trait for random seeders
pub trait Seeder {
    /// Returns a new random seeded AES key
    fn seed_key(&mut self) -> Result<AesKey, crate::Error> {
        self.seed().map(AesKey)
    }

    /// Returns a new random seeded number
    fn seed(&mut self) -> Result<u128, crate::Error>;
}

/// Returns the seeder to be used by default
///
/// Tries to create a hardware-based seeder,
/// fallbacks to a software seeder if no hardware-based seeder is available.
///
/// # Example
///
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use concrete_csprng::{seeders, Seeder};
///
/// let mut seeder = seeders::default()?;
/// let random_value = seeder.seed();
/// let random_key = seeder.seed_key();
/// # Ok(())
/// # }
/// ```
pub fn default() -> Result<Box<dyn Seeder>, crate::Error> {
    let seeder = hardware::x86_64::RDSeed::try_new();
    if let Ok(s) = seeder {
        Ok(Box::new(s))
    } else {
        DevRandom::try_new(None).map(|seeder| Box::new(seeder) as Box<dyn Seeder>)
    }
}

pub mod software {
    //! Software-based random seeders.
    use crate::seeders::Seeder;
    use std::io::Read;

    /// A Seeder that uses `/dev/random` as a source of randomness
    ///
    /// # Example
    ///
    /// ```no_run
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use concrete_csprng::{seeders, DevRandom, Seeder};
    /// let mut random_key = DevRandom::try_new(None)?.seed_key();
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ```no_run
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use concrete_csprng::{seeders, DevRandom, Seeder};
    /// let mut random_key = DevRandom::try_new(Some(213981239u128))?.seed_key();
    /// # Ok(())
    /// # }
    /// ```
    pub struct DevRandom {
        counter: u128,
        // TODO remove the option and use 0 as uninitialized ?
        secret: Option<u128>,
    }

    impl Seeder for DevRandom {
        fn seed(&mut self) -> Result<u128, crate::Error> {
            let secret = match self.secret {
                Some(s) => s,
                None => {
                    if cfg!(not(test)) {
                        eprintln!(
                            "WARNING: You are currently using the software variant of concrete-csprng \
                        which does not have access to a hardware source of randomness. To ensure the \
                        security of your application, please arrange to provide a secret \
                        `to the DevRandom::new function."
                        );
                    }
                    0
                }
            };
            let rnd_value = dev_random().map_err(|err| crate::Error::Other {
                error: Box::new(err),
            })?;
            let output = secret ^ self.counter ^ rnd_value;
            self.counter = self.counter.wrapping_add(1);
            Ok(output)
        }
    }

    impl DevRandom {
        pub fn try_new(secret: Option<u128>) -> Result<Self, crate::Error> {
            let counter = std::time::UNIX_EPOCH
                .elapsed()
                .map_err(|err| crate::Error::Other {
                    error: Box::new(err),
                })?
                .as_nanos();
            Ok(Self { counter, secret })
        }
    }

    fn dev_random() -> std::io::Result<u128> {
        let mut random = std::fs::File::open("/dev/random")?;
        let mut buf = [0u8; 16];
        random.read_exact(&mut buf[..])?;
        Ok(u128::from_ne_bytes(buf))
    }
}

pub mod hardware {
    //! Hardware-based random seeders.
    //!
    //! The availability and of these seeders depends on your CPU and its features.

    #[cfg(target_arch = "x86_64")]
    pub type HardSeed = x86_64::RDSeed;

    #[cfg(target_arch = "x86_64")]
    pub mod x86_64 {
        use crate::seeders::Seeder;
        use core::arch::x86_64::__m128i;

        /// A Seeder that uses the `x86_64`'s `rdseed` special instructions
        ///
        /// # Example
        ///
        /// ```no_run
        /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
        /// use concrete_csprng::{seeders, Seeder};
        ///
        /// let mut seeder = seeders::hardware::x86_64::RDSeed::try_new()?;
        /// let random_key = seeder.seed_key();
        /// # Ok(())
        /// # }
        /// ```
        #[derive(Copy, Clone)]
        pub struct RDSeed {
            // To prevent user from building one without used
            // the appropriate constructor
            _dummy: (),
        }

        impl Seeder for RDSeed {
            fn seed(&mut self) -> Result<u128, crate::Error> {
                unsafe {
                    // Safe because this self cannot be created if "rdseed" feature
                    // was not detected
                    Ok(rdseed_random_m128())
                }
            }
        }

        impl RDSeed {
            pub fn try_new() -> Result<Self, crate::Error> {
                if is_x86_feature_detected!("rdseed") {
                    Ok(Self { _dummy: () })
                } else {
                    Err(crate::Error::UnsupportedCpuFeatures { features: "rdseed" })
                }
            }
        }

        /// Generates a random 128 bits value from rdseed
        ///
        /// # Safety
        ///
        /// You __must__ make sure the CPU's arch is `x86_64` and supports `rdseed` instructions
        #[target_feature(enable = "rdseed")]
        unsafe fn rdseed_random_m128() -> u128 {
            let mut rand1: u64 = 0;
            let mut rand2: u64 = 0;
            loop {
                if core::arch::x86_64::_rdseed64_step(&mut rand1) == 1 {
                    break;
                }
            }
            loop {
                if core::arch::x86_64::_rdseed64_step(&mut rand2) == 1 {
                    break;
                }
            }
            std::mem::transmute(std::mem::transmute::<(u64, u64), __m128i>((rand1, rand2)))
        }
    }
}
