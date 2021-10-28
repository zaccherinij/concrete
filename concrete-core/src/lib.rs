// #![deny(rustdoc::broken_intra_doc_links)]
//! Welcome to the `concrete-core` documentation!
//!
//! This library contains a set of low-level primitives which can be used to implement *fully
//! homomorphically encrypted* programs. In a nutshell, fully homomorphic encryption makes it
//! possible to perform arbitrary computations over encrypted data. With fhe, you can perform
//! computations without putting your trust on third-party computation providers.
//!
//! # Audience
//!
//! This library is geared towards people who already know their way around Fhe. If you are not a
//! cryptographer, this library may be unsafe/unsecure for you to use, as it requires you to tune
//! a breadth of parameters which have an impact on the security/speed trade-off.
//!
//! Hopefully, we propose multiple libraries that build on top of `concrete-core` and which propose
//! a safer/secure API. To see which one best suits your needs, see the
//! [concrete homepage](https://zama.ai/concrete).
//!
//! # Architecture
//!
//! `concrete-core` is a modular library which makes it possible to use different backends to
//! perform fhe operations. Its design revolves around two modules:
//!
//! + The [`specification`] module contains a specification (in the form of traits) of the concrete
//! fhe scheme. It describes the fhe objects and operators, which are exposed by the library.
//! + The [`backends`] module contains various backends implementing all or a part of this scheme.
//! These different backends can be activated by feature flags, each making use of different
//! hardware or system libraries to make the operations faster.
//!
//! # Activating backends
//!
//! The different backends can be activated using the feature flags `backend_*`. The `backend_core`
//! contains an engine executing operations on a single thread of the cpu. It is activated by
//! default.
//!
//! # Navigating the code
//!
//! If this is your first time looking at the `concrete-core` code-base, it may be simpler for you
//! to first have a look at the [`specification`] module, which contains explanations on the
//! abstract API, and navigate from there.

pub mod backends;
pub mod prelude;
pub mod commons;
pub mod specification;
