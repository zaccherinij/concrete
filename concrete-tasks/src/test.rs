use crate::utils::{project_root, Environment};
use crate::{cmd, ENV_TARGET_NATIVE};
use std::collections::HashMap;
use std::io::Error;
use std::path::PathBuf;

lazy_static! {
    static ref CONCRETE_FFI_TEST_DIR: PathBuf = {
        let mut path = project_root();
        path.push("concrete-ffi");
        path.push("build");
        path
    };
    static ref ENV_COVERAGE: Environment = {
        let mut env = HashMap::new();
        env.insert("CARGO_INCREMENTAL", "0");
        env.insert("RUSTFLAGS", "-Zprofile -Ccodegen-units=1 -Cinline-threshold=0 -Clink-dead-code -Coverflow-checks=off -Cpanic=abort -Zpanic_abort_tests");
        env.insert("RUSTDOCFLAGS", "-Zprofile -Ccodegen-units=1 -Cinline-threshold=0 -Clink-dead-code -Coverflow-checks=off -Cpanic=abort -Zpanic_abort_tests");
        env
    };
}

pub fn toplevel() -> Result<(), Error> {
    cmd!(<ENV_TARGET_NATIVE> "cargo test --release --no-fail-fast --all-features -p concrete")
}

pub fn commons() -> Result<(), Error> {
    cmd!(<ENV_TARGET_NATIVE> "cargo test --release --no-fail-fast --all-features -p concrete-commons")
}

pub fn core() -> Result<(), Error> {
    cmd!(<ENV_TARGET_NATIVE> "cargo test --release --no-fail-fast --all-features -p concrete-core")
}

pub fn csprng() -> Result<(), Error> {
    cmd!(<ENV_TARGET_NATIVE> "cargo test --release --no-fail-fast --all-features -p concrete-csprng")
}

pub fn npe() -> Result<(), Error> {
    cmd!(<ENV_TARGET_NATIVE> "cargo test --release --no-fail-fast --all-features -p concrete-npe")
}

pub fn ffi() -> Result<(), Error> {
    if !CONCRETE_FFI_TEST_DIR.exists() {
        std::fs::create_dir(&*CONCRETE_FFI_TEST_DIR)?;
    }
    cmd!("cargo build --release -p concrete-ffi")?;
    cmd!(<<CONCRETE_FFI_TEST_DIR>> "cmake make ..")?;
    cmd!(<<CONCRETE_FFI_TEST_DIR>> "make")?;
    cmd!(<<CONCRETE_FFI_TEST_DIR>> "ctest --verbose --output-on-failure")
}

pub fn crates() -> Result<(), Error> {
    cmd!(<ENV_TARGET_NATIVE> "cargo test --release --no-fail-fast --all-features")
}

pub fn cov_crates() -> Result<(), Error> {
    cmd!(<ENV_COVERAGE> "cargo +nightly test --release --no-fail-fast --all-features")
}
