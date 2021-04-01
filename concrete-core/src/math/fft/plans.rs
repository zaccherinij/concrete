use fftw::plan::{C2CPlan, C2CPlan128, C2CPlan32, C2CPlan64};
use fftw::types::{Flag, Sign};
use lazy_static::lazy_static;

lazy_static! {
    pub static ref C2C_256_32_F: C2CPlan32 =
        <C2CPlan32 as C2CPlan>::aligned(&[256], Sign::Forward, Flag::MEASURE).unwrap();
    pub static ref C2C_256_32_B: C2CPlan32 =
        <C2CPlan32 as C2CPlan>::aligned(&[256], Sign::Backward, Flag::MEASURE).unwrap();
    pub static ref C2C_512_32_F: C2CPlan32 =
        <C2CPlan32 as C2CPlan>::aligned(&[512], Sign::Forward, Flag::MEASURE).unwrap();
    pub static ref C2C_512_32_B: C2CPlan32 =
        <C2CPlan32 as C2CPlan>::aligned(&[512], Sign::Backward, Flag::MEASURE).unwrap();
    pub static ref C2C_1024_32_F: C2CPlan32 =
        <C2CPlan32 as C2CPlan>::aligned(&[1024], Sign::Forward, Flag::MEASURE).unwrap();
    pub static ref C2C_1024_32_B: C2CPlan32 =
        <C2CPlan32 as C2CPlan>::aligned(&[1024], Sign::Backward, Flag::MEASURE).unwrap();
    pub static ref C2C_2048_32_F: C2CPlan32 =
        <C2CPlan32 as C2CPlan>::aligned(&[2048], Sign::Forward, Flag::MEASURE).unwrap();
    pub static ref C2C_2048_32_B: C2CPlan32 =
        <C2CPlan32 as C2CPlan>::aligned(&[2048], Sign::Backward, Flag::MEASURE).unwrap();
    pub static ref C2C_4096_32_F: C2CPlan32 =
        <C2CPlan32 as C2CPlan>::aligned(&[4096], Sign::Forward, Flag::MEASURE).unwrap();
    pub static ref C2C_4096_32_B: C2CPlan32 =
        <C2CPlan32 as C2CPlan>::aligned(&[4096], Sign::Backward, Flag::MEASURE).unwrap();
    pub static ref C2C_256_64_F: C2CPlan64 =
        <C2CPlan64 as C2CPlan>::aligned(&[256], Sign::Forward, Flag::MEASURE).unwrap();
    pub static ref C2C_256_64_B: C2CPlan64 =
        <C2CPlan64 as C2CPlan>::aligned(&[256], Sign::Backward, Flag::MEASURE).unwrap();
    pub static ref C2C_512_64_F: C2CPlan64 =
        <C2CPlan64 as C2CPlan>::aligned(&[512], Sign::Forward, Flag::MEASURE).unwrap();
    pub static ref C2C_512_64_B: C2CPlan64 =
        <C2CPlan64 as C2CPlan>::aligned(&[512], Sign::Backward, Flag::MEASURE).unwrap();
    pub static ref C2C_1024_64_F: C2CPlan64 =
        <C2CPlan64 as C2CPlan>::aligned(&[1024], Sign::Forward, Flag::MEASURE).unwrap();
    pub static ref C2C_1024_64_B: C2CPlan64 =
        <C2CPlan64 as C2CPlan>::aligned(&[1024], Sign::Backward, Flag::MEASURE).unwrap();
    pub static ref C2C_2048_64_F: C2CPlan64 =
        <C2CPlan64 as C2CPlan>::aligned(&[2048], Sign::Forward, Flag::MEASURE).unwrap();
    pub static ref C2C_2048_64_B: C2CPlan64 =
        <C2CPlan64 as C2CPlan>::aligned(&[2048], Sign::Backward, Flag::MEASURE).unwrap();
    pub static ref C2C_4096_64_F: C2CPlan64 =
        <C2CPlan64 as C2CPlan>::aligned(&[4096], Sign::Forward, Flag::MEASURE).unwrap();
    pub static ref C2C_4096_64_B: C2CPlan64 =
        <C2CPlan64 as C2CPlan>::aligned(&[4096], Sign::Backward, Flag::MEASURE).unwrap();
    pub static ref C2C_256_128_F: C2CPlan128 =
        <C2CPlan128 as C2CPlan>::aligned(&[256], Sign::Forward, Flag::MEASURE).unwrap();
    pub static ref C2C_256_128_B: C2CPlan128 =
        <C2CPlan128 as C2CPlan>::aligned(&[256], Sign::Backward, Flag::MEASURE).unwrap();
    pub static ref C2C_512_128_F: C2CPlan128 =
        <C2CPlan128 as C2CPlan>::aligned(&[512], Sign::Forward, Flag::MEASURE).unwrap();
    pub static ref C2C_512_128_B: C2CPlan128 =
        <C2CPlan128 as C2CPlan>::aligned(&[512], Sign::Backward, Flag::MEASURE).unwrap();
    pub static ref C2C_1024_128_F: C2CPlan128 =
        <C2CPlan128 as C2CPlan>::aligned(&[1024], Sign::Forward, Flag::MEASURE).unwrap();
    pub static ref C2C_1024_128_B: C2CPlan128 =
        <C2CPlan128 as C2CPlan>::aligned(&[1024], Sign::Backward, Flag::MEASURE).unwrap();
    pub static ref C2C_2048_128_F: C2CPlan128 =
        <C2CPlan128 as C2CPlan>::aligned(&[2048], Sign::Forward, Flag::MEASURE).unwrap();
    pub static ref C2C_2048_128_B: C2CPlan128 =
        <C2CPlan128 as C2CPlan>::aligned(&[2048], Sign::Backward, Flag::MEASURE).unwrap();
    pub static ref C2C_4096_128_F: C2CPlan128 =
        <C2CPlan128 as C2CPlan>::aligned(&[4096], Sign::Forward, Flag::MEASURE).unwrap();
    pub static ref C2C_4096_128_B: C2CPlan128 =
        <C2CPlan128 as C2CPlan>::aligned(&[4096], Sign::Backward, Flag::MEASURE).unwrap();
}
