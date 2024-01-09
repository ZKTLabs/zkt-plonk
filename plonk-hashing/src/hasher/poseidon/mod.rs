pub mod constants;
pub mod matrix;
pub mod mds;
pub mod spec;
pub mod preprocessing;
pub mod round_constant;
pub mod round_numbers;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum PoseidonError {
    #[error("Buffer is full")]
    FullBuffer,
}
