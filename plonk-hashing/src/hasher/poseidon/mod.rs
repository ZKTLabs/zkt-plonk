mod spec;
mod preprocessing;
mod constants;
mod matrix;
mod mds;
mod round_constant;
mod round_numbers;

pub use constants::*;
pub use matrix::*;
pub use mds::*;
pub use spec::*;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum PoseidonError {
    #[error("Buffer is full")]
    FullBuffer,
}
