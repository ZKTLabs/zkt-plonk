// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! A collection of all possible errors encountered in PLONK.

use thiserror::Error;

use crate::commitment::HomomorphicCommitment;

/// Defines all possible errors that can be encountered in PLONK.
#[derive(Error, Debug)]
pub enum Error {
    // FFT errors
    /// This error occurs when an error triggers on any of the fft module
    /// functions.
    #[error("Invalid evaluation domain size: {log_size_of_group} > {adicity}")]
    InvalidEvalDomainSize {
        /// Log size of the group
        log_size_of_group: u32,
        /// Two adicity generated
        adicity: u32,
    },

    // Prover/Verifier errors
    /// This error occurs when a proof verification fails.
    #[error("proof verification failed")]
    ProofVerificationError,

    /// Polynomial Commitment errors
    #[error("PCError: {error}")]
    PCError {
        /// Polynomial Commitment errors
        error: String,
    },

    // KZG10 errors
    // XXX: Are these errors still used?
    /// This error occurs when the user tries to create PublicParameters
    /// and supplies the max degree as zero.
    #[error("cannot create PublicParameters with max degree 0")]
    DegreeIsZero,
    /// This error occurs when the user tries to trim PublicParameters
    /// to a degree that is larger than the maximum degree.
    #[error("cannot trim more than the maximum degree")]
    TruncatedDegreeTooLarge,
    /// This error occurs when the user tries to trim PublicParameters
    /// down to a degree that is zero.
    #[error("cannot trim PublicParameters to a maximum size of zero")]
    TruncatedDegreeIsZero,
    /// This error occurs when the user tries to commit to a polynomial whose
    /// degree is larger than the supported degree for that proving key.
    #[error("proving key is not large enough to commit to said polynomial")]
    PolynomialDegreeTooLarge,
    /// This error occurs when the user tries to commit to a polynomial whose
    /// degree is zero.
    #[error("cannot commit to polynomial of zero degree")]
    PolynomialDegreeIsZero,
    /// This error occurs when the pairing check fails at being equal to the
    /// Identity point.
    #[error("pairing check failed")]
    PairingCheckFailure,

    /// This error occurs when a malformed point is decoded from a byte array.
    #[error("point bytes malformed")]
    PointMalformed,
    /// This error occurs when a malformed scalar is decoded from a byte
    /// array.
    #[error("scalar bytes malformed")]
    ScalarMalformed,

    // Plonk circuit errors
    /// Element is not found in lookup table.
    #[error("element not found in lookup table")]
    ElementNotIndexed,
    /// Synthesis errors
    #[error("Synthesis error: {error}")]
    SynthesisError {
        /// Circuit errors
        error: String,
    },
}

impl From<ark_poly_commit::error::Error> for Error {
    fn from(error: ark_poly_commit::error::Error) -> Self {
        Self::PCError {
            error: format!("Polynomial Commitment Error: {:?}", error),
        }
    }
}

/// Convert an ark_poly_commit error
pub fn to_pc_error<F, PC>(error: PC::Error) -> Error
where
    F: ark_ff::Field,
    PC: HomomorphicCommitment<F>,
{
    Error::PCError {
        error: format!("Polynomial Commitment Error: {:?}", error),
    }
}
