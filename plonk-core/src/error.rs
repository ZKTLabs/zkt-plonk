// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! A collection of all possible errors encountered in PLONK.

use crate::commitment::HomomorphicCommitment;

/// Defines all possible errors that can be encountered in PLONK.
#[derive(Debug)]
pub enum Error {
    // FFT errors
    /// This error occurs when an error triggers on any of the fft module
    /// functions.
    InvalidEvalDomainSize {
        /// Log size of the group
        log_size_of_group: u32,
        /// Two adicity generated
        adicity: u32,
    },

    // Prover/Verifier errors
    /// This error occurs when a proof verification fails.
    ProofVerificationError,
    /// Incorrect count of public inputs.
    IncorrectPublicInputs {
        ///
        expect: usize,
        ///
        actual: usize,
    },

    /// Polynomial Commitment errors
    PCError {
        /// Polynomial Commitment errors
        error: String,
    },

    // KZG10 errors
    // XXX: Are these errors still used?
    /// This error occurs when the user tries to create PublicParameters
    /// and supplies the max degree as zero.
    DegreeIsZero,
    /// This error occurs when the user tries to trim PublicParameters
    /// to a degree that is larger than the maximum degree.
    TruncatedDegreeTooLarge,
    /// This error occurs when the user tries to trim PublicParameters
    /// down to a degree that is zero.
    TruncatedDegreeIsZero,
    /// This error occurs when the user tries to commit to a polynomial whose
    /// degree is larger than the supported degree for that proving key.
    PolynomialDegreeTooLarge,
    /// This error occurs when the user tries to commit to a polynomial whose
    /// degree is zero.
    PolynomialDegreeIsZero,
    /// This error occurs when the pairing check fails at being equal to the
    /// Identity point.
    PairingCheckFailure,

    /// This error occurs when there are not enough bytes to read out of a
    /// slice during deserialization.
    NotEnoughBytes,
    /// This error occurs when a malformed point is decoded from a byte array.
    PointMalformed,
    /// This error occurs when a malformed scalar is decoded from a byte
    /// array.
    ScalarMalformed,

    // Plonkup circuit errors
    /// Element is not found in lookup table.
    ElementNotIndexed,
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

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidEvalDomainSize {
                log_size_of_group,
                adicity,
            } => write!(
                f,
                "Log-size of the EvaluationDomain group > TWO_ADICITY\
                Size: {:?} > TWO_ADICITY = {:?}",
                log_size_of_group,
                adicity,
            ),
            Self::ProofVerificationError => {
                write!(f, "proof verification failed")
            }
            Self::IncorrectPublicInputs{ expect, actual } => {
                write!(
                    f,
                    "incorrect count of public inputs, expect: {:?}, actual: {:?}",
                    expect,
                    actual,
                )
            }
            Self::PCError { error } => {
                write!(f, "{:?}", error)
            }
            Self::DegreeIsZero => {
                write!(f, "cannot create PublicParameters with max degree 0")
            }
            Self::TruncatedDegreeTooLarge => {
                write!(f, "cannot trim more than the maximum degree")
            }
            Self::TruncatedDegreeIsZero => write!(
                f,
                "cannot trim PublicParameters to a maximum size of zero"
            ),
            Self::PolynomialDegreeTooLarge => write!(
                f,
                "proving key is not large enough to commit to said polynomial"
            ),
            Self::PolynomialDegreeIsZero => {
                write!(f, "cannot commit to polynomial of zero degree")
            }
            Self::PairingCheckFailure => write!(f, "pairing check failed"),
            Self::NotEnoughBytes => write!(f, "not enough bytes left to read"),
            Self::PointMalformed => write!(f, "point bytes malformed"),
            Self::ScalarMalformed => write!(f, "scalar bytes malformed"),
            Self::ElementNotIndexed => {
                write!(f, "element not found in lookup table")
            }
        }
    }
}

impl std::error::Error for Error {}
