//! Typed errors. Nothing Stringly-typed crosses a public boundary.
//!
//! Policy *verdicts* carry structured [`crate::Refusal`]s (policy + reason);
//! operational failures — config I/O, TOML parsing, invalid policy
//! parameters, audit sink failures — surface as [`GovernorError`].

use std::io;

/// Every fallible operation in the crate fails with this type.
#[derive(Debug, thiserror::Error)]
pub enum GovernorError {
    /// The config file could not be read.
    #[error("cannot read config file '{path}': {source}")]
    ConfigRead {
        /// Path that was attempted.
        path: String,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// The config file is not valid TOML, or not a valid [`crate::GovernorConfig`].
    #[error("cannot parse config: {0}")]
    ConfigParse(#[from] toml::de::Error),

    /// A policy was constructed with invalid parameters (empty window,
    /// inverted hours, zero limit, unknown policy type in config, …).
    #[error("invalid policy: {0}")]
    InvalidPolicy(String),

    /// The audit sink refused or failed a record.
    #[error("audit sink failed: {0}")]
    Audit(String),
}
