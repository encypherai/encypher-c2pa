//! C2PA core data structures: JUMBF boxes, claim assembly, and parsing.
//!
//! This crate is I/O-free. It builds and parses the JUMBF/CBOR layer used by
//! the format and validation crates.

pub mod claim;
pub mod jumbf;
pub mod spec;

pub use c2pa_cbor as cbor;
pub use spec::{ComplianceLevel, EngineProfile, OperatingMode, SpecVersion};
