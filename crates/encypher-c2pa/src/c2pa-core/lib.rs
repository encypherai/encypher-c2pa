//! C2PA core data structures: JUMBF boxes, claim assembly, and parsing.
//!
//! This crate is I/O-free. It builds and parses the JUMBF/CBOR layer used by
//! the format and validation crates.

pub(crate) mod claim;
pub(crate) mod jumbf;
pub(crate) mod spec;

pub(crate) use crate::c2pa_cbor as cbor;
pub(crate) use spec::{ComplianceLevel, EngineProfile, OperatingMode, SpecVersion};
