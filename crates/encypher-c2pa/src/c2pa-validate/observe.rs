//! Lightweight, dependency-free verification metrics.
//!
//! A process-wide [`Metrics`] of atomic counters the host (sidecar/PyO3 shim)
//! can scrape and export to Prometheus/OTel without this crate taking a metrics
//! dependency. Counters cover outcomes (valid/invalid/trusted/no-manifest),
//! errors, and contained panics — the signals an operator needs at billions/day.

use std::sync::atomic::{AtomicU64, Ordering};

/// Process-wide verification counters. Construct one [`Metrics`] per process
/// (or use [`global`]) and read snapshots via [`Metrics::snapshot`].
#[derive(Default)]
pub struct Metrics {
    /// Total verify calls completed (any outcome).
    pub verifications: AtomicU64,
    /// Results with state `Trusted`.
    pub trusted: AtomicU64,
    /// Results with state `Valid` (not trusted).
    pub valid: AtomicU64,
    /// Results with state `Invalid`.
    pub invalid: AtomicU64,
    /// Assets with no C2PA manifest.
    pub no_manifest: AtomicU64,
    /// Verify calls that returned a [`crate::c2pa_validate::ValidateError`].
    pub errors: AtomicU64,
    /// Contained panics (defence-in-depth; should always be 0 in practice).
    pub panics: AtomicU64,
}

/// A point-in-time, plain-data snapshot of [`Metrics`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetricsSnapshot {
    /// See [`Metrics::verifications`].
    pub verifications: u64,
    /// See [`Metrics::trusted`].
    pub trusted: u64,
    /// See [`Metrics::valid`].
    pub valid: u64,
    /// See [`Metrics::invalid`].
    pub invalid: u64,
    /// See [`Metrics::no_manifest`].
    pub no_manifest: u64,
    /// See [`Metrics::errors`].
    pub errors: u64,
    /// See [`Metrics::panics`].
    pub panics: u64,
}

impl Metrics {
    /// A fresh zeroed metrics set.
    pub const fn new() -> Self {
        Metrics {
            verifications: AtomicU64::new(0),
            trusted: AtomicU64::new(0),
            valid: AtomicU64::new(0),
            invalid: AtomicU64::new(0),
            no_manifest: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            panics: AtomicU64::new(0),
        }
    }

    /// Record a completed verification by its state.
    pub fn record_state(&self, state: crate::c2pa_validate::ValidationState) {
        self.verifications.fetch_add(1, Ordering::Relaxed);
        match state {
            crate::c2pa_validate::ValidationState::Trusted => &self.trusted,
            crate::c2pa_validate::ValidationState::Valid => &self.valid,
            crate::c2pa_validate::ValidationState::Invalid => &self.invalid,
            // No provenance: count alongside the other no-manifest outcomes.
            crate::c2pa_validate::ValidationState::None => &self.no_manifest,
        }
        .fetch_add(1, Ordering::Relaxed);
    }

    /// Record an asset with no manifest.
    pub fn record_no_manifest(&self) {
        self.no_manifest.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a verify error.
    pub fn record_error(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a contained panic.
    pub fn record_panic(&self) {
        self.panics.fetch_add(1, Ordering::Relaxed);
    }

    /// Read a consistent-enough snapshot (relaxed; for export, not accounting).
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            verifications: self.verifications.load(Ordering::Relaxed),
            trusted: self.trusted.load(Ordering::Relaxed),
            valid: self.valid.load(Ordering::Relaxed),
            invalid: self.invalid.load(Ordering::Relaxed),
            no_manifest: self.no_manifest.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            panics: self.panics.load(Ordering::Relaxed),
        }
    }
}

/// The process-global metrics instance (for hosts that prefer a singleton).
pub fn global() -> &'static Metrics {
    static GLOBAL: Metrics = Metrics::new();
    &GLOBAL
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c2pa_validate::ValidationState;

    #[test]
    fn counts_states() {
        let m = Metrics::new();
        m.record_state(ValidationState::Trusted);
        m.record_state(ValidationState::Valid);
        m.record_state(ValidationState::Invalid);
        m.record_state(ValidationState::Invalid);
        m.record_no_manifest();
        m.record_error();
        m.record_panic();
        let s = m.snapshot();
        assert_eq!(s.verifications, 4);
        assert_eq!(s.trusted, 1);
        assert_eq!(s.valid, 1);
        assert_eq!(s.invalid, 2);
        assert_eq!(s.no_manifest, 1);
        assert_eq!(s.errors, 1);
        assert_eq!(s.panics, 1);
    }

    #[test]
    fn global_is_shared() {
        let before = global().snapshot().verifications;
        global().record_state(ValidationState::Valid);
        assert_eq!(global().snapshot().verifications, before + 1);
    }
}
