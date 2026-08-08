//! Content-addressed verification result cache.
//!
//! At billions/day, verification is read-heavy and highly cacheable: the same
//! asset is verified repeatedly (CDN revalidation, multi-consumer pipelines).
//! A verification result is a pure function of (asset bytes, trust config,
//! validation time), so it can be memoized by a content-address key.
//!
//! [`VerifyCache`] is an in-process LRU keyed by the SHA-256 of those inputs.
//! Entries carry a TTL so revocation-sensitive results (OCSP staples have a
//! `nextUpdate`) expire and are re-evaluated. The cache stores the compact
//! [`ValidationState`] + the status-code report, not the parsed manifest.
//!
//! A distributed cache may use the same content address as a shared key.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::c2pa_validate::ValidationState;

/// A cached verification outcome: the state plus the JSON report string.
#[derive(Clone)]
pub struct CachedResult {
    /// The overall validation state.
    pub state: ValidationState,
    /// The serialized `validation_results`/report JSON.
    pub report_json: String,
    inserted: Instant,
    ttl: Duration,
}

impl CachedResult {
    fn is_fresh(&self, now: Instant) -> bool {
        now.duration_since(self.inserted) < self.ttl
    }
}

/// An in-process, content-addressed, TTL'd LRU cache of verification results.
///
/// Thread-safety is the caller's concern (wrap in a `Mutex`/`RwLock` or shard);
/// keeping the core lock-free makes the sharding strategy explicit at the call
/// site rather than baked in.
pub struct VerifyCache {
    map: HashMap<[u8; 32], CachedResult>,
    order: Vec<[u8; 32]>,
    capacity: usize,
    default_ttl: Duration,
    hits: u64,
    misses: u64,
}

impl VerifyCache {
    /// Create a cache holding up to `capacity` entries with `default_ttl`.
    pub fn new(capacity: usize, default_ttl: Duration) -> Self {
        VerifyCache {
            map: HashMap::with_capacity(capacity),
            order: Vec::with_capacity(capacity),
            capacity: capacity.max(1),
            default_ttl,
            hits: 0,
            misses: 0,
        }
    }

    /// Compute the content-address key for a verification request.
    ///
    /// Keyed by asset bytes, MIME, the trust-config fingerprint, and the
    /// validation time (or a sentinel when using the system clock). Identical
    /// inputs always yield the same key; any change busts the entry.
    pub fn key(
        asset: &[u8],
        mime: &str,
        trust_fingerprint: &[u8],
        validation_time_rfc3339: Option<&str>,
    ) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update((asset.len() as u64).to_be_bytes());
        h.update(asset);
        h.update([0u8]);
        h.update(mime.as_bytes());
        h.update([0u8]);
        h.update(trust_fingerprint);
        h.update([0u8]);
        h.update(validation_time_rfc3339.unwrap_or("@now").as_bytes());
        h.finalize().into()
    }

    /// Look up a fresh entry, recording a hit/miss. Expired entries are evicted.
    pub fn get(&mut self, key: &[u8; 32]) -> Option<CachedResult> {
        let now = Instant::now();
        let fresh = self.map.get(key).map(|e| e.is_fresh(now)).unwrap_or(false);
        if fresh {
            self.hits += 1;
            // Move to MRU.
            if let Some(pos) = self.order.iter().position(|k| k == key) {
                let k = self.order.remove(pos);
                self.order.push(k);
            }
            self.map.get(key).cloned()
        } else {
            if self.map.remove(key).is_some() {
                if let Some(pos) = self.order.iter().position(|k| k == key) {
                    self.order.remove(pos);
                }
            }
            self.misses += 1;
            None
        }
    }

    /// Insert a result with the default TTL, evicting the LRU entry if full.
    pub fn put(&mut self, key: [u8; 32], state: ValidationState, report_json: String) {
        self.put_with_ttl(key, state, report_json, self.default_ttl);
    }

    /// Insert with an explicit TTL (e.g. derived from an OCSP `nextUpdate`).
    pub fn put_with_ttl(
        &mut self,
        key: [u8; 32],
        state: ValidationState,
        report_json: String,
        ttl: Duration,
    ) {
        if !self.map.contains_key(&key) && self.map.len() >= self.capacity {
            // Evict LRU.
            if !self.order.is_empty() {
                let lru = self.order.remove(0);
                self.map.remove(&lru);
            }
        }
        self.order.retain(|k| k != &key);
        self.order.push(key);
        self.map.insert(
            key,
            CachedResult {
                state,
                report_json,
                inserted: Instant::now(),
                ttl,
            },
        );
    }

    /// Number of live entries.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// True when the cache holds no entries.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Cache hit/miss counters, for observability.
    pub fn stats(&self) -> (u64, u64) {
        (self.hits, self.misses)
    }

    /// Verify `input`, consulting and populating the cache. This is the
    /// request-path integration: it derives the content-address [`key`] from the
    /// input, returns a cached [`CachedResult`] on a fresh hit, or otherwise runs
    /// [`crate::c2pa_validate::verify`] and stores the result. The TTL is the cache default.
    ///
    /// The cache is owned by the calling service (sidecar), not by the pure
    /// `verify` function, so the verifier stays side-effect-free and the cache
    /// lifecycle/sharding is explicit at the service layer.
    ///
    /// Returns `(result, was_cache_hit)`. On a cache hit the parsed
    /// [`crate::c2pa_validate::VerifyOutput`] is not reconstructed — the caller gets the stored
    /// state + report JSON, which is what a verify response serializes anyway.
    pub fn verify_cached(
        &mut self,
        input: &crate::c2pa_validate::VerifyInput,
    ) -> Result<(CachedResult, bool), crate::c2pa_validate::ValidateError> {
        // Trust fingerprint: hash the anchor DER set so a trust-list change busts
        // the entry. Empty when no trust list is configured.
        let trust_fp = trust_fingerprint(input);
        // Key on the validation instant's unix timestamp (stable, no formatting
        // dep). None -> the `key` sentinel for "system clock".
        let vt = input
            .validation_time
            .map(|t| t.unix_timestamp().to_string());
        let key = Self::key(input.data, input.mime, &trust_fp, vt.as_deref());
        if let Some(hit) = self.get(&key) {
            return Ok((hit, true));
        }
        let out = crate::c2pa_validate::verify(input)?;
        let report_json = serde_json::to_string(&out.report_json).unwrap_or_default();
        self.put(key, out.validation_state, report_json.clone());
        Ok((
            CachedResult {
                state: out.validation_state,
                report_json,
                inserted: Instant::now(),
                ttl: self.default_ttl,
            },
            false,
        ))
    }
}

/// Hash the trust-list anchor set (claim + TSA) into a fingerprint so a
/// trust-config change busts cache entries. Empty when no trust is configured.
fn trust_fingerprint(input: &crate::c2pa_validate::VerifyInput) -> Vec<u8> {
    let mut h = Sha256::new();
    if let Some(t) = input.claim_signer_trust {
        for a in &t.anchors {
            h.update((a.len() as u64).to_be_bytes());
            h.update(a);
        }
    }
    h.update([0xff]);
    if let Some(t) = input.tsa_trust {
        for a in &t.anchors {
            h.update((a.len() as u64).to_be_bytes());
            h.update(a);
        }
    }
    h.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(n: u8) -> [u8; 32] {
        [n; 32]
    }

    #[test]
    fn key_is_stable_and_input_sensitive() {
        let a = VerifyCache::key(
            b"asset",
            "image/jpeg",
            b"trustA",
            Some("2013-06-01T00:00:00Z"),
        );
        let a2 = VerifyCache::key(
            b"asset",
            "image/jpeg",
            b"trustA",
            Some("2013-06-01T00:00:00Z"),
        );
        assert_eq!(a, a2);
        // Any input change busts the key.
        assert_ne!(
            a,
            VerifyCache::key(
                b"asseT",
                "image/jpeg",
                b"trustA",
                Some("2013-06-01T00:00:00Z")
            )
        );
        assert_ne!(
            a,
            VerifyCache::key(
                b"asset",
                "image/png",
                b"trustA",
                Some("2013-06-01T00:00:00Z")
            )
        );
        assert_ne!(
            a,
            VerifyCache::key(
                b"asset",
                "image/jpeg",
                b"trustB",
                Some("2013-06-01T00:00:00Z")
            )
        );
        assert_ne!(a, VerifyCache::key(b"asset", "image/jpeg", b"trustA", None));
    }

    #[test]
    fn hit_and_miss() {
        let mut c = VerifyCache::new(8, Duration::from_secs(60));
        assert!(c.get(&k(1)).is_none());
        c.put(k(1), ValidationState::Valid, "{}".into());
        let got = c.get(&k(1)).expect("hit");
        assert_eq!(got.state, ValidationState::Valid);
        assert_eq!(c.stats(), (1, 1));
    }

    #[test]
    fn ttl_expiry() {
        let mut c = VerifyCache::new(8, Duration::from_millis(1));
        c.put(k(2), ValidationState::Trusted, "{}".into());
        std::thread::sleep(Duration::from_millis(5));
        assert!(c.get(&k(2)).is_none(), "expired entry must miss");
    }

    #[test]
    fn lru_eviction() {
        let mut c = VerifyCache::new(2, Duration::from_secs(60));
        c.put(k(1), ValidationState::Valid, "1".into());
        c.put(k(2), ValidationState::Valid, "2".into());
        // Touch k(1) so k(2) is LRU.
        let _ = c.get(&k(1));
        c.put(k(3), ValidationState::Valid, "3".into());
        assert!(c.get(&k(2)).is_none(), "k2 should be evicted");
        assert!(c.get(&k(1)).is_some());
        assert!(c.get(&k(3)).is_some());
    }

    #[test]
    fn verify_cached_miss_then_hit() {
        // A no-manifest JPEG verifies deterministically; the second call must be
        // a cache hit returning the identical stored result.
        let mut c = VerifyCache::new(8, Duration::from_secs(60));
        // Minimal structurally-valid JPEG (SOI + APP0/JFIF + EOI): no manifest,
        // so verify returns a graceful Invalid result (not a parse error).
        let asset: &[u8] = &[
            0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, b'J', b'F', b'I', b'F', 0x00, 0x01, 0x01, 0x00,
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0xFF, 0xD9,
        ];
        let input = crate::c2pa_validate::VerifyInput {
            data: asset,
            mime: "image/jpeg",
            claim_signer_trust: None,
            tsa_trust: None,
            allowed_certs: None,
            validation_time: None,
            profile: crate::c2pa_validate::EngineProfile::GENEROUS,
        };
        let (first, hit1) = c.verify_cached(&input).expect("verify");
        assert!(!hit1, "first call is a miss");
        let (second, hit2) = c.verify_cached(&input).expect("verify");
        assert!(hit2, "second identical call is a hit");
        assert_eq!(first.state, second.state);
        assert_eq!(first.report_json, second.report_json);
        let (hits, misses) = c.stats();
        assert_eq!((hits, misses), (1, 1));
    }
}
