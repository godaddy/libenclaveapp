// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

#![allow(unsafe_code)]

use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use zeroize::Zeroizing;

use super::memcall::page_size;
use super::secure_buffer::SecureBuffer;
use super::slab::{SecureSlab, DEFAULT_SLOT_SIZE, SLOT_WAIT_TIMEOUT};
use crate::error::{Error, Result};

/// Maximum number of recently-decrypted MemoryEnclaves kept in the hot cache.
const HOT_CACHE_MAX: usize = 8;

// ── Pool slot origin ────────────────────────────────────────────────

enum PoolSlotOrigin {
    /// Slot lives in a tier's slab. `tier_index` identifies which `Tier` to return it to.
    Slab {
        tier_index: usize,
        slot_index: usize,
    },
    /// Slot owns a standalone guard-paged buffer (no tier fits, or tier exhausted).
    Standalone(SecureBuffer),
}

/// A handle to a locked memory region containing secret data.
///
/// The slot is either backed by a tier slab (mlock'd single-page pool) or a
/// standalone `SecureBuffer` (guard pages + mlock, for larger allocations).
///
/// `PoolSlot` is `Send` but NOT `Sync`; exclusive reference semantics prevent
/// concurrent mutation.
///
/// # Safety of the slab pointer
///
/// When origin is `Slab`, `ptr` points into a `TieredPool` tier's `SecureSlab`
/// which lives in a `OnceLock<TieredPool>` and is never dropped for the
/// process lifetime. The pointer therefore cannot dangle as long as the
/// process is alive.
pub struct PoolSlot {
    ptr: *mut u8,
    len: usize,
    origin: PoolSlotOrigin,
}

unsafe impl Send for PoolSlot {}

impl std::fmt::Debug for PoolSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PoolSlot").field("len", &self.len).finish()
    }
}

impl PoolSlot {
    fn from_slab(ptr: *mut u8, len: usize, tier_index: usize, slot_index: usize) -> Self {
        Self {
            ptr,
            len,
            origin: PoolSlotOrigin::Slab {
                tier_index,
                slot_index,
            },
        }
    }

    fn from_standalone(mut buf: SecureBuffer) -> Self {
        // buf starts Mutable (freshly allocated); melt is a no-op if already mutable.
        drop(buf.melt());
        let ptr = buf.bytes().as_mut_ptr();
        let len = buf.size();
        Self {
            ptr,
            len,
            origin: PoolSlotOrigin::Standalone(buf),
        }
    }

    /// Mutable access to the slot's bytes.
    pub fn bytes(&mut self) -> &mut [u8] {
        // Safety: ptr is valid for len bytes (either in global slab or standalone buf).
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }

    /// Read-only access to the slot's bytes.
    pub fn as_slice(&self) -> &[u8] {
        // Safety: ptr is valid for len bytes; no aliased mutable reference exists
        // because PoolSlot is not Sync.
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }

    /// Total capacity of this slot in bytes.
    pub fn size(&self) -> usize {
        self.len
    }

    /// Returns the slab slot index if this slot is backed by the global slab.
    #[allow(dead_code)]
    pub(crate) fn slab_index(&self) -> Option<usize> {
        match &self.origin {
            PoolSlotOrigin::Slab { slot_index, .. } => Some(*slot_index),
            PoolSlotOrigin::Standalone(_) => None,
        }
    }

    /// Returns the tier index if this slot is backed by the global slab.
    #[allow(dead_code)]
    pub(crate) fn tier_index(&self) -> Option<usize> {
        match &self.origin {
            PoolSlotOrigin::Slab { tier_index, .. } => Some(*tier_index),
            PoolSlotOrigin::Standalone(_) => None,
        }
    }
}

impl Drop for PoolSlot {
    fn drop(&mut self) {
        match &mut self.origin {
            PoolSlotOrigin::Slab {
                tier_index,
                slot_index,
            } => {
                // Zeroize here before acquiring the tier lock, so the memory is
                // clean even if the lock is contended.
                // Safety: ptr points into the global TieredPool's slab page which is alive.
                unsafe {
                    let s = std::slice::from_raw_parts_mut(self.ptr, self.len);
                    use zeroize::Zeroize;
                    s.zeroize();
                }
                // Return slot to the correct tier's slab.
                // Safety: POOL lives in OnceLock (never dropped); tier_index is valid
                // because it was set during acquire from this same pool.
                let pool = global_pool();
                if let Some(tier) = pool.tiers.get(*tier_index) {
                    tier.slab
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .release(*slot_index);
                }
            }
            PoolSlotOrigin::Standalone(buf) => {
                // Zeroize before buf's own drop, which also zeroizes.
                drop(buf.melt());
                // Safety: ptr points into buf's inner region which is still alive.
                unsafe {
                    let s = std::slice::from_raw_parts_mut(self.ptr, self.len);
                    use zeroize::Zeroize;
                    s.zeroize();
                }
                // buf drops here: zeroizes again + unmaps.
            }
        }
    }
}

// ── Hot cache ─────────────────────────────────────────────────────

/// Entry in the hot cache: (enclave_id, plaintext_copy).
/// Stored as `Zeroizing<Vec<u8>>` so evicted entries are zeroed automatically.
struct HotEntry {
    id: u64,
    plaintext: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for HotEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HotEntry")
            .field("id", &self.id)
            .field("plaintext", &"<redacted>")
            .finish()
    }
}

#[derive(Debug)]
struct HotCache {
    /// Front = LRU (oldest), back = MRU (newest).
    entries: VecDeque<HotEntry>,
}

impl HotCache {
    fn new() -> Self {
        Self {
            entries: VecDeque::with_capacity(HOT_CACHE_MAX),
        }
    }

    /// Look up and return a copy of the plaintext. Promotes the entry to MRU.
    ///
    /// The returned copy lives in regular heap memory; it should be consumed
    /// promptly and not stored long-term, as it is not mlock'd.
    fn get(&mut self, id: u64) -> Option<Zeroizing<Vec<u8>>> {
        let pos = self.entries.iter().position(|e| e.id == id)?;
        let entry = self.entries.remove(pos)?;
        let copy = Zeroizing::new((*entry.plaintext).clone());
        self.entries.push_back(HotEntry {
            id: entry.id,
            plaintext: entry.plaintext,
        });
        Some(copy)
    }

    /// Insert plaintext for `id`. Evicts LRU if at capacity.
    fn insert(&mut self, id: u64, plaintext: Zeroizing<Vec<u8>>) {
        // Remove existing entry for same id if present.
        self.entries.retain(|e| e.id != id);
        // Evict LRU if full.
        if self.entries.len() >= HOT_CACHE_MAX {
            drop(self.entries.pop_front()); // Zeroizing drop zeroes the plaintext.
        }
        self.entries.push_back(HotEntry { id, plaintext });
    }

    /// Evict the entry for `id` if present.
    fn evict(&mut self, id: u64) {
        self.entries.retain(|e| e.id != id);
    }
}

// ── Tiered pool ───────────────────────────────────────────────────

/// One tier: a single mlock'd-page slab with a fixed slot size.
#[derive(Debug)]
struct Tier {
    slot_size: usize,
    slab: Mutex<SecureSlab>,
}

/// Configuration for the tiered pool.
///
/// `tier_sizes` lists the slot sizes for each tier. Must be non-empty.
/// Duplicate sizes are deduplicated; the list is sorted ascending internally.
/// Each size must satisfy: `1 <= size <= page_size() / 3`.
#[derive(Debug, Clone)]
pub struct TieredPoolConfig {
    /// Slot sizes for each tier, non-empty, each in `1..=page_size()/3`.
    pub tier_sizes: Vec<usize>,
}

impl Default for TieredPoolConfig {
    /// Single 32-byte tier (asherah-ffi compatible).
    fn default() -> Self {
        Self {
            tier_sizes: vec![DEFAULT_SLOT_SIZE],
        }
    }
}

/// Statically-owned tiered pool combining N slabs + one shared hot cache.
///
/// `TieredPool` is `Send + Sync`: all mutable state is behind `Mutex`-guarded
/// fields. The `Vec<Tier>` contains raw pointers inside `SecureSlab`, which
/// requires explicit `Send`/`Sync` impls.
#[derive(Debug)]
pub struct TieredPool {
    tiers: Vec<Tier>,
    hot_cache: Mutex<HotCache>,
}

// Safety: TieredPool contains Mutex<SecureSlab> (which contains raw pointers).
// All pointer access is through Mutex guards; there is no unguarded shared mutable state.
unsafe impl Send for TieredPool {}
unsafe impl Sync for TieredPool {}

impl TieredPool {
    /// Create a new `TieredPool` from `config`.
    ///
    /// Validates, deduplicates, and sorts `config.tier_sizes`, then allocates
    /// one mlock'd page per tier.
    pub fn new(config: TieredPoolConfig) -> Result<Self> {
        let ps = page_size();
        let max_slot = ps / 3;

        if config.tier_sizes.is_empty() {
            return Err(Error::Memory(
                "TieredPoolConfig: tier_sizes must be non-empty".into(),
            ));
        }

        // Sort and dedup.
        let mut sizes = config.tier_sizes;
        sizes.sort_unstable();
        sizes.dedup();

        // Validate each size.
        for &sz in &sizes {
            if sz == 0 {
                return Err(Error::Memory(
                    "TieredPoolConfig: tier size 0 is invalid".into(),
                ));
            }
            if sz > max_slot {
                return Err(Error::Memory(format!(
                    "TieredPoolConfig: tier size {sz} exceeds page_size/3 ({max_slot})"
                )));
            }
        }

        // Allocate one SecureSlab per tier.
        let mut tiers = Vec::with_capacity(sizes.len());
        for sz in sizes {
            let slab = SecureSlab::new(sz)?;
            tiers.push(Tier {
                slot_size: sz,
                slab: Mutex::new(slab),
            });
        }

        Ok(Self {
            tiers,
            hot_cache: Mutex::new(HotCache::new()),
        })
    }

    /// Index of the smallest tier whose slot_size >= `size`, or `None` if all tiers are too small.
    fn tier_for_size(&self, size: usize) -> Option<usize> {
        self.tiers.iter().position(|t| t.slot_size >= size)
    }

    /// Acquire a slot from the appropriate tier.
    ///
    /// Routes to the smallest tier whose slot_size >= `size`. Spin-waits up
    /// to 30 s for a free slot; falls back to a standalone `SecureBuffer` if
    /// the tier is exhausted or no tier fits the requested size.
    pub fn acquire(&self, size: usize) -> Result<PoolSlot> {
        if let Some(tier_idx) = self.tier_for_size(size) {
            let deadline = std::time::Instant::now() + SLOT_WAIT_TIMEOUT;
            loop {
                {
                    let mut slab = self.tiers[tier_idx]
                        .slab
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    if let Some(slot_idx) = slab.find_free_slot() {
                        slab.checkout(slot_idx).map_err(|e| {
                            Error::Memory(format!("TieredPool::acquire checkout: {e}"))
                        })?;
                        let (ptr, len) = slab.slot_raw(slot_idx);
                        return Ok(PoolSlot::from_slab(ptr, len, tier_idx, slot_idx));
                    }
                }
                if std::time::Instant::now() >= deadline {
                    tracing::warn!(
                        size,
                        tier_idx,
                        "TieredPool::acquire: tier exhausted after 30 s; \
                         falling back to standalone SecureBuffer"
                    );
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }

        // Standalone fallback (no tier fits, or tier exhausted).
        let buf = SecureBuffer::new(size)?;
        Ok(PoolSlot::from_standalone(buf))
    }

    /// Reconstruct the Coffer master key into a `PoolSlot`.
    pub fn coffer_view(&self) -> Result<PoolSlot> {
        let key = super::coffer::master_key()?;
        let mut slot = self.acquire(key.len())?;
        slot.bytes()[..key.len()].copy_from_slice(key.as_ref());
        Ok(slot)
    }

    /// The largest slot size available in any tier.
    pub fn max_slab_slot_size(&self) -> usize {
        self.tiers.iter().map(|t| t.slot_size).max().unwrap_or(0)
    }

    /// Number of configured tiers.
    pub fn tier_count(&self) -> usize {
        self.tiers.len()
    }

    /// Slot size for tier `i`, or `None` if out of range.
    pub fn tier_slot_size(&self, i: usize) -> Option<usize> {
        self.tiers.get(i).map(|t| t.slot_size)
    }
}

// ── Global pool ───────────────────────────────────────────────────

static POOL: OnceLock<TieredPool> = OnceLock::new();

/// Initialize the global pool with a custom config.
///
/// Must be called before any pool operation. If the pool is already initialized
/// (via a prior call or via lazy default init), returns
/// `Error::Memory("pool already initialized")`.
pub fn init_pool(config: TieredPoolConfig) -> Result<()> {
    let pool = TieredPool::new(config)?;
    POOL.set(pool)
        .map_err(|_| Error::Memory("pool already initialized".into()))
}

fn global_pool() -> &'static TieredPool {
    POOL.get_or_init(|| {
        TieredPool::new(TieredPoolConfig::default())
            .expect("enclave: default tiered pool init failed — OsRng unavailable")
    })
}

/// Acquire a pool slot for `size` bytes.
///
/// Routes to the smallest tier whose slot_size >= `size`. Waits up to 30 s
/// for a free slot, then falls back to a standalone guard-paged `SecureBuffer`.
pub fn pool_acquire(size: usize) -> Result<PoolSlot> {
    global_pool().acquire(size)
}

/// Release a pool slot. The slot's contents are zeroized.
/// Prefer dropping the `PoolSlot` directly; this is provided for explicit release.
pub fn pool_release(slot: PoolSlot) {
    drop(slot);
}

/// Get a `PoolSlot` containing the Coffer master key.
/// Release promptly after use; holding it blocks coffer key rotation.
pub fn coffer_view() -> Result<PoolSlot> {
    global_pool().coffer_view()
}

/// Insert plaintext into the hot cache for `id`.
pub(super) fn hot_cache_insert(id: u64, plaintext: Zeroizing<Vec<u8>>) {
    global_pool()
        .hot_cache
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(id, plaintext);
}

/// Look up plaintext from the hot cache.
pub(super) fn hot_cache_get(id: u64) -> Option<Zeroizing<Vec<u8>>> {
    global_pool()
        .hot_cache
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(id)
}

/// Evict an entry from the hot cache.
pub(super) fn hot_cache_evict(id: u64) {
    global_pool()
        .hot_cache
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .evict(id);
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    /// Serializes tests that touch the global TieredPool to prevent interference.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    // ── Existing tests ──────────────────────────────────────────────────

    #[test]
    fn pool_acquire_small_uses_slab() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let slot = pool_acquire(16).unwrap();
        assert!(slot.slab_index().is_some());
        assert_eq!(slot.size(), DEFAULT_SLOT_SIZE);
    }

    #[test]
    fn pool_acquire_large_uses_standalone() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let slot = pool_acquire(8192).unwrap();
        assert!(slot.slab_index().is_none());
        assert_eq!(slot.size(), 8192);
    }

    #[test]
    fn pool_acquire_zero_uses_slab() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // size 0 <= slot_size, so it should use the slab.
        let slot = pool_acquire(0).unwrap();
        assert!(slot.slab_index().is_some());
    }

    #[test]
    fn pool_slot_write_and_read() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut slot = pool_acquire(16).unwrap();
        let data = b"test data 12345!";
        // slot.size() may be larger than 16 (slab slot size is DEFAULT_SLOT_SIZE).
        slot.bytes()[..data.len()].copy_from_slice(data);
        assert_eq!(&slot.as_slice()[..data.len()], data);
    }

    #[test]
    fn hot_cache_insert_get_evict() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let plaintext = Zeroizing::new(b"cached secret".to_vec());
        hot_cache_insert(9999, plaintext.clone());
        let got = hot_cache_get(9999).unwrap();
        assert_eq!(*got, *plaintext);
        hot_cache_evict(9999);
        assert!(hot_cache_get(9999).is_none());
    }

    #[test]
    fn hot_cache_eviction_at_capacity() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Insert HOT_CACHE_MAX + 1 entries; the first should be evicted.
        for i in 0_u64..=(HOT_CACHE_MAX as u64) {
            let pt = Zeroizing::new(vec![i as u8; 4]);
            hot_cache_insert(10000 + i, pt);
        }
        // Entry 0 should have been evicted (LRU).
        assert!(hot_cache_get(10000).is_none());
        // Entry HOT_CACHE_MAX should still be present.
        assert!(hot_cache_get(10000 + HOT_CACHE_MAX as u64).is_some());
        // Clean up.
        for i in 1_u64..=(HOT_CACHE_MAX as u64) {
            hot_cache_evict(10000 + i);
        }
    }

    #[test]
    fn coffer_view_returns_key_sized_slot() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let slot = coffer_view().unwrap();
        assert_eq!(slot.size(), 32);
        assert!(slot.slab_index().is_some());
    }

    // ── New tiered pool tests ────────────────────────────────────────────

    #[test]
    fn tiered_pool_routes_small_to_first_tier() {
        let pool = TieredPool::new(TieredPoolConfig {
            tier_sizes: vec![32, 64, 128],
        })
        .unwrap();
        // Acquire something that fits in the 32-byte tier.
        let slot = pool.acquire(16).unwrap();
        assert_eq!(
            slot.tier_index(),
            Some(0),
            "should route to tier 0 (32-byte)"
        );
        assert_eq!(slot.size(), 32);
    }

    #[test]
    fn tiered_pool_routes_medium_to_second_tier() {
        let pool = TieredPool::new(TieredPoolConfig {
            tier_sizes: vec![32, 64, 128],
        })
        .unwrap();
        // Acquire something that doesn't fit in 32 but fits in 64.
        let slot = pool.acquire(48).unwrap();
        assert_eq!(
            slot.tier_index(),
            Some(1),
            "should route to tier 1 (64-byte)"
        );
        assert_eq!(slot.size(), 64);
    }

    #[test]
    fn tiered_pool_routes_large_to_standalone() {
        let pool = TieredPool::new(TieredPoolConfig {
            tier_sizes: vec![32, 64, 128],
        })
        .unwrap();
        // Acquire more than the largest tier — must be standalone.
        let slot = pool.acquire(8192).unwrap();
        assert!(slot.tier_index().is_none(), "should be standalone");
        assert_eq!(slot.size(), 8192);
    }

    #[test]
    fn init_pool_default_config_has_one_tier() {
        // Use a local TieredPool (not the global) to avoid contaminating test state.
        let pool = TieredPool::new(TieredPoolConfig::default()).unwrap();
        assert_eq!(pool.tier_count(), 1);
        assert_eq!(pool.tier_slot_size(0), Some(DEFAULT_SLOT_SIZE));
        assert_eq!(pool.max_slab_slot_size(), DEFAULT_SLOT_SIZE);
    }

    #[test]
    fn tiered_pool_config_validates_ascending() {
        // Duplicate tier sizes should be deduped, not rejected.
        // The resulting pool should have 1 tier, not 2.
        let pool = TieredPool::new(TieredPoolConfig {
            tier_sizes: vec![32, 32],
        })
        .unwrap();
        assert_eq!(pool.tier_count(), 1, "duplicates should be deduped");
    }

    #[test]
    fn tiered_pool_config_validates_max_slot_size() {
        let ps = page_size();
        let too_large = ps / 3 + 1;
        let err = TieredPool::new(TieredPoolConfig {
            tier_sizes: vec![too_large],
        });
        assert!(err.is_err(), "slot size > page_size/3 must be rejected");
    }
}
