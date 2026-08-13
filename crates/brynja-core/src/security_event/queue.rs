//! Fixed-capacity caller-drained FIFO buffering and visible loss accounting.

use super::SecurityEventRecord;

/// Result of one non-blocking enqueue attempt.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SecurityEventPush {
    /// The event was stored in deterministic FIFO order.
    Stored,
    /// The queue was full and the event was observationally dropped.
    Dropped,
}

/// Saturating count of observational events dropped by a full queue.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SecurityEventDropCount {
    count: u64,
    saturated: bool,
}

impl SecurityEventDropCount {
    const fn none() -> Self {
        Self {
            count: 0,
            saturated: false,
        }
    }

    fn record(&mut self) {
        match self.count.checked_add(1) {
            Some(count) => self.count = count,
            None => self.saturated = true,
        }
    }

    /// Returns the exact count until saturation, then `u64::MAX`.
    #[must_use]
    pub const fn count(self) -> u64 {
        self.count
    }

    /// Reports that more events were lost than the numeric count can express.
    #[must_use]
    pub const fn is_saturated(self) -> bool {
        self.saturated
    }
}

/// Read-only bounded queue state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SecurityEventQueueSnapshot {
    capacity: usize,
    len: usize,
    dropped: SecurityEventDropCount,
}

impl SecurityEventQueueSnapshot {
    /// Returns the compile-time queue capacity.
    #[must_use]
    pub const fn capacity(self) -> usize {
        self.capacity
    }

    /// Returns the number of stored records.
    #[must_use]
    pub const fn len(self) -> usize {
        self.len
    }

    /// Reports whether no records are currently stored.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    /// Returns visible saturating loss accounting.
    #[must_use]
    pub const fn dropped(self) -> SecurityEventDropCount {
        self.dropped
    }
}

/// Caller-owned, allocation-free, fixed-capacity observational event queue.
///
/// The API performs no callback, I/O, allocation, retry, wait, or protocol
/// transition. Exclusive mutable borrowing prevents safe reentrant mutation.
///
/// ```compile_fail
/// use brynja_core::SecurityEventQueue;
/// let mut queue = SecurityEventQueue::<1>::new();
/// let first = &mut queue;
/// let second = &mut queue;
/// let _ = (first, second);
/// ```
pub struct SecurityEventQueue<const CAPACITY: usize> {
    entries: [Option<SecurityEventRecord>; CAPACITY],
    head: usize,
    len: usize,
    dropped: SecurityEventDropCount,
}

impl<const CAPACITY: usize> SecurityEventQueue<CAPACITY> {
    /// Creates an empty fixed-capacity queue without allocation.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: [None; CAPACITY],
            head: 0,
            len: 0,
            dropped: SecurityEventDropCount::none(),
        }
    }

    /// Stores one record or drops it immediately when full.
    pub fn push(&mut self, record: SecurityEventRecord) -> SecurityEventPush {
        if self.len == CAPACITY {
            self.dropped.record();
            return SecurityEventPush::Dropped;
        }
        let Some(remaining) = CAPACITY.checked_sub(self.head) else {
            self.dropped.record();
            return SecurityEventPush::Dropped;
        };
        let tail = if self.len >= remaining {
            self.len.checked_sub(remaining)
        } else {
            self.head.checked_add(self.len)
        };
        let Some(tail) = tail else {
            self.dropped.record();
            return SecurityEventPush::Dropped;
        };
        let Some(next_len) = self.len.checked_add(1) else {
            self.dropped.record();
            return SecurityEventPush::Dropped;
        };
        let Some(slot) = self.entries.get_mut(tail) else {
            self.dropped.record();
            return SecurityEventPush::Dropped;
        };
        *slot = Some(record);
        self.len = next_len;
        SecurityEventPush::Stored
    }

    /// Removes the oldest record, if one is available.
    pub fn pop(&mut self) -> Option<SecurityEventRecord> {
        if self.len == 0 {
            return None;
        }
        let record = self.entries.get(self.head).copied().flatten()?;
        let next_len = self.len.checked_sub(1)?;
        let next_head = if next_len == 0 {
            0
        } else {
            let advanced = self.head.checked_add(1)?;
            if advanced == CAPACITY { 0 } else { advanced }
        };
        let slot = self.entries.get_mut(self.head)?;
        *slot = None;
        self.len = next_len;
        if next_len == 0 {
            self.head = 0;
        } else {
            self.head = next_head;
        }
        Some(record)
    }

    /// Returns bounded queue and loss state without draining it.
    #[must_use]
    pub const fn snapshot(&self) -> SecurityEventQueueSnapshot {
        SecurityEventQueueSnapshot {
            capacity: CAPACITY,
            len: self.len,
            dropped: self.dropped,
        }
    }
}

impl<const CAPACITY: usize> Default for SecurityEventQueue<CAPACITY> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drop_counter_saturation_is_visible() {
        let mut count = SecurityEventDropCount {
            count: u64::MAX,
            saturated: false,
        };
        count.record();
        assert_eq!(count.count(), u64::MAX);
        assert!(count.is_saturated());
        count.record();
        assert_eq!(count.count(), u64::MAX);
        assert!(count.is_saturated());
    }
}
