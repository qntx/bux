//! Audit event system for observable VM lifecycle operations.
//!
//! Events are emitted at key lifecycle points (create, start, stop, exec,
//! snapshot, file copy) and delivered to registered [`EventListener`]
//! implementations.
//!
//! The built-in [`RingBufferListener`] stores the most recent N events
//! in a bounded, lock-free ring buffer for querying.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

/// Kinds of auditable events emitted by the bux runtime.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum AuditEventKind {
    /// A new VM was created.
    BoxCreated {
        /// VM identifier.
        id: String,
        /// OCI image reference, if any.
        image: Option<String>,
        /// Tenant the VM belongs to.
        tenant: String,
    },
    /// A VM was started (or restarted).
    BoxStarted {
        /// VM identifier.
        id: String,
    },
    /// A VM was stopped.
    BoxStopped {
        /// VM identifier.
        id: String,
        /// Exit code, if available.
        exit_code: Option<i32>,
    },
    /// A VM was removed.
    BoxRemoved {
        /// VM identifier.
        id: String,
    },
    /// A command execution was started inside a VM.
    ExecStarted {
        /// VM identifier.
        box_id: String,
        /// Command that was executed.
        command: String,
        /// Unique execution identifier.
        exec_id: String,
    },
    /// A command execution completed inside a VM.
    ExecCompleted {
        /// VM identifier.
        box_id: String,
        /// Unique execution identifier.
        exec_id: String,
        /// Exit code of the command.
        exit_code: i32,
        /// Wall-clock duration in milliseconds.
        duration_ms: u64,
    },
    /// A snapshot was created.
    SnapshotCreated {
        /// VM identifier.
        box_id: String,
        /// Snapshot identifier.
        snapshot_id: String,
    },
    /// A file was copied into or out of a VM.
    FileCopied {
        /// VM identifier.
        box_id: String,
        /// Direction of the copy.
        direction: CopyDirection,
        /// Path involved in the copy.
        path: String,
    },
}

/// Direction of a file copy operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CopyDirection {
    /// Host → guest.
    In,
    /// Guest → host.
    Out,
}

/// A timestamped audit event.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct AuditEvent {
    /// When the event occurred.
    pub timestamp: SystemTime,
    /// What happened.
    pub kind: AuditEventKind,
}

impl AuditEvent {
    /// Creates a new event with the current timestamp.
    pub fn now(kind: AuditEventKind) -> Self {
        Self {
            timestamp: SystemTime::now(),
            kind,
        }
    }
}

/// Trait for receiving audit events.
///
/// Implementations must be `Send + Sync` since events may be emitted
/// from any thread. The `on_event` method should return quickly —
/// perform any expensive processing (logging, network I/O) asynchronously.
pub trait EventListener: Send + Sync {
    /// Called when an auditable event occurs.
    fn on_event(&self, event: &AuditEvent);
}

/// A fan-out dispatcher that forwards events to multiple listeners.
#[derive(Default)]
pub struct EventDispatcher {
    /// Registered listeners.
    listeners: Mutex<Vec<Arc<dyn EventListener>>>,
}

impl std::fmt::Debug for EventDispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self
            .listeners
            .lock()
            .map_or(0, |l| l.len());
        f.debug_struct("EventDispatcher")
            .field("listener_count", &count)
            .finish()
    }
}

impl EventDispatcher {
    /// Creates a new dispatcher with no listeners.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a listener that will receive all future events.
    pub fn add_listener(&self, listener: Arc<dyn EventListener>) {
        if let Ok(mut listeners) = self.listeners.lock() {
            listeners.push(listener);
        }
    }

    /// Emits an event to all registered listeners.
    #[allow(clippy::needless_pass_by_value)]
    pub fn emit(&self, event: AuditEvent) {
        if let Ok(listeners) = self.listeners.lock() {
            for listener in listeners.iter() {
                listener.on_event(&event);
            }
        }
    }
}

/// A bounded ring buffer that stores the most recent N audit events.
///
/// Thread-safe: uses a `Mutex` for writes and atomic index for reads.
/// Suitable for in-process querying of recent activity.
pub struct RingBufferListener {
    /// Fixed-size event buffer.
    buffer: Mutex<Vec<Option<AuditEvent>>>,
    /// Buffer capacity.
    capacity: usize,
    /// Write position (wraps around).
    write_pos: AtomicUsize,
    /// Total number of events ever recorded.
    total: AtomicU64,
}

use std::sync::atomic::AtomicU64;

impl std::fmt::Debug for RingBufferListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RingBufferListener")
            .field("capacity", &self.capacity)
            .field("total_events", &self.total_events())
            .finish_non_exhaustive()
    }
}

impl RingBufferListener {
    /// Creates a ring buffer with the given capacity.
    pub fn new(capacity: usize) -> Self {
        let cap = capacity.max(1);
        Self {
            buffer: Mutex::new(vec![None; cap]),
            capacity: cap,
            write_pos: AtomicUsize::new(0),
            total: AtomicU64::new(0),
        }
    }

    /// Total number of events ever recorded (may exceed capacity).
    pub fn total_events(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }

    /// Returns the most recent events, up to `limit`.
    ///
    /// Events are returned in chronological order (oldest first).
    pub fn recent(&self, limit: usize) -> Vec<AuditEvent> {
        let Ok(buffer) = self.buffer.lock() else {
            return Vec::new();
        };
        #[allow(clippy::cast_possible_truncation)]
        let total = self.total.load(Ordering::Relaxed) as usize;
        let available = total.min(self.capacity);
        let take = limit.min(available);

        if take == 0 {
            return Vec::new();
        }

        let write_pos = self.write_pos.load(Ordering::Relaxed);
        let mut events = Vec::with_capacity(take);

        // Start from the oldest event we want.
        let start = if write_pos >= take {
            write_pos - take
        } else {
            self.capacity - (take - write_pos)
        };

        for i in 0..take {
            let idx = (start + i) % self.capacity;
            if let Some(ref event) = buffer[idx] {
                events.push(event.clone());
            }
        }

        events
    }
}

impl EventListener for RingBufferListener {
    fn on_event(&self, event: &AuditEvent) {
        if let Ok(mut buffer) = self.buffer.lock() {
            let pos = self.write_pos.load(Ordering::Relaxed);
            buffer[pos % self.capacity] = Some(event.clone());
            self.write_pos.store((pos + 1) % self.capacity, Ordering::Relaxed);
            self.total.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn make_event(id: &str) -> AuditEvent {
        AuditEvent::now(AuditEventKind::BoxCreated {
            id: id.to_owned(),
            image: None,
            tenant: "default".to_owned(),
        })
    }

    #[test]
    fn ring_buffer_stores_and_retrieves() {
        let ring = RingBufferListener::new(3);
        ring.on_event(&make_event("vm1"));
        ring.on_event(&make_event("vm2"));

        let events = ring.recent(10);
        assert_eq!(events.len(), 2);
        assert_eq!(ring.total_events(), 2);
    }

    #[test]
    fn ring_buffer_wraps_around() {
        let ring = RingBufferListener::new(2);
        ring.on_event(&make_event("vm1"));
        ring.on_event(&make_event("vm2"));
        ring.on_event(&make_event("vm3"));

        assert_eq!(ring.total_events(), 3);
        let events = ring.recent(10);
        assert_eq!(events.len(), 2);

        // Should have vm2 and vm3 (vm1 was evicted).
        if let AuditEventKind::BoxCreated { ref id, .. } = events[0].kind {
            assert_eq!(id, "vm2");
        }
        if let AuditEventKind::BoxCreated { ref id, .. } = events[1].kind {
            assert_eq!(id, "vm3");
        }
    }

    #[test]
    fn dispatcher_fans_out() {
        let dispatcher = EventDispatcher::new();
        let ring = Arc::new(RingBufferListener::new(10));
        #[allow(clippy::clone_on_ref_ptr)] // coercion to dyn trait requires .clone()
        let listener: Arc<dyn EventListener> = ring.clone();
        dispatcher.add_listener(listener);

        dispatcher.emit(make_event("vm1"));
        dispatcher.emit(make_event("vm2"));

        assert_eq!(ring.total_events(), 2);
    }
}
