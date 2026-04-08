//! VM introspection -- observe guest behavior without guest knowledge.

/// Memory-region watch descriptor.
#[derive(Debug, Clone, Copy)]
pub struct MemWatch {
    pub guest_phys: u64,
    pub size: u64,
    pub on_write: bool,
    pub on_read: bool,
    pub on_exec: bool,
}

/// Event captured by the introspector's ring buffer.
#[derive(Debug, Clone, Copy)]
pub enum IntrospectionEvent {
    MemoryAccess {
        addr: u64,
        size: u32,
        write: bool,
        rip: u64,
    },
    CpuidExit {
        leaf: u32,
        subleaf: u32,
    },
    MsrAccess {
        msr: u32,
        write: bool,
        value: u64,
    },
    IoPort {
        port: u16,
        size: u8,
        write: bool,
    },
    Interrupt {
        vector: u8,
    },
    CrAccess {
        cr: u8,
        value: u64,
    },
}

const EVENT_CAP: usize = 256;
const MEM_WATCH_CAP: usize = 32;

/// Per-VM introspection state: memory watches + event ring buffer.
pub struct VmIntrospector {
    pub vm_id: u32,
    /// Watched physical memory regions.
    pub mem_watches: [Option<MemWatch>; MEM_WATCH_CAP],
    pub watch_count: usize,
    /// Ring buffer of intercepted events.
    events: [Option<IntrospectionEvent>; EVENT_CAP],
    event_head: usize,
    event_tail: usize,
}

impl VmIntrospector {
    /// Create an introspector for the given VM.
    pub fn new(vm_id: u32) -> Self {
        Self {
            vm_id,
            mem_watches: [None; MEM_WATCH_CAP],
            watch_count: 0,
            events: [None; EVENT_CAP],
            event_head: 0,
            event_tail: 0,
        }
    }

    // --- Memory watches ---

    /// Add a memory watch.  Returns the watch index, or `None` if full.
    pub fn add_watch(&mut self, watch: MemWatch) -> Option<usize> {
        if self.watch_count >= MEM_WATCH_CAP {
            return None;
        }
        let idx = self.watch_count;
        self.mem_watches[idx] = Some(watch);
        self.watch_count += 1;
        Some(idx)
    }

    /// Remove a watch by index.
    pub fn remove_watch(&mut self, idx: usize) {
        if idx < MEM_WATCH_CAP {
            self.mem_watches[idx] = None;
        }
    }

    /// Check whether a guest-physical access hits any watch.
    pub fn check_access(&self, addr: u64, size: u64, write: bool, exec: bool) -> bool {
        for entry in &self.mem_watches[..self.watch_count] {
            if let Some(w) = entry {
                let end = w.guest_phys.saturating_add(w.size);
                let access_end = addr.saturating_add(size);
                // Overlapping ranges?
                if addr < end && access_end > w.guest_phys {
                    if write && w.on_write {
                        return true;
                    }
                    if exec && w.on_exec {
                        return true;
                    }
                    if !write && !exec && w.on_read {
                        return true;
                    }
                }
            }
        }
        false
    }

    // --- Event ring buffer ---

    /// Record an event.  Silently drops the oldest event on overflow.
    pub fn record(&mut self, event: IntrospectionEvent) {
        self.events[self.event_head] = Some(event);
        self.event_head = (self.event_head + 1) % EVENT_CAP;
        if self.event_head == self.event_tail {
            // Overflow -- advance tail (drop oldest).
            self.event_tail = (self.event_tail + 1) % EVENT_CAP;
        }
    }

    /// Pop the oldest event, or `None` if the ring is empty.
    pub fn poll(&mut self) -> Option<IntrospectionEvent> {
        if self.event_tail == self.event_head {
            return None;
        }
        let ev = self.events[self.event_tail].take();
        self.event_tail = (self.event_tail + 1) % EVENT_CAP;
        ev
    }

    /// Number of events currently in the ring.
    pub fn pending(&self) -> usize {
        if self.event_head >= self.event_tail {
            self.event_head - self.event_tail
        } else {
            EVENT_CAP - self.event_tail + self.event_head
        }
    }

    /// Drain all pending events into a provided buffer.
    /// Returns the number of events written.
    pub fn drain(&mut self, buf: &mut [IntrospectionEvent]) -> usize {
        let mut n = 0;
        while n < buf.len() {
            match self.poll() {
                Some(ev) => {
                    buf[n] = ev;
                    n += 1;
                }
                None => break,
            }
        }
        n
    }
}
