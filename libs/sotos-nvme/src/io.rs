//! High-level NVMe I/O entry points: sector reads, sector writes, and
//! the multi-page PRP-list variants used for transfers larger than two
//! host pages.

use crate::cmd;
use crate::controller::{NvmeController, WaitFn};

/// Maximum number of physical pages a single PRP-list transfer can
/// reference, limited by the 4 KiB PRP-list page (512 × `u64`
/// entries). At 4 KiB MPS this caps a single I/O at 2 MiB.
pub const MAX_PRP_LIST_ENTRIES: usize = 512;

impl NvmeController {
    /// Read up to one host page of sectors from namespace 1 using a
    /// single-PRP NVM Read command.
    ///
    /// - `lba`: starting logical block address.
    /// - `count`: number of sectors to read (1-based; converted to the
    ///   0-based NLB field internally). Limited by the configured MPS:
    ///   for 4 KiB MPS and 512-byte LBAs that's at most 8 sectors.
    /// - `buf_phys`: physical address of the destination buffer; must
    ///   be page-aligned.
    ///
    /// Returns `Err` if the I/O SQ has not been created, the controller
    /// times out, or the CQE reports a non-zero status.
    pub fn read_sectors(&mut self, lba: u64, count: u16, buf_phys: u64, wait: WaitFn) -> Result<(), &'static str> {
        let sq = self.io_sq.as_mut().ok_or("NVMe: I/O SQ not initialized")?;
        let entry = cmd::io_read(1, lba, count - 1, buf_phys); // NLB is 0-based
        let _cid = sq.submit(entry);
        self.ring_io_sq_doorbell();
        self.poll_io_completion(wait)
    }

    /// Write up to one host page of sectors to namespace 1 using a
    /// single-PRP NVM Write command.
    ///
    /// Mirror of [`read_sectors`](Self::read_sectors); same alignment
    /// and length constraints apply to `buf_phys`.
    pub fn write_sectors(&mut self, lba: u64, count: u16, buf_phys: u64, wait: WaitFn) -> Result<(), &'static str> {
        let sq = self.io_sq.as_mut().ok_or("NVMe: I/O SQ not initialized")?;
        let entry = cmd::io_write(1, lba, count - 1, buf_phys); // NLB is 0-based
        let _cid = sq.submit(entry);
        self.ring_io_sq_doorbell();
        self.poll_io_completion(wait)
    }

    /// Read sectors spanning more than one host page using a PRP list.
    ///
    /// - `lba`: starting LBA.
    /// - `count`: 0-based NLB written directly to CDW12.
    /// - `page_phys`: physical addresses of the data pages, in order.
    ///   `page_phys[0]` becomes PRP1; one or two entries skip the
    ///   PRP-list page entirely.
    /// - `prp_list_phys` / `prp_list_virt`: physical and virtual
    ///   address of a 4 KiB scratch page used as the PRP list when
    ///   `page_phys.len() > 2`. Up to [`MAX_PRP_LIST_ENTRIES`] pages.
    ///
    /// Returns `Err` for empty page lists, oversized transfers, or any
    /// of the standard I/O failure modes (uninitialised SQ, timeout,
    /// non-zero CQE status).
    pub fn read_sectors_prp(
        &mut self,
        lba: u64,
        count: u16,
        page_phys: &[u64],
        prp_list_phys: u64,
        prp_list_virt: *mut u64,
        wait: WaitFn,
    ) -> Result<(), &'static str> {
        if page_phys.is_empty() {
            return Err("NVMe: empty page list");
        }

        let prp1 = page_phys[0];
        let prp2 = if page_phys.len() == 1 {
            0
        } else if page_phys.len() == 2 {
            page_phys[1]
        } else {
            // Build PRP List: page_phys[1..] entries in the PRP List page.
            let list_entries = page_phys.len() - 1;
            if list_entries > MAX_PRP_LIST_ENTRIES {
                return Err("NVMe: too many pages for PRP List");
            }
            for i in 0..list_entries {
                unsafe { core::ptr::write_volatile(prp_list_virt.add(i), page_phys[i + 1]); }
            }
            prp_list_phys
        };

        let sq = self.io_sq.as_mut().ok_or("NVMe: I/O SQ not initialized")?;
        let entry = cmd::io_read_prp(1, lba, count, prp1, prp2);
        let _cid = sq.submit(entry);
        self.ring_io_sq_doorbell();
        self.poll_io_completion(wait)
    }

    /// Write sectors spanning more than one host page using a PRP list.
    ///
    /// Symmetric counterpart of
    /// [`read_sectors_prp`](Self::read_sectors_prp). The same length
    /// limits and error semantics apply.
    pub fn write_sectors_prp(
        &mut self,
        lba: u64,
        count: u16,
        page_phys: &[u64],
        prp_list_phys: u64,
        prp_list_virt: *mut u64,
        wait: WaitFn,
    ) -> Result<(), &'static str> {
        if page_phys.is_empty() {
            return Err("NVMe: empty page list");
        }

        let prp1 = page_phys[0];
        let prp2 = if page_phys.len() == 1 {
            0
        } else if page_phys.len() == 2 {
            page_phys[1]
        } else {
            let list_entries = page_phys.len() - 1;
            if list_entries > MAX_PRP_LIST_ENTRIES {
                return Err("NVMe: too many pages for PRP List");
            }
            for i in 0..list_entries {
                unsafe { core::ptr::write_volatile(prp_list_virt.add(i), page_phys[i + 1]); }
            }
            prp_list_phys
        };

        let sq = self.io_sq.as_mut().ok_or("NVMe: I/O SQ not initialized")?;
        let entry = cmd::io_write_prp(1, lba, count, prp1, prp2);
        let _cid = sq.submit(entry);
        self.ring_io_sq_doorbell();
        self.poll_io_completion(wait)
    }

    /// Busy-poll the I/O CQ for the next completion (or dispatch to
    /// the interrupt path if `use_interrupts` is set). Consumes one
    /// CQE, rings the CQ doorbell, fires the optional callback, and
    /// returns success / a static error.
    fn poll_io_completion(&mut self, wait: WaitFn) -> Result<(), &'static str> {
        if self.use_interrupts {
            return self.interrupt_io_completion(wait);
        }

        for _ in 0..10_000_000 {
            let cq = self.io_cq.as_mut().ok_or("NVMe: I/O CQ not initialized")?;
            if let Some(cqe) = cq.poll() {
                cq.advance();
                self.ring_io_cq_doorbell();
                if let Some(cb) = self.completion_callback {
                    cb(cqe.cid());
                }
                if cqe.status() != 0 {
                    return Err("NVMe: I/O operation failed");
                }
                return Ok(());
            }
            wait();
        }
        Err("NVMe: I/O timeout")
    }

    /// Interrupt-driven completion path.
    ///
    /// Calls `notify_wait()` on the configured cap to block until the
    /// kernel ISR signals, then polls the CQ once for the new entry.
    /// Repeats up to 1000 times before giving up. Falls back to plain
    /// polling if `notify_cap` is `None`.
    fn interrupt_io_completion(&mut self, wait: WaitFn) -> Result<(), &'static str> {
        let notify = match self.notify_cap {
            Some(cap) => cap,
            None => return self.poll_io_completion_fallback(wait),
        };

        // Wait for interrupt notification (blocks the thread, yields CPU).
        for _ in 0..1000 {
            sotos_common::sys::notify_wait(notify);

            let cq = self.io_cq.as_mut().ok_or("NVMe: I/O CQ not initialized")?;
            if let Some(cqe) = cq.poll() {
                cq.advance();
                self.ring_io_cq_doorbell();
                if let Some(cb) = self.completion_callback {
                    cb(cqe.cid());
                }
                if cqe.status() != 0 {
                    return Err("NVMe: I/O operation failed");
                }
                return Ok(());
            }
        }
        Err("NVMe: I/O interrupt timeout")
    }

    /// Polling fallback used by [`interrupt_io_completion`] when
    /// interrupt mode is requested but no notification cap has been
    /// installed yet.
    fn poll_io_completion_fallback(&mut self, wait: WaitFn) -> Result<(), &'static str> {
        for _ in 0..10_000_000 {
            let cq = self.io_cq.as_mut().ok_or("NVMe: I/O CQ not initialized")?;
            if let Some(cqe) = cq.poll() {
                cq.advance();
                self.ring_io_cq_doorbell();
                if let Some(cb) = self.completion_callback {
                    cb(cqe.cid());
                }
                if cqe.status() != 0 {
                    return Err("NVMe: I/O operation failed");
                }
                return Ok(());
            }
            wait();
        }
        Err("NVMe: I/O timeout")
    }

    /// Switch the controller into interrupt-driven completion mode.
    ///
    /// `notify_cap` is the notification capability the kernel ISR will
    /// signal on each device interrupt. `callback` (if `Some`) is fired
    /// with the completing CID after each I/O completion is consumed.
    pub fn enable_interrupt_mode(&mut self, notify_cap: u64, callback: Option<fn(u16)>) {
        self.notify_cap = Some(notify_cap);
        self.completion_callback = callback;
        self.use_interrupts = true;
    }

    /// Revert to busy-polling for completions. Leaves `notify_cap`
    /// installed so the caller can re-enable interrupt mode later.
    pub fn disable_interrupt_mode(&mut self) {
        self.use_interrupts = false;
    }

    /// Block on the configured notification cap until the next device
    /// interrupt fires. No-op if no `notify_cap` is set.
    pub fn wait_for_interrupt(&self) {
        if let Some(cap) = self.notify_cap {
            sotos_common::sys::notify_wait(cap);
        }
    }
}
