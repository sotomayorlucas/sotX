//! NVMe controller initialization and admin queue management.
//!
//! Builds the [`NvmeController`] state machine on top of caller-supplied
//! [`DmaPages`] and walks the controller through the NVMe 1.4 §7.6.1
//! initialization sequence (CC.EN handshake → AQA/ASQ/ACQ → Identify →
//! I/O queue creation).

use crate::regs;
use crate::queue::{SubmissionQueue, CompletionQueue, QUEUE_DEPTH};
use crate::cmd;

/// Live state for one initialised NVMe controller.
///
/// Holds the MMIO base, the doorbell stride, the admin queue pair, the
/// (optional) I/O queue pair, the parsed namespace geometry, and the
/// hooks needed to drive completions either by polling or via an
/// interrupt notification cap.
pub struct NvmeController {
    /// MMIO base virtual address (BAR0, must be UC-mapped by caller).
    pub mmio_base: *mut u8,
    /// Doorbell stride captured from `CAP.DSTRD` at init.
    pub dstrd: u8,
    /// Admin Submission Queue (QID 0).
    pub admin_sq: SubmissionQueue,
    /// Admin Completion Queue (QID 0).
    pub admin_cq: CompletionQueue,
    /// I/O Submission Queue (QID 1). `None` until [`init`](Self::init)
    /// has issued *Create I/O SQ*.
    pub io_sq: Option<SubmissionQueue>,
    /// I/O Completion Queue (QID 1). `None` until [`init`](Self::init)
    /// has issued *Create I/O CQ*.
    pub io_cq: Option<CompletionQueue>,
    /// Namespace 1 size in logical blocks (NSZE field of Identify
    /// Namespace).
    pub ns_size: u64,
    /// Logical block size in bytes — usually 512, derived from the
    /// LBADS exponent of the active LBA Format.
    pub lba_size: u32,
    /// Optional callback fired with the completing CID after each I/O
    /// completion is consumed.
    pub completion_callback: Option<fn(u16)>,
    /// Notification capability used when `use_interrupts` is set:
    /// `notify_wait()` blocks the thread until the kernel ISR signals.
    pub notify_cap: Option<u64>,
    /// Selects the completion strategy: `false` = busy-poll the CQ,
    /// `true` = block on `notify_cap` then poll once.
    pub use_interrupts: bool,
}

/// Caller-provided DMA layout for [`NvmeController::init`].
///
/// All `*_phys` fields are physical addresses and all `*_virt` fields
/// are kernel/userspace virtual addresses for the same pages. Pages
/// must be 4 KiB-aligned and at least one host page each.
pub struct DmaPages {
    /// Admin SQ — virtual address.
    pub admin_sq_virt: *mut u8,
    /// Admin SQ — physical address (programmed into `ASQ`).
    pub admin_sq_phys: u64,
    /// Admin CQ — virtual address.
    pub admin_cq_virt: *mut u8,
    /// Admin CQ — physical address (programmed into `ACQ`).
    pub admin_cq_phys: u64,
    /// I/O SQ — virtual address.
    pub io_sq_virt: *mut u8,
    /// I/O SQ — physical address (PRP1 of *Create I/O SQ*).
    pub io_sq_phys: u64,
    /// I/O CQ — virtual address.
    pub io_cq_virt: *mut u8,
    /// I/O CQ — physical address (PRP1 of *Create I/O CQ*).
    pub io_cq_phys: u64,
    /// Identify scratch buffer (4 KiB) — virtual address. Reused for
    /// Identify Controller and Identify Namespace.
    pub identify_virt: *mut u8,
    /// Identify scratch buffer — physical address.
    pub identify_phys: u64,
}

/// Information returned from a successful
/// [`NvmeController::init`] call.
pub struct InitResult {
    /// Major version from the `VS` register (e.g. `1` for NVMe 1.4).
    pub version_major: u16,
    /// Minor version from the `VS` register (e.g. `4` for NVMe 1.4).
    pub version_minor: u16,
    /// Namespace 1 size in logical blocks.
    pub ns_size: u64,
    /// Logical block size in bytes.
    pub lba_size: u32,
}

/// Spin-wait callback. Invoked from the inside of polling loops so the
/// caller can yield, halt, or otherwise avoid burning cycles. The
/// kernel-side wrapper typically passes a `notify_wait` or `hlt` stub.
pub type WaitFn = fn();

impl NvmeController {
    /// Drive an NVMe controller through its full bring-up sequence.
    ///
    /// Steps (NVMe 1.4 §7.6.1):
    /// 1. Read `CAP` → derive `MQES`, `DSTRD`, queue depth.
    /// 2. Disable controller (`CC.EN = 0`, wait for `CSTS.RDY = 0`).
    /// 3. Program `AQA`, `ASQ`, `ACQ` from [`DmaPages`].
    /// 4. Enable (`CC.EN = 1`, wait for `CSTS.RDY = 1`).
    /// 5. Issue *Identify Controller* and *Identify Namespace 1*; parse
    ///    `NSZE` and the active LBA Format to populate `ns_size` /
    ///    `lba_size`.
    /// 6. Create I/O CQ (QID 1) and I/O SQ (QID 1, CQID 1).
    ///
    /// Returns the initialised controller and an [`InitResult`]
    /// summary, or a static error string if the controller fails to
    /// become ready or any admin command returns non-zero status.
    ///
    /// # Safety
    /// The caller must guarantee that `mmio_base` points at a valid
    /// UC-mapped BAR0 mapping for the lifetime of the returned
    /// controller, and that all addresses in `dma` are valid DMA pages
    /// for the controller. The function performs raw MMIO and
    /// physical-address writes.
    pub unsafe fn init(
        mmio_base: *mut u8,
        dma: &DmaPages,
        wait: WaitFn,
    ) -> Result<(Self, InitResult), &'static str> {
        // 1. Read CAP.
        let cap = unsafe { regs::read64(mmio_base, regs::REG_CAP) };
        let mqes = regs::cap_mqes(cap);
        let dstrd = regs::cap_dstrd(cap);

        // Queue depth: min of our desired depth and hardware max.
        let depth = core::cmp::min(QUEUE_DEPTH as u16, mqes + 1);

        // 2. Disable controller.
        let cc = unsafe { regs::read32(mmio_base, regs::REG_CC) };
        if cc & regs::CC_EN != 0 {
            unsafe { regs::write32(mmio_base, regs::REG_CC, cc & !regs::CC_EN); }
            // Wait for CSTS.RDY = 0.
            // TCG fix (run-full deadlock U3): cap from 100K -> 50K, yield every
            // 256 iters. Each MMIO read costs ~1000 host cycles on TCG; the
            // old per-iter wait() generated context switches that starved init.
            for i in 0..50_000_u32 {
                let csts = unsafe { regs::read32(mmio_base, regs::REG_CSTS) };
                if csts & regs::CSTS_RDY == 0 {
                    break;
                }
                if (i & 0xFF) == 0 {
                    wait();
                }
            }
        }

        // 3. Set Admin Queue Attributes.
        // AQA: ACQS (27:16) | ASQS (11:0), both 0-based.
        let aqa = ((depth as u32 - 1) << 16) | (depth as u32 - 1);
        unsafe {
            regs::write32(mmio_base, regs::REG_AQA, aqa);
            regs::write64(mmio_base, regs::REG_ASQ, dma.admin_sq_phys);
            regs::write64(mmio_base, regs::REG_ACQ, dma.admin_cq_phys);
        }

        // 4. Enable controller.
        let cc_val = regs::CC_EN
            | regs::CC_CSS_NVM
            | regs::CC_MPS_4K
            | regs::CC_AMS_RR
            | regs::CC_IOSQES_64
            | regs::CC_IOCQES_16;
        unsafe { regs::write32(mmio_base, regs::REG_CC, cc_val); }

        // Wait for CSTS.RDY = 1.
        // TCG fix (run-full deadlock U3): cap from 1M -> 100K, yield every 256.
        let mut ready = false;
        for i in 0..100_000_u32 {
            let csts = unsafe { regs::read32(mmio_base, regs::REG_CSTS) };
            if csts & regs::CSTS_RDY != 0 {
                ready = true;
                break;
            }
            if (i & 0xFF) == 0 {
                wait();
            }
        }
        if !ready {
            return Err("NVMe: controller failed to become ready");
        }

        // Read version.
        let vs = unsafe { regs::read32(mmio_base, regs::REG_VS) };
        let ver_major = (vs >> 16) as u16;
        let ver_minor = ((vs >> 8) & 0xFF) as u16;

        // Create admin queues.
        let admin_sq = SubmissionQueue::new(dma.admin_sq_virt, dma.admin_sq_phys, depth);
        let admin_cq = CompletionQueue::new(dma.admin_cq_virt, dma.admin_cq_phys, depth);

        let mut ctrl = NvmeController {
            mmio_base,
            dstrd,
            admin_sq,
            admin_cq,
            io_sq: None,
            io_cq: None,
            ns_size: 0,
            lba_size: 512,
            completion_callback: None,
            notify_cap: None,
            use_interrupts: false,
        };

        // 5. Identify Controller.
        let id_cmd = cmd::identify_controller(dma.identify_phys);
        ctrl.admin_submit_and_wait(id_cmd, wait)?;

        // Serial number at bytes 4-23 — informational only, not parsed.

        // 5b. Identify Namespace 1.
        let ns_cmd = cmd::identify_namespace(1, dma.identify_phys);
        ctrl.admin_submit_and_wait(ns_cmd, wait)?;

        // Parse namespace size (NSZE, bytes 0-7) and LBA format.
        let nsze = unsafe {
            let ptr = dma.identify_virt as *const u64;
            core::ptr::read_volatile(ptr)
        };
        // FLBAS byte 26 → index into LBA Format table (bytes 128+).
        let flbas = unsafe { *dma.identify_virt.add(26) } & 0x0F;
        let lbaf_offset = 128 + (flbas as usize) * 4;
        let lbaf = unsafe {
            let ptr = dma.identify_virt.add(lbaf_offset) as *const u32;
            core::ptr::read_volatile(ptr)
        };
        // LBADS = bits 23:16 of LBAF (log2 of LBA data size).
        let lbads = ((lbaf >> 16) & 0xFF) as u32;
        let lba_size = 1u32 << lbads;

        ctrl.ns_size = nsze;
        ctrl.lba_size = lba_size;

        // 6. Create I/O Completion Queue (QID=1).
        let cq_cmd = cmd::create_io_cq(1, dma.io_cq_phys, depth - 1);
        ctrl.admin_submit_and_wait(cq_cmd, wait)?;

        // 6b. Create I/O Submission Queue (QID=1, CQID=1).
        let sq_cmd = cmd::create_io_sq(1, dma.io_sq_phys, depth - 1, 1);
        ctrl.admin_submit_and_wait(sq_cmd, wait)?;

        // Init I/O queues.
        ctrl.io_sq = Some(SubmissionQueue::new(dma.io_sq_virt, dma.io_sq_phys, depth));
        ctrl.io_cq = Some(CompletionQueue::new(dma.io_cq_virt, dma.io_cq_phys, depth));

        let result = InitResult {
            version_major: ver_major,
            version_minor: ver_minor,
            ns_size: nsze,
            lba_size,
        };

        Ok((ctrl, result))
    }

    /// Submit one admin command, ring the admin SQ doorbell, and
    /// busy-poll the admin CQ until either a completion arrives or the
    /// 10M-iter timeout fires. Returns the raw CQE on success or a
    /// static error string on timeout / non-zero status.
    fn admin_submit_and_wait(&mut self, entry: crate::queue::SqEntry, wait: WaitFn) -> Result<crate::queue::CqEntry, &'static str> {
        let _cid = self.admin_sq.submit(entry);

        // Ring the admin SQ doorbell (QID=0).
        let db_offset = regs::sq_doorbell_offset(0, self.dstrd);
        unsafe {
            regs::write32(self.mmio_base, db_offset, self.admin_sq.tail as u32);
        }

        // Poll for completion.
        // TCG fix (run-full deadlock U3): cap from 10M -> 100K, yield every 256.
        for i in 0..100_000_u32 {
            if let Some(cqe) = self.admin_cq.poll() {
                self.admin_cq.advance();
                // Ring the admin CQ doorbell.
                let cq_db = regs::cq_doorbell_offset(0, self.dstrd);
                unsafe { regs::write32(self.mmio_base, cq_db, self.admin_cq.head as u32); }

                if cqe.status() != 0 {
                    return Err("NVMe: admin command failed");
                }
                return Ok(cqe);
            }
            if (i & 0xFF) == 0 {
                wait();
            }
        }
        Err("NVMe: admin command timeout")
    }

    /// Write the current I/O SQ tail to the QID 1 SQ doorbell. No-op
    /// if the I/O SQ has not been created yet.
    pub fn ring_io_sq_doorbell(&self) {
        if let Some(ref sq) = self.io_sq {
            let db_offset = regs::sq_doorbell_offset(1, self.dstrd);
            unsafe {
                regs::write32(self.mmio_base, db_offset, sq.tail as u32);
            }
        }
    }

    /// Write the current I/O CQ head to the QID 1 CQ doorbell. No-op
    /// if the I/O CQ has not been created yet.
    pub fn ring_io_cq_doorbell(&self) {
        if let Some(ref cq) = self.io_cq {
            let cq_db = regs::cq_doorbell_offset(1, self.dstrd);
            unsafe {
                regs::write32(self.mmio_base, cq_db, cq.head as u32);
            }
        }
    }
}
