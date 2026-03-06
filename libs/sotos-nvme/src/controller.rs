//! NVMe controller initialization and admin queue management.

use crate::regs;
use crate::queue::{SubmissionQueue, CompletionQueue, QUEUE_DEPTH};
use crate::cmd;

/// NVMe controller state.
pub struct NvmeController {
    /// MMIO base virtual address (BAR0, UC-mapped).
    pub mmio_base: *mut u8,
    /// Doorbell stride from CAP register.
    pub dstrd: u8,
    /// Admin Submission Queue.
    pub admin_sq: SubmissionQueue,
    /// Admin Completion Queue.
    pub admin_cq: CompletionQueue,
    /// I/O Submission Queue (QID=1).
    pub io_sq: Option<SubmissionQueue>,
    /// I/O Completion Queue (QID=1).
    pub io_cq: Option<CompletionQueue>,
    /// Namespace size in logical blocks.
    pub ns_size: u64,
    /// LBA size in bytes (usually 512).
    pub lba_size: u32,
    /// Optional callback invoked on I/O completion (CID passed).
    pub completion_callback: Option<fn(u16)>,
    /// Optional notification cap for interrupt-driven completion.
    /// When set, `wait_for_interrupt()` uses notify_wait instead of polling.
    pub notify_cap: Option<u64>,
    /// Whether to use interrupt-driven completion (true) or polling (false).
    pub use_interrupts: bool,
}

/// DMA memory layout provided by the caller.
pub struct DmaPages {
    /// Admin SQ: virtual + physical.
    pub admin_sq_virt: *mut u8,
    pub admin_sq_phys: u64,
    /// Admin CQ: virtual + physical.
    pub admin_cq_virt: *mut u8,
    pub admin_cq_phys: u64,
    /// I/O SQ: virtual + physical.
    pub io_sq_virt: *mut u8,
    pub io_sq_phys: u64,
    /// I/O CQ: virtual + physical.
    pub io_cq_virt: *mut u8,
    pub io_cq_phys: u64,
    /// Identify buffer (4 KiB): virtual + physical.
    pub identify_virt: *mut u8,
    pub identify_phys: u64,
}

/// Result from controller initialization.
pub struct InitResult {
    pub version_major: u16,
    pub version_minor: u16,
    pub ns_size: u64,
    pub lba_size: u32,
}

/// Wait callback — called while spinning for controller state changes.
/// The caller provides this to yield or sleep instead of busy-spinning.
pub type WaitFn = fn();

impl NvmeController {
    /// Initialize the NVMe controller.
    ///
    /// Performs the full init sequence:
    /// 1. Read CAP → MQES, DSTRD
    /// 2. Disable controller (CC.EN=0, wait CSTS.RDY=0)
    /// 3. Set AQA/ASQ/ACQ
    /// 4. Enable (CC.EN=1, wait CSTS.RDY=1)
    /// 5. Identify Controller + Namespace
    /// 6. Create I/O CQ + SQ
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
            for _ in 0..100_000 {
                let csts = unsafe { regs::read32(mmio_base, regs::REG_CSTS) };
                if csts & regs::CSTS_RDY == 0 {
                    break;
                }
                wait();
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
        let mut ready = false;
        for _ in 0..1_000_000 {
            let csts = unsafe { regs::read32(mmio_base, regs::REG_CSTS) };
            if csts & regs::CSTS_RDY != 0 {
                ready = true;
                break;
            }
            wait();
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

    /// Submit an admin command and wait for completion.
    fn admin_submit_and_wait(&mut self, entry: crate::queue::SqEntry, wait: WaitFn) -> Result<crate::queue::CqEntry, &'static str> {
        let _cid = self.admin_sq.submit(entry);

        // Ring the admin SQ doorbell (QID=0).
        let db_offset = regs::sq_doorbell_offset(0, self.dstrd);
        unsafe {
            regs::write32(self.mmio_base, db_offset, self.admin_sq.tail as u32);
        }

        // Poll for completion.
        for _ in 0..10_000_000 {
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
            wait();
        }
        Err("NVMe: admin command timeout")
    }

    /// Ring the I/O SQ doorbell (QID=1).
    pub fn ring_io_sq_doorbell(&self) {
        if let Some(ref sq) = self.io_sq {
            let db_offset = regs::sq_doorbell_offset(1, self.dstrd);
            unsafe {
                regs::write32(self.mmio_base, db_offset, sq.tail as u32);
            }
        }
    }

    /// Ring the I/O CQ doorbell (QID=1).
    pub fn ring_io_cq_doorbell(&self) {
        if let Some(ref cq) = self.io_cq {
            let cq_db = regs::cq_doorbell_offset(1, self.dstrd);
            unsafe {
                regs::write32(self.mmio_base, cq_db, cq.head as u32);
            }
        }
    }
}
