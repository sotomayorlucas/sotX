//! Device driver lifecycle trait and supporting types.
//!
//! Every driver that runs inside a SOT domain implements [`DeviceDriver`].
//! The framework calls the methods in order: `probe` -> `attach` ->
//! (normal operation) -> `detach`.  `suspend`/`resume` are optional
//! power-management hooks.

use crate::dma::DmaCap;
use crate::irq_channel::IrqChannel;
use crate::mmio_so::MmioRegion;
use crate::DriverError;

/// PCI configuration space access for a single function.
#[derive(Debug, Clone, Copy)]
pub struct PciConfigSpace {
    /// BDF encoded as (bus << 8 | dev << 3 | func).
    pub bdf: u16,
    /// Base address of the ECAM region for this function (4 KiB).
    pub ecam_base: u64,
    /// Capability guarding config-space access.
    pub cap: u64,
}

/// Information returned by a successful probe.
#[derive(Debug, Clone, Copy)]
pub struct DeviceInfo {
    /// PCI vendor ID (or 0 for platform devices).
    pub vendor_id: u16,
    /// PCI device ID (or 0 for platform devices).
    pub device_id: u16,
    /// Driver-defined device class tag.
    pub class: u32,
}

/// Resources the framework hands to a driver domain.
///
/// All fields use fixed-size arrays so no heap allocation is needed.
pub struct DeviceResources {
    /// Up to 8 MMIO regions (BARs, platform MMIO, etc.).
    pub mmio_regions: [Option<MmioRegion>; 8],
    /// Up to 4 IRQ channels.
    pub irq_channels: [Option<IrqChannel>; 4],
    /// Up to 4 DMA capabilities.
    pub dma_caps: [Option<DmaCap>; 4],
    /// Optional PCI config-space accessor.
    pub config_space: Option<PciConfigSpace>,
}

impl DeviceResources {
    /// Create an empty resource set.
    pub const fn empty() -> Self {
        Self {
            mmio_regions: [None; 8],
            irq_channels: [None; 4],
            dma_caps: [None; 4],
            config_space: None,
        }
    }
}

/// Device driver lifecycle -- every driver domain implements this.
pub trait DeviceDriver {
    /// Probe: detect if hardware is present.  Returns device info on
    /// success or `DriverError::NotFound` if the hardware is absent.
    fn probe(&mut self, resources: &DeviceResources) -> Result<DeviceInfo, DriverError>;

    /// Attach: initialise the device and allocate runtime resources.
    fn attach(&mut self, resources: &DeviceResources) -> Result<(), DriverError>;

    /// Detach: release resources and power down the device.
    fn detach(&mut self) -> Result<(), DriverError>;

    /// Suspend: save device state for a low-power transition.
    /// Default implementation returns `Unsupported`.
    fn suspend(&mut self) -> Result<(), DriverError> {
        Err(DriverError::Unsupported)
    }

    /// Resume: restore device state after suspension.
    /// Default implementation returns `Unsupported`.
    fn resume(&mut self) -> Result<(), DriverError> {
        Err(DriverError::Unsupported)
    }
}
