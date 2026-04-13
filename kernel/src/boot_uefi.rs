//! UEFI Boot Protocol Type Definitions — Design Document.
//!
//! This module contains the UEFI protocol type definitions needed for
//! future UEFI boot support in sotX. Currently, sotX boots via the
//! Limine BIOS protocol. This module defines the structures that would
//! be needed for a UEFI boot path.
//!
//! # UEFI Boot Flow (Design)
//!
//! 1. **EFI Application Entry**: The kernel is compiled as an EFI application
//!    (PE32+ format, not ELF). The UEFI firmware loads it and calls
//!    `efi_main(image_handle, system_table)`.
//!
//! 2. **System Table Access**: Through `EFI_SYSTEM_TABLE`, access
//!    `BootServices` and `RuntimeServices`. Boot services are only
//!    available before `ExitBootServices()`.
//!
//! 3. **Memory Map**: Call `GetMemoryMap()` to get the system memory layout.
//!    This is required before calling `ExitBootServices()`. The memory map
//!    tells us which regions are usable RAM, reserved, MMIO, etc.
//!
//! 4. **Framebuffer (GOP)**: Locate the Graphics Output Protocol (GOP) to
//!    get the framebuffer address, dimensions, and pixel format. This
//!    replaces the Limine framebuffer response.
//!
//! 5. **Exit Boot Services**: Call `ExitBootServices(image_handle, map_key)`
//!    to take ownership of the system. After this:
//!    - No more UEFI boot service calls (memory allocation, file I/O, etc.)
//!    - Runtime services (RTC, ACPI, reset) remain available
//!    - The OS has full control of all hardware
//!
//! 6. **Set Up Page Tables**: Create our own page tables (the UEFI identity
//!    mapping is no longer guaranteed). Map the kernel, framebuffer, and
//!    HHDM region.
//!
//! 7. **Kernel Init**: Jump to `kmain()` with the gathered boot info
//!    (memory map, framebuffer, ACPI RSDP pointer).
//!
//! # Differences from Limine Boot
//!
//! - Limine provides ready-made structures (memory map, framebuffer, HHDM).
//!   UEFI requires manual protocol queries.
//! - Limine loads the kernel as ELF. UEFI expects PE32+ or uses a loader stub.
//! - Limine sets up HHDM. With UEFI, we must set up our own.
//! - Limine provides an initrd mechanism. With UEFI, we'd load files from
//!   the EFI system partition using the Simple File System Protocol.

// ---------------------------------------------------------------------------
// EFI Status Codes
// ---------------------------------------------------------------------------

/// UEFI status code type.
pub type EfiStatus = usize;

/// Success.
pub const EFI_SUCCESS: EfiStatus = 0;

/// Error bit (high bit set = error).
pub const EFI_ERROR_BIT: EfiStatus = 1 << (core::mem::size_of::<usize>() * 8 - 1);

/// Common EFI error codes.
pub const EFI_LOAD_ERROR: EfiStatus = EFI_ERROR_BIT | 1;
pub const EFI_INVALID_PARAMETER: EfiStatus = EFI_ERROR_BIT | 2;
pub const EFI_UNSUPPORTED: EfiStatus = EFI_ERROR_BIT | 3;
pub const EFI_BAD_BUFFER_SIZE: EfiStatus = EFI_ERROR_BIT | 4;
pub const EFI_BUFFER_TOO_SMALL: EfiStatus = EFI_ERROR_BIT | 5;
pub const EFI_NOT_READY: EfiStatus = EFI_ERROR_BIT | 6;
pub const EFI_DEVICE_ERROR: EfiStatus = EFI_ERROR_BIT | 7;
pub const EFI_OUT_OF_RESOURCES: EfiStatus = EFI_ERROR_BIT | 9;
pub const EFI_NOT_FOUND: EfiStatus = EFI_ERROR_BIT | 14;

/// Check if an EFI status is an error.
pub const fn efi_error(status: EfiStatus) -> bool {
    status & EFI_ERROR_BIT != 0
}

// ---------------------------------------------------------------------------
// EFI Handle & GUID
// ---------------------------------------------------------------------------

/// Opaque handle type (pointer-sized).
pub type EfiHandle = *mut core::ffi::c_void;

/// EFI GUID (128-bit identifier for protocols).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EfiGuid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl EfiGuid {
    pub const fn new(d1: u32, d2: u16, d3: u16, d4: [u8; 8]) -> Self {
        Self {
            data1: d1,
            data2: d2,
            data3: d3,
            data4: d4,
        }
    }
}

/// GOP GUID: {9042A9DE-23DC-4A38-96FB-7ADED080516A}
pub const EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID: EfiGuid = EfiGuid::new(
    0x9042A9DE,
    0x23DC,
    0x4A38,
    [0x96, 0xFB, 0x7A, 0xDE, 0xD0, 0x80, 0x51, 0x6A],
);

// ---------------------------------------------------------------------------
// EFI System Table
// ---------------------------------------------------------------------------

/// EFI Table Header — present at the start of all EFI tables.
#[repr(C)]
pub struct EfiTableHeader {
    pub signature: u64,
    pub revision: u32,
    pub header_size: u32,
    pub crc32: u32,
    pub reserved: u32,
}

/// EFI System Table — the root data structure provided to the EFI application.
///
/// # Usage (design)
/// ```ignore
/// fn efi_main(image_handle: EfiHandle, system_table: *mut EfiSystemTable) -> EfiStatus {
///     let st = unsafe { &*system_table };
///     let boot_services = unsafe { &*st.boot_services };
///     // ... use boot_services to allocate memory, locate protocols, etc.
///     // ... call ExitBootServices when ready
/// }
/// ```
#[repr(C)]
pub struct EfiSystemTable {
    pub hdr: EfiTableHeader,
    pub firmware_vendor: *const u16, // UCS-2 string
    pub firmware_revision: u32,
    pub console_in_handle: EfiHandle,
    pub con_in: *mut core::ffi::c_void, // EFI_SIMPLE_TEXT_INPUT_PROTOCOL
    pub console_out_handle: EfiHandle,
    pub con_out: *mut core::ffi::c_void, // EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL
    pub standard_error_handle: EfiHandle,
    pub std_err: *mut core::ffi::c_void,
    pub runtime_services: *mut EfiRuntimeServices,
    pub boot_services: *mut EfiBootServices,
    pub number_of_table_entries: usize,
    pub configuration_table: *mut EfiConfigurationTable,
}

// ---------------------------------------------------------------------------
// EFI Boot Services
// ---------------------------------------------------------------------------

/// EFI Boot Services table (simplified — function pointers as *const ()).
///
/// In a real implementation, each field would be a function pointer with
/// the correct signature. Here we define the layout for reference.
#[repr(C)]
pub struct EfiBootServices {
    pub hdr: EfiTableHeader,

    // Task Priority Services
    pub raise_tpl: *const (),
    pub restore_tpl: *const (),

    // Memory Services
    pub allocate_pages: *const (),
    pub free_pages: *const (),
    pub get_memory_map: *const (),
    pub allocate_pool: *const (),
    pub free_pool: *const (),

    // Event & Timer Services
    pub create_event: *const (),
    pub set_timer: *const (),
    pub wait_for_event: *const (),
    pub signal_event: *const (),
    pub close_event: *const (),
    pub check_event: *const (),

    // Protocol Handler Services
    pub install_protocol_interface: *const (),
    pub reinstall_protocol_interface: *const (),
    pub uninstall_protocol_interface: *const (),
    pub handle_protocol: *const (),
    pub reserved: *const (),
    pub register_protocol_notify: *const (),
    pub locate_handle: *const (),
    pub locate_device_path: *const (),
    pub install_configuration_table: *const (),

    // Image Services
    pub load_image: *const (),
    pub start_image: *const (),
    pub exit: *const (),
    pub unload_image: *const (),
    pub exit_boot_services: *const (),

    // Miscellaneous Services
    pub get_next_monotonic_count: *const (),
    pub stall: *const (),
    pub set_watchdog_timer: *const (),

    // DriverSupport Services
    pub connect_controller: *const (),
    pub disconnect_controller: *const (),

    // Open and Close Protocol Services
    pub open_protocol: *const (),
    pub close_protocol: *const (),
    pub open_protocol_information: *const (),

    // Library Services
    pub protocols_per_handle: *const (),
    pub locate_handle_buffer: *const (),
    pub locate_protocol: *const (),
    pub install_multiple_protocol_interfaces: *const (),
    pub uninstall_multiple_protocol_interfaces: *const (),

    // CRC Services
    pub calculate_crc32: *const (),

    // Misc
    pub copy_mem: *const (),
    pub set_mem: *const (),
    pub create_event_ex: *const (),
}

// ---------------------------------------------------------------------------
// EFI Runtime Services
// ---------------------------------------------------------------------------

/// EFI Runtime Services table (simplified).
#[repr(C)]
pub struct EfiRuntimeServices {
    pub hdr: EfiTableHeader,
    pub get_time: *const (),
    pub set_time: *const (),
    pub get_wakeup_time: *const (),
    pub set_wakeup_time: *const (),
    pub set_virtual_address_map: *const (),
    pub convert_pointer: *const (),
    pub get_variable: *const (),
    pub get_next_variable_name: *const (),
    pub set_variable: *const (),
    pub get_next_high_monotonic_count: *const (),
    pub reset_system: *const (),
    pub update_capsule: *const (),
    pub query_capsule_capabilities: *const (),
    pub query_variable_info: *const (),
}

// ---------------------------------------------------------------------------
// EFI Configuration Table
// ---------------------------------------------------------------------------

/// Configuration table entry (ACPI, SMBIOS, etc.).
#[repr(C)]
pub struct EfiConfigurationTable {
    pub vendor_guid: EfiGuid,
    pub vendor_table: *mut core::ffi::c_void,
}

// ---------------------------------------------------------------------------
// Memory Map Structures
// ---------------------------------------------------------------------------

/// EFI memory type.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EfiMemoryType {
    ReservedMemory = 0,
    LoaderCode = 1,
    LoaderData = 2,
    BootServicesCode = 3,
    BootServicesData = 4,
    RuntimeServicesCode = 5,
    RuntimeServicesData = 6,
    ConventionalMemory = 7,
    UnusableMemory = 8,
    AcpiReclaimMemory = 9,
    AcpiNvsMemory = 10,
    MemoryMappedIo = 11,
    MemoryMappedIoPortSpace = 12,
    PalCode = 13,
    PersistentMemory = 14,
    MaxMemoryType = 15,
}

/// EFI memory descriptor — one entry in the memory map.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EfiMemoryDescriptor {
    pub memory_type: u32,
    pub physical_start: u64,
    pub virtual_start: u64,
    pub number_of_pages: u64,
    pub attribute: u64,
}

impl EfiMemoryDescriptor {
    /// Check if this region is usable RAM after ExitBootServices.
    pub fn is_usable(&self) -> bool {
        matches!(
            self.memory_type,
            x if x == EfiMemoryType::ConventionalMemory as u32
                || x == EfiMemoryType::BootServicesCode as u32
                || x == EfiMemoryType::BootServicesData as u32
                || x == EfiMemoryType::LoaderCode as u32
                || x == EfiMemoryType::LoaderData as u32
        )
    }

    /// Size in bytes.
    pub fn size(&self) -> u64 {
        self.number_of_pages * 4096
    }
}

/// Memory attribute flags.
pub const EFI_MEMORY_UC: u64 = 0x1;
pub const EFI_MEMORY_WC: u64 = 0x2;
pub const EFI_MEMORY_WT: u64 = 0x4;
pub const EFI_MEMORY_WB: u64 = 0x8;
pub const EFI_MEMORY_UCE: u64 = 0x10;
pub const EFI_MEMORY_WP: u64 = 0x1000;
pub const EFI_MEMORY_RP: u64 = 0x2000;
pub const EFI_MEMORY_XP: u64 = 0x4000;
pub const EFI_MEMORY_RUNTIME: u64 = 0x8000_0000_0000_0000;

// ---------------------------------------------------------------------------
// Graphics Output Protocol (GOP) — Framebuffer Access
// ---------------------------------------------------------------------------

/// GOP pixel format.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GopPixelFormat {
    /// Red=bits[0:7], Green=bits[8:15], Blue=bits[16:23], Reserved=bits[24:31].
    RedGreenBlueReserved = 0,
    /// Blue=bits[0:7], Green=bits[8:15], Red=bits[16:23], Reserved=bits[24:31].
    BlueGreenRedReserved = 1,
    /// Custom pixel format (use pixel_information mask).
    BitMask = 2,
    /// No framebuffer (BLT operations only).
    BltOnly = 3,
}

/// GOP pixel bitmask (for BitMask format).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct GopPixelBitmask {
    pub red_mask: u32,
    pub green_mask: u32,
    pub blue_mask: u32,
    pub reserved_mask: u32,
}

/// GOP mode information — describes a video mode.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct GopModeInformation {
    /// Version of this structure (should be 0).
    pub version: u32,
    /// Horizontal resolution in pixels.
    pub horizontal_resolution: u32,
    /// Vertical resolution in pixels.
    pub vertical_resolution: u32,
    /// Pixel format.
    pub pixel_format: GopPixelFormat,
    /// Pixel bitmask (only valid if pixel_format == BitMask).
    pub pixel_information: GopPixelBitmask,
    /// Number of pixels per scanline (may be > horizontal_resolution due to padding).
    pub pixels_per_scan_line: u32,
}

/// GOP mode — current mode information and framebuffer pointer.
#[repr(C)]
pub struct GopMode {
    /// Maximum mode number supported (0-based).
    pub max_mode: u32,
    /// Current mode number.
    pub mode: u32,
    /// Information about the current mode.
    pub info: *mut GopModeInformation,
    /// Size of the GopModeInformation structure.
    pub size_of_info: usize,
    /// Physical address of the framebuffer.
    pub frame_buffer_base: u64,
    /// Size of the framebuffer in bytes.
    pub frame_buffer_size: usize,
}

/// Graphics Output Protocol (GOP) interface.
///
/// # Usage (design)
/// ```ignore
/// // Locate GOP:
/// let mut gop: *mut GraphicsOutputProtocol = core::ptr::null_mut();
/// boot_services.locate_protocol(&EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID, &mut gop);
///
/// // Read framebuffer info:
/// let mode = unsafe { &*(*gop).mode };
/// let info = unsafe { &*mode.info };
/// let fb_addr = mode.frame_buffer_base;
/// let width = info.horizontal_resolution;
/// let height = info.vertical_resolution;
/// let stride = info.pixels_per_scan_line;
/// ```
#[repr(C)]
pub struct GraphicsOutputProtocol {
    pub query_mode: *const (),
    pub set_mode: *const (),
    pub blt: *const (),
    pub mode: *mut GopMode,
}
