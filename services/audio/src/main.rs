//! sotOS Audio Service — AC97 sound output
//!
//! Detects AC97 audio on PCI, initializes the controller, and plays
//! a boot chime (1 kHz sine wave for ~0.5 seconds).

#![no_std]
#![no_main]

use sotos_common::sys;
use sotos_common::{BootInfo, BOOT_INFO_ADDR};
use sotos_pci::PciBus;
use sotos_audio::controller::Ac97Controller;
use sotos_audio::playback::PcmPlayback;
use sotos_audio::bdl::Bdl;

const CAP_PCI: usize = 0;

// Address space layout
const DMA_BASE: u64 = 0xD00000;      // DMA buffers (BDL + audio data)
const BDL_OFFSET: u64 = 0;            // BDL at start of DMA region
const BUF_OFFSET: u64 = 0x1000;       // Audio buffers at DMA_BASE + 4K

fn print(s: &[u8]) {
    for &b in s { sys::debug_print(b); }
}

fn print_u16(mut n: u16) {
    if n == 0 { sys::debug_print(b'0'); return; }
    let mut buf = [0u8; 6];
    let mut i = 0;
    while n > 0 { buf[i] = b'0' + (n % 10) as u8; n /= 10; i += 1; }
    while i > 0 { i -= 1; sys::debug_print(buf[i]); }
}

fn wait() { sys::yield_now(); }

/// Generate a 1 kHz sine wave tone as 16-bit PCM samples at 48 kHz.
/// Fills `buf` with stereo interleaved samples (L, R, L, R, ...).
fn generate_tone(buf: &mut [u8], freq: u32, sample_rate: u32) {
    // Pre-computed sine table (64 entries, scaled to i16 range)
    const SINE_TABLE: [i16; 64] = [
        0, 3212, 6393, 9512, 12539, 15446, 18204, 20787,
        23170, 25330, 27245, 28898, 30273, 31357, 32138, 32610,
        32767, 32610, 32138, 31357, 30273, 28898, 27245, 25330,
        23170, 20787, 18204, 15446, 12539, 9512, 6393, 3212,
        0, -3212, -6393, -9512, -12539, -15446, -18204, -20787,
        -23170, -25330, -27245, -28898, -30273, -31357, -32138, -32610,
        -32767, -32610, -32138, -31357, -30273, -28898, -27245, -25330,
        -23170, -20787, -18204, -15446, -12539, -9512, -6393, -3212,
    ];

    let samples = buf.len() / 4; // 4 bytes per stereo sample (2x i16)
    let mut phase: u64 = 0;
    let phase_inc = (freq as u64 * 64) / sample_rate as u64; // fixed-point

    for i in 0..samples {
        let idx = (phase % 64) as usize;
        let sample = SINE_TABLE[idx] / 2; // reduce volume to 50%
        let bytes = sample.to_le_bytes();
        let off = i * 4;
        if off + 3 < buf.len() {
            buf[off] = bytes[0];     // L low
            buf[off + 1] = bytes[1]; // L high
            buf[off + 2] = bytes[0]; // R low
            buf[off + 3] = bytes[1]; // R high
        }
        phase += phase_inc;
    }
}

/// Allocate physical pages and return physical address of first page.
fn alloc_dma(vaddr: u64, pages: usize) -> u64 {
    let mut first_phys = 0u64;
    for i in 0..pages {
        let frame = sys::frame_alloc().expect("AC97: frame_alloc");
        let phys = sys::frame_phys(frame).unwrap_or(0);
        sys::map(vaddr + (i as u64) * 0x1000, frame, 2).expect("AC97: map");
        unsafe { core::ptr::write_bytes((vaddr + (i as u64) * 0x1000) as *mut u8, 0, 4096); }
        if i == 0 { first_phys = phys; }
    }
    first_phys
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let boot_info = unsafe { &*(BOOT_INFO_ADDR as *const BootInfo) };
    if boot_info.cap_count == 0 {
        print(b"AUDIO: no caps\n");
        sys::thread_exit();
    }

    let pci = PciBus::new(boot_info.caps[CAP_PCI]);
    let (devs, count) = pci.enumerate::<32>();

    // Find AC97 device: class=0x04 (Multimedia), subclass=0x01 (Audio)
    let mut ac97_dev = None;
    for i in 0..count {
        if devs[i].class == 0x04 && (devs[i].subclass == 0x01 || devs[i].subclass == 0x03) {
            ac97_dev = Some(devs[i]);
            break;
        }
    }

    let dev = match ac97_dev {
        Some(d) => d,
        None => {
            print(b"AUDIO: no AC97 device found\n");
            sys::thread_exit();
        }
    };

    print(b"AUDIO: AC97 found, vendor=");
    print_u16(dev.vendor_id);
    print(b"\n");

    // Enable bus master + I/O space
    pci.enable_bus_master(dev.addr);
    // Enable I/O space (bit 0 of PCI command register)
    let cmd = pci.read32(dev.addr, 0x04) as u16;
    pci.write32(dev.addr, 0x04, (cmd | 0x05) as u32); // I/O + bus master

    // Read BAR0 (mixer) and BAR1 (bus master) I/O port bases
    let bar0 = pci.read32(dev.addr, 0x10) as u16;
    let bar1 = pci.read32(dev.addr, 0x14) as u16;
    let mixer_base = bar0 & 0xFFFC;
    let bm_base = bar1 & 0xFFFC;

    print(b"AUDIO: mixer=");
    print_u16(mixer_base);
    print(b" bm=");
    print_u16(bm_base);
    print(b"\n");

    // Allocate DMA pages: 1 page for BDL + 4 pages for audio buffers (16 KB)
    let dma_phys = alloc_dma(DMA_BASE, 5);
    let bdl_phys = dma_phys as u32;
    let buf_phys = (dma_phys + BUF_OFFSET) as u32;

    // Initialize AC97 controller
    let (ctrl, result) = match unsafe {
        Ac97Controller::init(bm_base, mixer_base, 48000, wait)
    } {
        Ok(r) => r,
        Err(e) => {
            print(b"AUDIO: init failed: ");
            print(e.as_bytes());
            print(b"\n");
            sys::thread_exit();
        }
    };

    print(b"AUDIO: init OK, rate=");
    print_u16(result.sample_rate);
    print(b" VRA=");
    print(if result.vra_enabled { b"yes" } else { b"no" });
    print(b"\n");

    // Generate 1 kHz boot tone into DMA buffers
    let buf_size: u32 = 4096; // 4 KB per buffer = ~21ms at 48kHz stereo 16-bit
    let buf_count = 4usize;   // 4 buffers = ~85ms of audio

    for i in 0..buf_count {
        let buf_addr = (DMA_BASE + BUF_OFFSET + i as u64 * buf_size as u64) as *mut u8;
        let buf_slice = unsafe { core::slice::from_raw_parts_mut(buf_addr, buf_size as usize) };
        generate_tone(buf_slice, 1000, result.sample_rate as u32);
    }

    // Configure BDL and start playback
    let bdl = unsafe { &mut *(DMA_BASE as *mut Bdl) };
    let mut playback = PcmPlayback::new();

    match unsafe { playback.configure(&ctrl, bdl, buf_count, buf_phys, buf_size, bdl_phys, wait) } {
        Ok(()) => print(b"AUDIO: playback configured\n"),
        Err(e) => {
            print(b"AUDIO: configure failed: ");
            print(e.as_bytes());
            print(b"\n");
            sys::thread_exit();
        }
    }

    match unsafe { playback.start(&ctrl) } {
        Ok(()) => print(b"AUDIO: playing boot chime (1 kHz)\n"),
        Err(e) => {
            print(b"AUDIO: start failed: ");
            print(e.as_bytes());
            print(b"\n");
        }
    }

    // Play for ~1 second then stop
    for _ in 0..100 {
        for _ in 0..10000 { wait(); }
    }

    print(b"AUDIO: boot chime done\n");

    // Keep service alive (could serve IPC for audio playback requests)
    loop { sys::yield_now(); }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    print(b"AUDIO: PANIC!\n");
    loop { sys::yield_now(); }
}
