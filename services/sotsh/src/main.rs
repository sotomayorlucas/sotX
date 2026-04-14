//! sotSh REPL entry point (native sotOS userspace binary).
//!
//! Address layout: the linker places `.text` at 0x1000000 (see
//! `linker.ld`). A fixed-size BSS bump allocator backs `alloc::*`; no
//! dynamic mmap() support yet. The REPL reads scancodes from the shared
//! KB ring and echoes typed characters through the debug serial.

#![no_std]
#![no_main]

extern crate alloc;

use core::sync::atomic::{AtomicUsize, Ordering};

use sotos_common::sys;

use sotos_sotsh::ast::Ast;
use sotos_sotsh::builtins;
use sotos_sotsh::context::Context;
use sotos_sotsh::error::Error;
use sotos_sotsh::history::History;
use sotos_sotsh::linedit::LineEditor;
use sotos_sotsh::parser;
use sotos_sotsh::runtime;
use sotos_sotsh::value::Value;

// ---------------------------------------------------------------------------
// Bump allocator
// ---------------------------------------------------------------------------
//
// `alloc::vec::Vec`, `alloc::string::String`, and chumsky's internals all
// need a global allocator. We follow the pattern used by `services/net` and
// `services/sotfs`: a fixed 512 KiB BSS buffer with lock-free bump
// allocation. `dealloc` is a no-op — the REPL loop is short-lived enough
// that fragmentation is acceptable for the B1 milestone. B4 will swap this
// for a proper heap (likely `linked_list_allocator`).

const HEAP_SIZE: usize = 512 * 1024;
static mut HEAP: [u8; HEAP_SIZE] = [0; HEAP_SIZE];
static HEAP_POS: AtomicUsize = AtomicUsize::new(0);

struct BumpAlloc;

unsafe impl core::alloc::GlobalAlloc for BumpAlloc {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        let size = layout.size();
        let align = layout.align();
        loop {
            let pos = HEAP_POS.load(Ordering::Relaxed);
            let aligned = (pos + align - 1) & !(align - 1);
            let new_pos = aligned + size;
            if new_pos > HEAP_SIZE {
                return core::ptr::null_mut();
            }
            if HEAP_POS
                .compare_exchange_weak(pos, new_pos, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                // Safety: HEAP is a BSS buffer with a static lifetime.
                // Successful CAS reserved [aligned, aligned+size). Using
                // `addr_of_mut!` avoids forming a reference to the mutable
                // static (2024-edition-compatible).
                let base = core::ptr::addr_of_mut!(HEAP) as *mut u8;
                return unsafe { base.add(aligned) };
            }
        }
    }
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: core::alloc::Layout) {}
}

#[global_allocator]
static ALLOCATOR: BumpAlloc = BumpAlloc;

// ---------------------------------------------------------------------------
// Serial output helpers
// ---------------------------------------------------------------------------

fn write_bytes(s: &[u8]) {
    for &b in s {
        sys::debug_print(b);
    }
}

const PROMPT: &[u8] = b"sotsh> ";

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn _start() -> ! {
    write_bytes(b"sotsh: entered REPL\n");
    print_banner();

    let mut ctx = Context::new();
    let mut editor = LineEditor::new();
    let mut history = History::new();
    // Persistent history lives at `/var/sotsh/history`. The file may
    // not exist on first boot (ENOENT) — that's benign, so we discard
    // the result.
    let _ = history.load_from(b"/var/sotsh/history");

    loop {
        let line = editor.read_line(PROMPT, &mut history);
        let trimmed = line.trim_ascii();
        if trimmed.is_empty() {
            continue;
        }

        // Meta-commands (':quit' / ':help') short-circuit the parser.
        match handle_meta(trimmed) {
            Some(true) => break,
            Some(false) => continue,
            None => {}
        }

        // Convert the line bytes to a &str for the parser. Lines are
        // ASCII-only today (the scancode table doesn't produce multi-byte
        // UTF-8), so this is safe; any non-ASCII would just fail to parse.
        let s = match core::str::from_utf8(trimmed) {
            Ok(s) => s,
            Err(_) => {
                write_bytes(b"sotsh: non-UTF-8 input rejected\n");
                continue;
            }
        };

        match run_line(s, &mut ctx) {
            Ok(value) => print_value(&value),
            Err(e) => {
                write_bytes(b"sotsh: ");
                write_display(&e);
                write_bytes(b"\n");
            }
        }
    }

    write_bytes(b"sotsh: exit\n");
    sys::thread_exit();
}

// ---------------------------------------------------------------------------
// Line handling
// ---------------------------------------------------------------------------

/// Handle `:` meta-commands. Returns `Some(true)` to exit the REPL,
/// `Some(false)` when the line was a consumed meta-command, and `None`
/// when the line should flow through the normal pipeline path.
fn handle_meta(line: &[u8]) -> Option<bool> {
    if line.first() != Some(&b':') {
        return None;
    }
    // The verb is the first whitespace-delimited token after ':'.
    let rest = &line[1..];
    let verb_end = rest
        .iter()
        .position(|&c| c == b' ' || c == b'\t')
        .unwrap_or(rest.len());
    let verb = &rest[..verb_end];
    match verb {
        b"quit" | b"q" | b"exit" => Some(true),
        b"help" | b"h" | b"?" => {
            write_bytes(help_text());
            Some(false)
        }
        _ => {
            write_bytes(b"sotsh: unknown meta-command (try :help)\n");
            Some(false)
        }
    }
}

fn run_line(line: &str, ctx: &mut Context) -> Result<Value, Error> {
    let ast = parser::parse(line)?;
    let Ast::Pipeline(pipeline) = ast;
    // Capability check every stage *before* dispatching anything — keeps
    // the failure mode deterministic even when one mid-pipeline built-in
    // would have failed its own check.
    for cmd in &pipeline.commands {
        check_caps(&cmd.name)?;
    }
    runtime::execute_pipeline(&pipeline, ctx)
}

/// Stub capability check. B2+ will wire this to the real cap set held
/// in [`Context`]; today every cap is "held" so dispatch succeeds.
fn check_caps(name: &str) -> Result<(), Error> {
    let _required = builtins::required_caps(name);
    Ok(())
}

fn print_value(v: &Value) {
    if matches!(v, Value::Nil) {
        return;
    }
    write_display(v);
    write_bytes(b"\n");
}

fn print_banner() {
    write_bytes(b"sotSh v0.1.0 -- capability-first native shell for sotOS\n");
    write_bytes(b"Type :help for meta-commands, :quit to exit.\n");
}

fn help_text() -> &'static [u8] {
    b"meta-commands:\n\
      :help, :h, :?       show this help\n\
      :quit, :q, :exit    leave the shell\n\
      built-ins: ls cat cd ps cap arm (ls/cat/cd are stubbed pending B2a)\n"
}

/// `core::fmt::Display` -> serial, via a tiny adapter. Avoids pulling in
/// `alloc::format!` (which would allocate per-call).
fn write_display<T: core::fmt::Display>(v: &T) {
    use core::fmt::Write;
    struct SerialWriter;
    impl core::fmt::Write for SerialWriter {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            write_bytes(s.as_bytes());
            Ok(())
        }
    }
    let _ = write!(SerialWriter, "{v}");
}

// ---------------------------------------------------------------------------
// Panic handler
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    write_bytes(b"SOTSH PANIC\n");
    loop {
        sys::yield_now();
    }
}
