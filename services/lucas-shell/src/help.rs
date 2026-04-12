//! Structured help system for the LUCAS shell.
//!
//! Every built-in is described by a [`CommandDoc`] entry inside
//! [`crate::builtins::help_data::ALL_DOCS`]. This module provides lookup
//! helpers and Tokyo-Night-coloured renderers for:
//!
//! * `help` (no args)          — categorized command listing.
//! * `help <cmd>` / `man <cmd>` — single-command detail page.
//! * `<cmd> --help`            — same detail page, wired from dispatch.
//!
//! No allocations: every string is `&'static`, output is pushed straight
//! through `syscall::print()` → `linux_write(1, ...)`.

use crate::builtins::help_data::ALL_DOCS;
use crate::syscall::print;
use crate::util::eq;

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// Broad grouping used by the category listing.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Category {
    File,
    Text,
    System,
    Net,
    Script,
    Util,
}

impl Category {
    pub fn title(self) -> &'static [u8] {
        match self {
            Category::File => b"File system",
            Category::Text => b"Text processing",
            Category::System => b"System & processes",
            Category::Net => b"Networking",
            Category::Script => b"Scripting",
            Category::Util => b"Utilities",
        }
    }

    /// Stable ordering used when rendering the full list.
    const ORDER: &'static [Category] = &[
        Category::File,
        Category::Text,
        Category::System,
        Category::Net,
        Category::Script,
        Category::Util,
    ];
}

/// One entry in the help registry.
pub struct CommandDoc {
    pub name: &'static str,
    pub category: Category,
    pub usage: &'static str,
    pub summary: &'static str,
    pub examples: &'static [&'static str],
}

// ---------------------------------------------------------------------------
// Tokyo Night ANSI escapes (raw, no deps)
// ---------------------------------------------------------------------------

const FG:     &[u8] = b"\x1b[38;2;192;202;245m";
const ACCENT: &[u8] = b"\x1b[38;2;122;162;247m";
const DIM:    &[u8] = b"\x1b[2m";
const BOLD:   &[u8] = b"\x1b[1m";
const RESET:  &[u8] = b"\x1b[0m";

// ---------------------------------------------------------------------------
// Lookup
// ---------------------------------------------------------------------------

/// Find a doc entry by command name.
pub fn find(name: &[u8]) -> Option<&'static CommandDoc> {
    for doc in ALL_DOCS.iter() {
        if eq(name, doc.name.as_bytes()) {
            return Some(doc);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Rendering helpers
// ---------------------------------------------------------------------------

fn print_str(s: &str) {
    print(s.as_bytes());
}

fn print_header(title: &[u8]) {
    print(BOLD);
    print(ACCENT);
    print(b"== ");
    print(title);
    print(b" ==");
    print(RESET);
    print(b"\n");
}

/// Print `name` padded with spaces so the column is exactly `width` wide.
fn print_padded_name(name: &str, width: usize) {
    print(ACCENT);
    print_str(name);
    print(RESET);
    let pad = if width > name.len() { width - name.len() } else { 1 };
    for _ in 0..pad {
        print(b" ");
    }
}

/// `help` with no args — render every category with its commands.
pub fn print_all_categorized() {
    print(FG);
    print(b"LUCAS shell -");
    print(b" type `help <cmd>` or `man <cmd>` for details, `<cmd> --help` also works.\n");
    print(RESET);
    print(b"\n");

    for &cat in Category::ORDER.iter() {
        print_header(cat.title());
        for doc in ALL_DOCS.iter() {
            if doc.category != cat {
                continue;
            }
            print(b"  ");
            print_padded_name(doc.name, 12);
            print(FG);
            print_str(doc.summary);
            print(RESET);
            print(b"\n");
        }
        print(b"\n");
    }

    print(DIM);
    print(b"operators : && || | > >> < &  |  ");
    print(b"scripting: if/for/while/function\n");
    print(b"variables : $VAR $? $$ $# $@ $0..$9  |  ");
    print(b"expansion: $(cmd) `cmd` $((expr))\n");
    print(RESET);
}

/// `help <cmd>` / `man <cmd>` / `<cmd> --help` — detailed page.
pub fn print_command_doc(name: &[u8]) {
    let doc = match find(name) {
        Some(d) => d,
        None => {
            print(FG);
            print(b"help: no entry for `");
            print(name);
            print(b"`. Try `help` for the full list.\n");
            print(RESET);
            return;
        }
    };

    // Header: NAME - summary
    print(BOLD);
    print(ACCENT);
    print_str(doc.name);
    print(RESET);
    print(FG);
    print(b" - ");
    print_str(doc.summary);
    print(RESET);
    print(b"\n");

    // Category tag
    print(DIM);
    print(b"category: ");
    print(doc.category.title());
    print(RESET);
    print(b"\n\n");

    // Usage
    print(BOLD);
    print(b"USAGE\n");
    print(RESET);
    print(b"  ");
    print(ACCENT);
    print_str(doc.usage);
    print(RESET);
    print(b"\n\n");

    // Examples
    if !doc.examples.is_empty() {
        print(BOLD);
        print(b"EXAMPLES\n");
        print(RESET);
        for ex in doc.examples.iter() {
            print(b"  ");
            print(DIM);
            print(b"$ ");
            print(RESET);
            print(FG);
            print_str(ex);
            print(RESET);
            print(b"\n");
        }
        print(b"\n");
    }
}

/// Category listing only — useful for future integrations.
pub fn print_category_list() {
    for &cat in Category::ORDER.iter() {
        print(b"  ");
        print(ACCENT);
        print(cat.title());
        print(RESET);
        print(b"\n");
    }
}

// ---------------------------------------------------------------------------
// --help argument detection
// ---------------------------------------------------------------------------

/// True if `args` begins with `--help` (possibly followed by space/EOL).
pub fn is_help_flag(args: &[u8]) -> bool {
    const FLAG: &[u8] = b"--help";
    if args.len() < FLAG.len() {
        return false;
    }
    if &args[..FLAG.len()] != FLAG {
        return false;
    }
    // Must be end-of-string or followed by whitespace.
    args.len() == FLAG.len() || args[FLAG.len()] == b' ' || args[FLAG.len()] == b'\t'
}
