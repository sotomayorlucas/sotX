#!/usr/bin/env python
"""ABI diff bot for sotOS.

Usage:
    python scripts/abi_diff.py <base_ref> <head_ref>

Compares the `Syscall` enum and `ABI_VERSION` constant in
`libs/sotos-common/src/lib.rs` between two git refs and prints a
markdown report describing added, removed and renumbered syscalls.

A ref of the form `FILE:<path>` reads the file at <path> directly
instead of going through `git show` — useful for local sanity tests.

Always exits 0: the diff is informational, not a gate.
"""

from __future__ import annotations

import re
import subprocess
import sys
from typing import Dict, Optional, Tuple

ABI_FILE = "libs/sotos-common/src/lib.rs"


def load_source(ref: str) -> str:
    """Return the contents of ABI_FILE at the given ref."""
    if ref.startswith("FILE:"):
        with open(ref[len("FILE:"):], "r", encoding="utf-8") as fh:
            return fh.read()
    try:
        out = subprocess.check_output(
            ["git", "show", f"{ref}:{ABI_FILE}"],
            stderr=subprocess.PIPE,
        )
    except subprocess.CalledProcessError as exc:
        sys.stderr.write(
            f"abi_diff: failed to read {ABI_FILE} at {ref}: "
            f"{exc.stderr.decode('utf-8', 'replace').strip()}\n"
        )
        return ""
    return out.decode("utf-8", "replace")


def strip_comments(text: str) -> str:
    """Remove Rust // line comments and /* ... */ block comments.

    Doc comments (`///`, `//!`, `/** */`) are stripped too — for our
    purposes (extracting `Name = number` pairs) they are noise.
    String/char literals are not interpreted: the enum body never
    contains them, so a simple state machine is sufficient.
    """
    out = []
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            if j == -1:
                break
            i = j + 2
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i + 2)
            if j == -1:
                break
            i = j  # leave the newline in place
            continue
        out.append(c)
        i += 1
    return "".join(out)


def find_enum_body(source: str) -> Optional[str]:
    """Return the body (text inside the braces) of `pub enum Syscall`."""
    m = re.search(r"pub\s+enum\s+Syscall\s*\{", source)
    if not m:
        return None
    start = m.end()
    depth = 1
    i = start
    n = len(source)
    while i < n and depth > 0:
        c = source[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return source[start:i]
        i += 1
    return None


VARIANT_RE = re.compile(
    r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(0[xX][0-9A-Fa-f]+|[0-9]+)\s*,",
)


def parse_syscalls(source: str) -> Dict[str, int]:
    """Extract `{Name: number}` pairs from the Syscall enum."""
    body = find_enum_body(source)
    if body is None:
        return {}
    body = strip_comments(body)
    syscalls: Dict[str, int] = {}
    for name, num in VARIANT_RE.findall(body):
        try:
            value = int(num, 0)
        except ValueError:
            continue
        syscalls[name] = value
    return syscalls


ABI_VERSION_RE = re.compile(
    r"pub\s+const\s+ABI_VERSION\s*:\s*u32\s*=\s*(0[xX][0-9A-Fa-f]+|[0-9]+)",
)


def parse_abi_version(source: str) -> Optional[int]:
    """Extract `pub const ABI_VERSION: u32 = N` if present."""
    cleaned = strip_comments(source)
    m = ABI_VERSION_RE.search(cleaned)
    if not m:
        return None
    try:
        return int(m.group(1), 0)
    except ValueError:
        return None


def diff_syscalls(
    base: Dict[str, int],
    head: Dict[str, int],
) -> Tuple[Dict[str, int], Dict[str, int], Dict[str, Tuple[int, int]]]:
    """Compute added, removed and renumbered syscalls."""
    added = {n: v for n, v in head.items() if n not in base}
    removed = {n: v for n, v in base.items() if n not in head}
    renumbered: Dict[str, Tuple[int, int]] = {}
    for name, head_val in head.items():
        if name in base and base[name] != head_val:
            renumbered[name] = (base[name], head_val)
    return added, removed, renumbered


def render(
    base_ref: str,
    head_ref: str,
    base_version: Optional[int],
    head_version: Optional[int],
    added: Dict[str, int],
    removed: Dict[str, int],
    renumbered: Dict[str, Tuple[int, int]],
) -> str:
    header = f"## ABI Diff: {base_ref}..{head_ref}"

    syscalls_changed = bool(added or removed or renumbered)
    version_changed = base_version != head_version

    if not syscalls_changed and not version_changed:
        return f"{header}\n\nNo ABI changes.\n"

    lines = [header, ""]

    if base_version is None and head_version is None:
        if syscalls_changed:
            lines.append(
                "**ABI_VERSION**: not declared "
                "(consider adding `pub const ABI_VERSION: u32 = N`)"
            )
    else:
        bv = "absent" if base_version is None else str(base_version)
        hv = "absent" if head_version is None else str(head_version)
        if version_changed:
            lines.append(f"**ABI_VERSION**: {bv} -> {hv} (OK, bumped)")
        elif syscalls_changed:
            lines.append(
                f"**ABI_VERSION**: {bv} (WARNING: unchanged but syscalls changed)"
            )
        else:
            lines.append(f"**ABI_VERSION**: {bv}")

    lines.append("")

    lines.append("### Added syscalls")
    if added:
        for name in sorted(added):
            lines.append(f"- `{name} = {added[name]}`")
    else:
        lines.append("- (none)")
    lines.append("")

    lines.append("### Removed syscalls")
    if removed:
        for name in sorted(removed):
            lines.append(f"- `{name} = {removed[name]}`")
    else:
        lines.append("- (none)")
    lines.append("")

    lines.append("### Renumbered syscalls")
    if renumbered:
        for name in sorted(renumbered):
            old, new = renumbered[name]
            lines.append(f"- `{name}`: {old} -> {new}")
    else:
        lines.append("- (none)")
    lines.append("")

    return "\n".join(lines)


def main(argv: list) -> int:
    if len(argv) != 3:
        sys.stderr.write(
            "usage: python scripts/abi_diff.py <base_ref> <head_ref>\n"
        )
        return 0

    base_ref, head_ref = argv[1], argv[2]
    base_src = load_source(base_ref)
    head_src = load_source(head_ref)

    base_syscalls = parse_syscalls(base_src)
    head_syscalls = parse_syscalls(head_src)
    base_version = parse_abi_version(base_src)
    head_version = parse_abi_version(head_src)

    added, removed, renumbered = diff_syscalls(base_syscalls, head_syscalls)
    report = render(
        base_ref,
        head_ref,
        base_version,
        head_version,
        added,
        removed,
        renumbered,
    )
    sys.stdout.write(report)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
