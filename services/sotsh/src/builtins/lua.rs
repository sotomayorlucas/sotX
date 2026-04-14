//! Built-in: `eval` (alias `lua`) — embed a Lua 5.4 subset.
//!
//! Required capabilities: none for `eval "code"`; the `lua file.lua` form
//! reads the script via the VFS IPC client, which may require `fs:read`
//! at a higher layer once the cap enforcement lands.
//!
//! Forms:
//! - `eval "print(1+2)"`  — run the string as a Lua chunk, return the
//!                          trailing expression as a [`Value`].
//! - `eval script.lua`    — `vfs_open` + `vfs_read` the file (bounded by
//!                          a 4 KiB buffer, matching the sotos-lua VM's
//!                          internal caps) and run it.
//!
//! Value mapping:
//! - `LuaValue::Nil`      → `Value::Nil`
//! - `LuaValue::Boolean`  → `Value::Bool`
//! - `LuaValue::Number`   → `Value::Int`      (sotos-lua is integer-only)
//! - `LuaValue::String`   → `Value::Str`
//! - `LuaValue::Table`    → `Value::Table`    (array portion only; keys
//!                                             stringified, values mapped
//!                                             recursively via the VM)
//! - `LuaValue::Function` → `Value::Str("<function>")`
//!
//! `print()` output goes to the serial console via [`sys::debug_print`].

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use sotos_common::{sys, vfs};
use sotos_lua::{LuaTable, LuaValue, LuaVm};

use crate::context::Context;
use crate::error::Error;
use crate::value::{Row, Value};

/// `print()` callback wired into the VM. Forwards bytes to the serial
/// console one byte at a time — matching `main.rs::write_bytes`.
fn lua_print(s: &[u8]) {
    for &b in s {
        sys::debug_print(b);
    }
}

pub fn run(args: &[Value], _ctx: &mut Context) -> Result<Value, Error> {
    let source = match args.first() {
        Some(Value::Str(s)) => load_source(s)?,
        Some(_) => {
            return Err(Error::BadArgs(
                "eval: expected a string (Lua code or script path)".to_string(),
            ));
        }
        None => {
            return Err(Error::BadArgs(
                "eval: missing argument (code string or script path)".to_string(),
            ));
        }
    };

    // sotos-lua's VM is large (stack + globals + tables arrays) — keep it
    // on the heap to avoid blowing the sotSh thread stack.
    let mut vm: alloc::boxed::Box<LuaVm> = alloc::boxed::Box::new(LuaVm::new());
    vm.set_output(lua_print);

    let result = vm.run(source.as_bytes());
    Ok(convert(&result, &vm))
}

/// Decide whether `arg` is a literal Lua string (contains whitespace, `=`,
/// `(`, `;`, etc., or ends in something other than `.lua`) or the name of
/// a script file that should be slurped via the VFS. Heuristic: if the
/// string ends with `.lua` and contains no newline or paren, treat it as
/// a path; otherwise treat it as code.
fn load_source(arg: &str) -> Result<String, Error> {
    let looks_like_path = arg.ends_with(".lua")
        && !arg.contains('\n')
        && !arg.contains('(')
        && !arg.contains('=');
    if !looks_like_path {
        return Ok(arg.to_string());
    }

    let open = vfs::vfs_open(arg.as_bytes(), 0).map_err(|e| Error::Io(e as i32))?;
    let mut buf = [0u8; 4096];
    let n = vfs::vfs_read(open.fd, &mut buf).map_err(|e| Error::Io(e as i32))?;
    let _ = vfs::vfs_close(open.fd);
    let s = core::str::from_utf8(&buf[..n])
        .map_err(|_| Error::Other("eval: script is not valid UTF-8"))?;
    Ok(s.to_string())
}

fn convert(v: &LuaValue, vm: &LuaVm) -> Value {
    match v {
        LuaValue::Nil => Value::Nil,
        LuaValue::Boolean(b) => Value::Bool(*b),
        LuaValue::Number(n) => Value::Int(*n),
        LuaValue::String(ls) => {
            let bytes = ls.as_bytes();
            match core::str::from_utf8(bytes) {
                Ok(s) => Value::Str(s.to_string()),
                Err(_) => Value::Str(lossy_ascii(bytes)),
            }
        }
        LuaValue::Table(idx) => convert_table(*idx, vm),
        LuaValue::Function(_) => Value::Str("<function>".to_string()),
    }
}

fn convert_table(idx: u16, vm: &LuaVm) -> Value {
    let i = idx as usize;
    if i >= vm.tables.len() {
        return Value::Nil;
    }
    let tbl: &LuaTable = &vm.tables[i];
    let mut rows: Vec<Row> = Vec::with_capacity(tbl.len);
    for n in 0..tbl.len {
        let key_str = key_to_string(&tbl.keys[n]);
        // Avoid infinite recursion: if a cell is the same table, stringify
        // instead of recursing. sotos-lua disallows closures so this is a
        // belt-and-braces guard against malformed bytecode.
        let cell = match &tbl.values[n] {
            LuaValue::Table(child) if *child == idx => Value::Str("<cycle>".to_string()),
            other => convert(other, vm),
        };
        rows.push(Row::new().with("key", Value::Str(key_str)).with("value", cell));
    }
    Value::Table(rows)
}

fn key_to_string(k: &LuaValue) -> String {
    match k {
        LuaValue::String(ls) => match core::str::from_utf8(ls.as_bytes()) {
            Ok(s) => s.to_string(),
            Err(_) => lossy_ascii(ls.as_bytes()),
        },
        LuaValue::Number(n) => {
            // Reuse Value::Int's Display impl rather than sotos-lua's
            // fixed-buffer formatter so the output matches what the shell
            // prints elsewhere.
            Value::Int(*n).to_string()
        }
        LuaValue::Boolean(b) => if *b { "true" } else { "false" }.to_string(),
        LuaValue::Nil => "nil".to_string(),
        _ => "?".to_string(),
    }
}

fn lossy_ascii(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len());
    for &b in bytes {
        if b.is_ascii() && b != 0 {
            s.push(b as char);
        } else {
            s.push('?');
        }
    }
    s
}
