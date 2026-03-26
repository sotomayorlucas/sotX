use crate::syscall::*;

// ---------------------------------------------------------------------------
// Lua interpreter
// ---------------------------------------------------------------------------

/// Lua output callback — writes to stdout.
fn lua_output(s: &[u8]) {
    linux_write(1, s.as_ptr(), s.len());
}

/// Execute Lua code from the command line.
pub fn cmd_lua(code: &[u8]) {
    let mut vm = sotos_lua::LuaVm::new();
    vm.init_stdlib();
    vm.set_output(lua_output);
    let _result = vm.run(code);
}
