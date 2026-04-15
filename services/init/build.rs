fn main() {
    // Link liblkl_fused.a (LKL kernel + bridge code) only if LKL feature enabled.
    // Build: cd services/init/lkl && wsl -d Ubuntu -- make
    // Enable: SOTOS_LKL=1 cargo build OR set env in justfile
    let lkl_dir = std::path::Path::new("lkl");
    let lkl_enabled = std::env::var("SOTOS_LKL").unwrap_or_default() == "1";

    // Force re-link whenever the static lib OR any bridge C source changes.
    // Without these rerun-if-changed hints cargo's incremental cache holds
    // onto the previously-linked binary even when liblkl_fused.a updates.
    println!("cargo:rerun-if-env-changed=SOTOS_LKL");
    println!("cargo:rerun-if-changed=lkl/liblkl_fused.a");
    println!("cargo:rerun-if-changed=lkl/lkl_bridge.c");
    println!("cargo:rerun-if-changed=lkl/host_ops.c");
    println!("cargo:rerun-if-changed=lkl/disk_backend.c");
    println!("cargo:rerun-if-changed=lkl/net_backend.c");
    println!("cargo:rerun-if-changed=lkl/guest_mem.c");
    println!("cargo:rerun-if-changed=lkl/allocator.c");
    println!("cargo:rerun-if-changed=lkl/libc_stubs.c");
    println!("cargo:rerun-if-changed=build.rs");

    if lkl_enabled && lkl_dir.join("liblkl_fused.a").exists() {
        println!("cargo:rustc-link-search=native=lkl");
        println!("cargo:rustc-link-lib=static=lkl_fused");
        println!("cargo:rustc-cfg=lkl");
        println!("cargo:warning=LKL: ENABLED (Linux 6.6 fused)");
    } else {
        println!("cargo:warning=LKL: disabled (set SOTOS_LKL=1 to enable)");
    }
}
