// Build script for rump-vfs.
//
// Links the fused NetBSD rump kernel library (librump_fused.a) into the
// freestanding sotOS service binary. The .a was produced by buildrump.sh
// in WSL Ubuntu, then merged via `ld -r` against rumpuser_sot.o so that
// the resulting archive only references rumpuser_*, link_set_* markers,
// and the GOT — all of which are satisfied at final link time.

fn main() {
    // The .a sits beside vendor/netbsd-rump/rumpuser_sot.{c,h} so it stays
    // co-located with the source it depends on.
    let lib_dir = std::path::Path::new("../../vendor/netbsd-rump");
    let lib_path = lib_dir.join("librump_fused.a");

    if lib_path.exists() {
        println!("cargo:rustc-link-search=native=../../vendor/netbsd-rump");
        println!("cargo:rustc-link-lib=static=rump_fused");
        println!("cargo:rustc-cfg=rump_real");
        println!("cargo:warning=rump-vfs: real librump_fused.a linked");
    } else {
        println!(
            "cargo:warning=rump-vfs: librump_fused.a not found at {} -- using stub backend",
            lib_path.display()
        );
    }

    println!("cargo:rerun-if-changed=../../vendor/netbsd-rump/librump_fused.a");
    println!("cargo:rerun-if-changed=build.rs");
}
