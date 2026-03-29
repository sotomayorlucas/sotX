fn main() {
    // Link liblkl_fused.a (LKL kernel + bridge code) only if LKL feature enabled.
    // Build: cd services/init/lkl && wsl -d Ubuntu -- make
    // Enable: SOTOS_LKL=1 cargo build OR set env in justfile
    let lkl_dir = std::path::Path::new("lkl");
    let lkl_enabled = std::env::var("SOTOS_LKL").unwrap_or_default() == "1";
    if lkl_enabled && lkl_dir.join("liblkl_fused.a").exists() {
        println!("cargo:rustc-link-search=native=lkl");
        println!("cargo:rustc-link-lib=static=lkl_fused");
        println!("cargo:rustc-cfg=lkl");
        println!("cargo:warning=LKL: ENABLED (Linux 6.6 fused)");
    } else {
        println!("cargo:warning=LKL: disabled (set SOTOS_LKL=1 to enable)");
    }
}
