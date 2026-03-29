fn main() {
    // Link liblkl_fused.a (LKL kernel + bridge code)
    // Built via: cd services/init/lkl && wsl -d Ubuntu -- make
    let lkl_dir = std::path::Path::new("lkl");
    if lkl_dir.join("liblkl_fused.a").exists() {
        println!("cargo:rustc-link-search=native=lkl");
        println!("cargo:rustc-link-lib=static=lkl_fused");
        println!("cargo:warning=LKL: linking liblkl_fused.a (Linux 6.6 as backend)");
    } else {
        println!("cargo:warning=LKL: liblkl_fused.a not found, LKL disabled");
    }
}
