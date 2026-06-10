fn main() {
    // Copy wintun.dll to the output directory so LoadLibrary can find it
    let dll_src = std::path::Path::new("wintun.dll");
    if dll_src.exists() {
        let out_dir = std::env::var("OUT_DIR").unwrap();
        // OUT_DIR is target/debug/build/... so we need to go up to target/debug
        let target_dir = std::path::Path::new(&out_dir)
            .ancestors()
            .nth(3)
            .unwrap()
            .to_path_buf();
        let dll_dst = target_dir.join("wintun.dll");
        std::fs::copy(dll_src, &dll_dst).unwrap();
        println!("cargo:rerun-if-changed=wintun.dll");
    } else {
        println!("cargo:warning=wintun.dll not found in project root — copy it here");
    }
}