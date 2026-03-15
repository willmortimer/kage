fn main() {
    println!("cargo:rerun-if-changed=objc/kage_xpc.m");

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os == "macos" {
        cc::Build::new()
            .file("objc/kage_xpc.m")
            .flag("-fobjc-arc")
            .compile("kage_xpc");

        println!("cargo:rustc-link-lib=framework=Foundation");
        println!("cargo:rustc-link-lib=framework=Security");
    }
}
