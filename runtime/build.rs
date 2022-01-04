fn main() {
    // Tell Cargo that if the given file changes, to rerun this build script (i.e. recompile)
    println!("cargo:rerun-if-changed=metadata-parachain.scale");
    println!("cargo:rerun-if-changed=metadata-standalone.scale");
}
