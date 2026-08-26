#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::missing_docs_in_private_items,
    reason = "build script"
)]

fn main() {
    let target = std::env::var("TARGET").expect("TARGET not set");
    if target.contains("apple") {
        println!("cargo:rustc-link-arg=-Wl,-rpath,@executable_path");
    } else if target.contains("linux") {
        println!("cargo:rustc-link-arg=-Wl,-rpath,$ORIGIN");
    }
}
