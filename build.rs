extern crate cc;

#[cfg(target_family = "unix")]
fn main() {
    cc::Build::new()
        .file("src/udp_sas.c")
        .compile("librust_udp_sas.a");
}

#[cfg(target_family = "windows")]
fn main() {
    cc::Build::new()
        .file("src/udp_sas.c")
        .define("__Windows__", None)
        .compile("librust_udp_sas.a");
}
