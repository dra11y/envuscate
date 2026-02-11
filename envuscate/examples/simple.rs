use envuscate::envuscate;

// build with `cargo b --example simple`
// then search the binary for embedded strings:
// `strings target/debug/examples/simple | grep supersecret`
//
// only the non-obfuscated text will show up
fn main() {
    let non_obfuscated = env!("MY_ENV_VAR");
    let obfuscated = envuscate!("MY_ENV_VAR");
    println!("{non_obfuscated}");
    println!("{obfuscated}");
}
