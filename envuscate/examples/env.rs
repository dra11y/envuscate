use envuscate::envuscate;

// running `cargo b --example env`
// will print out `RUNTIME_KEY='DF5C842962F76A25B7402524FC8B5C68174584BEC2B6318BBAC5EB1B83767CF0'`
// to the console
//
// This key will then need to be provided at runtime, otherwise the program will panic:
// `RUNTIME_KEY='DF5C842962F76A25B7402524FC8B5C68174584BEC2B6318BBAC5EB1B83767CF0' cargo r --example
// env`
//
fn main() {
    let text = envuscate!(env = "RUNTIME_KEY", "MY_OBFUSCATED_VAR");
    println!("{text}");
}
