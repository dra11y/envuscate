[![CI](https://img.shields.io/github/check-runs/dra11y/envuscate/main?style=flat-square&label=CI)](https://github.com/dra11y/envuscate/actions/workflows/rust.yml)
[![Docs.rs](https://img.shields.io/docsrs/envuscate?style=flat-square-orange)](https://docs.rs/envuscate)
[![Crates.io](https://img.shields.io/crates/v/envuscate?style=flat-square)](https://crates.io/crates/envuscate)
[![Downloads](https://img.shields.io/crates/d/envuscate?style=flat-square&color=red)](https://crates.io/crates/envuscate)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue?style=flat-square)](./LICENSE-APACHE)
[![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](./LICENSE-MIT)
<!-- cargo-rdme start -->

# envuscate

envuscate is an env string obfuscation library, designed to provide an easy way of avoiding simple static binary analysis tools such as `strings` or YARA rules.
It functions by encrypting texts at build time, and embedding an in-place decrypter that is evaluated at runtime.


## Usage & Examples

```rust
// examples/simple.rs
use envuscate::envuscate;

let non_obfuscated = env!("MY_OBFUSCATED_VAR");
let obfuscated = envuscate!("MY_OBFUSCATED_VAR");
println!("{non_obfuscated}");
println!("{obfuscated}");
```


> Compile this example and grep the binary for `obfuscated`:
>
> `cargo b --example simple`
>
> `strings ./target/debug/examples/simple | grep obfuscated`
> Only the second nonobfuscated line should appear.
>


`envuscate` primarily provides the exported `envuscate!()` and `envuscate_unchecked!()`, macros, which
each take an environment variable name as input, expect and encrypt its value at buildtime, and generate
an in-place decrypter which is evaluated to the plaintext `&'static str` at runtime.


By default, these macros will encrypt env strings with the [`chacha20poly1305`] implementation
and embed the key inside the binary.

#### Runtime-provided decryption

If the env argument is provided to the macro invocation, the deobfuscation key
will not be embedded into the binary. Instead, it will be generated at buildtime
and must be provided at runtime.

```rust
use envuscate::envuscate;

let obfuscated = envuscate!(env, "MY_OBFUSCATED_VAR");
println!("{obfuscated}");
```


Running `cargo b` will print out `ENVUSCATE='<SOME_KEY>'` to stderr.

This env will then need to be set at runtime, otherwise the program will panic: `ENVUSCATE='<SOME_KEY>' cargo r`

> You may also set your own key identifiers: `envuscate!(env = "MY_KEY_NAME", "MY_OBFUSCATED_VAR")`
>

### `envuscate_unchecked!()`

The difference between `envuscate!()` and `envuscate_unchecked!()` is that the `envuscate!()` macro
checks that the macro invocation is not evaluated multiple times.
Opt for `envuscate_unchecked!()` if you can uphold this guarantee.

```rust
use envuscate::{envuscate, envuscate_unchecked};

fn f() -> &'static str {
  envuscate!(env, "supersecret1")
}

fn f2() -> &'static str {
  envuscate_unchecked!(env, "MY_OBFUSCATED_VAR")
}

fn f3() -> &'static str {
  envuscate_unchecked!(env, "ANOTHER_ENV_VAR")
}

for _ in 0..2 {
  println!("{}", f()); // <----- fine, since `envuscate!()` provides checks against multiple evaluations
}

for _ in 0..2 {
  println!("{}", f2()); // <---- panics at the second evaluation
}

for _ in 0..2 {
  std::thread::spawn(|| {
    println!("{}", f3()); // <-  panics at the second evaluation
  });
}
```

Alternatively:
```rust
use envuscate::envuscate_unchecked;

// only evaluated once
let plaintext = envuscate_unchecked!("MY_OBFUSCATED_VAR");
for _ in 0..2 {
  println!("{}", plaintext); // <--- fine
}

for _ in 0..2 {
  std::thread::spawn(move || {
    println!("{}", plaintext); // <- also fine
  });
}
```


### Note on obfuscation and encryption

This crate does not provide any form of real encryption. It only makes the task of understanding strings
in your binary more difficult. [Obfuscation is not security](https://cwe.mitre.org/data/definitions/656.html).

This crate also _does not_ obfuscate any debug symbols you may have.
Profile settings such as
```toml
# inside Cargo.toml

[profile]
strip = true
panic = "abort"
# ...
```
and more can be found in the [cargo reference](https://doc.rust-lang.org/cargo/reference/profiles.html).

### Macro expansion

To check what this macro expands to:
- install [cargo expand](https://github.com/dtolnay/cargo-expand)
- run: `cargo expand -p envuscate --example simple`


#### Unstable API

This crate is still very much a work-in-progress. Expect breaking changes between minor
releases.


<!-- cargo-rdme end -->

### Migrating from previous versions

Previous versions of this crate provided obfuscation for static strings. This behavior may be achieved with the current API by using a [`once_cell::Lazy`](https://docs.rs/once_cell/latest/once_cell/sync/struct.Lazy.html):
```
use once_cell::sync::Lazy;
use envuscate::envuscate_unchecked;

static MY_STRING: Lazy<&'static str> = Lazy::new(|| envuscate_unchecked!("MY_OBFUSCATED_VAR"));
```

### Next steps:
- [ ]  check proc macro testing suites

### Disclaimer
This library is developed with the sole intention of providing a tool to challenge and educate cybersecurity professionals. It is not intended for any malicious or unlawful activities. The creators and contributors of this library do not endorse, encourage, or support the use of this tool for any illegal purposes.

### Shoutouts
- thanks to [@orph3usLyre](https://github.com/orph3usLyre/muddy-waters) for `muddy`

### Similar/related projects
- [muddy](https://github.com/orph3usLyre/muddy-waters)
- [cryptify](https://github.com/dronavallipranav/rust-obfuscator/tree/main/cryptify)
- [litcrypt](https://github.com/anvie/litcrypt.rs)
- [include-crypt-bytes](https://github.com/breakpointninja/include-crypt-bytes)
- [obfstr](https://github.com/CasualX/obfstr)
- [Interesting related article by vrls.ws](https://vrls.ws/posts/2023/06/obfuscating-rust-binaries-using-llvm-obfuscator-ollvm/)

### License

Dual-licensed under Apache 2.0 and MIT terms.
