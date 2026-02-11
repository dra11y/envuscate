#![forbid(unsafe_code)]
#![warn(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    rustdoc::broken_intra_doc_links,
    missing_docs
)]

//! # `envuscate_macro`
//!
//! This crate provides macros that are reexported by the [envuscate](https://github.com/dra11y/envuscate/tree/main/envuscate) crate and should **not** be used
//! outside the context of that crate.
//!

// TODO: look at https://github.com/dtolnay/proc-macro-workshop
// for crate organization
use chacha20poly1305::{
    AeadCore, ChaCha20Poly1305,
    aead::{Aead, KeyInit, OsRng},
};
use proc_macro::TokenStream;
use proc_macro_error2::proc_macro_error;
use rand::{
    distr::{Alphabetic, Alphanumeric, Distribution, SampleString},
    rng,
};
#[cfg(not(feature = "env"))]
use syn::LitStr;

// frontend (parsing)
#[cfg(feature = "env")]
struct EnvuscateInput {
    env_var_name: syn::LitStr,
    env: Option<String>,
}

#[cfg(feature = "env")]
impl syn::parse::Parse for EnvuscateInput {
    fn parse(input: syn::parse::ParseStream) -> Result<Self, syn::Error> {
        let env = if let Ok(env) = input.parse::<proc_macro2::Ident>() {
            if !env.to_string().eq("env") {
                return Err(syn::Error::new(
                    proc_macro2::Span::call_site(),
                    "only 'env' is a supported envuscate argument",
                ));
            }
            let env = if input.parse::<syn::Token![=]>().is_ok() {
                input.parse::<syn::LitStr>()?.value()
            } else {
                "ENVUSCATE".to_string()
            };
            let _ = input.parse::<syn::Token![,]>()?;
            Some(env)
        } else {
            None
        };
        let env_var_name = input.parse::<syn::LitStr>()?;
        Ok(Self { env_var_name, env })
    }
}

// Decrypter
struct Assignment<T> {
    t: T,
    ident: proc_macro2::Ident,
}

impl<T> Assignment<T> {
    fn new(t: T) -> Self {
        Self {
            t,
            ident: proc_macro2::Ident::new(&gen_snake_case(10), proc_macro2::Span::call_site()),
        }
    }
}

struct InPlaceDecrypter {
    text_len: usize,
    env_var_name: String,
    obfuscated_text: Assignment<Vec<u8>>,
    key: Assignment<chacha20poly1305::Key>,
    nonce: Assignment<chacha20poly1305::Nonce>,
    array_ident: proc_macro2::Ident,
    checked: bool,
    env: Option<String>,
}

fn gen_snake_case(len: usize) -> String {
    let mut rng = rng();

    let first = Alphabetic.sample(&mut rng) as char;
    let rest = Alphanumeric.sample_string(&mut rng, len).to_lowercase();

    format!("{first}_{rest}")
}

#[cfg(not(feature = "env"))]
impl InPlaceDecrypter {
    fn new(env_var_name: LitStr, checked: bool) -> Self {
        use proc_macro_error2::abort;

        let text = std::env::var(env_var_name.value()).unwrap_or_else(|_| {
            abort!(
                env_var_name.span(),
                "environment variable `{env_var_name}` not defined at compile time"
            )
        });
        let text_len = text.len();
        let key = ChaCha20Poly1305::generate_key(&mut OsRng);
        let encryption = ChaCha20Poly1305::new(&key);
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let text = encryption.encrypt(&nonce, text.as_bytes()).unwrap();
        Self {
            text_len,
            env_var_name,
            obfuscated_text: Assignment::new(text),
            key: Assignment::new(key),
            nonce: Assignment::new(nonce),
            array_ident: proc_macro2::Ident::new(
                &gen_snake_case(5).to_uppercase(),
                proc_macro2::Span::call_site(),
            ),
            checked,
            env: None,
        }
    }
}

#[cfg(feature = "env")]
impl InPlaceDecrypter {
    fn new(envuscate_input: EnvuscateInput, checked: bool) -> Self {
        use proc_macro_error2::abort;
        use std::fmt::Write;

        let env_var_name = envuscate_input.env_var_name.value();
        let text = std::env::var(&env_var_name).unwrap_or_else(|_| {
            abort!(
                envuscate_input.env_var_name.span(),
                "environment variable `{env_var_name}` not defined at compile time"
            )
        });
        let text_len = text.len();
        let key = ChaCha20Poly1305::generate_key(&mut OsRng);
        let encryption = ChaCha20Poly1305::new(&key);
        if let Some(env) = &envuscate_input.env {
            let key = key.as_slice().iter().fold(String::new(), |mut out, c| {
                let _ = write!(out, "{c:02X}");
                out
            });
            #[cfg(windows)]
            // language=cmd
            eprintln!(r#"set "{env}={key}""#);
            #[cfg(not(windows))]
            // language=sh
            eprintln!(r"{env}='{key}'");
        }
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let text = encryption.encrypt(&nonce, text.as_bytes()).unwrap();
        Self {
            text_len,
            env_var_name,
            obfuscated_text: Assignment::new(text),
            key: Assignment::new(key),
            nonce: Assignment::new(nonce),
            array_ident: proc_macro2::Ident::new(
                &gen_snake_case(5).to_uppercase(),
                proc_macro2::Span::call_site(),
            ),
            checked,
            env: envuscate_input.env,
        }
    }
}

// backend (codegen)
//
// TODO: use https://doc.rust-lang.org/core/cell/struct.SyncUnsafeCell.html when stable
impl quote::ToTokens for InPlaceDecrypter {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        let env_var_name = &self.env_var_name;
        let key_literal = proc_macro2::Literal::byte_string(&self.key.t);
        let nonce_literal = proc_macro2::Literal::byte_string(&self.nonce.t);
        let encrypted_literal = proc_macro2::Literal::byte_string(&self.obfuscated_text.t);
        let key = &self.key.ident;
        let nonce = &self.nonce.ident;
        let encrypted = &self.obfuscated_text.ident;
        let array_ident = &self.array_ident;
        let len = self.text_len + 16; // overhead for auth tag, not currently used here
        // https://docs.rs/chacha20poly1305/latest/chacha20poly1305/
        let cipher_key_nonce = self.env.as_ref().map_or_else(|| quote::quote! {
                 let #key: [u8; 32] = *#key_literal;
                 let #nonce: [u8; 12] = *#nonce_literal;
                 let mut #encrypted = <::envuscate::chacha20poly1305::ChaCha20Poly1305 as ::envuscate::aead::KeyInit>::new(&#key.into());
             }, |env| quote::quote! {
                 let #nonce: [u8; 12] = *#nonce_literal;
                 let Some(var) = std::env::var_os(#env) else {
                     #[cfg(debug_assertions)]
                     panic!("Need to set `{}` env variable", #env);
                     #[cfg(not(debug_assertions))]
                     panic!();
                 };
                 let Ok(bytes) = <[u8; 32] as ::envuscate::const_hex::FromHex>::from_hex(var.as_encoded_bytes()) else {
                     #[cfg(debug_assertions)]
                     panic!("Can't get bytes from `{}` env variable, secret key needs to be a hex string with 64 symbols length.", #env);
                     #[cfg(not(debug_assertions))]
                     panic!();
                 };

                 let #key = ::envuscate::chacha20poly1305::Key::clone_from_slice(&bytes);
                 let mut #encrypted = <::envuscate::chacha20poly1305::ChaCha20Poly1305 as ::envuscate::aead::KeyInit>::new(&#key);
             });

        let out = if self.checked {
            quote::quote! {
                {
                    {
                        const _: &str = env!(#env_var_name);
                    }

                    #cipher_key_nonce
                    struct Untouchable<T> {
                        cell: ::core::cell::UnsafeCell<T>,
                        decrypted: ::core::sync::atomic::AtomicU8,
                    }
                    /// # Safety
                    /// This type cannot be sent across threads since it's not accessible from
                    /// outside the scope
                    unsafe impl<T> Sync for Untouchable<T> {}
                    static #array_ident: Untouchable<::envuscate::aead::arrayvec::ArrayVec<u8, #len>> = Untouchable {
                        cell: ::core::cell::UnsafeCell::new(::envuscate::aead::arrayvec::ArrayVec::new_const()),
                        decrypted: ::core::sync::atomic::AtomicU8::new(0),
                    };

                    let static_ref: &'static _ = loop {
                      match #array_ident.decrypted.compare_exchange(
                          0,
                          1,
                          ::core::sync::atomic::Ordering::AcqRel,
                          ::core::sync::atomic::Ordering::Acquire,
                      ) {
                          Ok(0) => {
                              let mutable_ref: &'static mut _ = unsafe { &mut *(#array_ident.cell).get() };
                              mutable_ref.extend(*#encrypted_literal);
                              ::envuscate::aead::AeadMutInPlace::decrypt_in_place(
                                  &mut #encrypted,
                                  &#nonce.into(),
                                  b"",
                                  mutable_ref,
                              )
                              .unwrap();
                              #array_ident.decrypted
                                  .store(2, ::core::sync::atomic::Ordering::SeqCst);

                              let static_arr: &'static _ = mutable_ref;
                              break static_arr;
                          }
                          Err(1) => {}
                          Err(2) => {
                              let static_ref: &'static _ = unsafe { &*(#array_ident.cell).get() };
                              break static_ref;
                          }
                          _ => {
                              unreachable!()
                          }
                      }
                    };

                    /// # Safety
                    /// This must be valid utf8 since it was originally valid utf8
                    unsafe { ::core::str::from_utf8_unchecked(static_ref) }
                }
            }
        } else {
            quote::quote! {
                {
                    {
                        const _: &str = env!(#env_var_name);
                    }

                    #cipher_key_nonce
                    struct Untouchable<T>(::core::cell::UnsafeCell<T>);
                    /// # Safety
                    /// This type cannot be sent across threads since it's not accessible from
                    /// outside the scope
                    unsafe impl<T> Sync for Untouchable<T> {}
                    static #array_ident: Untouchable<envuscate::arrayvec::ArrayVec<u8, #len>> = Untouchable(
                        ::core::cell::UnsafeCell::new(::envuscate::aead::arrayvec::ArrayVec::new_const()),
                    );

                    /// # Safety
                    /// There is only ever one mutable reference and it cannot escape the scope
                    let mutable_ref: &'static mut _ = unsafe { &mut *(#array_ident.0).get() };
                    mutable_ref.extend(*#encrypted_literal);

                    ::envuscate::aead::AeadMutInPlace::decrypt_in_place(&mut #encrypted, &#nonce.into(), b"", mutable_ref)
                        .unwrap();

                    let static_ref: &'static _ = mutable_ref;
                    /// # Safety
                    /// This must be valid utf8 since it was originally valid utf8
                    unsafe { ::core::str::from_utf8_unchecked(static_ref) }
                }

            }
        };
        tokens.extend(out);
    }
}

/// Obfuscates an environment variable's value at compile time. The generated code will provide checks against multiple evaluations.
/// Neither the environment variable name nor its value will appear in the binary `strings`.
///
/// # Example
///
/// ```ignore
/// fn f() -> &'static str {
///   envuscate!("MY_OBFUSCATED_VAR")
/// }
///
/// for _ in 0..2 {
///   println!("{}", f());
/// }
/// ```
///
/// This macro also takes in an optional `env` argument, with an optional value.
/// If set, the deobfuscation key must be set at runtime, or the macro invocation
/// will panic.
///
/// # Example
///
/// ```ignore
/// println!("{}", envuscate!(env, "my text")); // will provide the generated deobfuscation key
///                                         // at build time using the default 'envuscate' key:
///                                         // `ENVUSCATE='<SOME_KEY>'`
/// ```
///
/// An alternative env key may be set by the caller:
/// # Example
///
/// ```ignore
/// println!("{}", envuscate!(env = "RUNTIME_KEY", "MY_ENV_VAR")); // will provide the generated deobfuscation key
///                                  // at build time
///                                  // `RUNTIME_KEY='<SOME_KEY>'`
/// ```
///
#[proc_macro]
#[proc_macro_error]
pub fn envuscate(input: TokenStream) -> TokenStream {
    encrypt(input, true)
}

/// Obfuscates an environment variable's value at compile time. The generated code will _NOT_ provide checks against multiple evaluations.
/// Neither the environment variable name nor its value will appear in the binary `strings`.
///
/// # Example
///
/// ```ignore
/// fn f() -> &'static str {
///   envuscate_unchecked!("MY_OBFUSCATED_VAR")
/// }
///
/// let plaintext = f();
///
/// for _ in 0..2 {
///   println!("{}", plaintext);
/// }
/// ```
///
/// This macro also takes in an optional `env` argument, with an optional value.
/// If set, the deobfuscation key must be set at runtime, or the macro invocation
/// will panic.
///
/// # Example
///
/// ```ignore
/// println!("{}", envuscate_unchecked!(env, "MY_OBFUSCATED_VAR")); // will provide the generated deobfuscation key
///                                           // at build time using the default 'envuscate' key:
///                                           // `ENVUSCATE='<SOME_KEY>'`
/// ```
///
/// An alternative env key may be set by the caller:
/// # Example
///
/// ```ignore
/// println!("{}", envuscate_unchecked!(env = "RUNTIME_KEY", "MY_OBFUSCATED_VAR")); // will provide the generated deobfuscation key
///                                               // at build time
///                                               // `RUNTIME_KEY='<SOME_KEY>'`
/// ```
///
#[proc_macro]
#[proc_macro_error]
pub fn envuscate_unchecked(input: TokenStream) -> TokenStream {
    encrypt(input, false)
}

#[cfg(feature = "env")]
fn encrypt(input: TokenStream, checked: bool) -> TokenStream {
    let envuscate_input = syn::parse_macro_input!(input as EnvuscateInput);
    let in_place_dec = InPlaceDecrypter::new(envuscate_input, checked);
    quote::quote! { #in_place_dec }.into()
}

#[cfg(not(feature = "env"))]
fn encrypt(input: TokenStream, checked: bool) -> TokenStream {
    let env_var_name = syn::parse_macro_input!(input as syn::LitStr);
    let in_place_dec = InPlaceDecrypter::new(env_var_name.clone(), checked);
    quote::quote! { #in_place_dec }.into()
}
