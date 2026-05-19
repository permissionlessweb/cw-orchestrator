#![recursion_limit = "128"]

extern crate proc_macro;

use proc_macro::TokenStream;

use quote::quote;

use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::token::Comma;
use syn::{parse_macro_input, Expr, Fields, GenericArgument, Item, Path, Token};

mod kw {
    syn::custom_keyword!(id);
    syn::custom_keyword!(vk_dir);
    syn::custom_keyword!(artifacts_dir);
    syn::custom_keyword!(circuit_keys_dir);
}

/// Parsed input for the `circuit_interface` macro.
///
/// # Syntax
/// ```ignore
/// #[circuit_interface(id = "headstash", vk_dir = "circuit_keys", artifacts_dir = "artifacts")]
/// pub struct HeadstashCircuit;
/// ```
struct CircuitInterfaceInput {
    /// Required: circuit identifier used for contract_id and file lookup
    circuit_id: Expr,
    /// Optional: directory for VK combined binaries (default: "circuit_keys")
    vk_dir: Option<Expr>,
    /// Optional: directory for circuit binaries (default: "artifacts")
    artifacts_dir: Option<Expr>,
}
impl Parse for CircuitInterfaceInput {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut circuit_id: Option<Expr> = None;
        let mut vk_dir: Option<Expr> = None;
        let mut artifacts_dir: Option<Expr> = None;

        // Parse comma-separated key=value pairs
        while !input.is_empty() {
            // Look ahead for which keyword
            if input.peek(kw::id) {
                let _: kw::id = input.parse()?;
                let _: Token![=] = input.parse()?;
                circuit_id = Some(input.parse()?);
            } else if input.peek(kw::vk_dir) {
                let _: kw::vk_dir = input.parse()?;
                let _: Token![=] = input.parse()?;
                vk_dir = Some(input.parse()?);
            } else if input.peek(kw::artifacts_dir) {
                let _: kw::artifacts_dir = input.parse()?;
                let _: Token![=] = input.parse()?;
                artifacts_dir = Some(input.parse()?);
            } else {
                return Err(syn::Error::new(
                    input.span(),
                    "expected `id`, `vk_dir`, or `artifacts_dir`",
                ));
            }

            // Optional trailing comma
            let _: Option<Token![,]> = input.parse().ok();
        }

        let circuit_id = circuit_id.ok_or_else(|| {
            syn::Error::new(
                input.span(),
                "circuit_interface requires `id = \"circuit_name\"`",
            )
        })?;

        Ok(Self {
            circuit_id,
            vk_dir,
            artifacts_dir,
        })
    }
}

// Gets the generics associated with a type
fn get_generics_from_path(p: &Path) -> Punctuated<GenericArgument, Comma> {
    let mut generics = Punctuated::new();

    for segment in p.segments.clone() {
        if let syn::PathArguments::AngleBracketed(generic_args) = &segment.arguments {
            for arg in generic_args.args.clone() {
                generics.push(arg);
            }
        }
    }

    generics
}

#[proc_macro_attribute]
pub fn circuit_interface(attrs: TokenStream, input: TokenStream) -> TokenStream {
    let mut item = parse_macro_input!(input as syn::Item);

    let attributes = parse_macro_input!(attrs as CircuitInterfaceInput);

    let Item::Struct(circuit_struct) = &mut item else {
        panic!("circuit_interface only works on structs");
    };
    let Fields::Unit = &mut circuit_struct.fields else {
        panic!("circuit_interface requires a unit struct (no fields)");
    };

    let name = circuit_struct.ident.clone();
    let circuit_id = &attributes.circuit_id;

    // Determine directory paths — allow customization
    let artifacts_dir_expr = attributes
        .artifacts_dir
        .map(|expr| quote!(#expr))
        .unwrap_or(quote!("artifacts"));

    let vk_dir_expr = attributes
        .vk_dir
        .map(|expr| quote!(#expr))
        .unwrap_or(quote!("circuit_keys"));

    let struct_def = quote!(
        #[cfg(not(target_arch = "wasm32"))]
        #[derive(::std::clone::Clone)]
        pub struct #name<Chain>(::cw_orch::core::contract::circuits::Circuit<Chain>);

        #[cfg(target_arch = "wasm32")]
        #[derive(::std::clone::Clone)]
        pub struct #name;

        #[cfg(not(target_arch = "wasm32"))]
        impl<Chain> #name<Chain> {
            /// Constructor for the circuit interface.
            /// Uses the circuit ID as the contract identifier.
            pub fn new(chain: Chain) -> Self {
            Self(::cw_orch::core::contract::circuits::Circuit::new(#circuit_id, chain))
            }
        }



        // ─── CircuitUploadable ─────────────────────────────────────────────────
        // VK + circuit binary resolution. No .wasm extension enforcement.

        #[cfg(not(target_arch = "wasm32"))]
        impl<Chain: ::cw_orch::core::environment::ChainState>
            ::cw_orch::core::contract::circuits::circuit_interface_traits::CircuitUploadable
            for #name<Chain>
        {
            fn circuit_name() -> ::std::string::String {
                #circuit_id.to_string()
            }

            fn circuit_path(
                _chain: &::cw_orch::core::environment::ChainInfoOwned,
            ) -> ::std::path::PathBuf {
                let mut path = ::std::path::PathBuf::from(#artifacts_dir_expr);
                path.push(Self::circuit_name());
                path     
            }

            fn circuit_bytes(
                chain: &::cw_orch::core::environment::ChainInfoOwned,
            ) -> ::std::vec::Vec<u8> {
                let path = Self::circuit_path(chain);
                ::std::fs::read(&path).unwrap_or_else(|e| {
                    panic!(
                        "Failed to read circuit binary at path {}: {}",
                        path.to_string_lossy(),
                        e
                    )
                })
            }

            fn vk_combined_path(
                _chain: &::cw_orch::core::environment::ChainInfoOwned,
            ) -> ::std::path::PathBuf {
                let mut path = ::std::path::PathBuf::from(#vk_dir_expr);
                path.push(Self::circuit_name());
                path.push("vk_combined.bin");
                path
            }

           fn vk_combined_bytes(
                chain: &::cw_orch::core::environment::ChainInfoOwned,
            ) -> ::std::vec::Vec<u8> {
                let path = Self::vk_combined_path(chain);
                ::std::fs::read(&path).unwrap_or_else(|e| {
                    panic!(
                        "Failed to read VK combined binary at path {}: {}",
                        path.to_string_lossy(),
                        e
                    )
                })
            }
        }

        // ─── CircuitInstance ───────────────────────────────────────────────────
        // Required by CwOrchCircuitUpload
        #[cfg(not(target_arch = "wasm32"))]
        impl<Chain: ::cw_orch::core::environment::ChainState>
            ::cw_orch::prelude::CircuitInstance<Chain>
            for #name<Chain>
        {
            fn as_circuit(&self) -> &::cw_orch::core::contract::circuits::Circuit<Chain> {
                &self.0
            }

            fn as_circuit_mut(&mut self) -> &mut ::cw_orch::core::contract::circuits::Circuit<Chain> {
                &mut self.0
            }
        }
        // ─── CwOrchCircuitUpload ───────────────────────────────────────────────
        // Auto-implement so `.upload_circuit()` works in Deploy
        #[cfg(not(target_arch = "wasm32"))]
        impl<Chain> ::cw_orch::prelude::CwOrchCircuitUpload<Chain>
            for #name<Chain>
        where
            Chain: ::cw_orch::core::environment::CwEnv + ::cw_orch::environment::ZkCwEnv,
        {
            fn upload_circuit(
                &self,
            ) -> ::std::result::Result<
                <Chain as ::cw_orch::core::environment::TxHandler>::Response,
                ::cw_orch::core::CwEnvError,
            > {
                self.0.upload_circuit(self)
            }
        }
    );

    struct_def.into()
}
