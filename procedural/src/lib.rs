use proc_macro::TokenStream;
use quote::quote;
use syn::{ItemFn, Result};

// todo: This can probably be removed when we upgrade to tokio 1.13 (we need https://github.com/tokio-rs/tokio/pull/4203)
#[proc_macro_attribute]
pub fn with_big_stack(attr: TokenStream, input: TokenStream) -> TokenStream {
    _with_big_stack(attr, input).unwrap_or_else(|e| e.to_compile_error().into())
}

fn _with_big_stack(_attr: TokenStream, input: TokenStream) -> Result<TokenStream> {
    let ItemFn { attrs, vis, sig, block } = syn::parse(input)?;

    let output = quote! {
        #(#attrs)*
        #vis #sig {
            let child = std::thread::Builder::new().stack_size(8 * 1024 * 1024).spawn(move || -> () {
                #block
            });
            child.unwrap().join().unwrap();
        }
    };

    Ok(output.into())
}
