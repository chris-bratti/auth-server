use darling::FromDeriveInput;
use encryption_libs::AutoEncryption;
use encryption_libs::EncryptionKey;
use proc_macro::TokenStream;
use proc_macro2::Group;
use quote::{ToTokens, quote};
use syn::parse::Parse;
use syn::{Data, DeriveInput, Fields, Path, parse_macro_input};
use syn::{Meta, token};

struct EncryptedArgs {
    key: syn::Path,
}

impl Parse for EncryptedArgs {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        Ok(Self {
            key: input.parse()?,
        })
    }
}

#[proc_macro_derive(AutoEncryption, attributes(encrypted))]
pub fn auto_encryption(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let struct_name = &input.ident;

    let mut encrypt = Vec::new();
    let mut decrypt = Vec::new();

    // Process fields
    if let syn::Data::Struct(data_struct) = input.data {
        for field in data_struct.fields {
            let field_name = field.ident.unwrap();
            let mut is_encrypted = false;

            for attr in field.attrs {
                if attr.path().is_ident("encrypted") {
                    eprintln!("Path: {:#?} ", attr.path());
                    let args: EncryptedArgs = attr.parse_args().unwrap();
                    // Extract the path as a string for conversion
                    let encryption_key_string = args.key.segments.last().unwrap().ident.to_string();

                    // Convert the string to your `EncryptionKey` enum
                    let encryption_key = EncryptionKey::from(encryption_key_string.clone());

                    eprintln!("Parsed encryption key: {:?}", encryption_key.get());

                    encrypt.push(quote! {
                        encrypted.#field_name = encryption_libs::test_encryption(&self.#field_name); //EncryptionKey::from(#encryption_key_string)
                    });

                    decrypt.push(quote! {
                        decrypted.#field_name = encryption_libs::test_decryption(&self.#field_name);
                    });
                } else {
                    //eprintln!("Found #[skip] attribute on field: {:?}", field.ident);
                }
            }
        }
    }

    // Generate the implementation for the encrypt/decrypt methods
    let expanded = quote! {
        impl AutoEncryption for #struct_name {
            fn encrypt(&self) -> Self {
                let mut encrypted = Self::default();
                #(#encrypt)*
                encrypted
            }

            fn decrypt(&self) -> Self {
                let mut decrypted = Self::default();
                #(#decrypt)*
                decrypted
            }
        }
    };

    TokenStream::from(expanded)
}
