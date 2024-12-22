use encryption_libs::EncryptionKey;
use proc_macro::TokenStream;
use quote::quote;
use syn::parse::Parse;
use syn::{DeriveInput, parse_macro_input};

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

#[proc_macro_derive(Encryptable, attributes(encrypted))]
pub fn encryptable(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let struct_name = &input.ident;

    let mut encrypt_fields = Vec::new();
    let mut decrypt_fields = Vec::new();

    // Process fields
    if let syn::Data::Struct(data_struct) = input.data {
        for field in data_struct.fields {
            let field_name = field.ident.unwrap();

            if let syn::Type::Path(type_path) = &field.ty {
                if type_path.path.segments.last().unwrap().ident == "EncryptableString" {
                    for attr in field.attrs {
                        if attr.path().is_ident("encrypted") {
                            let args: EncryptedArgs = attr.parse_args().unwrap();
                            let encryption_key_string =
                                args.key.segments.last().unwrap().ident.to_string();

                            let encryption_key = EncryptionKey::from(&encryption_key_string);

                            encrypt_fields.push(quote! {
                                if !self.#field_name.encrypted{
                                    self.#field_name.value = encryption_libs::encrypt_string(&self.#field_name.value, #encryption_key).unwrap();
                                    self.#field_name.encrypted = true;
                                }
                            });

                            decrypt_fields.push(quote! {
                                if self.#field_name.encrypted{
                                    self.#field_name.value = encryption_libs::decrypt_string(&self.#field_name.value, #encryption_key).unwrap();
                                    self.#field_name.encrypted = false;
                                }
                            });
                        }
                    }
                }
            }
        }
    }

    let expanded = quote! {
        impl Encryptable for #struct_name {
            fn encrypt(&mut self){
                #(#encrypt_fields)*
            }

            fn decrypt(&mut self){
                #(#decrypt_fields)*
            }
        }
    };

    TokenStream::from(expanded)
}
