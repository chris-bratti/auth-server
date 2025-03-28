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

#[proc_macro_derive(Encryptable, attributes(encrypted, hashed))]
pub fn encryptable(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let struct_name = &input.ident;

    let mut encrypt_fields = Vec::new();
    let mut decrypt_fields = Vec::new();

    // Prepare generics and where clauses for the implementation
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    // Process fields
    if let syn::Data::Struct(data_struct) = input.data {
        for field in data_struct.fields {
            let field_name = field.ident.unwrap();

            if let syn::Type::Path(type_path) = &field.ty {
                if type_path.path.segments.last().unwrap().ident == "String" {
                    for attr in field.attrs {
                        if attr.path().is_ident("hashed") {
                            encrypt_fields.push(quote! {
                                self.#field_name = encryption_libs::hash_field(&self.#field_name).unwrap();
                            });
                        } else if attr.path().is_ident("encrypted") {
                            let args: EncryptedArgs = attr.parse_args().unwrap();
                            let encryption_key_string =
                                args.key.segments.last().unwrap().ident.to_string();

                            let encryption_key = EncryptionKey::from(&encryption_key_string);

                            encrypt_fields.push(quote! {
                                self.#field_name = encryption_libs::encrypt_string(&self.#field_name, #encryption_key).unwrap();
                            });

                            decrypt_fields.push(quote! {
                                self.#field_name = encryption_libs::decrypt_string(&self.#field_name, #encryption_key).unwrap();
                            });
                        }
                    }
                }
            }
        }
    }
    let expanded = quote! {
        impl #impl_generics Encryptable for #struct_name #ty_generics #where_clause {
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
