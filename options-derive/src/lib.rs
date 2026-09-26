// III-IV
// Copyright 2026 Julio Merino
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License.  You may obtain a copy
// of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
// License for the specific language governing permissions and limitations
// under the License.

//! Derive macro implementation for III-IV configuration options.

use proc_macro::TokenStream;
use proc_macro_crate::{FoundCrate, crate_name};
use quote::quote;
use syn::{
    Attribute, Data, DeriveInput, Error, Expr, Fields, GenericArgument, Ident, LitStr,
    PathArguments, Result, Type, parse_macro_input,
};

/// Derives `iii_iv_core::config::Options` for a named struct.
#[proc_macro_derive(Options, attributes(option, options))]
pub fn derive_options(input: TokenStream) -> TokenStream {
    match derive_options_impl(parse_macro_input!(input as DeriveInput)) {
        Ok(tokens) => tokens.into(),
        Err(error) => error.into_compile_error().into(),
    }
}

/// Derives the implementation for `input`.
fn derive_options_impl(input: DeriveInput) -> Result<proc_macro2::TokenStream> {
    let (prefix, constructor) = parse_options(&input.attrs)?;
    let fields = match input.data {
        Data::Struct(data) => match data.fields {
            Fields::Named(fields) => fields.named,
            Fields::Unnamed(_) | Fields::Unit => {
                return Err(Error::new_spanned(
                    input.ident,
                    "Options can only be derived for structs with named fields",
                ));
            }
        },
        Data::Enum(_) | Data::Union(_) => {
            return Err(Error::new_spanned(input.ident, "Options can only be derived for structs"));
        }
    };

    let core = core_crate_path()?;
    let ident = input.ident;
    let mut field_idents = Vec::with_capacity(fields.len());
    let mut values = Vec::with_capacity(fields.len());
    let mut formatters = Vec::with_capacity(fields.len());

    for field in fields {
        let field_ident = field.ident.expect("Named fields have an identifier");
        let default = parse_default(&field.attrs)?;
        let suffix = if prefix.value().is_empty() {
            upper_snake_case(&field_ident)
        } else {
            format!("{}_{}", prefix.value(), upper_snake_case(&field_ident))
        };
        let field_type = field.ty;

        let value = match (option_inner_type(&field_type), default) {
            (Some(_), Some(default)) => {
                let mut error =
                    Error::new_spanned(field_ident, "Option fields cannot declare a default");
                error.combine(Error::new_spanned(default, "Remove this default expression"));
                return Err(error);
            }
            (Some(inner), None) => quote! {
                #core::env::get_optional_var::<#inner>(prefix, #suffix)?
            },
            (None, Some(default)) => quote! {
                #core::env::get_optional_var::<#field_type>(prefix, #suffix)?
                    .unwrap_or(#default)
            },
            (None, None) => quote! {
                #core::env::get_required_var::<#field_type>(prefix, #suffix)?
            },
        };
        field_idents.push(field_ident.clone());
        values.push(value);
        let formatter = if option_inner_type(&field_type).is_some() {
            quote! { #core::env::format_optional_value(&self.#field_ident) }
        } else {
            quote! { Some(#core::env::format_value(&self.#field_ident)) }
        };
        formatters.push(quote! {
            (#core::env::var_name(prefix, #suffix), #formatter)
        });
    }

    let construction = match constructor {
        Some(constructor) => quote! {
            #(let #field_idents = #values;)*
            #constructor(#(#field_idents),*)
        },
        None => quote! { Ok(Self { #(#field_idents: #values),* }) },
    };

    Ok(quote! {
        impl #core::config::Options for #ident {
            fn from_env(prefix: &str) -> ::std::result::Result<Self, String> {
                #construction
            }

            fn format_all(&self, prefix: &str) -> ::std::vec::Vec<(String, Option<String>)> {
                vec![#(#formatters),*]
            }
        }
    })
}

/// Obtains the path to the core crate at the macro call site.
fn core_crate_path() -> Result<proc_macro2::TokenStream> {
    match crate_name("iii-iv-core") {
        Ok(FoundCrate::Itself) => Ok(quote!(crate)),
        Ok(FoundCrate::Name(name)) => {
            let ident = Ident::new(&name, proc_macro2::Span::call_site());
            Ok(quote!(::#ident))
        }
        Err(error) => Err(Error::new(proc_macro2::Span::call_site(), error)),
    }
}

/// Parses the struct-level options.
fn parse_options(attributes: &[Attribute]) -> Result<(LitStr, Option<Expr>)> {
    let mut prefix = None;
    let mut constructor = None;
    for attribute in attributes {
        if !attribute.path().is_ident("options") {
            continue;
        }
        attribute.parse_nested_meta(|meta| {
            if meta.path.is_ident("prefix") {
                if prefix.is_some() {
                    return Err(meta.error("Options prefix was declared more than once"));
                }
                prefix = Some(meta.value()?.parse()?);
            } else if meta.path.is_ident("constructor") {
                if constructor.is_some() {
                    return Err(meta.error("Options constructor was declared more than once"));
                }
                constructor = Some(meta.value()?.parse()?);
            } else {
                return Err(meta.error("Unsupported options attribute"));
            }
            Ok(())
        })?;
    }
    Ok((
        prefix.ok_or_else(|| {
            Error::new(proc_macro2::Span::call_site(), "Missing #[options(prefix = \"…\")]")
        })?,
        constructor,
    ))
}

/// Parses the optional default expression on a field.
fn parse_default(attributes: &[Attribute]) -> Result<Option<Expr>> {
    let mut default = None;
    for attribute in attributes {
        if !attribute.path().is_ident("option") {
            continue;
        }
        attribute.parse_nested_meta(|meta| {
            if !meta.path.is_ident("default") {
                return Err(meta.error("Unsupported option attribute"));
            }
            if default.is_some() {
                return Err(meta.error("Option default was declared more than once"));
            }
            default = Some(meta.value()?.parse()?);
            Ok(())
        })?;
    }
    Ok(default)
}

/// Extracts the inner type of a syntactic `Option<T>`.
fn option_inner_type(ty: &Type) -> Option<&Type> {
    let Type::Path(path) = ty else {
        return None;
    };
    let segment = path.path.segments.last()?;
    if segment.ident != "Option" {
        return None;
    }
    let PathArguments::AngleBracketed(arguments) = &segment.arguments else {
        return None;
    };
    match arguments.args.first()? {
        GenericArgument::Type(ty) => Some(ty),
        _ => None,
    }
}

/// Converts a Rust field identifier into an uppercase environment suffix.
fn upper_snake_case(ident: &Ident) -> String {
    ident.to_string().trim_start_matches("r#").to_ascii_uppercase()
}
