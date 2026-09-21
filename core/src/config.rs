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

//! Centralized service configuration.
//!
//! A service registers all of its component configuration types with a [`ConfigBuilder`] and
//! loads them from the environment under a shared service prefix.  The resulting [`Config`]
//! provides type-directed access to every options object:
//!
//! ```
//! use iii_iv_core::config::{Config, Options};
//!
//! struct ServiceOptions;
//!
//! impl Options for ServiceOptions {
//!     fn from_env(_prefix: &str) -> Result<Self, String> {
//!         Ok(Self)
//!     }
//!
//!     fn format_all(&self, prefix: &str) -> Vec<(String, String)> {
//!         vec![(format!("{}_SERVICE_OPTION", prefix), "value".to_owned())]
//!     }
//! }
//!
//! let mut config = Config::builder()
//!     .register::<ServiceOptions>()
//!     .from_env("SERVICE")?;
//! let options = config.take::<ServiceOptions>();
//! # Ok::<(), String>(())
//! ```
//!
//! Services can use [`Config::get`] to inspect options without consuming them or with
//! [`Config::take`] to extract the options.  Configuration should be dumped before components
//! take ownership of their options.

use log::info;
use std::any::{Any, TypeId, type_name};

pub use iii_iv_options_derive::Options;

/// Interface implemented by all component configuration objects.
pub trait Options: Any + Send + Sync {
    /// Creates a new set of options from environment variables for the service named by `prefix`.
    fn from_env(prefix: &str) -> Result<Self, String>
    where
        Self: Sized;

    /// Formats all environment settings that configure this object.
    ///
    /// The returned names must include `prefix` and the values must reflect the effective parsed
    /// configuration, including defaults.
    fn format_all(&self, prefix: &str) -> Vec<(String, String)>;
}

/// A collection of configuration objects loaded for a service.
pub struct Config {
    /// The loaded configuration objects.
    options: Vec<Box<dyn Options>>,

    /// Prefix used to load the configuration objects.
    prefix: String,
}

impl Config {
    /// Creates a builder for a service configuration.
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder { registrations: vec![] }
    }

    /// Dumps all available configuration settings to the log.
    pub fn log(&self) {
        for (name, value) in self.formatted_entries() {
            info!("{}={}", name, value);
        }
    }

    /// Formats all available configuration settings in lexicographical name order.
    fn formatted_entries(&self) -> Vec<(String, String)> {
        let mut entries = self
            .options
            .iter()
            .flat_map(|options| options.format_all(&self.prefix))
            .collect::<Vec<_>>();
        entries.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
        entries
    }

    /// Returns the configuration object of type `T`.
    ///
    /// # Panics
    ///
    /// Panics if `T` is not available because it was not registered or was previously taken.  A
    /// missing value is a programming error because services declare their complete configuration
    /// when constructing the builder.
    pub fn get<T: Options>(&self) -> &T {
        self.options
            .iter()
            .find_map(|options| {
                let options: &dyn Any = options.as_ref();
                options.downcast_ref::<T>()
            })
            .unwrap_or_else(|| panic!("Options type {} is not available", type_name::<T>()))
    }

    /// Removes and returns the configuration object of type `T`.
    ///
    /// # Panics
    ///
    /// Panics if `T` is not available because it was not registered or was previously taken.
    pub fn take<T: Options>(&mut self) -> T {
        let index = self
            .options
            .iter()
            .position(|options| {
                let options: &dyn Any = options.as_ref();
                options.is::<T>()
            })
            .unwrap_or_else(|| panic!("Options type {} is not available", type_name::<T>()));
        let options: Box<dyn Any> = self.options.remove(index);
        match options.downcast::<T>() {
            Ok(options) => *options,
            Err(_) => unreachable!("Type-checked options must downcast"),
        }
    }
}

/// Loads a type-erased configuration object from the environment.
type Loader = fn(&str) -> Result<Box<dyn Options>, String>;

/// A configuration type waiting to be loaded.
struct Registration {
    /// Function that loads the configuration object.
    loader: Loader,

    /// Identifier of the configuration type.
    type_id: TypeId,

    /// Name of the configuration type, for diagnostics.
    type_name: &'static str,
}

/// Builder for a [`Config`].
pub struct ConfigBuilder {
    /// The configuration types to load.
    registrations: Vec<Registration>,
}

impl ConfigBuilder {
    /// Registers configuration type `T` for loading.
    ///
    /// # Panics
    ///
    /// Panics if `T` has already been registered with this builder.
    pub fn register<T: Options>(mut self) -> Self {
        let type_id = TypeId::of::<T>();
        assert!(
            !self.registrations.iter().any(|registration| registration.type_id == type_id),
            "Options type {} was registered more than once",
            type_name::<T>()
        );
        self.registrations.push(Registration {
            loader: |prefix| {
                T::from_env(prefix).map(|options| Box::new(options) as Box<dyn Options>)
            },
            type_id,
            type_name: type_name::<T>(),
        });
        self
    }

    /// Loads all registered configuration objects from environment variables.
    ///
    /// Types are loaded in registration order and loading stops at the first error.
    pub fn from_env(self, prefix: &str) -> Result<Config, String> {
        let mut options = Vec::with_capacity(self.registrations.len());
        for registration in self.registrations {
            let value = (registration.loader)(prefix).map_err(|error| {
                format!("Failed to load options type {}: {}", registration.type_name, error)
            })?;
            options.push(value);
        }
        let config = Config { options, prefix: prefix.to_owned() };
        config.log();
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// Records whether options after a failing registration were loaded.
    static LOADED_AFTER_ERROR: AtomicBool = AtomicBool::new(false);

    /// Records whether a successfully loaded configuration was formatted.
    static FORMATTED: AtomicBool = AtomicBool::new(false);

    /// Records the order in which dummy options are loaded.
    static TRACE: Mutex<Vec<usize>> = Mutex::new(vec![]);

    /// First dummy options type.
    #[derive(Debug, Eq, PartialEq)]
    struct FirstOptions(String);

    impl Options for FirstOptions {
        fn from_env(prefix: &str) -> Result<Self, String> {
            Ok(Self(format!("{}-first", prefix)))
        }

        fn format_all(&self, prefix: &str) -> Vec<(String, String)> {
            FORMATTED.store(true, Ordering::SeqCst);
            vec![(format!("{}_FIRST", prefix), self.0.clone())]
        }
    }

    /// Dummy options type that fails to load.
    struct InvalidOptions;

    impl Options for InvalidOptions {
        fn from_env(prefix: &str) -> Result<Self, String> {
            Err(format!("Invalid {} settings", prefix))
        }

        fn format_all(&self, _prefix: &str) -> Vec<(String, String)> {
            vec![]
        }
    }

    /// Dummy options type used to verify that loading stops at the first error.
    struct NeverOptions;

    impl Options for NeverOptions {
        fn from_env(_prefix: &str) -> Result<Self, String> {
            LOADED_AFTER_ERROR.store(true, Ordering::SeqCst);
            Ok(Self)
        }

        fn format_all(&self, _prefix: &str) -> Vec<(String, String)> {
            vec![]
        }
    }

    /// Dummy options type used to verify loading order.
    struct OrderedOptions<const N: usize>;

    impl<const N: usize> Options for OrderedOptions<N> {
        fn from_env(_prefix: &str) -> Result<Self, String> {
            TRACE.lock().unwrap().push(N);
            Ok(Self)
        }

        fn format_all(&self, _prefix: &str) -> Vec<(String, String)> {
            vec![]
        }
    }

    /// Second dummy options type.
    #[derive(Debug, Eq, PartialEq)]
    struct SecondOptions(String);

    impl Options for SecondOptions {
        fn from_env(prefix: &str) -> Result<Self, String> {
            Ok(Self(format!("{}-second", prefix)))
        }

        fn format_all(&self, prefix: &str) -> Vec<(String, String)> {
            vec![(format!("{}_SECOND", prefix), self.0.clone())]
        }
    }

    #[test]
    fn test_from_env_and_get() {
        let config = Config::builder()
            .register::<FirstOptions>()
            .register::<SecondOptions>()
            .from_env("TEST")
            .unwrap();

        assert_eq!(&FirstOptions("TEST-first".to_owned()), config.get::<FirstOptions>());
        assert_eq!(&SecondOptions("TEST-second".to_owned()), config.get::<SecondOptions>());
    }

    #[test]
    fn test_log_sorts_entries() {
        let config = Config::builder()
            .register::<SecondOptions>()
            .register::<FirstOptions>()
            .from_env("TEST")
            .unwrap();

        assert_eq!(
            vec![
                ("TEST_FIRST".to_owned(), "TEST-first".to_owned()),
                ("TEST_SECOND".to_owned(), "TEST-second".to_owned()),
            ],
            config.formatted_entries()
        );
    }

    #[test]
    fn test_from_env_logs() {
        FORMATTED.store(false, Ordering::SeqCst);

        let _ = Config::builder().register::<FirstOptions>().from_env("TEST").unwrap();

        assert!(FORMATTED.load(Ordering::SeqCst));
    }

    #[test]
    fn test_take() {
        let mut config = Config::builder()
            .register::<FirstOptions>()
            .register::<SecondOptions>()
            .from_env("TEST")
            .unwrap();

        assert_eq!(FirstOptions("TEST-first".to_owned()), config.take::<FirstOptions>());
        assert_eq!(&SecondOptions("TEST-second".to_owned()), config.get::<SecondOptions>());
    }

    #[test]
    fn test_from_env_error() {
        LOADED_AFTER_ERROR.store(false, Ordering::SeqCst);
        let error = Config::builder()
            .register::<InvalidOptions>()
            .register::<NeverOptions>()
            .from_env("TEST")
            .err()
            .unwrap();

        assert_eq!(
            format!(
                "Failed to load options type {}: Invalid TEST settings",
                type_name::<InvalidOptions>()
            ),
            error
        );
        assert!(!LOADED_AFTER_ERROR.load(Ordering::SeqCst));
    }

    #[test]
    fn test_from_env_preserves_registration_order() {
        TRACE.lock().unwrap().clear();

        Config::builder()
            .register::<OrderedOptions<1>>()
            .register::<OrderedOptions<2>>()
            .register::<OrderedOptions<3>>()
            .from_env("TEST")
            .unwrap();

        assert_eq!(&[1, 2, 3], TRACE.lock().unwrap().as_slice());
    }

    #[test]
    #[should_panic(
        expected = "Options type iii_iv_core::config::tests::SecondOptions is not available"
    )]
    fn test_get_missing() {
        Config::builder().from_env("TEST").unwrap().get::<SecondOptions>();
    }

    #[test]
    #[should_panic(
        expected = "Options type iii_iv_core::config::tests::FirstOptions is not available"
    )]
    fn test_take_twice() {
        let mut config = Config::builder().register::<FirstOptions>().from_env("TEST").unwrap();
        let _ = config.take::<FirstOptions>();
        let _ = config.take::<FirstOptions>();
    }

    #[test]
    #[should_panic(
        expected = "Options type iii_iv_core::config::tests::FirstOptions was registered more than once"
    )]
    fn test_register_duplicate() {
        let _ = Config::builder().register::<FirstOptions>().register::<FirstOptions>();
    }
}
