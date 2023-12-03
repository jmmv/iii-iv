// III-IV
// Copyright 2023 Julio Merino
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

//! Geolocation API implementation backed by Azure Maps.

use crate::{CountryIsoCode, GeoLocator, GeoResult};
use async_trait::async_trait;
use bytes::Buf;
use derivative::Derivative;
use iii_iv_core::env::get_required_var;
use reqwest::{Client, Response, StatusCode};
use serde::{Deserialize, Serialize};
use std::io;
use std::net::IpAddr;

/// Converts a `reqwest::Error` to an `io::Error`.
fn reqwest_error_to_io_error(e: reqwest::Error) -> io::Error {
    io::Error::new(io::ErrorKind::Other, format!("{}", e))
}

/// Converts a `reqwest::Response` to an `io::Error`.  The response should have a non-OK status.
async fn http_response_to_io_error(response: Response) -> io::Error {
    let status = response.status();

    let kind = match status {
        StatusCode::OK => panic!("Should not have been called on a successful request"),

        // Match against the codes we know the server explicitly hands us.
        StatusCode::BAD_REQUEST => io::ErrorKind::InvalidInput,
        StatusCode::UNAUTHORIZED => io::ErrorKind::PermissionDenied,
        StatusCode::FORBIDDEN => io::ErrorKind::PermissionDenied,
        StatusCode::NOT_FOUND => io::ErrorKind::NotFound,
        StatusCode::INTERNAL_SERVER_ERROR => io::ErrorKind::Other,

        _ => io::ErrorKind::Other,
    };

    match response.text().await {
        Ok(text) => io::Error::new(
            kind,
            format!("HTTP request returned status {} with text '{}'", status, text),
        ),
        Err(e) => io::Error::new(
            kind,
            format!("HTTP request returned status {} and failed to get text due to {}", status, e),
        ),
    }
}

/// Request to the Azure Maps service to geolocate an IP address.
#[derive(Serialize)]
struct LocateRequest<'a> {
    /// Desired format of the response.
    format: &'static str,

    /// Version number of the API in use.
    #[serde(rename = "api-version")]
    api_version: &'static str,

    /// The IP to geolocate.
    ip: String,

    /// The Azure Maps key to use.
    #[serde(rename = "subscription-key")]
    subscription_key: &'a str,
}

/// Country region information as encoded within `LocateResponse`.
#[derive(Deserialize)]
struct CountryRegionResponse {
    /// The ISO country code as returned from the server.  Must be validated and converted into a
    /// `CountryIsoCode` object before use.
    #[serde(rename = "isoCode")]
    iso_code: Option<String>,
}

/// Response from the Azure Maps service on a successful `LocateRequest`.
#[derive(Deserialize)]
struct LocateResponse {
    /// Object containing the country region information.
    #[serde(rename = "countryRegion")]
    country_region: Option<CountryRegionResponse>,

    /// The IP passed in the request.
    #[serde(rename = "ipAddress")]
    ip: String,
}

/// Options to configure an `AzureGeoLocator`.
#[derive(Derivative)]
#[derivative(Debug)]
#[cfg_attr(test, derivative(PartialEq))]
pub struct AzureGeoLocatorOptions {
    /// The API key to use to contact Azure Maps.
    #[derivative(Debug = "ignore")]
    pub key: String,
}

impl AzureGeoLocatorOptions {
    /// Creates a set of options from from environment variables whose name is prefixed with the
    /// given `prefix`.
    ///
    /// This will use variables such as `<prefix>_KEY`.
    pub fn from_env(prefix: &str) -> Result<Self, String> {
        Ok(Self { key: get_required_var::<String>(prefix, "KEY")? })
    }
}

/// Geolocator that uses an Azure Maps account.
#[derive(Clone)]
pub struct AzureGeoLocator {
    /// Azure Maps service key.
    key: String,

    /// Asynchronous HTTP client with which to issue the service requests.
    client: Client,
}

impl AzureGeoLocator {
    /// Creates a new Azure Maps-backed geolocator using `opts` for configuration.
    pub fn new(opts: AzureGeoLocatorOptions) -> Self {
        Self { key: opts.key, client: Client::default() }
    }
}

#[async_trait]
impl GeoLocator for AzureGeoLocator {
    async fn locate(&self, ip: &IpAddr) -> GeoResult<Option<CountryIsoCode>> {
        let request = LocateRequest {
            format: "json",
            api_version: "1.0",
            ip: ip.to_string(),
            subscription_key: &self.key,
        };
        let response = self
            .client
            .get("https://atlas.microsoft.com/geolocation/ip/json")
            .query(&request)
            .send()
            .await
            .map_err(reqwest_error_to_io_error)?;
        match response.status() {
            StatusCode::OK => {
                let bytes = response.bytes().await.map_err(reqwest_error_to_io_error)?;
                let response: LocateResponse = serde_json::from_reader(bytes.reader())?;

                match response.ip.parse::<IpAddr>() {
                    Ok(response_ip) => {
                        if ip != &response_ip {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!(
                                    "Mismatched IP in response: got {} but want {}",
                                    response_ip, ip
                                ),
                            ));
                        }
                    }
                    Err(e) => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("Invalid {} IP in the response: {}", response.ip, e),
                        ))
                    }
                }

                match response.country_region {
                    Some(country_region) => match country_region.iso_code {
                        Some(iso_code) => Ok(Some(CountryIsoCode::new(iso_code)?)),
                        None => Ok(None),
                    },
                    None => Ok(None),
                }
            }
            _ => Err(http_response_to_io_error(response).await),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    pub fn test_azuregeolocatoroptions_from_env_all_present() {
        let overrides = [("AZURE_MAPS_KEY", Some("the-key"))];
        temp_env::with_vars(overrides, || {
            let opts = AzureGeoLocatorOptions::from_env("AZURE_MAPS").unwrap();
            assert_eq!(AzureGeoLocatorOptions { key: "the-key".to_owned() }, opts);
        });
    }

    #[test]
    pub fn test_azuregeolocatoroptions_from_env_use_defaults() {
        let overrides = [("AZURE_MAPS_KEY", Some("the-key"))];
        temp_env::with_vars(overrides, || {
            let opts = AzureGeoLocatorOptions::from_env("AZURE_MAPS").unwrap();
            assert_eq!(AzureGeoLocatorOptions { key: "the-key".to_owned() }, opts);
        });
    }

    #[test]
    pub fn test_azuregeolocatoroptions_from_env_missing() {
        temp_env::with_var_unset("AZURE_MAPS_KEY", || {
            let err = AzureGeoLocatorOptions::from_env("AZURE_MAPS").unwrap_err();
            assert!(err.contains("AZURE_MAPS_KEY not present"));
        });
    }

    fn setup() -> AzureGeoLocator {
        AzureGeoLocator::new(AzureGeoLocatorOptions::from_env("AZURE_MAPS").unwrap())
    }

    /// Performs an Azure geolocation query with retries.
    ///
    /// I've observed that, sometimes, the queries randomly return a 401 Unauthorized error, but we
    /// are passing the key correctly.  Retrying might help under this condition and others.
    async fn geolocate(
        geolocator: &AzureGeoLocator,
        ip: &str,
    ) -> GeoResult<Option<CountryIsoCode>> {
        let ip = ip.parse().unwrap();

        let mut retries = 5;
        loop {
            match geolocator.locate(&ip).await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    if retries == 0 {
                        return Err(e);
                    }
                    retries -= 1;
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }

    #[tokio::test]
    #[ignore = "Requires environment configuration and is expensive"]
    async fn test_ok() {
        let geolocator = setup();
        assert_eq!("ES", geolocate(&geolocator, "212.170.36.79").await.unwrap().unwrap().as_str());
        assert_eq!("IE", geolocate(&geolocator, "185.2.66.42").await.unwrap().unwrap().as_str());
        assert_eq!(
            "US",
            geolocate(&geolocator, "2001:4898:80e8:3c::").await.unwrap().unwrap().as_str()
        );
    }

    #[tokio::test]
    #[ignore = "Requires environment configuration and is expensive"]
    async fn test_missing() {
        let geolocator = setup();
        assert_eq!(None, geolocate(&geolocator, "198.18.0.1").await.unwrap());
    }
}
