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

//! Geolocation API implementation backed by IP-API.

use crate::counter::RequestCounter;
use crate::{CountryIsoCode, GeoLocator, GeoResult};
use async_trait::async_trait;
use bytes::Buf;
use futures::lock::Mutex;
use iii_iv_core::clocks::Clock;
use log::warn;
use reqwest::{Client, Response, StatusCode};
use serde::Deserialize;
use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;

/// Delay until retrying queries when we receive a 429 response.
const BACKOFF_SECS: u64 = 30;

/// Maximum number of requests per minute allowed at the free tier.
const MAX_REQUESTS_PER_MINUTE: usize = 45;

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

        // Special status code handling when exceeding the default free quota.
        StatusCode::TOO_MANY_REQUESTS => io::ErrorKind::ConnectionRefused,

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

/// Response from the IP-API service on a successful request.
#[derive(Deserialize)]
struct QueryResponse {
    /// Whether the query succeeded (`success`) or failed (`fail`).
    status: String,

    /// Error message when the status is `fail`.
    message: Option<String>,

    /// Country code when the status is `success`.
    #[serde(rename = "countryCode")]
    country_code: Option<String>,
}

/// Geolocator that uses an IP-API account in the free tier.
///
/// Because the free tier has per-minute limits, this geolocator requires backing by another
/// geolocator to which delegate requests when the limits are reached.
#[derive(Clone)]
pub struct FreeIpApiGeoLocator<G> {
    /// Asynchronous HTTP client with which to issue the service requests.
    client: Client,

    /// The clock used to query the current time.
    clock: Arc<dyn Clock + Send + Sync>,

    /// The time to wait until issuing more requests, in case we are backing off.
    backoff_until: Arc<Mutex<OffsetDateTime>>,

    /// The number of requests in the current minute.
    counter: Arc<Mutex<RequestCounter>>,

    /// The geolocator to delegate to when we have detected overload.
    delegee: G,
}

impl<G> FreeIpApiGeoLocator<G> {
    /// Creates a new IP-API-backed geolocator using `opts` for configuration.
    pub fn new(clock: Arc<dyn Clock + Send + Sync>, delegee: G) -> Self {
        Self {
            client: Client::default(),
            clock: clock.clone(),
            backoff_until: Arc::from(Mutex::from(OffsetDateTime::UNIX_EPOCH)),
            counter: Arc::from(Mutex::from(RequestCounter::new(clock))),
            delegee,
        }
    }

    /// Helper function to `locate` that issues a direct query against the backend, without
    /// controlling for quota limits.
    async fn locate_raw(&self, ip: &IpAddr) -> GeoResult<Option<CountryIsoCode>> {
        let request = format!("http://ip-api.com/json/{}?fields=status,message,countryCode", ip);

        let response = self.client.get(&request).send().await.map_err(reqwest_error_to_io_error)?;
        match response.status() {
            StatusCode::OK => {
                let bytes = response.bytes().await.map_err(reqwest_error_to_io_error)?;
                let response: QueryResponse = serde_json::from_reader(bytes.reader())?;

                match response.status.as_ref() {
                    "success" => match response.country_code {
                        Some(country_code) => Ok(Some(CountryIsoCode::new(country_code)?)),
                        None => Ok(None),
                    },

                    "fail" => match response.message.as_deref() {
                        Some("private range") | Some("reserved range") => Ok(None),
                        message => Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "Query {} returned failure: {}",
                                request,
                                message.unwrap_or("No message")
                            ),
                        )),
                    },

                    status => Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "Query {} returned invalid status {}: {}",
                            request,
                            status,
                            response.message.as_deref().unwrap_or("No message")
                        ),
                    )),
                }
            }
            _ => Err(http_response_to_io_error(response).await),
        }
    }
}

#[async_trait]
impl<G> GeoLocator for FreeIpApiGeoLocator<G>
where
    G: GeoLocator + Send + Sync,
{
    async fn locate(&self, ip: &IpAddr) -> GeoResult<Option<CountryIsoCode>> {
        {
            let now = self.clock.now_utc();

            let mut backoff_until = self.backoff_until.lock().await;
            if *backoff_until < now {
                let mut counter = self.counter.lock().await;
                if counter.last_minute() < MAX_REQUESTS_PER_MINUTE {
                    counter.account();

                    match self.locate_raw(ip).await {
                        Ok(result) => return Ok(result),
                        Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {
                            warn!("IP-API returned 429; falling back to delegee");
                            *backoff_until = now + Duration::from_secs(BACKOFF_SECS);
                        }
                        Err(e) => return Err(e),
                    }
                } else {
                    warn!("Out of quota; falling back to delegee");
                }
            }
        }

        self.delegee.locate(ip).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MockGeoLocator;
    use iii_iv_core::clocks::testutils::SettableClock;
    use time::macros::datetime;

    const IP_IN_ES: &str = "212.170.36.79";
    const IP_IN_IE: &str = "185.2.66.42";
    const IP_IN_US: &str = "2001:4898:80e8:3c::";
    const FAKE_DATA: &[(&str, &str)] = &[(IP_IN_ES, "XX"), (IP_IN_IE, "XX"), (IP_IN_US, "XX")];

    #[tokio::test]
    #[ignore = "Talks to an external service"]
    async fn test_ok() {
        let clock = Arc::from(SettableClock::new(datetime!(2023-09-23 22:00:00 UTC)));
        let geolocator = FreeIpApiGeoLocator::new(clock, MockGeoLocator::new(FAKE_DATA));
        assert_eq!(
            "ES",
            geolocator.locate(&IP_IN_ES.parse().unwrap()).await.unwrap().unwrap().as_str()
        );
        assert_eq!(
            "IE",
            geolocator.locate(&IP_IN_IE.parse().unwrap()).await.unwrap().unwrap().as_str()
        );
        assert_eq!(
            "US",
            geolocator.locate(&IP_IN_US.parse().unwrap()).await.unwrap().unwrap().as_str()
        );
    }

    #[tokio::test]
    #[ignore = "Talks to an external service"]
    async fn test_backoff_by_counter() {
        let clock = Arc::from(SettableClock::new(datetime!(2023-09-23 22:00:00 UTC)));
        let geolocator = FreeIpApiGeoLocator::new(clock.clone(), MockGeoLocator::new(FAKE_DATA));
        {
            let mut counter = geolocator.counter.lock().await;
            for _ in 0..MAX_REQUESTS_PER_MINUTE {
                counter.account();
            }
        }
        assert_eq!(
            "XX",
            geolocator.locate(&IP_IN_ES.parse().unwrap()).await.unwrap().unwrap().as_str()
        );

        clock.advance(Duration::from_secs(50));
        assert_eq!(
            "XX",
            geolocator.locate(&IP_IN_ES.parse().unwrap()).await.unwrap().unwrap().as_str()
        );

        clock.advance(Duration::from_secs(10));
        assert_eq!(
            "ES",
            geolocator.locate(&IP_IN_ES.parse().unwrap()).await.unwrap().unwrap().as_str()
        );
    }

    #[tokio::test]
    #[ignore = "Talks to an external service"]
    async fn test_missing() {
        let clock = Arc::from(SettableClock::new(datetime!(2023-09-23 22:00:00 UTC)));
        let geolocator = FreeIpApiGeoLocator::new(clock, MockGeoLocator::new(FAKE_DATA));
        assert_eq!(None, geolocator.locate(&"198.18.0.1".parse().unwrap()).await.unwrap());
    }
}
