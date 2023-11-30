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

//! Geolocation API implementation backed by an in-memory map for testing purposes.

use crate::{CountryIsoCode, GeoLocator};
use async_trait::async_trait;
use futures::lock::Mutex;
use std::{collections::HashMap, io, net::IpAddr, sync::Arc};

/// Details of an entry in the mock geolocator.
struct IpData {
    /// The country returned by this entry.
    country: Option<CountryIsoCode>,

    /// The number of times this entry was queried.
    query_count: usize,
}

/// Geolocator that uses an in-memory map of IPs to country codes.
#[derive(Clone)]
pub struct MockGeoLocator {
    /// Mapping of IPs to country codes.
    data: Arc<Mutex<HashMap<IpAddr, IpData>>>,
}

impl MockGeoLocator {
    /// Mock country code that causes this geolocator to return an error for a query.
    pub const RETURN_ERROR: &'static str = "..";

    /// Creates a new mock geolocator based on a list of `(ip, code)` pairs.
    ///
    /// If the `code` in a pair is `RETURN_ERROR`, the query for the `ip` will return an error.
    pub fn new(raw_data: &[(&'static str, &'static str)]) -> Self {
        let mut data = HashMap::with_capacity(raw_data.len());
        for (ip, code) in raw_data {
            data.insert(
                (*ip).parse::<IpAddr>().expect("Test IPs must be valid"),
                IpData {
                    country: Some(CountryIsoCode::new(*code).expect("Invalid country code")),
                    query_count: 0,
                },
            );
        }
        Self { data: Arc::from(Mutex::from(data)) }
    }

    /// Returns the number of times the geolocation data was queried for `ip`.
    pub async fn query_count(&self, ip: &IpAddr) -> usize {
        let data = self.data.lock().await;
        data.get(ip).map(|e| e.query_count).unwrap_or(0)
    }
}

#[async_trait]
impl GeoLocator for MockGeoLocator {
    async fn locate(&self, ip: &IpAddr) -> super::GeoResult<Option<CountryIsoCode>> {
        let mut data = self.data.lock().await;

        data.entry(*ip)
            .and_modify(|e| e.query_count += 1)
            .or_insert(IpData { country: None, query_count: 1 });

        let country = data.get(ip).expect("Must be present").country.as_ref();
        if let Some(country) = country {
            if country.as_str() == Self::RETURN_ERROR {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "This query is supposed to return an error",
                ));
            }
        }
        Ok(country.map(CountryIsoCode::clone))
    }
}
