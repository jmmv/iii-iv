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
use std::{collections::HashMap, net::IpAddr, sync::Arc};

/// Geolocator that uses an in-memory map of IPs to country codes.
#[derive(Clone)]
pub struct MockGeoLocator {
    /// Mapping of IPs to country codes.
    data: Arc<HashMap<IpAddr, CountryIsoCode>>,
}

impl MockGeoLocator {
    /// Creates a new mock geolocator based on a list of `(ip, code)` pairs.
    pub fn new(raw_data: &[(&'static str, &'static str)]) -> Self {
        let mut data = HashMap::with_capacity(raw_data.len());
        for (ip, code) in raw_data {
            data.insert(
                (*ip).parse::<IpAddr>().expect("Test IPs must be valid"),
                CountryIsoCode::new(*code).expect("Invalid country code"),
            );
        }
        Self { data: Arc::from(data) }
    }
}

#[async_trait]
impl GeoLocator for MockGeoLocator {
    async fn locate(&self, ip: &IpAddr) -> super::GeoResult<Option<CountryIsoCode>> {
        Ok(self.data.get(ip).map(CountryIsoCode::clone))
    }
}
