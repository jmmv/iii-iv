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

//! Collection of clock implementations.

use time::OffsetDateTime;

/// Generic definition of a clock.
pub trait Clock {
    /// Returns the current UTC time.
    fn now_utc(&self) -> OffsetDateTime;
}

/// Clock implementation that uses the system clock.
#[derive(Clone, Default)]
pub struct SystemClock {}

impl Clock for SystemClock {
    fn now_utc(&self) -> OffsetDateTime {
        let nanos = OffsetDateTime::now_utc().unix_timestamp_nanos();

        // Truncate the timestamp to microsecond resolution as this is the resolution supported by
        // timestamps in the PostgreSQL database.  We could do this in the database instead, but
        // then we would get some strange behavior throughout the program.  Better be consistent.
        let nanos = nanos / 1000 * 1000;

        OffsetDateTime::from_unix_timestamp_nanos(nanos)
            .expect("nanos must be in range because they come from the current timestamp")
    }
}

/// Test utilities.
#[cfg(feature = "testutils")]
pub mod testutils {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use time::{Date, Month, Time};

    /// A clock that returns a monotonically increasing instant every time it is queried.
    #[derive(Clone)]
    pub struct MonotonicClock {
        /// Current fake time.
        now: Arc<AtomicU64>,
    }

    impl MonotonicClock {
        /// Creates a new clock whose "now" start time is `now`.
        pub fn new(now: u64) -> Self {
            Self { now: Arc::from(AtomicU64::new(now)) }
        }
    }

    impl Clock for MonotonicClock {
        fn now_utc(&self) -> OffsetDateTime {
            let now = self.now.fetch_add(1, Ordering::SeqCst);
            OffsetDateTime::from_unix_timestamp(now as i64).unwrap()
        }
    }

    /// Creates an `OffsetDateTime` with the given values, assuming UTC.
    pub fn utc_datetime(
        year: i32,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
    ) -> OffsetDateTime {
        let month = Month::try_from(month).expect("Hardcoded month must be valid");
        Date::from_calendar_date(year, month, day)
            .expect("Hardcoded dates must be valid")
            .with_time(Time::from_hms(hour, minute, second).expect("Hardcoded times must be valid"))
            .assume_utc()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_monotonicclock() {
            let clock = MonotonicClock::new(123);
            assert_eq!(OffsetDateTime::from_unix_timestamp(123).unwrap(), clock.now_utc());
            assert_eq!(OffsetDateTime::from_unix_timestamp(124).unwrap(), clock.now_utc());
            assert_eq!(OffsetDateTime::from_unix_timestamp(125).unwrap(), clock.now_utc());
        }

        #[test]
        fn test_utc_datetime() {
            let exp = Date::from_calendar_date(2022, Month::January, 18)
                .unwrap()
                .with_time(Time::from_hms(17, 45, 2).unwrap())
                .assume_utc();
            assert_eq!(exp, utc_datetime(2022, 1, 18, 17, 45, 2));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_systemclock_trivial() {
        let clock = SystemClock::default();
        let now1 = clock.now_utc();
        assert!(now1.unix_timestamp_nanos() > 0);
        let now2 = clock.now_utc();
        assert!(now2 >= now1);
    }

    #[test]
    fn test_systemclock_microsecond_resolution() {
        let clock = SystemClock::default();
        let now = clock.now_utc();
        assert!(now.unix_timestamp_nanos() > 0);
        assert_eq!(0, now.nanosecond() % 1000);
    }
}
