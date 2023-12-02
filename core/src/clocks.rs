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

use async_trait::async_trait;
use std::time::Duration;
use time::OffsetDateTime;

/// Generic definition of a clock.
#[async_trait]
pub trait Clock {
    /// Returns the current UTC time.
    fn now_utc(&self) -> OffsetDateTime;

    /// Pauses execution of the current task for `duration`.
    async fn sleep(&self, duration: Duration);
}

/// Clock implementation that uses the system clock.
#[derive(Clone, Default)]
pub struct SystemClock {}

#[async_trait]
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

    async fn sleep(&self, duration: Duration) {
        tokio::time::sleep(duration).await
    }
}

/// Test utilities.
#[cfg(feature = "testutils")]
pub mod testutils {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    /// A clock that returns a preconfigured instant and that can be modified at will.
    ///
    /// Only supports microsecond-level precision.
    pub struct SettableClock {
        /// Current fake time in microseconds.
        now_us: AtomicU64,
    }

    impl SettableClock {
        /// Creates a new clock that returns `now` until reconfigured with `set`.
        pub fn new(now: OffsetDateTime) -> Self {
            let now_ns = now.unix_timestamp_nanos();
            assert!(now_ns % 1000 == 0, "Nanosecond precision not supported");
            let now_us = u64::try_from(now_ns / 1000).unwrap();
            Self { now_us: AtomicU64::new(now_us) }
        }

        /// Sets the new value of `now` that the clock returns.
        pub fn set(&self, now: OffsetDateTime) {
            let now_ns = now.unix_timestamp_nanos();
            assert!(now_ns % 1000 == 0, "Nanosecond precision not supported");
            let now_us = u64::try_from(now_ns / 1000).unwrap();
            self.now_us.store(now_us, Ordering::SeqCst);
        }

        /// Advances the current time by `delta`.
        pub fn advance(&self, delta: Duration) {
            let delta_ns = delta.as_nanos();
            assert!(delta_ns % 1000 == 0, "Nanosecond precision not supported");
            let delta_us = u64::try_from(delta_ns / 1000).unwrap();
            self.now_us.fetch_add(delta_us, Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl Clock for SettableClock {
        fn now_utc(&self) -> OffsetDateTime {
            let now_us = self.now_us.load(Ordering::SeqCst);
            OffsetDateTime::from_unix_timestamp_nanos(now_us as i128 * 1000).unwrap()
        }

        async fn sleep(&self, duration: Duration) {
            self.advance(duration);
            tokio::task::yield_now().await;
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::panic::catch_unwind;
        use time::macros::datetime;

        #[test]
        fn test_settableclock_microsecond_precision_supported() {
            let now = datetime!(2023-12-01 10:15:00.123456 UTC);
            let clock = SettableClock::new(now);
            assert_eq!(now, clock.now_utc());

            let now = datetime!(2023-12-01 10:15:00.987654 UTC);
            clock.set(now);
            assert_eq!(now, clock.now_utc());

            let now = datetime!(2023-12-01 10:15:00.987655 UTC);
            clock.advance(Duration::from_nanos(1000));
            assert_eq!(now, clock.now_utc());
        }

        #[test]
        fn test_settableclock_nanosecond_precision_unsupported() {
            catch_unwind(|| {
                SettableClock::new(datetime!(2023-12-01 10:20:00.123456001 UTC));
            })
            .unwrap_err();

            let clock = SettableClock::new(datetime!(2023-12-01 10:20:00 UTC));
            catch_unwind(|| {
                clock.set(datetime!(2023-12-01 10:20:00.123456001 UTC));
            })
            .unwrap_err();

            catch_unwind(|| {
                clock.advance(Duration::from_nanos(1));
            })
            .unwrap_err();
        }

        #[tokio::test]
        async fn test_settableclock_sleep_advances_time() {
            let clock = SettableClock::new(datetime!(2023-12-01 10:40:00 UTC));
            // Sleep for an unreasonable period to ensure we don't block for long.
            clock.sleep(Duration::from_secs(3600)).await;
            assert_eq!(datetime!(2023-12-01 11:40:00 UTC), clock.now_utc());
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
