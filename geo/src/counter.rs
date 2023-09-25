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

//! Counter of requests for a period of time.

use iii_iv_core::clocks::Clock;
use std::{sync::Arc, time::Duration};

/// Counts the number of requests over the last minute with second resolution.
pub(crate) struct RequestCounter {
    /// Clock to obtain the current time from.
    clock: Arc<dyn Clock + Send + Sync>,

    /// Tracker of per-second counts within a minute.
    ///
    /// Each pair contains the timestamp of the ith second in the array and
    /// the counter of requests at that second.
    counts: [(i64, u16); 60],
}

impl RequestCounter {
    /// Creates a new request counter backed by `clock`.
    pub(crate) fn new(clock: Arc<dyn Clock + Send + Sync>) -> Self {
        Self { clock, counts: [(0, 0); 60] }
    }

    /// Adds a request to the counter at the current time.
    pub(crate) fn account(&mut self) {
        let now = self.clock.now_utc();
        let i = usize::from(now.second()) % 60;
        let (ts, count) = self.counts[i];
        if ts == now.unix_timestamp() {
            self.counts[i] = (ts, count + 1);
        } else {
            self.counts[i] = (now.unix_timestamp(), 1);
        }
    }

    /// Counts the number of requests during the last minute.
    pub(crate) fn last_minute(&self) -> usize {
        let now = self.clock.now_utc();
        let since = (now - Duration::from_secs(60)).unix_timestamp();

        let mut total = 0;
        for (ts, count) in self.counts {
            if ts > since {
                total += usize::from(count);
            }
        }
        total
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iii_iv_core::clocks::testutils::SettableClock;
    use std::time::Duration;
    use time::macros::datetime;

    #[test]
    fn test_continuous() {
        let clock = Arc::from(SettableClock::new(datetime!(2023-09-26 18:20:15 UTC)));
        let mut counter = RequestCounter::new(clock.clone());

        assert_eq!(0, counter.last_minute());
        for i in 0..60 {
            clock.advance(Duration::from_secs(1));
            counter.account();
            counter.account();
            assert_eq!((i + 1) * 2, counter.last_minute());
        }
        assert_eq!(120, counter.last_minute());
        for i in 0..60 {
            clock.advance(Duration::from_secs(1));
            counter.account();
            assert_eq!(120 - (i + 1), counter.last_minute());
        }
        assert_eq!(60, counter.last_minute());
        for i in 0..60 {
            clock.advance(Duration::from_secs(1));
            assert_eq!(60 - (i + 1), counter.last_minute());
        }
        assert_eq!(0, counter.last_minute());
    }

    #[test]
    fn test_gaps() {
        let clock = Arc::from(SettableClock::new(datetime!(2023-09-26 17:20:56 UTC)));
        let mut counter = RequestCounter::new(clock.clone());

        assert_eq!(0, counter.last_minute());
        for _ in 0..1000 {
            counter.account();
        }
        assert_eq!(1000, counter.last_minute());

        clock.advance(Duration::from_secs(30));
        counter.account();
        assert_eq!(1001, counter.last_minute());

        clock.advance(Duration::from_secs(29));
        counter.account();
        assert_eq!(1002, counter.last_minute());

        clock.advance(Duration::from_secs(1));
        counter.account();
        assert_eq!(3, counter.last_minute());
    }
}
