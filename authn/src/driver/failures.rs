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

//! Policies for persistent authentication failure history.

use crate::model::FailureHistory;
use std::time::Duration;
use time::OffsetDateTime;

/// Progressive delay after repeated failures, reset after a quiet interval.
pub(super) struct ProgressiveBackoff {
    /// Failures required to start blocking.
    pub(super) threshold: u32,

    /// Interval without failures required to reset history.
    pub(super) quiet_window: Duration,

    /// Delay at the threshold.
    pub(super) initial_delay: Duration,

    /// Maximum delay.
    pub(super) max_delay: Duration,
}

impl ProgressiveBackoff {
    /// Records an admitted failure and computes the next block.
    pub(super) fn record(&self, state: &mut FailureHistory, now: OffsetDateTime) {
        if now - state.last_failure >= self.quiet_window {
            state.count = 0;
        }
        state.count = state.count.saturating_add(1);
        state.last_failure = now;

        let threshold = self.threshold.max(1);
        if state.count >= threshold {
            let cap = self.max_delay;
            let mut delay = self.initial_delay.min(cap);
            if !delay.is_zero() {
                for _ in 0..state.count - threshold {
                    delay = delay.saturating_mul(2).min(cap);
                    if delay == cap {
                        break;
                    }
                }
            }
            state.blocked_until = Some(now + delay);
        } else {
            state.blocked_until = None;
        }
    }
}
