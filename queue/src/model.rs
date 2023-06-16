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

//! Generic data types for the queue.
//!
//! State transitions for a task are represented as different types, each with the minimal
//! set of data required to represent the state.  There is no single type that represents
//! the full state of a task as stored in the database because such a type is unnecessary
//! at runtime and introduces the possibility of invalid in-memory states.
//!
//! A consequence of the above is that certain properties of a task that are stored in the
//! database are not accessible from the data model.  For example: the creation time of a
//! task is required only to enqueue a task into the queue and it is useful to keep this
//! detail in the database for troubleshooting purposes---but the consumers of the task
//! have no need for this information.
//!
//! Task execution is decoupled from task representation.  The queue only cares about the
//! ability to serialize and deserialize task definitions, and it must be possible for the
//! clients of the queue to enqueue tasks without knowing how to execute them.  This poses
//! difficulties in mutating in-process state from the tasks, but that's very much
//! intentional because it should not be done.

#[cfg(test)]
use derivative::Derivative;
use iii_iv_core::{db::DbError, driver::DriverError};
use serde_json::Result as SerdeJsonResult;
use std::time::Duration;
use time::OffsetDateTime;
use uuid::Uuid;

/// Describes the completion state of the task.
#[derive(Debug)]
#[cfg_attr(any(test, feature = "testutils"), derive(Clone, Eq, PartialEq))]
pub enum TaskResult {
    /// The task successfully completed execution.
    Done(Option<String>),

    /// The task finished processing but it failed with the given reason.
    Failed(String),

    /// The task asked to be retried at the specified time.
    Retry(OffsetDateTime, String),

    /// The task failed to run after a configurable amount of max runs, so it is now abandoned
    /// (quarantined).  The associated string contains details on the reason for abandonment.
    Abandoned(String),
}

/// Error type returned by the closure used to run tasks.
pub enum ExecError {
    /// Indicates that the task has failed in a controlled manner.
    Failed(String),

    /// Indicates that the task wants to rerun after the specified delay.
    RetryAfterDelay(Duration, String),

    /// Indicates that the task wants to rerun at the specified time.
    RetryAfterTimestamp(OffsetDateTime, String),

    /// Simulates that the task has caused the worker to crash.
    //
    // TODO(jmmv): It would be nice to trigger an actual crash via a `panic`, but it's not
    // easy to make the code panic-safe and I'm not sure what kind of restrictions that would
    // impose on the execution logic.
    #[cfg(test)]
    SimulatedCrash,
}

impl From<DbError> for ExecError {
    fn from(value: DbError) -> Self {
        // In the common case, the closure used to run tasks lives in the driver layer and
        // thus deals with errors of type `DriverError`.  But given that all we will do with
        // the error is persist it in the database as a string, we can perform this flattening
        // here and forget about different types.
        ExecError::Failed(value.to_string())
    }
}

impl From<DriverError> for ExecError {
    fn from(value: DriverError) -> Self {
        // In the common case, the closure used to run tasks lives in the driver layer and
        // thus deals with errors of type `DriverError`.  But given that all we will do with
        // the error is persist it in the database as a string, we can perform this flattening
        // here and forget about different types.
        ExecError::Failed(value.to_string())
    }
}

/// Result type returned by the closue used to run tasks.
pub type ExecResult = Result<Option<String>, ExecError>;

/// A runnable task.
///
/// Runnable tasks are those that have never started running or that may have started running
/// in the past but whose worker died prior task completion.
///
/// To distinguish the two cases above, and to prevent a bad task from poisoning execution
/// perpetually, tasks have a `runs` counter that specify how many times they have been
/// attempted.
#[cfg_attr(test, derive(Derivative))]
#[cfg_attr(test, derivative(Debug, PartialEq))]
pub struct RunnableTask<T: Send + Sync> {
    /// Unique identifier of the task.
    id: Uuid,

    /// Task description as extracted from the database.
    #[cfg_attr(test, derivative(PartialEq(compare_with = "crate::model::cmp_json_task")))]
    json_task: SerdeJsonResult<T>,

    /// Number of times the task started to run.
    runs: u8,
}

impl<T: Send + Sync> RunnableTask<T> {
    /// Creates a new runnable task as extracted from the database.
    pub(crate) fn new(id: Uuid, json_task: SerdeJsonResult<T>, runs: u8) -> Self {
        Self { id, json_task, runs }
    }

    /// Returns the unique identifier for the task.
    pub(crate) fn id(&self) -> Uuid {
        self.id
    }

    /// Transitions the task into the running state.
    ///
    /// This must be called only after the task has been marked as running in the database,
    /// and the `runs` counter in the database must be updated to account for this new run.
    pub(crate) fn try_run(self) -> RunningTask<T> {
        RunningTask { id: self.id, json_task: self.json_task, runs: self.runs + 1 }
    }

    /// Extracts the deserialized task in order to inspect it.
    #[cfg(feature = "testutils")]
    pub fn into_json_task(self) -> SerdeJsonResult<T> {
        self.json_task
    }
}

/// A running task.
///
/// This type provides access to the task description and the ability to apply an execution
/// function to produce a task result.
#[cfg_attr(test, derive(Derivative))]
#[cfg_attr(test, derivative(Debug, PartialEq))]
pub struct RunningTask<T: Send + Sync> {
    /// Unique identifier of the task.
    id: Uuid,

    /// Task description as extracted from the database.
    #[cfg_attr(test, derivative(PartialEq(compare_with = "crate::model::cmp_json_task")))]
    json_task: SerdeJsonResult<T>,

    /// Number of times the task started to run.
    runs: u8,
}

impl<T: Send + Sync> RunningTask<T> {
    /// Returns the unique identifier for the task.
    pub(crate) fn id(&self) -> Uuid {
        self.id
    }

    /// Returns the number of times the task started to run, including this execution attempt.
    pub(crate) fn runs(&self) -> u8 {
        self.runs
    }

    /// Extracts the deserialized task in order to run it.
    pub(crate) fn into_json_task(self) -> SerdeJsonResult<T> {
        self.json_task
    }
}

/// Compares two JSON task deserialization results for testing purposes only.
#[cfg(test)]
fn cmp_json_task<T: PartialEq>(lhs: &SerdeJsonResult<T>, rhs: &SerdeJsonResult<T>) -> bool {
    let lhs = lhs.as_ref().map_err(|e| e.to_string());
    let rhs = rhs.as_ref().map_err(|e| e.to_string());
    lhs == rhs
}
