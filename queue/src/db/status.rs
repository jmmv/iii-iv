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

//! Conversions between `TaskResult`s and their persisted representation.

use crate::model::TaskResult;
use iii_iv_core::db::{DbError, DbResult};
use uuid::Uuid;

/// Task status as stored in the database.
#[derive(Debug, Eq, PartialEq)]
#[repr(i8)]
pub(super) enum TaskStatus {
    /// The task is either new or running.
    ///
    /// The `runs` field of the task can be used to distinguish between the two statuses.
    ///
    /// Even though a task may be marked as runnable, it should only be attempted to run if
    /// either it is new (`runs == 0`) or if can be declared as lost (its `updated` timestamp
    /// is older than the maximum allowed runtime for the task).
    Runnable = 1,

    /// The task completed successfully.  The `reason` will not be present.
    Done = 2,

    /// The task failed and the reason for the failure is in `reason`.
    Failed = 3,

    /// The task was abandoned and the reason for the failure is in `reason`.
    Abandoned = 4,
}

/// Converts a task result into the status code and reason to be stored into the database.
pub(super) fn result_to_status(result: &TaskResult) -> (TaskStatus, Option<&str>) {
    match result {
        TaskResult::Done => (TaskStatus::Done, None),
        TaskResult::Failed(e) => (TaskStatus::Failed, Some(e)),
        TaskResult::Abandoned(e) => (TaskStatus::Abandoned, Some(e)),
    }
}

/// Parses a status `code`/`reason` pair as extracted from the database into a `TaskResult`.
///
/// If the task is still running, there is no result yet.
///
/// The `id` is used for error reporting reasons only.
pub(super) fn status_to_result(
    id: Uuid,
    code: i8,
    reason: Option<String>,
) -> DbResult<Option<TaskResult>> {
    match code {
        x if x == (TaskStatus::Runnable as i8) => Ok(None),

        x if x == (TaskStatus::Done as i8) => match reason {
            None => Ok(Some(TaskResult::Done)),
            Some(_) => Err(DbError::DataIntegrityError(format!(
                "Task {} is Done but status_reason is not empty",
                id
            ))),
        },

        x if x == (TaskStatus::Failed as i8) => match reason {
            None => Err(DbError::DataIntegrityError(format!(
                "Task {} is Failed but status_reason is missing",
                id
            ))),
            Some(reason) => Ok(Some(TaskResult::Failed(reason))),
        },

        x if x == (TaskStatus::Abandoned as i8) => match reason {
            None => Err(DbError::DataIntegrityError(format!(
                "Task {} is Abandoned but status_reason is missing",
                id
            ))),
            Some(reason) => Ok(Some(TaskResult::Abandoned(reason))),
        },

        x => Err(DbError::DataIntegrityError(format!("Task {} code {} is unknown", id, x))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_result_to_status() {
        assert_eq!((TaskStatus::Done, None), result_to_status(&TaskResult::Done));

        assert_eq!(
            (TaskStatus::Failed, Some("foo")),
            result_to_status(&TaskResult::Failed("foo".to_owned()))
        );

        assert_eq!(
            (TaskStatus::Abandoned, Some("foo")),
            result_to_status(&TaskResult::Abandoned("foo".to_owned()))
        );
    }

    #[test]
    fn test_status_to_result_runnable_is_none() {
        match status_to_result(Uuid::new_v4(), TaskStatus::Runnable as i8, None) {
            Ok(None) => (),
            r => panic!("Unexpected result: {:?}", r),
        }

        match status_to_result(Uuid::new_v4(), TaskStatus::Runnable as i8, Some("foo".to_owned())) {
            Ok(None) => (),
            r => panic!("Unexpected result: {:?}", r),
        }
    }

    #[test]
    fn test_status_to_result_failed_must_have_reason() {
        assert_eq!(
            Ok(Some(TaskResult::Failed("msg".to_owned()))),
            status_to_result(Uuid::new_v4(), TaskStatus::Failed as i8, Some("msg".to_owned()))
        );

        match status_to_result(Uuid::new_v4(), TaskStatus::Failed as i8, None) {
            Err(DbError::DataIntegrityError(_)) => (),
            r => panic!("Unexpected result: {:?}", r),
        }
    }

    #[test]
    fn test_status_to_result_abandoned_must_have_reason() {
        assert_eq!(
            Ok(Some(TaskResult::Abandoned("msg".to_owned()))),
            status_to_result(Uuid::new_v4(), TaskStatus::Abandoned as i8, Some("msg".to_owned()))
        );

        match status_to_result(Uuid::new_v4(), TaskStatus::Abandoned as i8, None) {
            Err(DbError::DataIntegrityError(_)) => (),
            r => panic!("Unexpected result: {:?}", r),
        }
    }

    #[test]
    fn test_status_to_result_unknown_code() {
        match status_to_result(Uuid::new_v4(), 123, None) {
            Err(DbError::DataIntegrityError(e)) => assert!(e.contains("unknown")),
            r => panic!("Unexpected result: {:?}", r),
        }

        match status_to_result(Uuid::new_v4(), 123, Some("foo".to_owned())) {
            Err(DbError::DataIntegrityError(e)) => assert!(e.contains("unknown")),
            r => panic!("Unexpected result: {:?}", r),
        }
    }
}
