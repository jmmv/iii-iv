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
use time::OffsetDateTime;
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
    /// either it is new (`runs == 0`) or if it can be retried.  Retryable tasks are those
    /// that asked to be retried or those that can be declared as lost (their `updated`
    /// timestamp is older than the maximum allowed runtime for the task).
    Runnable = 1,

    /// The task completed successfully.  The `reason` will not be present.
    Done = 2,

    /// The task failed and the reason for the failure is in `reason`.
    Failed = 3,

    /// The task was abandoned and the reason for the failure is in `reason`.
    Abandoned = 4,
}

/// Converts a task result into the separate fields to be stored into the database.
pub(super) fn result_to_status(
    result: &TaskResult,
) -> (TaskStatus, Option<&str>, Option<OffsetDateTime>) {
    match result {
        TaskResult::Done(msg) => (TaskStatus::Done, msg.as_deref(), None),
        TaskResult::Failed(e) => (TaskStatus::Failed, Some(e), None),
        TaskResult::Retry(only_after, msg) => (TaskStatus::Runnable, Some(msg), Some(*only_after)),
        TaskResult::Abandoned(e) => (TaskStatus::Abandoned, Some(e), None),
    }
}

/// Parses a status `code`/`reason` pair as extracted from the database into a `TaskResult`.
///
/// If the task is still running, there is no result yet, unless the task has been deferred after
/// a retry, in which case there will be a result.
///
/// The `id` is used for error reporting reasons only.
pub(super) fn status_to_result(
    id: Uuid,
    code: i8,
    reason: Option<String>,
    runs: i16,
    only_after: Option<OffsetDateTime>,
) -> DbResult<Option<TaskResult>> {
    match code {
        x if x == (TaskStatus::Runnable as i8) => match (runs, only_after) {
            (0, _) => Ok(None),
            (runs, Some(only_after)) => match reason {
                Some(reason) => Ok(Some(TaskResult::Retry(only_after, reason))),
                None => Err(DbError::DataIntegrityError(format!(
                    "Task {} is Retry with runs={} but status_reason is missing",
                    id, runs
                ))),
            },
            (_, None) => Ok(None),
        },

        x if x == (TaskStatus::Done as i8) => Ok(Some(TaskResult::Done(reason))),

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
    use time::macros::datetime;

    #[test]
    fn test_result_to_status() {
        assert_eq!((TaskStatus::Done, None, None), result_to_status(&TaskResult::Done(None)));

        assert_eq!(
            (TaskStatus::Done, Some("foo"), None),
            result_to_status(&TaskResult::Done(Some("foo".to_owned())))
        );

        assert_eq!(
            (TaskStatus::Failed, Some("foo"), None),
            result_to_status(&TaskResult::Failed("foo".to_owned()))
        );

        assert_eq!(
            (TaskStatus::Runnable, Some("foo"), Some(datetime!(2023-06-11 6:55 UTC))),
            result_to_status(&TaskResult::Retry(datetime!(2023-06-11 6:55 UTC), "foo".to_owned()))
        );

        assert_eq!(
            (TaskStatus::Abandoned, Some("foo"), None),
            result_to_status(&TaskResult::Abandoned("foo".to_owned()))
        );
    }

    #[test]
    fn test_status_to_result_runnable_is_none() {
        match status_to_result(Uuid::new_v4(), TaskStatus::Runnable as i8, None, 3, None) {
            Ok(None) => (),
            r => panic!("Unexpected result: {:?}", r),
        }

        match status_to_result(
            Uuid::new_v4(),
            TaskStatus::Runnable as i8,
            Some("foo".to_owned()),
            0,
            None,
        ) {
            Ok(None) => (),
            r => panic!("Unexpected result: {:?}", r),
        }
    }

    #[test]
    fn test_status_to_result_runnable_in_the_future_is_none() {
        let now = datetime!(2023-10-19 15:50:00 UTC);

        match status_to_result(Uuid::new_v4(), TaskStatus::Runnable as i8, None, 0, Some(now)) {
            Ok(None) => (),
            r => panic!("Unexpected result: {:?}", r),
        }

        match status_to_result(
            Uuid::new_v4(),
            TaskStatus::Runnable as i8,
            Some("foo".to_owned()),
            0,
            Some(now),
        ) {
            Ok(None) => (),
            r => panic!("Unexpected result: {:?}", r),
        }
    }

    #[test]
    fn test_status_to_result_retry_after_failure() {
        let now = datetime!(2023-10-19 15:50:00 UTC);

        match status_to_result(Uuid::new_v4(), TaskStatus::Runnable as i8, None, 1, Some(now)) {
            Err(DbError::DataIntegrityError(_)) => (),
            r => panic!("Unexpected result: {:?}", r),
        }

        assert_eq!(
            Ok(Some(TaskResult::Retry(now, "foo".to_owned()))),
            status_to_result(
                Uuid::new_v4(),
                TaskStatus::Runnable as i8,
                Some("foo".to_owned()),
                1,
                Some(now),
            )
        );
    }

    #[test]
    fn test_status_to_result_done_may_have_reason() {
        assert_eq!(
            Ok(Some(TaskResult::Done(None))),
            status_to_result(Uuid::new_v4(), TaskStatus::Done as i8, None, 123, None)
        );

        assert_eq!(
            Ok(Some(TaskResult::Done(Some("msg".to_owned())))),
            status_to_result(
                Uuid::new_v4(),
                TaskStatus::Done as i8,
                Some("msg".to_owned()),
                0,
                None
            )
        );
    }

    #[test]
    fn test_status_to_result_failed_must_have_reason() {
        assert_eq!(
            Ok(Some(TaskResult::Failed("msg".to_owned()))),
            status_to_result(
                Uuid::new_v4(),
                TaskStatus::Failed as i8,
                Some("msg".to_owned()),
                0,
                None
            )
        );

        match status_to_result(Uuid::new_v4(), TaskStatus::Failed as i8, None, 1, None) {
            Err(DbError::DataIntegrityError(_)) => (),
            r => panic!("Unexpected result: {:?}", r),
        }
    }

    #[test]
    fn test_status_to_result_abandoned_must_have_reason() {
        assert_eq!(
            Ok(Some(TaskResult::Abandoned("msg".to_owned()))),
            status_to_result(
                Uuid::new_v4(),
                TaskStatus::Abandoned as i8,
                Some("msg".to_owned()),
                1,
                None
            )
        );

        match status_to_result(Uuid::new_v4(), TaskStatus::Abandoned as i8, None, 0, None) {
            Err(DbError::DataIntegrityError(_)) => (),
            r => panic!("Unexpected result: {:?}", r),
        }
    }

    #[test]
    fn test_status_to_result_unknown_code() {
        match status_to_result(Uuid::new_v4(), 123, None, 0, None) {
            Err(DbError::DataIntegrityError(e)) => assert!(e.contains("unknown")),
            r => panic!("Unexpected result: {:?}", r),
        }

        match status_to_result(Uuid::new_v4(), 123, Some("foo".to_owned()), 0, None) {
            Err(DbError::DataIntegrityError(e)) => assert!(e.contains("unknown")),
            r => panic!("Unexpected result: {:?}", r),
        }
    }
}
