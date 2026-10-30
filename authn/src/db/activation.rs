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

//! Persistence of pending account activation.

use crate::db::get_user_by_id;
use crate::model::{ActivationState, User};
#[cfg(feature = "postgres")]
use iii_iv_core::db::postgres;
#[cfg(any(feature = "sqlite", test))]
use iii_iv_core::db::sqlite;
use iii_iv_core::db::{DbError, DbResult, Executor};
use sqlx::Row;
#[cfg(feature = "postgres")]
use sqlx::postgres::PgRow;
#[cfg(any(feature = "sqlite", test))]
use sqlx::sqlite::SqliteRow;
use uuid::Uuid;

#[cfg(feature = "postgres")]
impl TryFrom<PgRow> for ActivationState {
    type Error = DbError;

    fn try_from(row: PgRow) -> DbResult<Self> {
        let code: i64 = row.try_get("code").map_err(postgres::map_sqlx_error)?;
        Ok(Self { code: code as u64 })
    }
}

#[cfg(any(feature = "sqlite", test))]
impl TryFrom<SqliteRow> for ActivationState {
    type Error = DbError;

    fn try_from(row: SqliteRow) -> DbResult<Self> {
        let code: i64 = row.try_get("code").map_err(sqlite::map_sqlx_error)?;
        Ok(Self { code: code as u64 })
    }
}

/// Reads pending activation state.
pub async fn get_user_activation(
    ex: &mut Executor,
    user_id: Uuid,
) -> DbResult<Option<ActivationState>> {
    match ex {
        #[cfg(feature = "postgres")]
        Executor::Postgres(ex) => {
            let row = sqlx::query("SELECT * FROM activation_state WHERE user_id = $1")
                .bind(user_id)
                .fetch_optional(ex)
                .await
                .map_err(postgres::map_sqlx_error)?;
            row.map(ActivationState::try_from).transpose()
        }

        #[cfg(any(feature = "sqlite", test))]
        Executor::Sqlite(ex) => {
            let row = sqlx::query("SELECT * FROM activation_state WHERE user_id = ?")
                .bind(user_id)
                .fetch_optional(ex)
                .await
                .map_err(sqlite::map_sqlx_error)?;
            row.map(ActivationState::try_from).transpose()
        }

        #[allow(unused)]
        _ => unreachable!(),
    }
}

/// Inserts pending activation, or removes it to mark a user active.
///
/// Returns `DbError::AlreadyExists` if the user already has pending activation.
pub async fn set_user_activation(
    ex: &mut Executor,
    user: User,
    activation: Option<ActivationState>,
) -> DbResult<User> {
    get_user_by_id(ex, user.id).await?;
    match ex {
        #[cfg(feature = "postgres")]
        Executor::Postgres(ex) => match activation {
            None => {
                sqlx::query("DELETE FROM activation_state WHERE user_id = $1")
                    .bind(user.id)
                    .execute(ex)
                    .await
                    .map_err(postgres::map_sqlx_error)?;
            }

            Some(activation) => {
                sqlx::query("INSERT INTO activation_state (user_id, code) VALUES ($1, $2)")
                    .bind(user.id)
                    .bind(activation.code as i64)
                    .execute(ex)
                    .await
                    .map_err(postgres::map_sqlx_error)?;
            }
        },

        #[cfg(any(feature = "sqlite", test))]
        Executor::Sqlite(ex) => match activation {
            None => {
                sqlx::query("DELETE FROM activation_state WHERE user_id = ?")
                    .bind(user.id)
                    .execute(ex)
                    .await
                    .map_err(sqlite::map_sqlx_error)?;
            }

            Some(activation) => {
                sqlx::query("INSERT INTO activation_state (user_id, code) VALUES (?, ?)")
                    .bind(user.id)
                    .bind(activation.code as i64)
                    .execute(ex)
                    .await
                    .map_err(sqlite::map_sqlx_error)?;
            }
        },

        #[allow(unused)]
        _ => unreachable!(),
    }
    get_user_by_id(ex, user.id).await
}
