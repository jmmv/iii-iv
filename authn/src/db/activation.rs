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
use crate::model::User;
#[cfg(feature = "postgres")]
use iii_iv_core::db::postgres;
#[cfg(any(feature = "sqlite", test))]
use iii_iv_core::db::sqlite;
use iii_iv_core::db::{DbResult, Executor};
use uuid::Uuid;

/// Reads the code for a pending activation.
pub async fn get_user_activation_code(ex: &mut Executor, user_id: Uuid) -> DbResult<Option<u64>> {
    let code: Option<i64> = match ex {
        #[cfg(feature = "postgres")]
        Executor::Postgres(ex) => {
            sqlx::query_scalar("SELECT code FROM activation_state WHERE user_id = $1")
                .bind(user_id)
                .fetch_optional(ex)
                .await
                .map_err(postgres::map_sqlx_error)?
        }

        #[cfg(any(feature = "sqlite", test))]
        Executor::Sqlite(ex) => {
            sqlx::query_scalar("SELECT code FROM activation_state WHERE user_id = ?")
                .bind(user_id)
                .fetch_optional(ex)
                .await
                .map_err(sqlite::map_sqlx_error)?
        }

        #[allow(unused)]
        _ => unreachable!(),
    };
    Ok(code.map(|code| code as u64))
}

/// Inserts pending activation, or removes it to mark a user active.
///
/// Returns `DbError::AlreadyExists` if the user already has pending activation.
pub async fn set_user_activation_code(
    ex: &mut Executor,
    user: User,
    code: Option<u64>,
) -> DbResult<User> {
    get_user_by_id(ex, user.id).await?;
    match ex {
        #[cfg(feature = "postgres")]
        Executor::Postgres(ex) => match code {
            None => {
                sqlx::query("DELETE FROM activation_state WHERE user_id = $1")
                    .bind(user.id)
                    .execute(ex)
                    .await
                    .map_err(postgres::map_sqlx_error)?;
            }

            Some(code) => {
                sqlx::query("INSERT INTO activation_state (user_id, code) VALUES ($1, $2)")
                    .bind(user.id)
                    .bind(code as i64)
                    .execute(ex)
                    .await
                    .map_err(postgres::map_sqlx_error)?;
            }
        },

        #[cfg(any(feature = "sqlite", test))]
        Executor::Sqlite(ex) => match code {
            None => {
                sqlx::query("DELETE FROM activation_state WHERE user_id = ?")
                    .bind(user.id)
                    .execute(ex)
                    .await
                    .map_err(sqlite::map_sqlx_error)?;
            }

            Some(code) => {
                sqlx::query("INSERT INTO activation_state (user_id, code) VALUES (?, ?)")
                    .bind(user.id)
                    .bind(code as i64)
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
