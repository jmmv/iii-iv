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

//! Persistence of purpose-bound email credentials.

use crate::model::{CredentialPurpose, EmailCredential};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
#[cfg(feature = "postgres")]
use iii_iv_core::db::postgres;
#[cfg(any(feature = "sqlite", test))]
use iii_iv_core::db::sqlite::{self, build_timestamp, unpack_timestamp};
use iii_iv_core::db::{DbError, DbResult, Executor};
use iii_iv_core::model::Sha256Sum;
use sqlx::Row;
use uuid::Uuid;

/// Encodes a digest for the database's existing text representation.
pub(super) fn encode_digest(digest: Sha256Sum) -> String {
    URL_SAFE_NO_PAD.encode(digest.as_bytes())
}

/// Validates the encoding and SHA-256 length of a persisted digest.
fn decode_digest(value: &str) -> DbResult<Sha256Sum> {
    let bytes = URL_SAFE_NO_PAD.decode(value).map_err(|error| {
        DbError::DataIntegrityError(format!("Invalid credential digest encoding: {error}"))
    })?;
    Sha256Sum::try_from(bytes).map_err(DbError::DataIntegrityError)
}

/// Reads a credential while the caller holds the account lock.
pub async fn get_email_credential(
    ex: &mut Executor,
    user: Uuid,
    purpose: CredentialPurpose,
) -> DbResult<Option<EmailCredential>> {
    match ex {
        #[cfg(feature = "postgres")]
        Executor::Postgres(ex) => {
            let row =
                sqlx::query("SELECT * FROM email_credentials WHERE user_id = $1 AND purpose = $2")
                    .bind(user)
                    .bind(purpose.as_str())
                    .fetch_optional(ex)
                    .await
                    .map_err(postgres::map_sqlx_error)?;
            row.map(|row| {
                let digest: String = row.try_get("digest").map_err(postgres::map_sqlx_error)?;
                Ok(EmailCredential {
                    digest: decode_digest(&digest)?,
                    issued_at: row.try_get("issued_at").map_err(postgres::map_sqlx_error)?,
                    expires_at: row.try_get("expires_at").map_err(postgres::map_sqlx_error)?,
                })
            })
            .transpose()
        }

        #[cfg(any(feature = "sqlite", test))]
        Executor::Sqlite(ex) => {
            let row =
                sqlx::query("SELECT * FROM email_credentials WHERE user_id = ? AND purpose = ?")
                    .bind(user)
                    .bind(purpose.as_str())
                    .fetch_optional(ex)
                    .await
                    .map_err(sqlite::map_sqlx_error)?;
            row.map(|row| {
                let digest: String = row.try_get("digest").map_err(sqlite::map_sqlx_error)?;
                Ok(EmailCredential {
                    digest: decode_digest(&digest)?,
                    issued_at: build_timestamp(
                        row.try_get("issued_at_secs").map_err(sqlite::map_sqlx_error)?,
                        row.try_get("issued_at_nsecs").map_err(sqlite::map_sqlx_error)?,
                    )?,
                    expires_at: build_timestamp(
                        row.try_get("expires_at_secs").map_err(sqlite::map_sqlx_error)?,
                        row.try_get("expires_at_nsecs").map_err(sqlite::map_sqlx_error)?,
                    )?,
                })
            })
            .transpose()
        }

        #[allow(unused)]
        _ => unreachable!(),
    }
}

/// Replaces a credential while the caller holds the account lock.
pub async fn put_email_credential(
    ex: &mut Executor,
    user: Uuid,
    purpose: CredentialPurpose,
    state: &EmailCredential,
) -> DbResult<()> {
    let digest = encode_digest(state.digest);
    match ex {
        #[cfg(feature = "postgres")]
        Executor::Postgres(ex) => {
            sqlx::query("INSERT INTO email_credentials (user_id, purpose, digest, issued_at, expires_at) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (user_id, purpose) DO UPDATE SET digest = excluded.digest, issued_at = excluded.issued_at, expires_at = excluded.expires_at")
                .bind(user).bind(purpose.as_str()).bind(&digest).bind(state.issued_at).bind(state.expires_at).execute(ex).await.map_err(postgres::map_sqlx_error)?;
        }

        #[cfg(any(feature = "sqlite", test))]
        Executor::Sqlite(ex) => {
            let (issued_secs, issued_nsecs) = unpack_timestamp(state.issued_at);
            let (expires_secs, expires_nsecs) = unpack_timestamp(state.expires_at);
            sqlx::query("INSERT INTO email_credentials (user_id, purpose, digest, issued_at_secs, issued_at_nsecs, expires_at_secs, expires_at_nsecs) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (user_id, purpose) DO UPDATE SET digest = excluded.digest, issued_at_secs = excluded.issued_at_secs, issued_at_nsecs = excluded.issued_at_nsecs, expires_at_secs = excluded.expires_at_secs, expires_at_nsecs = excluded.expires_at_nsecs")
                .bind(user).bind(purpose.as_str()).bind(&digest).bind(issued_secs).bind(issued_nsecs).bind(expires_secs).bind(expires_nsecs).execute(ex).await.map_err(sqlite::map_sqlx_error)?;
        }

        #[allow(unused)]
        _ => unreachable!(),
    }
    Ok(())
}

/// Removes pending credentials for one purpose with the account locked.
pub async fn delete_email_credential(
    ex: &mut Executor,
    user: Uuid,
    purpose: CredentialPurpose,
) -> DbResult<()> {
    match ex {
        #[cfg(feature = "postgres")]
        Executor::Postgres(ex) => {
            sqlx::query("DELETE FROM email_credentials WHERE user_id = $1 AND purpose = $2")
                .bind(user)
                .bind(purpose.as_str())
                .execute(ex)
                .await
                .map_err(postgres::map_sqlx_error)?;
        }

        #[cfg(any(feature = "sqlite", test))]
        Executor::Sqlite(ex) => {
            sqlx::query("DELETE FROM email_credentials WHERE user_id = ? AND purpose = ?")
                .bind(user)
                .bind(purpose.as_str())
                .execute(ex)
                .await
                .map_err(sqlite::map_sqlx_error)?;
        }

        #[allow(unused)]
        _ => unreachable!(),
    }
    Ok(())
}
