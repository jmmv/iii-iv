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

//! Activation backed by purpose-bound email credentials.

use crate::db::credential::encode_digest;
use crate::db::{
    clear_failures, delete_email_credential, get_email_credential, get_user_by_id, lock_failures,
    put_email_credential,
};
use crate::model::{
    ActivationState, CredentialPurpose, EmailCredential, EmailToken, FailureOperation, User,
};
#[cfg(feature = "postgres")]
use iii_iv_core::db::postgres;
#[cfg(any(feature = "sqlite", test))]
use iii_iv_core::db::sqlite::{self, unpack_timestamp};
use iii_iv_core::db::{DbError, DbResult, Executor};
use time::OffsetDateTime;
use uuid::Uuid;

/// Sets account activation independently of pending credentials.
///
/// Call with the account locked in a transaction.
pub async fn set_user_active(ex: &mut Executor, user_id: Uuid, active: bool) -> DbResult<()> {
    match ex {
        #[cfg(feature = "postgres")]
        Executor::Postgres(ex) => {
            sqlx::query("UPDATE users SET is_active = $1 WHERE id = $2")
                .bind(active)
                .bind(user_id)
                .execute(ex)
                .await
                .map_err(postgres::map_sqlx_error)?;
        }

        #[cfg(any(feature = "sqlite", test))]
        Executor::Sqlite(ex) => {
            sqlx::query("UPDATE users SET is_active = ? WHERE id = ?")
                .bind(active)
                .bind(user_id)
                .execute(ex)
                .await
                .map_err(sqlite::map_sqlx_error)?;
        }
        #[allow(unused)]
        _ => unreachable!(),
    }
    Ok(())
}

/// Reads the pending activation credential digest and lifetime.
pub async fn get_user_activation(
    ex: &mut Executor,
    user_id: Uuid,
) -> DbResult<Option<ActivationState>> {
    Ok(get_email_credential(ex, user_id, CredentialPurpose::Activation).await?.map(|state| {
        ActivationState {
            code: state.digest,
            issued_at: state.issued_at,
            expires_at: state.expires_at,
        }
    }))
}

/// Sets activation state with the account locked in a transaction.
pub async fn set_user_activation(
    ex: &mut Executor,
    user: User,
    activation: Option<ActivationState>,
) -> DbResult<User> {
    let now = activation.as_ref().map_or(OffsetDateTime::UNIX_EPOCH, |state| state.issued_at);
    lock_failures(ex, user.id, FailureOperation::Activation, now).await?;
    let active = activation.is_none();
    if let Some(state) = activation {
        if get_user_activation(ex, user.id).await?.is_some() {
            return Err(DbError::AlreadyExists);
        }
        put_email_credential(
            ex,
            user.id,
            CredentialPurpose::Activation,
            &EmailCredential {
                digest: state.code,
                issued_at: state.issued_at,
                expires_at: state.expires_at,
            },
        )
        .await?;
    } else {
        delete_email_credential(ex, user.id, CredentialPurpose::Activation).await?;
    }
    set_user_active(ex, user.id, active).await?;
    clear_failures(ex, user.id, FailureOperation::Activation).await?;
    get_user_by_id(ex, user.id).await
}

/// Consumes a matching activation credential with the account locked in a transaction.
pub async fn consume_user_activation(
    ex: &mut Executor,
    user_id: Uuid,
    token: impl Into<EmailToken>,
    now: OffsetDateTime,
) -> DbResult<bool> {
    let token = token.into();
    let digest = encode_digest(token.digest(CredentialPurpose::Activation));
    let affected = match ex {
        #[cfg(feature = "postgres")]
        Executor::Postgres(ex) => sqlx::query(
            "DELETE FROM email_credentials
            WHERE user_id = $1 AND purpose = 'activation' AND digest = $2 AND expires_at > $3",
        )
        .bind(user_id)
        .bind(&digest)
        .bind(now)
        .execute(ex)
        .await
        .map_err(postgres::map_sqlx_error)?
        .rows_affected(),

        #[cfg(any(feature = "sqlite", test))]
        Executor::Sqlite(ex) => {
            let (secs, nsecs) = unpack_timestamp(now);
            sqlx::query(
                "DELETE FROM email_credentials
                WHERE user_id = ? AND purpose = 'activation' AND digest = ?
                    AND (expires_at_secs > ? OR (expires_at_secs = ? AND expires_at_nsecs > ?))",
            )
            .bind(user_id)
            .bind(&digest)
            .bind(secs)
            .bind(secs)
            .bind(nsecs)
            .execute(ex)
            .await
            .map_err(sqlite::map_sqlx_error)?
            .rows_affected()
        }

        #[allow(unused)]
        _ => unreachable!(),
    };
    if affected == 1 {
        set_user_active(ex, user_id, true).await?;
    }
    Ok(affected == 1)
}
