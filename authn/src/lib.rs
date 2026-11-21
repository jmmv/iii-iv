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

//! Common utilities to implement custom authentication.
//!
//! Password recovery uses `POST /password/recovery` with an email address and
//! `POST /password/reset` with the emailed user ID, token, and new password.  Recovery also
//! verifies inactive accounts and revokes existing sessions; it never enables password-disabled
//! accounts.  The task runner requires recovery email and reset URL templates at construction.
//! Recovery templates are plain text and support `reset_url`, `email`, `user`, `user_id`, and
//! `username`.  The trusted reset URL template supports `user_id` and `token` substitutions.
//!
//! `AUTHN_RECOVERY_MAX_AGE` defaults to one hour and `AUTHN_RECOVERY_RESEND_COOLDOWN` to one minute,
//! with the application's usual environment prefix.  Tokens are purpose-bound and digested in
//! credential storage, but queued delivery tasks contain their raw values.  Treat queue contents
//! as secrets and remove all account-owned tasks in the account deletion hook.

pub mod db;
pub mod driver;
pub mod model;
pub mod rest;
