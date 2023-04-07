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

//! Utilities to send canned messages to users over email.

use crate::driver::DriverResult;
use async_trait::async_trait;
use iii_iv_core::driver::DriverError;
use iii_iv_core::model::{EmailAddress, Username};
use iii_iv_lettre::{SmtpMailer, SmtpMessenger};

/// Address to use as the `From` field of messages sent by this service.
const FROM_ADDRESS: &str = "EndBASIC Service <noreply@endbasic.dev>";

/// Address to use as the `Reply-To` field of messages sent by this service.
const REPLY_TO_ADDRESS: &str = "EndBASIC Service <noreply@endbasic.dev>";

/// Operations to send canned messages.
#[async_trait]
pub trait Messenger {
    /// Sends the activation `code` for `username` to the given `email` address.
    async fn send_activation_code(
        &self,
        base_url: &str,
        username: &Username,
        email: &EmailAddress,
        code: u32,
    ) -> DriverResult<()>;
}

/// Sanity-check that the provided base URL is valid to generate our target links.
fn is_valid_base_url(base_url: &str) -> bool {
    base_url.starts_with("http") && base_url.ends_with('/')
}

#[async_trait]
impl<M> Messenger for SmtpMessenger<M>
where
    M: SmtpMailer + Clone + Send + Sync,
{
    async fn send_activation_code(
        &self,
        base_url: &str,
        username: &Username,
        email: &EmailAddress,
        code: u32,
    ) -> DriverResult<()> {
        if !is_valid_base_url(base_url) {
            return Err(DriverError::InvalidInput("Invalid base URL for the service".to_owned()));
        }

        let body = format!(
            r#"Hello {},

Thank you for signing up for an EndBASIC service account.

Before logging in for the first time, you must activate your account.
Follow this link:

    {}api/users/{}/activate?code={}

If you have any issues, please contact support@endbasic.dev.
"#,
            username.as_str(),
            base_url,
            username.as_str(),
            code
        );

        self.send(
            FROM_ADDRESS,
            REPLY_TO_ADDRESS,
            email,
            "Activate your EndBASIC service account",
            body,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iii_iv_lettre::testutils::setup;

    #[tokio::test]
    async fn test_send_activation_code() {
        let (messages, messenger) = setup();

        messenger
            .send_activation_code(
                "https://test.example.com:1234/",
                &Username::from("user-123"),
                &EmailAddress::from("user@example.com"),
                7654,
            )
            .await
            .unwrap();

        let messages = messages.lock().await;
        assert_eq!(1, messages.len());
        let message = messages.first().unwrap();
        let text = String::from_utf8(message.formatted()).unwrap();
        assert!(text.contains("To: user@example.com"));
        assert!(text.contains("Subject: Activate your"));
        assert!(
            text.contains("https://test.example.com:1234/api/users/user-123/activate?code=7654")
        );
    }
}
