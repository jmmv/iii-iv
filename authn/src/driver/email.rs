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
use iii_iv_core::model::{EmailAddress, Username};
use iii_iv_core::rest::BaseUrls;
use iii_iv_lettre::{EmailTemplate, SmtpMailer};

/// Sends the activation code `code` for `username` to the given `email` address.
///
/// The email contents are constructed from the `template` and are sent via `mailer`.
/// `base_urls` is used to compute the address to the account activation endpoint.
pub(super) async fn send_activation_code<M>(
    mailer: &M,
    template: &EmailTemplate,
    base_urls: &BaseUrls,
    username: &Username,
    email: &EmailAddress,
    code: u64,
) -> DriverResult<()>
where
    M: SmtpMailer,
{
    // TODO(jmmv): This doesn't really belong here because it's leaking details about the REST
    // router into the driver.
    let activate_url = base_urls.make_backend_url(&format!(
        "api/users/{}/activate?code={}",
        username.as_str(),
        code
    ));

    let replacements = [("activate_url", activate_url.as_str()), ("username", username.as_str())];
    let message = template.apply(email, &replacements)?;

    mailer.send(message).await
}

#[cfg(test)]
pub(crate) mod testutils {
    use super::*;
    use iii_iv_lettre::testutils::{parse_message, RecorderSmtpMailer};
    use url::Url;

    pub(crate) fn make_test_activation_template() -> EmailTemplate {
        let from = "from@example.com".parse().unwrap();
        EmailTemplate { from, subject_template: "Test activation", body_template: "%activate_url%" }
    }

    /// Gets the latest activation URL sent to `to` which, if any, should be for the username
    /// given in `exp_username`.
    pub(crate) async fn get_latest_activation_url(
        mailer: &RecorderSmtpMailer,
        to: &EmailAddress,
        exp_username: &Username,
    ) -> Option<Url> {
        let inboxes = mailer.inboxes.lock().await;
        match inboxes.get(to) {
            Some(inbox) => {
                let message = inbox.last().expect("Must have received at least one message");
                let (headers, body) = parse_message(message);
                let bad_message = "Email was not built by make_test_activation_template";
                assert_eq!("Test activation", headers.get("Subject").expect(bad_message));
                let url = Url::parse(&body).expect(bad_message);
                assert!(url.as_str().contains(&format!("api/users/{}/", exp_username.as_str())));
                Some(url)
            }
            None => None,
        }
    }

    /// Gets the latest activation code sent to `to` which, if any, should be for the username
    /// given in `exp_username`.
    pub(crate) async fn get_latest_activation_code(
        mailer: &RecorderSmtpMailer,
        to: &EmailAddress,
        exp_username: &Username,
    ) -> Option<u64> {
        let activation_url = get_latest_activation_url(mailer, to, exp_username).await;
        activation_url.map(|url| {
            url.as_str()
                .split_once('=')
                .map(|(_, code)| {
                    str::parse(code).expect("Want only one numerical parameter in query string")
                })
                .expect("No parameter found in query string")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::testutils::*;
    use super::*;
    use iii_iv_lettre::testutils::*;

    #[tokio::test]
    async fn test_send_activation_code() {
        let mailer = RecorderSmtpMailer::default();

        let to = EmailAddress::from("user@example.com");
        send_activation_code(
            &mailer,
            &make_test_activation_template(),
            &BaseUrls::from_strs(
                "https://test.example.com:1234/",
                Some("https://no-frontend.example.com"),
            ),
            &Username::from("user-123"),
            &to,
            7654,
        )
        .await
        .unwrap();

        let message = mailer.expect_one_message(&to).await;
        let (headers, body) = parse_message(&message);
        assert_eq!(to.as_str(), headers.get("To").unwrap());
        assert_eq!("https://test.example.com:1234/api/users/user-123/activate?code=7654", body);
    }
}
