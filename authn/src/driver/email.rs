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
use crate::model::User;
use iii_iv_core::rest::BaseUrls;
use iii_iv_smtp::model::{EmailTemplate, Message};

/// Builds a message with the activation code `code` for `user`.
///
/// The email contents are constructed from the `template`.  `base_urls` is used to compute the
/// address to the account activation endpoint.
pub(super) fn make_activation_code_message(
    template: &EmailTemplate,
    base_urls: &BaseUrls,
    user: &User,
    code: u64,
) -> DriverResult<Message> {
    // TODO(jmmv): This doesn't really belong here because it's leaking details about the REST
    // router into the driver.
    let activate_url =
        base_urls.make_backend_url(&format!("api/users/{}/activate?code={}", user.id, code));

    let user_id = user.id.to_string();
    let username = user.username.as_ref().map(|username| username.as_str()).unwrap_or("");
    let display_name = user
        .username
        .as_ref()
        .map(|username| username.as_str())
        .unwrap_or_else(|| user.email.as_str());
    let replacements = [
        ("activate_url", activate_url.as_str()),
        ("email", user.email.as_str()),
        ("user", display_name),
        ("user_id", user_id.as_str()),
        ("username", username),
    ];
    Ok(template.apply(&user.email, &replacements)?)
}

#[cfg(any(test, feature = "testutils"))]
pub(crate) mod testutils {
    //! Utilities to help testing services that integrate with the `authn` features.

    use super::*;
    use iii_iv_core::model::EmailAddress;
    use iii_iv_smtp::driver::testutils::RecorderSmtpMailer;
    use iii_iv_smtp::model::testutils::parse_message;
    use url::Url;
    use uuid::Uuid;

    /// Creates an email activation template to capture activation codes during tests.
    pub(crate) fn make_test_activation_template() -> EmailTemplate {
        let from = "from@example.com".parse().unwrap();
        EmailTemplate { from, subject_template: "Test activation", body_template: "%activate_url%" }
    }

    /// Gets the latest activation URL sent to `to` for `exp_user_id`, if any.
    pub(crate) async fn get_latest_activation_url(
        mailer: &RecorderSmtpMailer,
        to: &EmailAddress,
        exp_user_id: Option<Uuid>,
    ) -> Option<Url> {
        let inboxes = mailer.inboxes.lock().await;
        match inboxes.get(to) {
            Some(inbox) => {
                let message = inbox.last().expect("Must have received at least one message");
                let (headers, body) = parse_message(message);
                let bad_message = "Email was not built by make_test_activation_template";
                assert_eq!("Test activation", headers.get("Subject").expect(bad_message));
                let url = Url::parse(&body).expect(bad_message);
                if let Some(exp_user_id) = exp_user_id {
                    assert!(url.as_str().contains(&format!("api/users/{}/", exp_user_id)));
                }
                Some(url)
            }
            None => None,
        }
    }

    /// Gets the latest activation code sent to `to` for `exp_user_id`, if any.
    pub(crate) async fn get_latest_activation_code(
        mailer: &RecorderSmtpMailer,
        to: &EmailAddress,
        exp_user_id: Option<Uuid>,
    ) -> Option<u64> {
        let activation_url = get_latest_activation_url(mailer, to, exp_user_id).await;
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
    use iii_iv_core::model::{email_address, username};
    use iii_iv_smtp::model::testutils::parse_message;
    use uuid::Uuid;

    #[test]
    fn test_make_activation_code_message() {
        let to = email_address!("user@example.com");
        let user_id = Uuid::nil();
        let user = User::new(user_id, Some(username!("user-123")), to.clone());
        let message = make_activation_code_message(
            &make_test_activation_template(),
            &BaseUrls::from_strs(
                "https://test.example.com:1234/",
                Some("https://no-frontend.example.com"),
            ),
            &user,
            7654,
        )
        .unwrap();
        let (headers, body) = parse_message(&message);
        assert_eq!(to.as_str(), headers.get("To").unwrap());
        assert_eq!(
            format!("https://test.example.com:1234/api/users/{}/activate?code=7654", user_id),
            body
        );
    }
}
