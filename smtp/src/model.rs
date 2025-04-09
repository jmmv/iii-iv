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

//! Data types to interact with email messages.

use iii_iv_core::model::{EmailAddress, ModelError, ModelResult};
use iii_iv_core::template;
use lettre::message::Body;
use lettre::message::header::ContentTransferEncoding;
pub use lettre::message::{Mailbox, Message};

/// A template for an email message.
pub struct EmailTemplate {
    /// Who the message comes from.
    pub from: Mailbox,

    /// Subject of the message.
    pub subject_template: &'static str,

    /// Body of the message.
    pub body_template: &'static str,
}

impl EmailTemplate {
    /// Creates a message sent to `to` based on the template by applying the collection of
    /// `replacements` to it.
    ///
    /// The subject and body of the template are subject to string replacements per the rules
    /// described in `iii_iv_core::template::apply`.
    pub fn apply(
        &self,
        to: &EmailAddress,
        replacements: &[(&'static str, &str)],
    ) -> ModelResult<Message> {
        let to = to.as_str().parse().map_err(|e| {
            // TODO(jmmv): This should never happen... but there is no guarantee right now that we can
            // convert III-IV's `EmailAddress` into whatever Lettre expects.  It'd be nice if we didn't
            // need this though.
            ModelError(format!("Cannot parse email address {}: {}", to.as_str(), e))
        })?;

        let subject = template::apply(self.subject_template, replacements);

        let body = Body::new_with_encoding(
            template::apply(self.body_template, replacements),
            ContentTransferEncoding::QuotedPrintable,
        )
        .map_err(|e| ModelError(format!("Failed to encode message: {:?}", e)))?;

        let message = Message::builder()
            .from(self.from.clone())
            .to(to)
            .subject(subject)
            .body(body)
            .map_err(|e| ModelError(format!("Failed to encode message: {:?}", e)))?;
        Ok(message)
    }
}

/// Utilities to help testing email messages.
#[cfg(any(test, feature = "testutils"))]
pub mod testutils {
    use super::*;
    use std::collections::HashMap;

    /// Given an SMTP `message`, parses it and extracts its headers and body.
    pub fn parse_message(message: &Message) -> (HashMap<String, String>, String) {
        let text = String::from_utf8(message.formatted()).unwrap();
        let (raw_headers, encoded_body) = text
            .split_once("\r\n\r\n")
            .unwrap_or_else(|| panic!("Message seems to have the wrong format: {}", text));

        let mut headers = HashMap::default();
        for raw_header in raw_headers.split("\r\n") {
            let (key, value) = raw_header
                .split_once(": ")
                .unwrap_or_else(|| panic!("Header seems to have the wrong format: {}", raw_header));
            let previous = headers.insert(key.to_owned(), value.to_owned());
            assert!(previous.is_none(), "Duplicate header {}", raw_header);
        }

        let decoded_body =
            quoted_printable::decode(encoded_body, quoted_printable::ParseMode::Strict).unwrap();
        let body = String::from_utf8(decoded_body).unwrap().replace("\r\n", "\n");

        (headers, body)
    }
}

#[cfg(test)]
mod tests {
    use super::testutils::*;
    use super::*;

    #[test]
    fn test_email_template() {
        let template = EmailTemplate {
            from: "Sender <sender@example.com>".parse().unwrap(),
            subject_template: "The %s%",
            body_template: "The %b% with quoted printable =50 characters",
        };

        let message = template
            .apply(
                &EmailAddress::from("recipient@example.com"),
                &[("s", "replaced subject"), ("b", "replaced body")],
            )
            .unwrap();
        let (headers, body) = parse_message(&message);

        let exp_message = Message::builder()
            .from(template.from)
            .to("recipient@example.com".parse().unwrap())
            .subject("The replaced subject")
            .body(
                Body::new_with_encoding(
                    "The replaced body with quoted printable =50 characters".to_owned(),
                    ContentTransferEncoding::QuotedPrintable,
                )
                .unwrap(),
            )
            .unwrap();
        let (exp_headers, exp_body) = parse_message(&exp_message);

        assert_eq!(exp_headers, headers);
        assert_eq!(exp_body, body);
    }

    #[test]
    fn test_parse_message() {
        let exp_body = "
This is a sample message with a line that should be longer than 72 characters to test line wraps.

There is also a second paragraph with = quoted printable characters.
";
        let message = Message::builder()
            .from("From someone <from@example.com>".parse().unwrap())
            .to("to@example.com".parse().unwrap())
            .subject("This: is the: subject line")
            .body(exp_body.to_owned())
            .unwrap();

        // Make sure the encoding of the message is quoted-printable.  This isn't strictly required
        // because I suppose `parse_message` might succeed anyway, but it's good to encode our
        // assumption in a test.
        let text = String::from_utf8(message.formatted()).unwrap();
        assert!(text.contains("=3D"));

        let (headers, body) = parse_message(&message);

        assert!(headers.len() >= 3);
        assert_eq!("\"From someone\" <from@example.com>", headers.get("From").unwrap());
        assert_eq!("to@example.com", headers.get("To").unwrap());
        assert_eq!("This: is the: subject line", headers.get("Subject").unwrap());

        assert_eq!(exp_body, body);
    }
}
