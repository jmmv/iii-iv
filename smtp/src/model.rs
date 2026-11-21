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
use lettre::message::header::{ContentTransferEncoding, ContentType};
use lettre::message::{Body, MultiPart, SinglePart};
pub use lettre::message::{Mailbox, Message};

/// Builds a message with plain-text and HTML alternatives.
///
/// `html_body` must contain trusted markup with escaped text, or sanitized untrusted HTML.
pub fn make_message(
    from: Mailbox,
    to: &EmailAddress,
    subject: &str,
    body: String,
    html_body: String,
) -> ModelResult<Message> {
    let to = to
        .as_str()
        .parse()
        .map_err(|e| ModelError(format!("Cannot parse email address {}: {}", to.as_str(), e)))?;
    let encode = |body| {
        Body::new_with_encoding(body, ContentTransferEncoding::QuotedPrintable)
            .map_err(|e| ModelError(format!("Failed to encode message: {:?}", e)))
    };
    Message::builder()
        .from(from)
        .to(to)
        .subject(subject)
        .multipart(
            MultiPart::alternative()
                .singlepart(
                    SinglePart::builder().header(ContentType::TEXT_PLAIN).body(encode(body)?),
                )
                .singlepart(
                    SinglePart::builder().header(ContentType::TEXT_HTML).body(encode(html_body)?),
                ),
        )
        .map_err(|e| ModelError(format!("Failed to construct message: {}", e)))
}

/// A template for an email message.
pub struct EmailTemplate {
    /// Who the message comes from.
    pub from: Mailbox,

    /// Subject of the message.
    pub subject_template: &'static str,

    /// Plain-text body of the message.
    pub body_template: &'static str,

    /// HTML body with substitutions escaped for text and quoted ordinary attributes.
    ///
    /// Templates supply trusted markup and URL structure.  Substitutions in scripts, styles, and
    /// executable URL contexts are unsupported.
    pub html_body_template: &'static str,
}

impl EmailTemplate {
    /// Creates a message sent to `to` based on the template by applying the collection of
    /// `replacements` to it.
    ///
    /// The subject and body of the template are subject to string replacements per the rules
    /// described in `iii_iv_core::template::apply`.  HTML substitutions are escaped independently.
    pub fn apply(
        &self,
        to: &EmailAddress,
        replacements: &[(&'static str, &str)],
    ) -> ModelResult<Message> {
        let escaped: Vec<_> =
            replacements.iter().map(|(key, value)| (*key, template::escape_html(value))).collect();
        let html_replacements: Vec<_> =
            escaped.iter().map(|(key, value)| (*key, value.as_str())).collect();
        make_message(
            self.from.clone(),
            to,
            &template::apply(self.subject_template, replacements),
            template::apply(self.body_template, replacements),
            template::apply(self.html_body_template, &html_replacements),
        )
    }
}

/// Utilities to help testing email messages.
#[cfg(any(test, feature = "testutils"))]
pub mod testutils {
    use super::*;
    use std::collections::HashMap;

    /// Parses a message and returns its headers and decoded plain-text body.
    pub fn parse_message(message: &Message) -> (HashMap<String, String>, String) {
        let (headers, body, _) = parse_message_bodies(message);
        (headers, body)
    }

    /// Parses a message and returns its headers, decoded plain text, and optional decoded HTML.
    ///
    /// Supports single-part plain text and multipart alternatives.  Bodies use LF line endings.
    pub fn parse_message_bodies(
        message: &Message,
    ) -> (HashMap<String, String>, String, Option<String>) {
        let raw = message.formatted();
        let parsed = mailparse::parse_mail(&raw).unwrap();
        let headers = parsed.headers.iter().map(|h| (h.get_key(), h.get_value())).collect();
        let decode =
            |part: &mailparse::ParsedMail<'_>| part.get_body().unwrap().replace("\r\n", "\n");
        if parsed.ctype.mimetype == "multipart/alternative" {
            assert_eq!(2, parsed.subparts.len());
            assert_eq!("text/plain", parsed.subparts[0].ctype.mimetype);
            assert_eq!("text/html", parsed.subparts[1].ctype.mimetype);
            (headers, decode(&parsed.subparts[0]), Some(decode(&parsed.subparts[1])))
        } else {
            assert_eq!("text/plain", parsed.ctype.mimetype);
            (headers, decode(&parsed), None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testutils::*;
    use super::*;
    use iii_iv_core::model::email_address;
    use mailparse::MailHeaderMap;

    #[test]
    fn test_email_template() {
        let template = EmailTemplate {
            from: "Sender <sender@example.com>".parse().unwrap(),
            subject_template: "The %s%",
            body_template: "The %b% with quoted printable =50 characters",
            html_body_template: "<p>%b%</p><a href=\"%url%\">Link</a>",
        };

        let value = "héllo <b>&\"' %nested%";
        let message = template
            .apply(
                &email_address!("recipient@example.com"),
                &[("s", "subject & more"), ("b", value), ("url", "https://example.com/?a=1&b=2")],
            )
            .unwrap();

        let (headers, body, html) = parse_message_bodies(&message);
        assert_eq!("The subject & more", headers["Subject"]);
        assert_eq!("recipient@example.com", headers["To"]);
        assert_eq!(format!("The {value} with quoted printable =50 characters"), body);
        assert_eq!(Some("<p>héllo &lt;b&gt;&amp;&quot;&#39; %nested%</p><a href=\"https://example.com/?a=1&amp;b=2\">Link</a>".to_owned()), html);
        assert_eq!(body, parse_message(&message).1);
        let raw = message.formatted();
        let parsed = mailparse::parse_mail(&raw).unwrap();
        assert_eq!("multipart/alternative", parsed.ctype.mimetype);
        assert_eq!(2, parsed.subparts.len());
        for part in &parsed.subparts {
            assert_eq!("utf-8", part.ctype.params["charset"]);
            assert_eq!(
                "quoted-printable",
                part.headers.get_first_value("Content-Transfer-Encoding").unwrap()
            );
        }
    }

    #[test]
    fn test_make_message_long_bodies_and_empty_alternatives() {
        for text in [String::new(), "Unicode é = and a long line. ".repeat(30)] {
            let html = format!("<p>{}</p>", template::escape_html(&text));
            let message = make_message(
                "sender@example.com".parse().unwrap(),
                &email_address!("recipient@example.com"),
                "Subject",
                text.clone(),
                html.clone(),
            )
            .unwrap();
            let (_, plain, actual_html) = parse_message_bodies(&message);
            assert_eq!(text, plain);
            assert_eq!(Some(html), actual_html);
        }
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
