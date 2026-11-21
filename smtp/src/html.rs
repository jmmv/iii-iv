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

//! Sanitization of untrusted HTML fragments for email bodies.

use ammonia::{Builder, UrlRelative};
use url::Url;

/// Sanitizes untrusted HTML, retaining semantic markup, links, and images without styles.
///
/// Relative links and image sources resolve against `base_url`.  Without a base, relative URL
/// attributes are removed.  Only HTTP, HTTPS, and mailto URLs are retained.  This returns a fragment
/// suitable for insertion into an HTML body, not an attribute or a script.
pub fn sanitize_html(input: &str, base_url: Option<&Url>) -> String {
    let relative = match base_url {
        Some(base) => UrlRelative::RewriteWithBase(base.clone()),
        None => UrlRelative::Deny,
    };
    Builder::default()
        .url_schemes(["http", "https", "mailto"].into())
        .url_relative(relative)
        .clean(input)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_html_semantics_and_images() {
        let input = r#"<h2>Title</h2><p>Hello <em>world</em> &amp; friends.</p><ul><li>One</li></ul><img src="https://example.com/a.png" alt="A &amp; B"><a href="mailto:a@example.com">Mail</a>"#;
        let output = sanitize_html(input, None);
        assert!(output.contains("<h2>Title</h2>"));
        assert!(output.contains("<p>Hello <em>world</em> &amp; friends.</p>"));
        assert!(output.contains("<ul><li>One</li></ul>"));
        assert!(output.contains(r#"<img src="https://example.com/a.png" alt="A &amp; B">"#));
        assert!(output.contains(r#"href="mailto:a@example.com""#));
    }

    #[test]
    fn test_sanitize_html_removes_active_content_and_styles() {
        let input = r#"<style>p { color: red; }</style><script>alert(1)</script><p class="x" style="color:red" onclick="evil()">Safe</p><a href="javascript:evil()">Link</a><img src="data:text/html,evil" onerror="evil()"><iframe src="https://example.com/"></iframe>"#;
        let output = sanitize_html(input, None);
        assert!(output.contains("<p>Safe</p>"));
        for forbidden in [
            "style",
            "script",
            "alert",
            "class=",
            "onclick",
            "javascript:",
            "data:",
            "onerror",
            "iframe",
        ] {
            assert!(!output.contains(forbidden), "{output}");
        }
    }

    #[test]
    fn test_sanitize_html_relative_urls() {
        let input = r#"<a href="../post?q=a&amp;b=c">Post</a><img src="/image.png"><a href="//cdn.example.com/a">CDN</a>"#;
        let base = Url::parse("https://example.com/blog/feed.xml").unwrap();
        let output = sanitize_html(input, Some(&base));
        assert!(output.contains(r#"href="https://example.com/post?q=a&amp;b=c""#));
        assert!(output.contains(r#"src="https://example.com/image.png""#));
        assert!(output.contains(r#"href="https://cdn.example.com/a""#));
        let output = sanitize_html(input, None);
        assert!(!output.contains("href="));
        assert!(!output.contains("src="));
    }

    #[test]
    fn test_sanitize_html_malformed() {
        let output = sanitize_html("<p>héllo <b>world</p><p>again", None);
        assert!(output.contains("héllo"));
        assert!(output.contains("world"));
        assert!(output.contains("again"));
    }
}
