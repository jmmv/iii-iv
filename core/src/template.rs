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

//! Trivial templating engine.

/// Performs various named string replacements in `input` based on `replacements`.
///
/// The `input` string can have `%key%` strings in it where `key` must appear in `replacements` and
/// which will be replaced by its corresponding value.  Raw `%` characters can be escaped via `%%`
/// and nested expansions are not supported.
pub fn apply(input: &'static str, replacements: &[(&'static str, &str)]) -> String {
    let mut output = String::with_capacity(input.len());
    let mut partial_key: Option<String> = None;
    for ch in input.chars() {
        if ch == '%' {
            match partial_key {
                Some(key) if key.is_empty() => {
                    output.push('%');
                    partial_key = None;
                }
                Some(key) => {
                    let mut found = false;
                    for (candidate_key, value) in replacements {
                        if *candidate_key == key {
                            assert!(!found, "Found two values for replacement {}", key);
                            output.push_str(value);
                            found = true;
                            // We could "break" here but we don't because we want to check for
                            // duplicates.
                        }
                    }
                    assert!(found, "No replacement for {} but it must have been defined", key);
                    partial_key = None;
                }
                None => partial_key = Some(String::new()),
            }
        } else {
            match partial_key.as_mut() {
                Some(k) => k.push(ch),
                None => output.push(ch),
            }
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apply_empty() {
        assert_eq!("", apply("", &[]));
    }

    #[test]
    fn test_apply_none() {
        assert_eq!("this is % some text %%", apply("this is %% some text %%%%", &[]));
    }

    #[test]
    fn test_apply_some() {
        let replacements = &[("a", "single letter"), ("foo", "many letters")];
        assert_eq!("single lettermany letters", apply("%a%%foo%", replacements));
        assert_eq!(" single letter many letters ", apply(" %a% %foo% ", replacements));
        assert_eq!(
            "some single letter foo text many letters a",
            apply("some %a% foo text %foo% a", replacements)
        );
    }

    #[test]
    fn test_apply_no_nested_replacements() {
        let replacements = &[("a", "%nested% chunk")];
        assert_eq!("the %nested% chunk output", apply("the %a% output", replacements));
    }
}
