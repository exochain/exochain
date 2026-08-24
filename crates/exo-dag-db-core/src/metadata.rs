//! Deterministic metadata redaction for ExoChain DAG DB.

use exo_core::Hash256;
use exo_dag_db_api::{RedactionCode, SafeMetadata, SafeMetadataDecision};
use thiserror::Error;

/// Placeholder for detected Social Security numbers.
pub const SSN_PLACEHOLDER: &str = "[REDACTED_SSN]";
/// Placeholder for detected payment card numbers.
pub const CARD_PLACEHOLDER: &str = "[REDACTED_CARD]";
/// Placeholder for detected NDA or confidential markers.
pub const CONFIDENTIAL_PLACEHOLDER: &str = "[REDACTED_CONFIDENTIAL]";
/// Placeholder for detected protected health information markers.
pub const PHI_PLACEHOLDER: &str = "[REDACTED_PHI]";
/// Placeholder for detected private customer markers.
pub const CUSTOMER_PRIVATE_PLACEHOLDER: &str = "[REDACTED_CUSTOMER_PRIVATE]";
/// Placeholder for detected raw source code excerpts.
pub const CODE_EXCERPT_PLACEHOLDER: &str = "[REDACTED_CODE_EXCERPT]";
/// Placeholder for detected bearer or authorization tokens.
pub const TOKEN_PLACEHOLDER: &str = "[REDACTED_TOKEN]";
/// Placeholder for detected secret assignment values.
pub const SECRET_PLACEHOLDER: &str = "[REDACTED_SECRET]";
/// Placeholder for detected absolute filesystem paths.
pub const PATH_PLACEHOLDER: &str = "[REDACTED_PATH]";
/// Placeholder for detected URLs and connection strings.
pub const URL_PLACEHOLDER: &str = "[REDACTED_URL]";
/// Marker appended when sanitized metadata is truncated.
pub const TRUNCATION_MARKER: &str = "[TRUNCATED]";

const KEYWORD_LIMIT: usize = 32;
/// Metadata field class with its storage byte limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetadataField {
    /// Stored `title.text`, max 160 bytes.
    Title,
    /// Stored `summary.text`, max 1000 bytes.
    Summary,
    /// Stored keyword item text, max 64 bytes.
    Keyword,
    /// Stored validation notes, max 2000 bytes.
    ValidationNotes,
    /// Stored council notes, max 2000 bytes.
    CouncilNotes,
    /// Stored receipt free-text field, max 512 bytes.
    ReceiptFreeText,
    /// API response excerpt, max 512 bytes.
    ResponseExcerpt,
}

impl MetadataField {
    const fn limit(self) -> usize {
        match self {
            Self::Title => 160,
            Self::Summary => 1000,
            Self::Keyword => 64,
            Self::ValidationNotes | Self::CouncilNotes => 2000,
            Self::ReceiptFreeText | Self::ResponseExcerpt => 512,
        }
    }
}

/// Metadata sanitizer failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum MetadataError {
    /// Runtime metadata contained payload-equivalent content and must not persist.
    #[error("metadata rejected for field {field:?}")]
    Rejected {
        /// Field being sanitized.
        field: MetadataField,
        /// Deterministic redacted metadata that must not be persisted.
        metadata: SafeMetadata,
    },
    /// Runtime keyword list exceeded the hard item count bound.
    #[error("too many metadata keywords: {count} > {limit}")]
    TooManyKeywords {
        /// Actual keyword count.
        count: usize,
        /// Configured maximum keyword count.
        limit: usize,
    },
}

/// Sanitize untrusted metadata into the stored `SafeMetadata` JSON shape.
#[must_use]
pub fn sanitize_metadata(field: MetadataField, input: &str) -> SafeMetadata {
    let mut codes = detected_codes(input);
    let mut text = redacted_text(input, &codes);
    let mut decision = if codes.is_empty() {
        SafeMetadataDecision::Allow
    } else if codes.contains(&RedactionCode::CodeExcerpt) {
        SafeMetadataDecision::Reject
    } else {
        SafeMetadataDecision::Redact
    };

    let limit = field.limit();
    let truncated = text.len() > limit;
    if truncated {
        push_code(&mut codes, RedactionCode::LengthTruncation);
        text = truncate_with_marker(&text, limit);
        if decision == SafeMetadataDecision::Allow {
            decision = SafeMetadataDecision::Redact;
        }
    }

    sort_codes(&mut codes);
    SafeMetadata {
        decision,
        text,
        redaction_codes: codes,
        original_hash: Hash256::digest(input.as_bytes()).to_string(),
        truncated,
        byte_len: u32::try_from(input.len()).unwrap_or(u32::MAX),
    }
}

/// Sanitize runtime metadata and fail before persistence when the decision is `reject`.
pub fn sanitize_runtime_metadata(
    field: MetadataField,
    input: &str,
) -> Result<SafeMetadata, MetadataError> {
    let metadata = sanitize_metadata(field, input);
    if metadata.decision == SafeMetadataDecision::Reject {
        return Err(MetadataError::Rejected { field, metadata });
    }
    Ok(metadata)
}

/// Sanitize runtime keyword text values with the exact item count bound.
pub fn sanitize_keywords(inputs: &[String]) -> Result<Vec<SafeMetadata>, MetadataError> {
    if inputs.len() > KEYWORD_LIMIT {
        return Err(MetadataError::TooManyKeywords {
            count: inputs.len(),
            limit: KEYWORD_LIMIT,
        });
    }
    inputs
        .iter()
        .map(|input| sanitize_runtime_metadata(MetadataField::Keyword, input))
        .collect()
}

fn detected_codes(input: &str) -> Vec<RedactionCode> {
    let mut codes = Vec::new();
    let lower = input.to_ascii_lowercase();
    if contains_ssn(input) {
        push_code(&mut codes, RedactionCode::Ssn);
    }
    if contains_card(input) {
        push_code(&mut codes, RedactionCode::Card);
    }
    if contains_confidential_marker_phrase(&lower) || contains_secret_material(input) {
        push_code(&mut codes, RedactionCode::ConfidentialMarker);
    }
    if contains_phi_phrase(&lower) {
        push_code(&mut codes, RedactionCode::Phi);
    }
    if contains_customer_private_phrase(&lower) {
        push_code(&mut codes, RedactionCode::CustomerPrivate);
    }
    if lower.contains("```")
        || lower.contains("fn ")
        || lower.contains("class ")
        || lower.contains("function ")
        || lower.contains("impl ")
        || lower.contains("use std::")
        || lower.contains("def ")
        || lower.contains("-----begin private key-----")
    {
        push_code(&mut codes, RedactionCode::CodeExcerpt);
    }
    sort_codes(&mut codes);
    codes
}

fn redacted_text(input: &str, codes: &[RedactionCode]) -> String {
    if codes.contains(&RedactionCode::CodeExcerpt) {
        return CODE_EXCERPT_PLACEHOLDER.into();
    }
    let lower = input.to_ascii_lowercase();
    let mut placeholders = Vec::new();
    if contains_confidential_marker_phrase(&lower) {
        placeholders.push(CONFIDENTIAL_PLACEHOLDER);
    }
    if contains_phi_phrase(&lower) {
        placeholders.push(PHI_PLACEHOLDER);
    }
    if contains_customer_private_phrase(&lower) {
        placeholders.push(CUSTOMER_PRIVATE_PLACEHOLDER);
    }
    if !placeholders.is_empty() {
        return placeholders.join(" ");
    }

    let mut text = redact_ssns(input);
    text = redact_cards(&text);
    let url_ranges = url_ranges(&text);
    text = replace_ranges(&text, &url_ranges, URL_PLACEHOLDER);
    let path_ranges = absolute_path_ranges(&text);
    text = replace_ranges(&text, &path_ranges, PATH_PLACEHOLDER);
    let bearer_ranges = bearer_token_ranges(&text);
    text = replace_ranges(&text, &bearer_ranges, TOKEN_PLACEHOLDER);
    let secret_ranges = secret_assignment_ranges(&text);
    replace_ranges(&text, &secret_ranges, SECRET_PLACEHOLDER)
}

fn contains_confidential_marker_phrase(lower: &str) -> bool {
    lower.contains("nda")
        || lower.contains("non-disclosure")
        || lower.contains("non disclosure")
        || lower.contains("confidential")
}

fn contains_phi_phrase(lower: &str) -> bool {
    lower.contains("phi:")
        || lower.contains("protected health")
        || lower.contains("patient:")
        || lower.contains("medical record")
}

fn contains_customer_private_phrase(lower: &str) -> bool {
    lower.contains("private customer")
        || lower.contains("customer private")
        || lower.contains("customer-private")
}

fn contains_secret_material(input: &str) -> bool {
    !url_ranges(input).is_empty()
        || !absolute_path_ranges(input).is_empty()
        || !bearer_token_ranges(input).is_empty()
        || !secret_assignment_ranges(input).is_empty()
}

fn contains_ssn(input: &str) -> bool {
    input.as_bytes().windows(11).any(ssn_window)
}

fn ssn_window(window: &[u8]) -> bool {
    window.len() == 11
        && window[0].is_ascii_digit()
        && window[1].is_ascii_digit()
        && window[2].is_ascii_digit()
        && window[3] == b'-'
        && window[4].is_ascii_digit()
        && window[5].is_ascii_digit()
        && window[6] == b'-'
        && window[7].is_ascii_digit()
        && window[8].is_ascii_digit()
        && window[9].is_ascii_digit()
        && window[10].is_ascii_digit()
}

fn redact_ssns(input: &str) -> String {
    let mut output = String::new();
    let bytes = input.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if index + 11 <= bytes.len() && ssn_window(&bytes[index..index + 11]) {
            output.push_str(SSN_PLACEHOLDER);
            index += 11;
        } else if let Some(next) = input[index..].chars().next() {
            output.push(next);
            index += next.len_utf8();
        } else {
            break;
        }
    }
    output
}

fn contains_card(input: &str) -> bool {
    card_ranges(input).next().is_some()
}

fn redact_cards(input: &str) -> String {
    let mut output = String::new();
    let mut cursor = 0;
    for (start, end) in card_ranges(input) {
        output.push_str(&input[cursor..start]);
        output.push_str(CARD_PLACEHOLDER);
        cursor = end;
    }
    output.push_str(&input[cursor..]);
    output
}

fn card_ranges(input: &str) -> impl Iterator<Item = (usize, usize)> + '_ {
    let mut ranges = Vec::new();
    let mut start = None;
    let mut digit_count = 0usize;
    let mut last_digit_end = 0usize;

    for (index, ch) in input.char_indices() {
        if ch.is_ascii_digit() || ch == ' ' || ch == '-' {
            if start.is_none() && ch.is_ascii_digit() {
                start = Some(index);
            }
            if start.is_some() && ch.is_ascii_digit() {
                digit_count += 1;
                last_digit_end = index + ch.len_utf8();
            }
        } else if let Some(range_start) = start.take() {
            if (13..=19).contains(&digit_count) {
                ranges.push((range_start, last_digit_end));
            }
            digit_count = 0;
            last_digit_end = 0;
        }
    }
    if let Some(range_start) = start {
        if (13..=19).contains(&digit_count) {
            ranges.push((range_start, last_digit_end));
        }
    }
    ranges.into_iter()
}

const BEARER_KEYWORD: &str = "bearer";
const BEARER_TOKEN_MIN_LEN: usize = 8;
const SECRET_VALUE_MIN_LEN: usize = 4;
const SECRET_ASSIGNMENT_KEYWORDS: &[&str] = &[
    "access_key",
    "api-key",
    "api_key",
    "apikey",
    "passwd",
    "password",
    "private_key",
    "secret",
    "token",
];
const ABSOLUTE_PATH_MARKERS: &[&str] = &["/Users/", "/home/"];
const URL_SCHEME_MARKERS: &[&str] = &[
    "http://",
    "https://",
    "mongodb://",
    "mysql://",
    "postgres://",
    "postgresql://",
    "redis://",
    "sqlite://",
];

fn is_secret_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b'+' | b'/' | b'=' | b'-')
}

fn is_run_terminator_byte(byte: u8) -> bool {
    byte.is_ascii_whitespace() || matches!(byte, b'"' | b'\'' | b'`')
}

fn bearer_token_ranges(input: &str) -> Vec<(usize, usize)> {
    let lower = input.to_ascii_lowercase();
    let bytes = input.as_bytes();
    let mut ranges = Vec::new();
    let mut search = 0;
    while let Some(found) = lower[search..].find(BEARER_KEYWORD) {
        let start = search + found;
        let keyword_end = start + BEARER_KEYWORD.len();
        search = keyword_end;
        if start > 0 && bytes[start - 1].is_ascii_alphanumeric() {
            continue;
        }
        let mut token_start = keyword_end;
        while token_start < bytes.len() && bytes[token_start] == b' ' {
            token_start += 1;
        }
        if token_start == keyword_end {
            continue;
        }
        let mut token_end = token_start;
        while token_end < bytes.len() && is_secret_token_byte(bytes[token_end]) {
            token_end += 1;
        }
        let token = &bytes[token_start..token_end];
        if token.len() >= BEARER_TOKEN_MIN_LEN
            && token.iter().any(|byte| !byte.is_ascii_alphabetic())
        {
            ranges.push((start, token_end));
            search = token_end;
        }
    }
    sorted_non_overlapping(ranges)
}

fn secret_assignment_ranges(input: &str) -> Vec<(usize, usize)> {
    let lower = input.to_ascii_lowercase();
    let bytes = input.as_bytes();
    let mut ranges = Vec::new();
    for keyword in SECRET_ASSIGNMENT_KEYWORDS {
        let mut search = 0;
        while let Some(found) = lower[search..].find(keyword) {
            let keyword_end = search + found + keyword.len();
            search = keyword_end;
            let mut separator = keyword_end;
            while separator < bytes.len() && bytes[separator] == b' ' {
                separator += 1;
            }
            if separator >= bytes.len() || !matches!(bytes[separator], b':' | b'=') {
                continue;
            }
            let mut value_start = separator + 1;
            while value_start < bytes.len() && bytes[value_start] == b' ' {
                value_start += 1;
            }
            let mut value_end = value_start;
            while value_end < bytes.len() && !bytes[value_end].is_ascii_whitespace() {
                value_end += 1;
            }
            if value_end - value_start >= SECRET_VALUE_MIN_LEN {
                ranges.push((value_start, value_end));
            }
        }
    }
    sorted_non_overlapping(ranges)
}

fn absolute_path_ranges(input: &str) -> Vec<(usize, usize)> {
    marker_run_ranges(input, ABSOLUTE_PATH_MARKERS, false)
}

fn url_ranges(input: &str) -> Vec<(usize, usize)> {
    marker_run_ranges(input, URL_SCHEME_MARKERS, true)
}

fn marker_run_ranges(input: &str, markers: &[&str], case_insensitive: bool) -> Vec<(usize, usize)> {
    let haystack = if case_insensitive {
        input.to_ascii_lowercase()
    } else {
        input.to_owned()
    };
    let bytes = input.as_bytes();
    let mut ranges = Vec::new();
    for marker in markers {
        let mut search = 0;
        while let Some(found) = haystack[search..].find(marker) {
            let start = search + found;
            let mut end = start + marker.len();
            while end < bytes.len() && !is_run_terminator_byte(bytes[end]) {
                end += 1;
            }
            ranges.push((start, end));
            search = end;
        }
    }
    sorted_non_overlapping(ranges)
}

fn sorted_non_overlapping(mut ranges: Vec<(usize, usize)>) -> Vec<(usize, usize)> {
    ranges.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::new();
    for (start, end) in ranges {
        if let Some(last) = merged.last_mut() {
            if start < last.1 {
                last.1 = last.1.max(end);
                continue;
            }
        }
        merged.push((start, end));
    }
    merged
}

fn replace_ranges(input: &str, ranges: &[(usize, usize)], placeholder: &str) -> String {
    if ranges.is_empty() {
        return input.to_owned();
    }
    let mut output = String::new();
    let mut cursor = 0;
    for &(start, end) in ranges {
        output.push_str(&input[cursor..start]);
        output.push_str(placeholder);
        cursor = end;
    }
    output.push_str(&input[cursor..]);
    output
}

fn truncate_with_marker(input: &str, max_len: usize) -> String {
    let marker_len = TRUNCATION_MARKER.len();
    let content_limit = max_len.saturating_sub(marker_len);
    let mut boundary = 0;
    for (index, ch) in input.char_indices() {
        let next = index + ch.len_utf8();
        if next > content_limit {
            break;
        }
        boundary = next;
    }
    let mut output = input[..boundary].to_owned();
    output.push_str(TRUNCATION_MARKER);
    output
}

fn push_code(codes: &mut Vec<RedactionCode>, code: RedactionCode) {
    if !codes.contains(&code) {
        codes.push(code);
    }
}

fn sort_codes(codes: &mut [RedactionCode]) {
    codes.sort_by_key(|code| redaction_rank(*code));
}

const fn redaction_rank(code: RedactionCode) -> usize {
    match code {
        RedactionCode::Ssn => 0,
        RedactionCode::Card => 1,
        RedactionCode::ConfidentialMarker => 2,
        RedactionCode::Phi => 3,
        RedactionCode::CustomerPrivate => 4,
        RedactionCode::CodeExcerpt => 5,
        RedactionCode::LengthTruncation => 6,
    }
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;
    use serde_json::json;

    use super::*;

    #[test]
    fn metadata_redaction_golden() {
        let fixture: MetadataGoldenFixture = serde_json::from_str(include_str!(
            "../fixtures/metadata/safe_metadata_golden.json"
        ))
        .expect("parse metadata golden fixture");
        for case in fixture.cases {
            let field = parse_fixture_field(&case.field);
            assert_eq!(
                serde_json::to_value(sanitize_metadata(field, &case.input))
                    .expect("serialize metadata golden case"),
                case.stored,
                "metadata golden fixture case {}",
                case.field
            );
        }

        assert_eq!(
            serde_json::to_value(sanitize_metadata(MetadataField::Title, "Safe title"))
                .expect("serialize safe metadata"),
            expected_json(
                SafeMetadataDecision::Allow,
                "Safe title",
                Vec::new(),
                "Safe title",
                false,
            )
        );

        let ssn_input = "Customer SSN 123-45-6789";
        assert_eq!(
            serde_json::to_value(sanitize_metadata(MetadataField::Summary, ssn_input))
                .expect("serialize SSN metadata"),
            expected_json(
                SafeMetadataDecision::Redact,
                "Customer SSN [REDACTED_SSN]",
                vec![RedactionCode::Ssn],
                ssn_input,
                false,
            )
        );

        let card_input = "Use card 4111 1111 1111 1111";
        assert_eq!(
            serde_json::to_value(sanitize_metadata(MetadataField::Summary, card_input))
                .expect("serialize card metadata"),
            expected_json(
                SafeMetadataDecision::Redact,
                "Use card [REDACTED_CARD]",
                vec![RedactionCode::Card],
                card_input,
                false,
            )
        );

        let confidential_input = "CONFIDENTIAL private customer PHI: patient detail";
        assert_eq!(
            serde_json::to_value(sanitize_metadata(
                MetadataField::ReceiptFreeText,
                confidential_input,
            ))
            .expect("serialize confidential metadata"),
            expected_json(
                SafeMetadataDecision::Redact,
                "[REDACTED_CONFIDENTIAL] [REDACTED_PHI] [REDACTED_CUSTOMER_PRIVATE]",
                vec![
                    RedactionCode::ConfidentialMarker,
                    RedactionCode::Phi,
                    RedactionCode::CustomerPrivate,
                ],
                confidential_input,
                false,
            )
        );

        let code_input = "fn main() { println!(\"secret\"); }";
        assert_eq!(
            serde_json::to_value(sanitize_metadata(MetadataField::Summary, code_input))
                .expect("serialize code metadata"),
            expected_json(
                SafeMetadataDecision::Reject,
                "[REDACTED_CODE_EXCERPT]",
                vec![RedactionCode::CodeExcerpt],
                code_input,
                false,
            )
        );

        let long = "é".repeat(90);
        let truncated = sanitize_metadata(MetadataField::Title, &long);
        assert_eq!(truncated.decision, SafeMetadataDecision::Redact);
        assert_eq!(
            truncated.redaction_codes,
            vec![RedactionCode::LengthTruncation]
        );
        assert!(truncated.text.ends_with(TRUNCATION_MARKER));
        assert!(truncated.text.len() <= 160);
        assert_eq!(truncated.byte_len, 180);
    }

    #[test]
    fn metadata_redacts_tokens_secret_assignments_paths_and_urls() {
        let cases: [(&str, &str); 7] = [
            (
                "Retry failed with Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIifQ.sig123 returned 401",
                "Retry failed with Authorization: [REDACTED_TOKEN] returned 401",
            ),
            (
                "Set DATABASE_PASSWORD=hunter2rotation before rerun",
                "Set DATABASE_PASSWORD=[REDACTED_SECRET] before rerun",
            ),
            (
                "Rotate api_key: svc-9f8e7d6c5b4a then redeploy",
                "Rotate api_key: [REDACTED_SECRET] then redeploy",
            ),
            (
                "Wrote report to /Users/operator/repos/exo/report.json for review",
                "Wrote report to [REDACTED_PATH] for review",
            ),
            (
                "Logs rotated at /home/ubuntu/logs/app.log overnight",
                "Logs rotated at [REDACTED_PATH] overnight",
            ),
            (
                "Fetched https://internal.example.com/admin?page=2 during the run",
                "Fetched [REDACTED_URL] during the run",
            ),
            (
                "Connection used postgres://writer:hunterpass@localhost:5433/dagdb directly",
                "Connection used [REDACTED_URL] directly",
            ),
        ];
        for (input, expected_text) in cases {
            assert_eq!(
                serde_json::to_value(sanitize_metadata(MetadataField::Summary, input))
                    .expect("serialize secret material metadata"),
                expected_json(
                    SafeMetadataDecision::Redact,
                    expected_text,
                    vec![RedactionCode::ConfidentialMarker],
                    input,
                    false,
                ),
                "secret material case: {input}"
            );
        }
    }

    #[test]
    fn metadata_clean_summaries_pass_through_unchanged() {
        for input in [
            "M48 live proof generated from actual MCP retrieve, live writeback, \
             post-writeback relink, and continuation packet assembly without fixtures.",
            "Safe answer summary",
            "Selected 12 memory refs for task writeback relink within token budget 2048",
        ] {
            let metadata = sanitize_metadata(MetadataField::Summary, input);
            assert_eq!(
                metadata.decision,
                SafeMetadataDecision::Allow,
                "clean summary must stay allowed: {input}"
            );
            assert_eq!(
                metadata.text, input,
                "clean summary text must pass through unchanged: {input}"
            );
            assert!(
                metadata.redaction_codes.is_empty(),
                "clean summary must carry no redaction codes: {input}"
            );
        }
    }

    #[test]
    fn metadata_rejects_runtime_payloads() {
        let error = sanitize_runtime_metadata(
            MetadataField::Summary,
            "```rust\nfn main() { println!(\"secret\"); }\n```",
        )
        .expect_err("raw code excerpts must reject before persistence");
        assert!(matches!(
            error,
            MetadataError::Rejected {
                field: MetadataField::Summary,
                ..
            }
        ));

        let keywords = vec!["safe".to_owned(); 33];
        assert!(matches!(
            sanitize_keywords(&keywords),
            Err(MetadataError::TooManyKeywords {
                count: 33,
                limit: 32
            })
        ));

        let safe = sanitize_runtime_metadata(MetadataField::Keyword, "public")
            .expect("safe keyword metadata should persist");
        assert_eq!(safe.decision, SafeMetadataDecision::Allow);
    }

    #[test]
    fn metadata_detection_variants_are_deterministic() {
        for input in [
            "NDA restricted",
            "non-disclosure restricted",
            "non disclosure restricted",
            "confidential restricted",
        ] {
            assert_eq!(
                sanitize_metadata(MetadataField::ResponseExcerpt, input).redaction_codes,
                vec![RedactionCode::ConfidentialMarker]
            );
        }

        for input in [
            "PHI: detail",
            "protected health detail",
            "patient: detail",
            "medical record detail",
        ] {
            assert_eq!(
                sanitize_metadata(MetadataField::ResponseExcerpt, input).redaction_codes,
                vec![RedactionCode::Phi]
            );
        }

        for input in [
            "private customer note",
            "customer private note",
            "customer-private note",
        ] {
            assert_eq!(
                sanitize_metadata(MetadataField::ResponseExcerpt, input).redaction_codes,
                vec![RedactionCode::CustomerPrivate]
            );
        }

        for input in [
            "```python\nprint('x')\n```",
            "class Secret {}",
            "function secret() {}",
            "impl Secret {}",
            "use std::fs;",
            "def secret(): pass",
            "-----BEGIN PRIVATE KEY-----",
        ] {
            let metadata = sanitize_metadata(MetadataField::ResponseExcerpt, input);
            assert_eq!(metadata.decision, SafeMetadataDecision::Reject);
            assert_eq!(metadata.redaction_codes, vec![RedactionCode::CodeExcerpt]);
            assert_eq!(metadata.text, CODE_EXCERPT_PLACEHOLDER);
        }
    }

    #[test]
    fn metadata_card_and_truncation_edges_are_bounded() {
        assert_eq!(
            card_ranges("prefix 1234 suffix").collect::<Vec<_>>(),
            Vec::<(usize, usize)>::new()
        );
        assert_eq!(
            card_ranges("prefix 1234567890123 suffix").collect::<Vec<_>>(),
            vec![(7, 20)]
        );
        assert_eq!(
            card_ranges("prefix 12345678901234567890 suffix").collect::<Vec<_>>(),
            Vec::<(usize, usize)>::new()
        );

        let redacted = sanitize_metadata(
            MetadataField::Summary,
            "one 4111111111111 and two 5500-0000-0000-0004",
        );
        assert_eq!(redacted.redaction_codes, vec![RedactionCode::Card]);
        assert_eq!(redacted.text, "one [REDACTED_CARD] and two [REDACTED_CARD]");

        let exact = "a".repeat(160);
        let exact_metadata = sanitize_metadata(MetadataField::Title, &exact);
        assert_eq!(exact_metadata.decision, SafeMetadataDecision::Allow);
        assert!(!exact_metadata.truncated);

        let confidential_long = format!("{}{}", "confidential ", "a".repeat(600));
        let confidential_metadata =
            sanitize_metadata(MetadataField::ResponseExcerpt, &confidential_long);
        assert_eq!(
            confidential_metadata.redaction_codes,
            vec![RedactionCode::ConfidentialMarker]
        );
        assert!(!confidential_metadata.truncated);
    }

    fn expected_json(
        decision: SafeMetadataDecision,
        text: &str,
        redaction_codes: Vec<RedactionCode>,
        input: &str,
        truncated: bool,
    ) -> serde_json::Value {
        json!({
            "decision": decision,
            "text": text,
            "redaction_codes": redaction_codes,
            "original_hash": Hash256::digest(input.as_bytes()).to_string(),
            "truncated": truncated,
            "byte_len": u32::try_from(input.len()).expect("fixture input length fits u32"),
        })
    }

    #[derive(Debug, Deserialize)]
    struct MetadataGoldenFixture {
        cases: Vec<MetadataGoldenCase>,
    }

    #[derive(Debug, Deserialize)]
    struct MetadataGoldenCase {
        field: String,
        input: String,
        stored: serde_json::Value,
    }

    fn parse_fixture_field(field: &str) -> MetadataField {
        match field {
            "title" => MetadataField::Title,
            "summary" => MetadataField::Summary,
            "keyword" => MetadataField::Keyword,
            "validation_notes" => MetadataField::ValidationNotes,
            "council_notes" => MetadataField::CouncilNotes,
            "receipt_free_text" => MetadataField::ReceiptFreeText,
            "response_excerpt" => MetadataField::ResponseExcerpt,
            _ => panic!("unknown metadata fixture field {field}"),
        }
    }
}
