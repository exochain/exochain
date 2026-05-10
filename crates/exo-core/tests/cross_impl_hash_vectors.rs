// Copyright 2026 Exochain Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

use std::{
    env, fs,
    path::{Path, PathBuf},
};

use exo_core::hash::canonical_hash;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct HashVector {
    input: HashVectorInput,
    expected: HashVectorExpected,
}

#[derive(Debug, Deserialize)]
struct HashVectorInput {
    canonical_cbor_hex: String,
}

#[derive(Debug, Deserialize)]
struct HashVectorExpected {
    blake3_hex: String,
}

#[test]
fn cross_impl_hash_vectors_match_golden() -> Result<(), Box<dyn std::error::Error>> {
    let Some(vectors_dir) = env::var_os("EXOCHAIN_CROSS_IMPL_HASH_VECTORS") else {
        return Ok(());
    };

    let mut vector_files = Vec::new();
    for entry in fs::read_dir(PathBuf::from(vectors_dir))? {
        let path = entry?.path();
        if path
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            vector_files.push(path);
        }
    }
    vector_files.sort();

    let mut checked = 0usize;
    for vector_file in vector_files {
        let contents = fs::read_to_string(&vector_file)?;
        let Ok(vector) = serde_json::from_str::<HashVector>(&contents) else {
            continue;
        };

        let canonical_cbor = decode_hex(&vector.input.canonical_cbor_hex, &vector_file)?;
        let actual = canonical_hash(&canonical_cbor).to_string();
        assert_eq!(
            actual,
            vector.expected.blake3_hex.to_ascii_lowercase(),
            "{} canonical hash diverged",
            vector_file.display()
        );
        checked += 1;
    }

    assert!(
        checked > 0,
        "at least one canonical hash vector must be checked"
    );
    Ok(())
}

fn decode_hex(hex: &str, vector_file: &Path) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err(format!(
            "{} canonical_cbor_hex must be even-length",
            vector_file.display()
        ));
    }

    let decoded = hex
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = decode_hex_digit(pair[0], vector_file)?;
            let low = decode_hex_digit(pair[1], vector_file)?;
            Ok((high << 4) | low)
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(decoded)
}

fn decode_hex_digit(byte: u8, vector_file: &Path) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(format!(
            "{} canonical_cbor_hex must be hex",
            vector_file.display()
        )),
    }
}
