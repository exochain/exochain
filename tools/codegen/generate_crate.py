#!/usr/bin/env python3
# Copyright 2026 Exochain Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""
EXOCHAIN Crate Scaffolding Generator

Generates a new crate skeleton that conforms to the constitutional trust fabric
requirements: determinism enforcement, BTreeMap-only collections, no floats,
canonical serialization, and standard test scaffolding.

Usage:
    python3 tools/codegen/generate_crate.py <crate_name> [module1] [module2] ...

Example:
    python3 tools/codegen/generate_crate.py exo-audit trail verifier reporter

This generates:
    crates/exo-audit/
        Cargo.toml
        src/
            lib.rs
            error.rs
            trail.rs
            verifier.rs
            reporter.rs
        tests/
            trail_tests.rs
            verifier_tests.rs
            reporter_tests.rs
"""

import os
import sys
import textwrap
from pathlib import Path
from datetime import datetime, timezone


def to_snake_case(name: str) -> str:
    """Convert kebab-case to snake_case."""
    return name.replace("-", "_")


def to_pascal_case(name: str) -> str:
    """Convert kebab-case to PascalCase."""
    return "".join(word.capitalize() for word in name.split("-"))


def to_title(name: str) -> str:
    """Convert kebab-case to Title Words."""
    return " ".join(word.capitalize() for word in name.split("-"))


def find_workspace_root() -> Path:
    """Walk up from CWD to find Cargo.toml with [workspace]."""
    current = Path.cwd()
    while current != current.parent:
        cargo = current / "Cargo.toml"
        if cargo.exists() and "[workspace]" in cargo.read_text():
            return current
        current = current.parent
    # Fallback: use the script's location
    script_dir = Path(__file__).resolve().parent
    return script_dir.parent.parent


def generate_cargo_toml(crate_name: str, modules: list[str]) -> str:
    """Generate Cargo.toml with workspace dependencies."""
    snake = to_snake_case(crate_name)
    title = to_title(crate_name)
    return textwrap.dedent(f"""\
        [package]
        name = "{crate_name}"
        description = "EXOCHAIN constitutional trust fabric --- {title}"
        version.workspace = true
        edition.workspace = true
        rust-version.workspace = true
        license.workspace = true
        repository.workspace = true

        [lints]
        workspace = true

        [dependencies]
        exo-core = {{ path = "../exo-core" }}
        serde = {{ workspace = true }}
        serde_json = {{ workspace = true }}
        blake3 = {{ workspace = true }}
        thiserror = {{ workspace = true }}
        tracing = {{ workspace = true }}
        uuid = {{ workspace = true }}
        chrono = {{ workspace = true }}
        indexmap = {{ workspace = true }}

        [dev-dependencies]
        proptest = {{ workspace = true }}
        serde_json = {{ workspace = true }}
        tokio-test = {{ workspace = true }}
    """)


def generate_lib_rs(crate_name: str, modules: list[str]) -> str:
    """Generate src/lib.rs with module declarations and re-exports."""
    title = to_title(crate_name)
    snake = to_snake_case(crate_name)
    pascal = to_pascal_case(crate_name)

    mod_decls = "\n".join(f"pub mod {m};" for m in modules)
    mod_decls = f"pub mod error;\n{mod_decls}"

    re_exports = [f"pub use error::{pascal}Error;"]
    for m in modules:
        struct_name = to_pascal_case(m)
        re_exports.append(f"pub use {m}::{struct_name};")

    re_export_block = "\n".join(re_exports)

    return textwrap.dedent(f"""\
        //! # {crate_name}
        //!
        //! {title} module for the EXOCHAIN constitutional trust fabric.
        //!
        //! **Determinism contract**: this crate enforces absolute determinism.
        //! - No floating-point arithmetic.
        //! - `BTreeMap` only --- `HashMap` is never used.
        //! - Canonical CBOR serialization for all hashing.
        //! - Hybrid Logical Clock for causal ordering.

        {mod_decls}

        // Re-export primary types.
        {re_export_block}
    """)


def generate_error_rs(crate_name: str, modules: list[str]) -> str:
    """Generate src/error.rs with typed error variants."""
    pascal = to_pascal_case(crate_name)

    variants = []
    for m in modules:
        mod_pascal = to_pascal_case(m)
        variants.append(f"""\
    /// An error occurred in the {m} module.
    #[error("{m} error: {{reason}}")]
    {mod_pascal}Error {{ reason: String }},""")

    variant_block = "\n\n".join(variants)

    return textwrap.dedent(f"""\
        //! Error types for {crate_name}.
        //!
        //! Every failure mode has a dedicated variant ensuring exhaustive
        //! error handling at compile time.

        use thiserror::Error;

        /// Unified error type for all `{crate_name}` operations.
        #[derive(Debug, Clone, PartialEq, Eq, Error)]
        pub enum {pascal}Error {{
            /// A constitutional invariant was violated.
            #[error("invariant violation: {{invariant}}: {{detail}}")]
            InvariantViolation {{ invariant: String, detail: String }},

            /// An operation was not authorized.
            #[error("unauthorized: {{reason}}")]
            Unauthorized {{ reason: String }},

        {variant_block}

            /// An internal error that should not occur in correct operation.
            #[error("internal error: {{0}}")]
            Internal(String),
        }}

        /// Convenience result type for {crate_name}.
        pub type Result<T> = core::result::Result<T, {pascal}Error>;
    """)


def generate_module_rs(crate_name: str, module_name: str) -> str:
    """Generate src/<module>.rs with standard struct/trait/test skeleton."""
    mod_pascal = to_pascal_case(module_name)
    mod_title = to_title(module_name)
    crate_pascal = to_pascal_case(crate_name)
    crate_snake = to_snake_case(crate_name)

    return textwrap.dedent(f"""\
        //! {mod_title} module.
        //!
        //! Part of the {crate_name} constitutional trust fabric crate.

        use std::collections::BTreeMap;

        use exo_core::{{DeterministicMap, Hash256, Timestamp}};
        use serde::{{Deserialize, Serialize}};

        use crate::error::{crate_pascal}Error;

        // ---------------------------------------------------------------------------
        // Types
        // ---------------------------------------------------------------------------

        /// Primary type for the {module_name} module.
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        pub struct {mod_pascal} {{
            /// Unique identifier.
            pub id: String,
            /// Creation timestamp (HLC).
            pub created_at: Timestamp,
            /// Arbitrary metadata (deterministic ordering via BTreeMap).
            pub metadata: BTreeMap<String, String>,
        }}

        impl {mod_pascal} {{
            /// Create a new instance with the given identifier and timestamp.
            #[must_use]
            pub fn new(id: impl Into<String>, created_at: Timestamp) -> Self {{
                Self {{
                    id: id.into(),
                    created_at,
                    metadata: BTreeMap::new(),
                }}
            }}

            /// Add a metadata entry.
            pub fn set_metadata(
                &mut self,
                key: impl Into<String>,
                value: impl Into<String>,
            ) {{
                self.metadata.insert(key.into(), value.into());
            }}

            /// Validate this instance against constitutional invariants.
            pub fn validate(&self) -> Result<(), {crate_pascal}Error> {{
                if self.id.is_empty() {{
                    return Err({crate_pascal}Error::{mod_pascal}Error {{
                        reason: "id must not be empty".into(),
                    }});
                }}
                Ok(())
            }}
        }}

        // ---------------------------------------------------------------------------
        // Trait definition
        // ---------------------------------------------------------------------------

        /// Trait for types that participate in {module_name} operations.
        pub trait {mod_pascal}Ops {{
            /// Process this item, producing a deterministic result.
            fn process(&self) -> Result<{mod_pascal}Result, {crate_pascal}Error>;

            /// Verify integrity of this item.
            fn verify(&self) -> Result<bool, {crate_pascal}Error>;
        }}

        /// Result of a {module_name} processing operation.
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        pub struct {mod_pascal}Result {{
            /// Whether the operation succeeded.
            pub success: bool,
            /// Detail message.
            pub detail: String,
            /// Output data.
            pub output: BTreeMap<String, String>,
        }}

        impl {mod_pascal}Ops for {mod_pascal} {{
            fn process(&self) -> Result<{mod_pascal}Result, {crate_pascal}Error> {{
                self.validate()?;
                Ok({mod_pascal}Result {{
                    success: true,
                    detail: format!("{module_name} {{}} processed", self.id),
                    output: self.metadata.clone(),
                }})
            }}

            fn verify(&self) -> Result<bool, {crate_pascal}Error> {{
                self.validate()?;
                Ok(true)
            }}
        }}

        // ---------------------------------------------------------------------------
        // Tests
        // ---------------------------------------------------------------------------

        #[cfg(test)]
        mod tests {{
            use super::*;

            fn test_timestamp() -> Timestamp {{
                Timestamp {{
                    physical_ms: 1_700_000_000_000,
                    logical: 0,
                    node_id: 1,
                }}
            }}

            #[test]
            fn test_new() {{
                let item = {mod_pascal}::new("test-001", test_timestamp());
                assert_eq!(item.id, "test-001");
                assert!(item.metadata.is_empty());
            }}

            #[test]
            fn test_metadata() {{
                let mut item = {mod_pascal}::new("test-002", test_timestamp());
                item.set_metadata("key", "value");
                assert_eq!(item.metadata.get("key").unwrap(), "value");
            }}

            #[test]
            fn test_validate_empty_id_fails() {{
                let item = {mod_pascal}::new("", test_timestamp());
                assert!(item.validate().is_err());
            }}

            #[test]
            fn test_validate_ok() {{
                let item = {mod_pascal}::new("valid-id", test_timestamp());
                assert!(item.validate().is_ok());
            }}

            #[test]
            fn test_process() {{
                let item = {mod_pascal}::new("proc-001", test_timestamp());
                let result = item.process().unwrap();
                assert!(result.success);
            }}

            #[test]
            fn test_verify() {{
                let item = {mod_pascal}::new("verify-001", test_timestamp());
                assert!(item.verify().unwrap());
            }}

            #[test]
            fn test_deterministic_serialization() {{
                let mut item = {mod_pascal}::new("ser-001", test_timestamp());
                item.set_metadata("b_key", "second");
                item.set_metadata("a_key", "first");

                let json1 = serde_json::to_string(&item).unwrap();
                let json2 = serde_json::to_string(&item).unwrap();
                assert_eq!(json1, json2, "serialization must be deterministic");

                // BTreeMap guarantees key ordering
                assert!(
                    json1.find("a_key").unwrap() < json1.find("b_key").unwrap(),
                    "BTreeMap must serialize in sorted key order"
                );
            }}
        }}
    """)


def generate_integration_test(crate_name: str, module_name: str) -> str:
    """Generate tests/<module>_tests.rs integration test."""
    crate_snake = to_snake_case(crate_name)
    mod_pascal = to_pascal_case(module_name)

    return textwrap.dedent(f"""\
        //! Integration tests for {crate_name}::{module_name}.

        use exo_core::Timestamp;
        use {crate_snake}::{mod_pascal};
        use {crate_snake}::{module_name}::{mod_pascal}Ops;

        fn test_timestamp() -> Timestamp {{
            Timestamp {{
                physical_ms: 1_700_000_000_000,
                logical: 0,
                node_id: 1,
            }}
        }}

        #[test]
        fn integration_round_trip() {{
            let mut item = {mod_pascal}::new("int-001", test_timestamp());
            item.set_metadata("env", "integration");

            // Validate
            item.validate().expect("should validate");

            // Process
            let result = item.process().expect("should process");
            assert!(result.success);

            // Verify
            assert!(item.verify().expect("should verify"));

            // Serialize round-trip
            let json = serde_json::to_string(&item).expect("serialize");
            let restored: {mod_pascal} = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(item, restored, "round-trip must be lossless");
        }}

        #[test]
        fn integration_determinism() {{
            // Two identical items must produce identical outputs
            let a = {mod_pascal}::new("det-001", test_timestamp());
            let b = {mod_pascal}::new("det-001", test_timestamp());

            let result_a = a.process().expect("a");
            let result_b = b.process().expect("b");
            assert_eq!(result_a, result_b, "determinism: same input -> same output");
        }}
    """)


def update_workspace_cargo_toml(workspace_root: Path, crate_name: str) -> None:
    """Add the new crate to the workspace members list."""
    cargo_toml = workspace_root / "Cargo.toml"
    content = cargo_toml.read_text()

    member_entry = f'    "crates/{crate_name}",'
    if member_entry in content:
        print(f"  [skip] {crate_name} already in workspace members")
        return

    # Insert before the closing bracket of members
    marker = "]"
    # Find the members array
    members_start = content.find("members = [")
    if members_start == -1:
        print("  [warn] Could not find members array in Cargo.toml")
        return

    # Find the closing bracket after members
    members_end = content.find("]", members_start)
    if members_end == -1:
        print("  [warn] Could not find end of members array")
        return

    new_content = (
        content[:members_end]
        + f'    "crates/{crate_name}",\n'
        + content[members_end:]
    )
    cargo_toml.write_text(new_content)
    print(f"  [done] Added {crate_name} to workspace members")


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: generate_crate.py <crate_name> [module1] [module2] ...")
        print()
        print("Example:")
        print("  python3 tools/codegen/generate_crate.py exo-audit trail verifier reporter")
        sys.exit(1)

    crate_name = sys.argv[1]
    modules = sys.argv[2:] if len(sys.argv) > 2 else ["core"]

    # Validate crate name
    if not crate_name.startswith("exo-") and crate_name != "decision-forum":
        print(f"Warning: crate name '{crate_name}' does not follow exo-* convention")
        response = input("Continue? [y/N] ")
        if response.lower() != "y":
            sys.exit(0)

    workspace_root = find_workspace_root()
    crate_dir = workspace_root / "crates" / crate_name
    src_dir = crate_dir / "src"
    tests_dir = crate_dir / "tests"

    if crate_dir.exists():
        print(f"Error: {crate_dir} already exists")
        sys.exit(1)

    print(f"Generating crate: {crate_name}")
    print(f"  Modules: {', '.join(modules)}")
    print(f"  Location: {crate_dir}")
    print()

    # Create directories
    src_dir.mkdir(parents=True)
    tests_dir.mkdir(parents=True)

    # Generate files
    files = {
        crate_dir / "Cargo.toml": generate_cargo_toml(crate_name, modules),
        src_dir / "lib.rs": generate_lib_rs(crate_name, modules),
        src_dir / "error.rs": generate_error_rs(crate_name, modules),
    }

    for module in modules:
        files[src_dir / f"{module}.rs"] = generate_module_rs(crate_name, module)
        files[tests_dir / f"{module}_tests.rs"] = generate_integration_test(
            crate_name, module
        )

    for path, content in files.items():
        path.write_text(content)
        print(f"  [created] {path.relative_to(workspace_root)}")

    # Update workspace Cargo.toml
    print()
    update_workspace_cargo_toml(workspace_root, crate_name)

    print()
    print(f"Crate '{crate_name}' generated successfully.")
    print()
    print("Next steps:")
    print(f"  1. cd {crate_dir}")
    print(f"  2. cargo build -p {crate_name}")
    print(f"  3. cargo test -p {crate_name}")
    print(f"  4. Customize the generated types and traits for your domain")


if __name__ == "__main__":
    main()
