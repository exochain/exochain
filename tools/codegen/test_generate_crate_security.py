#!/usr/bin/env python3
"""Security regression tests for EXOCHAIN crate scaffolding."""

import importlib.util
import pathlib
import unittest


GENERATOR_PATH = pathlib.Path(__file__).with_name("generate_crate.py")
SPEC = importlib.util.spec_from_file_location("generate_crate", GENERATOR_PATH)
generate_crate = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(generate_crate)


class GenerateCrateSecurityTests(unittest.TestCase):
    def test_module_verify_requires_expected_canonical_digest(self) -> None:
        module_source = generate_crate.generate_module_rs("exo-audit", "trail")

        self.assertIn("pub fn canonical_digest(&self) -> Result<Hash256", module_source)
        self.assertIn("exo_core::hash::hash_structured(self)", module_source)
        self.assertIn(
            "fn verify(&self, expected_digest: &Hash256)",
            module_source,
        )
        self.assertIn("Ok(self.canonical_digest()? == *expected_digest)", module_source)
        self.assertNotIn("Ok(true)", module_source)

    def test_integration_verify_uses_caller_supplied_digest(self) -> None:
        test_source = generate_crate.generate_integration_test("exo-audit", "trail")

        self.assertIn("let digest = item.canonical_digest()", test_source)
        self.assertIn("item.verify(&digest)", test_source)
        self.assertNotIn("item.verify().expect", test_source)

    def test_generated_tests_use_current_timestamp_constructor(self) -> None:
        module_source = generate_crate.generate_module_rs("exo-audit", "trail")
        integration_source = generate_crate.generate_integration_test("exo-audit", "trail")

        self.assertNotIn("node_id", module_source)
        self.assertNotIn("node_id", integration_source)
        self.assertNotIn("DeterministicMap", module_source)
        self.assertIn("Timestamp::new(1_700_000_000_000, 0)", module_source)
        self.assertIn("Timestamp::new(1_700_000_000_000, 0)", integration_source)

    def test_generated_tests_do_not_emit_unwrap_or_expect(self) -> None:
        module_source = generate_crate.generate_module_rs("exo-audit", "trail")
        integration_source = generate_crate.generate_integration_test("exo-audit", "trail")

        self.assertNotIn(".unwrap()", module_source)
        self.assertNotIn(".expect(", module_source)
        self.assertNotIn(".unwrap()", integration_source)
        self.assertNotIn(".expect(", integration_source)


if __name__ == "__main__":
    unittest.main()
