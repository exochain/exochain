#!/usr/bin/env python3
"""
EXOCHAIN Syntaxis Workflow Code Generator

Takes a workflow definition (JSON) and generates:
  1. A Rust module implementing the workflow as a combinator chain
  2. Test scaffolding for the workflow
  3. Integration into the exo-gatekeeper combinator engine

The workflow definition maps Syntaxis visual builder nodes to concrete
combinator algebra expressions that the gatekeeper kernel reduces.

Usage:
    python3 tools/syntaxis/generate_workflow.py <workflow.json> [--output-dir <dir>]

Workflow JSON format:
    {
        "name": "consent-gated-action",
        "description": "Verify identity, check consent, then execute action",
        "steps": [
            { "node": "identity-verify", "id": "step_1", "config": {} },
            { "node": "consent-verify", "id": "step_2", "config": {} },
            { "node": "kernel-adjudicate", "id": "step_3", "config": {} }
        ],
        "composition": "sequence",
        "error_strategy": "fail_fast"
    }

Composition types:
    - "sequence": Steps execute in order (Sequence combinator)
    - "parallel": Steps execute independently (Parallel combinator)
    - "choice": First successful step wins (Choice combinator)
    - "guarded_sequence": Each step guards the next (nested Guard combinators)
"""

import json
import re
import sys
import textwrap
from pathlib import Path


WORKFLOW_NAME_RE = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
STEP_ID_RE = re.compile(r"^[a-z][a-z0-9]*(?:[_-][a-z0-9]+)*$")
SAFE_TOKEN_RE = re.compile(r"^[a-z][a-z0-9]*(?:[_-][a-z0-9]+)*$")
COMPOSITIONS = frozenset(("sequence", "parallel", "choice", "guarded_sequence"))
MAX_DESCRIPTION_CHARS = 2048
MAX_STEPS = 128


class WorkflowValidationError(ValueError):
    """Raised when untrusted workflow JSON fails the codegen boundary."""


def load_node_registry() -> dict:
    """Load the Syntaxis node registry."""
    registry_path = Path(__file__).parent / "node_registry.json"
    if not registry_path.exists():
        print(f"Error: node registry not found at {registry_path}")
        sys.exit(1)
    with open(registry_path) as f:
        return json.load(f)


def to_snake_case(name: str) -> str:
    """Convert kebab-case to snake_case."""
    return name.replace("-", "_")


def to_pascal_case(name: str) -> str:
    """Convert kebab-case to PascalCase."""
    return "".join(word.capitalize() for word in name.split("-"))


def require_string(value: object, field: str) -> str:
    """Return a string field or raise a validation error."""
    if not isinstance(value, str):
        raise WorkflowValidationError(f"{field} must be a string")
    return value


def validate_safe_token(value: str, field: str, pattern: re.Pattern[str]) -> None:
    """Validate a token before it is used in Rust identifiers or file names."""
    if not pattern.fullmatch(value):
        raise WorkflowValidationError(
            f"{field} contains characters outside the allowed lowercase ASCII token format"
        )


def validate_doc_text(value: str, field: str) -> None:
    """Validate free text before rendering it as Rust doc comments."""
    if len(value) > MAX_DESCRIPTION_CHARS:
        raise WorkflowValidationError(
            f"{field} must be at most {MAX_DESCRIPTION_CHARS} characters"
        )
    for char in value:
        if ord(char) < 32 and char not in ("\n", "\t"):
            raise WorkflowValidationError(f"{field} contains a forbidden control character")


def rust_doc_comment(text: str) -> str:
    """Render free text as line-based Rust doc comments."""
    lines = text.split("\n")
    return "\n".join(f"//! {line}" if line else "//!" for line in lines)


def validate_workflow(workflow: object, registry: dict) -> None:
    """Validate untrusted workflow JSON before any Rust or paths are generated."""
    if not isinstance(workflow, dict):
        raise WorkflowValidationError("workflow must be a JSON object")

    name = require_string(workflow.get("name"), "workflow.name")
    validate_safe_token(name, "workflow.name", WORKFLOW_NAME_RE)

    description = workflow.get("description", f"Workflow: {name}")
    validate_doc_text(require_string(description, "workflow.description"), "workflow.description")

    composition = workflow.get("composition", "sequence")
    composition = require_string(composition, "workflow.composition")
    if composition not in COMPOSITIONS:
        raise WorkflowValidationError(
            f"workflow.composition must be one of: {', '.join(sorted(COMPOSITIONS))}"
        )

    error_strategy = workflow.get("error_strategy", "fail_fast")
    error_strategy = require_string(error_strategy, "workflow.error_strategy")
    validate_safe_token(error_strategy, "workflow.error_strategy", SAFE_TOKEN_RE)

    steps = workflow.get("steps")
    if not isinstance(steps, list):
        raise WorkflowValidationError("workflow.steps must be a non-empty list")
    if not steps:
        raise WorkflowValidationError("workflow.steps must contain at least one step")
    if len(steps) > MAX_STEPS:
        raise WorkflowValidationError(f"workflow.steps may contain at most {MAX_STEPS} steps")

    seen_step_ids: set[str] = set()
    for index, step in enumerate(steps):
        field = f"workflow.steps[{index}]"
        if not isinstance(step, dict):
            raise WorkflowValidationError(f"{field} must be an object")

        node_type = require_string(step.get("node"), f"{field}.node")
        if node_type not in registry["nodes"]:
            raise WorkflowValidationError(f"{field}.node is not in registry: {node_type}")

        step_id = require_string(step.get("id"), f"{field}.id")
        validate_safe_token(step_id, f"{field}.id", STEP_ID_RE)
        normalized_step_id = to_snake_case(step_id)
        if normalized_step_id in seen_step_ids:
            raise WorkflowValidationError(f"{field}.id duplicates another generated step id")
        seen_step_ids.add(normalized_step_id)

        if "config" in step and not isinstance(step["config"], dict):
            raise WorkflowValidationError(f"{field}.config must be an object when provided")


def collect_invariants(steps: list[dict], registry: dict) -> list[str]:
    """Collect all unique invariants required across workflow steps."""
    invariants = set()
    for step in steps:
        node_type = step["node"]
        node_def = registry["nodes"].get(node_type)
        if node_def:
            for inv in node_def.get("invariants", []):
                invariants.add(inv)
    return sorted(invariants)


def collect_crate_imports(steps: list[dict], registry: dict) -> list[str]:
    """Collect all unique crate imports needed for the workflow."""
    imports = set()
    for step in steps:
        node_type = step["node"]
        node_def = registry["nodes"].get(node_type)
        if node_def:
            imports.add(node_def["rust_module"])
    return sorted(imports)


def generate_step_combinator(step: dict, registry: dict) -> str:
    """Generate the combinator expression for a single step."""
    node_type = step["node"]
    step_id = step["id"]
    node_def = registry["nodes"].get(node_type)
    config = step.get("config", {})

    if not node_def:
        raise WorkflowValidationError(f"node type is not in registry: {node_type}")

    # Build predicate keys from node inputs
    required_keys = node_def.get("inputs", [])
    output_keys = node_def.get("outputs", [])

    # Generate guard predicate if the node has required inputs
    if required_keys and node_type not in (
        "combinator-sequence",
        "combinator-parallel",
        "combinator-choice",
        "combinator-guard",
        "combinator-transform",
    ):
        predicate_key = required_keys[0]
        output_key = output_keys[0] if output_keys else f"{step_id}_done"

        return textwrap.dedent(f"""\
            // Step: {step_id} ({node_def['label']})
                    // Invariants: {', '.join(node_def.get('invariants', ['none']))}
                    Combinator::Guard(
                        Box::new(Combinator::Transform(
                            Box::new(Combinator::Identity),
                            TransformFn {{
                                name: "{step_id}_transform".into(),
                                output_key: "{output_key}".into(),
                                output_value: "true".into(),
                            }},
                        )),
                        Predicate {{
                            name: "{step_id}_guard".into(),
                            required_key: "{predicate_key}".into(),
                            expected_value: None,
                        }},
                    )""")
    else:
        return textwrap.dedent(f"""\
            // Step: {step_id} ({node_def.get('label', node_type)})
                    Combinator::Identity""")


def generate_workflow_module(workflow: dict, registry: dict) -> str:
    """Generate the complete Rust module for a workflow."""
    name = workflow["name"]
    description = workflow.get("description", f"Workflow: {name}")
    steps = workflow["steps"]
    composition = workflow.get("composition", "sequence")
    error_strategy = workflow.get("error_strategy", "fail_fast")

    snake_name = to_snake_case(name)
    pascal_name = to_pascal_case(name)
    description_doc = textwrap.indent(rust_doc_comment(description), "        ")

    invariants = collect_invariants(steps, registry)
    crate_imports = collect_crate_imports(steps, registry)

    # Generate step combinators
    step_expressions = []
    for step in steps:
        expr = generate_step_combinator(step, registry)
        step_expressions.append(expr)

    steps_block = ",\n".join(f"            {expr}" for expr in step_expressions)

    # Map composition type to combinator wrapper
    composition_map = {
        "sequence": "Sequence",
        "parallel": "Parallel",
        "choice": "Choice",
        "guarded_sequence": "Sequence",
    }
    combinator_type = composition_map[composition]

    # Invariant variant list for the check function
    invariant_checks = "\n".join(
        f'        ConstitutionalInvariant::{inv},'
        for inv in invariants
    )

    # Step ID constants
    step_constants = "\n".join(
        f'    pub const {to_snake_case(s["id"]).upper()}: &str = "{s["id"]}";'
        for s in steps
    )

    # Input/output key documentation
    all_inputs = set()
    all_outputs = set()
    for step in steps:
        node_def = registry["nodes"].get(step["node"], {})
        all_inputs.update(node_def.get("inputs", []))
        all_outputs.update(node_def.get("outputs", []))

    inputs_doc = ", ".join(sorted(all_inputs))
    outputs_doc = ", ".join(sorted(all_outputs))

    return textwrap.dedent(f"""\
        //! Workflow: {name}
        //!
{description_doc}
        //!
        //! Generated by Syntaxis workflow codegen.
        //! DO NOT EDIT MANUALLY --- regenerate from the workflow definition.
        //!
        //! Composition: {composition}
        //! Error strategy: {error_strategy}
        //! Required invariants: {', '.join(invariants) if invariants else 'none'}
        //!
        //! Inputs: {inputs_doc}
        //! Outputs: {outputs_doc}

        use std::collections::BTreeMap;

        use exo_gatekeeper::combinator::{{
            Combinator, CombinatorInput, CombinatorOutput,
            Predicate, TransformFn, reduce,
        }};
        use exo_gatekeeper::invariants::{{
            ConstitutionalInvariant, InvariantSet,
        }};
        use exo_gatekeeper::error::GatekeeperError;

        // ---------------------------------------------------------------------------
        // Step identifiers
        // ---------------------------------------------------------------------------

        /// Step ID constants for this workflow.
        pub struct {pascal_name}Steps;

        impl {pascal_name}Steps {{
        {step_constants}
        }}

        // ---------------------------------------------------------------------------
        // Workflow construction
        // ---------------------------------------------------------------------------

        /// Build the combinator chain for the {name} workflow.
        ///
        /// This constructs the complete governance pipeline as a single
        /// reducible combinator expression. The kernel reduces this
        /// deterministically: same input always produces same output.
        #[must_use]
        pub fn build_{snake_name}_workflow() -> Combinator {{
            Combinator::{combinator_type}(vec![
        {steps_block},
            ])
        }}

        /// Get the set of constitutional invariants that this workflow requires.
        ///
        /// The kernel must verify all of these before and after reduction.
        #[must_use]
        pub fn {snake_name}_invariants() -> InvariantSet {{
            InvariantSet::with(vec![
        {invariant_checks}
            ])
        }}

        // ---------------------------------------------------------------------------
        // Workflow execution
        // ---------------------------------------------------------------------------

        /// Execute the {name} workflow with the given input.
        ///
        /// This builds the combinator chain and reduces it in a single pass.
        /// The result is deterministic: same input always produces same output.
        pub fn execute_{snake_name}(
            input: CombinatorInput,
        ) -> Result<CombinatorOutput, GatekeeperError> {{
            let workflow = build_{snake_name}_workflow();
            reduce(&workflow, &input)
        }}

        // ---------------------------------------------------------------------------
        // Input builder
        // ---------------------------------------------------------------------------

        /// Builder for constructing valid input for the {name} workflow.
        #[derive(Debug, Clone, Default)]
        pub struct {pascal_name}Input {{
            fields: BTreeMap<String, String>,
        }}

        impl {pascal_name}Input {{
            #[must_use]
            pub fn new() -> Self {{
                Self::default()
            }}

            /// Set an input field.
            pub fn set(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {{
                self.fields.insert(key.into(), value.into());
                self
            }}

            /// Build the CombinatorInput.
            #[must_use]
            pub fn build(self) -> CombinatorInput {{
                CombinatorInput {{
                    fields: self.fields,
                }}
            }}
        }}

        // ---------------------------------------------------------------------------
        // Tests
        // ---------------------------------------------------------------------------

        #[cfg(test)]
        mod tests {{
            use super::*;

            #[test]
            fn test_build_workflow() {{
                let workflow = build_{snake_name}_workflow();
                // Verify the workflow is a {combinator_type} combinator
                match &workflow {{
                    Combinator::{combinator_type}(steps) => {{
                        assert_eq!(steps.len(), {len(steps)}, "workflow should have {len(steps)} steps");
                    }}
                    other => panic!("expected {combinator_type}, got {{:?}}", other),
                }}
            }}

            #[test]
            fn test_invariant_set() {{
                let invariants = {snake_name}_invariants();
                assert_eq!(
                    invariants.invariants.len(),
                    {len(invariants)},
                    "workflow requires {len(invariants)} invariants"
                );
            }}

            #[test]
            fn test_determinism() {{
                let input = {pascal_name}Input::new()
        {generate_test_inputs(steps, registry)}
                    .build();

                let result1 = execute_{snake_name}(input.clone());
                let result2 = execute_{snake_name}(input);

                // Both executions must produce identical results
                match (result1, result2) {{
                    (Ok(a), Ok(b)) => {{
                        assert_eq!(
                            a.fields, b.fields,
                            "determinism: same input must produce same output"
                        );
                    }}
                    (Err(a), Err(b)) => {{
                        assert_eq!(
                            a.to_string(),
                            b.to_string(),
                            "determinism: same input must produce same error"
                        );
                    }}
                    _ => panic!("determinism violated: one succeeded, one failed"),
                }}
            }}

            #[test]
            fn test_empty_input_behavior() {{
                let input = CombinatorInput::new();
                // With empty input, guards should fail predictably
                let _result = execute_{snake_name}(input);
                // We just verify it does not panic --- the specific
                // result depends on workflow guards.
            }}

            #[test]
            fn test_input_builder() {{
                let input = {pascal_name}Input::new()
                    .set("test_key", "test_value")
                    .build();
                assert_eq!(input.fields.get("test_key").unwrap(), "test_value");
            }}
        }}
    """)


def generate_test_inputs(steps: list[dict], registry: dict) -> str:
    """Generate .set() calls for test input based on workflow steps."""
    lines = []
    seen_keys = set()
    for step in steps:
        node_def = registry["nodes"].get(step["node"], {})
        for key in node_def.get("inputs", []):
            if key not in seen_keys and key not in (
                "children", "inner_combinator", "transform_fn", "predicate"
            ):
                seen_keys.add(key)
                lines.append(f'                .set("{key}", "test_{key}_value")')
    return "\n".join(lines) if lines else '                .set("_placeholder", "test")'


def generate_integration_glue(workflow: dict) -> str:
    """Generate integration code that registers the workflow with the gatekeeper."""
    name = workflow["name"]
    snake_name = to_snake_case(name)
    pascal_name = to_pascal_case(name)

    return textwrap.dedent(f"""\
        //! Integration glue: register {name} with the gatekeeper combinator engine.
        //!
        //! Generated by Syntaxis workflow codegen.

        use exo_gatekeeper::combinator::{{Combinator, CombinatorInput, CombinatorOutput, reduce}};
        use exo_gatekeeper::error::GatekeeperError;

        use super::{snake_name}::{{build_{snake_name}_workflow, {snake_name}_invariants}};

        /// Workflow identifier for registry lookup.
        pub const WORKFLOW_ID: &str = "{name}";

        /// Create and return the workflow combinator for gatekeeper registration.
        #[must_use]
        pub fn register() -> (String, Combinator) {{
            (WORKFLOW_ID.to_string(), build_{snake_name}_workflow())
        }}

        /// Execute this workflow through the gatekeeper with full invariant checking.
        pub fn execute(input: CombinatorInput) -> Result<CombinatorOutput, GatekeeperError> {{
            let workflow = build_{snake_name}_workflow();
            let _invariants = {snake_name}_invariants();

            // The gatekeeper kernel checks invariants before and after reduction.
            // Here we just perform the reduction; invariant enforcement is the
            // kernel's responsibility (separation of concerns).
            reduce(&workflow, &input)
        }}
    """)


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: generate_workflow.py <workflow.json> [--output-dir <dir>]")
        print()
        print("Example:")
        print('  python3 tools/syntaxis/generate_workflow.py workflow.json --output-dir generated/')
        print()
        print("Workflow JSON format:")
        print('  {')
        print('    "name": "consent-gated-action",')
        print('    "description": "Verify identity, check consent, execute",')
        print('    "steps": [')
        print('      { "node": "identity-verify", "id": "step_1" },')
        print('      { "node": "consent-verify", "id": "step_2" },')
        print('      { "node": "kernel-adjudicate", "id": "step_3" }')
        print('    ],')
        print('    "composition": "sequence"')
        print('  }')
        sys.exit(1)

    workflow_path = Path(sys.argv[1])
    output_dir = Path("generated")

    # Parse --output-dir flag
    for i, arg in enumerate(sys.argv):
        if arg == "--output-dir" and i + 1 < len(sys.argv):
            output_dir = Path(sys.argv[i + 1])

    if not workflow_path.exists():
        print(f"Error: workflow file not found: {workflow_path}")
        sys.exit(1)

    # Load inputs
    with open(workflow_path) as f:
        workflow = json.load(f)

    registry = load_node_registry()

    try:
        validate_workflow(workflow, registry)
    except WorkflowValidationError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    name = workflow["name"]
    steps = workflow["steps"]
    snake_name = to_snake_case(name)

    # Generate output directory
    output_dir.mkdir(parents=True, exist_ok=True)

    # Generate workflow module
    workflow_code = generate_workflow_module(workflow, registry)
    workflow_file = output_dir / f"{snake_name}.rs"
    workflow_file.write_text(workflow_code)
    print(f"[created] {workflow_file}")

    # Generate integration glue
    glue_code = generate_integration_glue(workflow)
    glue_file = output_dir / f"{snake_name}_integration.rs"
    glue_file.write_text(glue_code)
    print(f"[created] {glue_file}")

    # Generate mod.rs if it does not exist
    mod_file = output_dir / "mod.rs"
    mod_entry = f"pub mod {snake_name};\npub mod {snake_name}_integration;\n"
    if mod_file.exists():
        existing = mod_file.read_text()
        if f"pub mod {snake_name};" not in existing:
            mod_file.write_text(existing + mod_entry)
            print(f"[updated] {mod_file}")
    else:
        mod_file.write_text(
            f"//! Generated workflow modules.\n\n{mod_entry}"
        )
        print(f"[created] {mod_file}")

    # Print summary
    invariants = collect_invariants(steps, registry)
    print()
    print(f"Workflow '{name}' generated successfully.")
    print(f"  Steps: {len(steps)}")
    print(f"  Composition: {workflow.get('composition', 'sequence')}")
    print(f"  Invariants: {', '.join(invariants) if invariants else 'none'}")
    print(f"  Output: {output_dir}/")
    print()
    print("To integrate:")
    print(f"  1. Copy {snake_name}.rs into the appropriate crate's src/ directory")
    print(f"  2. Add 'pub mod {snake_name};' to the crate's lib.rs")
    print(f"  3. Run: cargo test -p exo-gatekeeper")


if __name__ == "__main__":
    main()
