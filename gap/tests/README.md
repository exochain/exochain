<!--
Copyright 2026 Exochain Foundation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at:

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

SPDX-License-Identifier: Apache-2.0
-->

# GAP Test Suite

This directory contains the End-to-End (E2E) test specifications for the `gap/` incubator layer. 

## Overview
These tests do not verify the underlying ExoChain crates; they verify the *orchestration* of those crates via the Syntaxis protocols defined in `gap/syntaxis/`. They ensure that the governance pipelines, agentic handoffs, and Decision Forum routing function flawlessly.

## How to Run
These test specs are machine-readable by the ExoForge Liaison during the CQI self-improvement loop. Before any system patch is deployed, the Liaison must execute the automated test runner against these specs.
```bash
# Example execution (simulated)
exo-test run ./gap/tests/
```

## CI Integration
These tests run automatically on every PR submitted to the `exochain` repository that modifies anything within the `gap/` directory.

## Coverage Requirements
The `gap/` layer requires 100% pass rate on all E2E tests and strict validation against `test-invariant-coverage.md`. A single failure constitutes a broken build and triggers a mandatory rollback.