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

//! MCP server errors.

use thiserror::Error;

#[derive(Debug, Error)]
#[allow(dead_code)] // Variants used as the API surface expands.
pub enum McpError {
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("tool not found: {0}")]
    ToolNotFound(String),
    #[error("invalid params: {0}")]
    InvalidParams(String),
    #[error("constitutional violation: {0}")]
    ConstitutionalViolation(String),
    #[error("mcp rule violation: {rule} — {description}")]
    McpRuleViolation { rule: String, description: String },
    #[error("authentication required")]
    AuthenticationRequired,
    #[error("internal error: {0}")]
    Internal(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, McpError>;
