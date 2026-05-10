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

use decision_forum::decision_object::DecisionClass;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ModelProvider {
    Anthropic,
    OpenAI,
    Google,
    XAI,
    Other(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ModelRole {
    Panelist,
    DevilsAdvocate,
    Synthesizer,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PanelModel {
    pub model_id: String,
    pub provider: ModelProvider,
    pub role: ModelRole,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Panel {
    pub id: String,
    pub models: Vec<PanelModel>,
    pub max_rounds: u32,
    pub convergence_threshold_bps: u64,
    pub devil_advocate_model: Option<String>,
}

impl Panel {
    /// Returns a sensible default panel configuration based on decision class.
    pub fn default_panel(question_class: DecisionClass) -> Self {
        match question_class {
            DecisionClass::Routine => Panel {
                id: "default-routine".into(),
                models: vec![
                    PanelModel {
                        model_id: "claude-3-haiku".into(),
                        provider: ModelProvider::Anthropic,
                        role: ModelRole::Panelist,
                    },
                    PanelModel {
                        model_id: "gpt-4o-mini".into(),
                        provider: ModelProvider::OpenAI,
                        role: ModelRole::Panelist,
                    },
                    PanelModel {
                        model_id: "gemini-1.5-flash".into(),
                        provider: ModelProvider::Google,
                        role: ModelRole::Panelist,
                    },
                ],
                max_rounds: 1,
                convergence_threshold_bps: 6000,
                devil_advocate_model: None,
            },
            DecisionClass::Operational => Panel {
                id: "default-operational".into(),
                models: vec![
                    PanelModel {
                        model_id: "claude-3-5-sonnet".into(),
                        provider: ModelProvider::Anthropic,
                        role: ModelRole::Panelist,
                    },
                    PanelModel {
                        model_id: "gpt-4o".into(),
                        provider: ModelProvider::OpenAI,
                        role: ModelRole::Panelist,
                    },
                    PanelModel {
                        model_id: "gemini-1.5-pro".into(),
                        provider: ModelProvider::Google,
                        role: ModelRole::Panelist,
                    },
                ],
                max_rounds: 2,
                convergence_threshold_bps: 7500,
                devil_advocate_model: Some("gpt-4o".into()),
            },
            DecisionClass::Strategic => Panel {
                id: "default-strategic".into(),
                models: vec![
                    PanelModel {
                        model_id: "claude-3-opus".into(),
                        provider: ModelProvider::Anthropic,
                        role: ModelRole::Panelist,
                    },
                    PanelModel {
                        model_id: "gpt-4o".into(),
                        provider: ModelProvider::OpenAI,
                        role: ModelRole::Panelist,
                    },
                    PanelModel {
                        model_id: "gemini-1.5-pro".into(),
                        provider: ModelProvider::Google,
                        role: ModelRole::Panelist,
                    },
                    PanelModel {
                        model_id: "grok-2".into(),
                        provider: ModelProvider::XAI,
                        role: ModelRole::Panelist,
                    },
                ],
                max_rounds: 3,
                convergence_threshold_bps: 8000,
                devil_advocate_model: Some("claude-3-opus".into()),
            },
            DecisionClass::Constitutional => Panel {
                id: "default-constitutional".into(),
                models: vec![
                    PanelModel {
                        model_id: "claude-3-opus".into(),
                        provider: ModelProvider::Anthropic,
                        role: ModelRole::Panelist,
                    },
                    PanelModel {
                        model_id: "gpt-4o".into(),
                        provider: ModelProvider::OpenAI,
                        role: ModelRole::Panelist,
                    },
                    PanelModel {
                        model_id: "gemini-1.5-pro".into(),
                        provider: ModelProvider::Google,
                        role: ModelRole::Panelist,
                    },
                    PanelModel {
                        model_id: "grok-2".into(),
                        provider: ModelProvider::XAI,
                        role: ModelRole::Panelist,
                    },
                    PanelModel {
                        model_id: "o1-preview".into(),
                        provider: ModelProvider::OpenAI,
                        role: ModelRole::Panelist,
                    },
                ],
                max_rounds: 4,
                convergence_threshold_bps: 9000,
                devil_advocate_model: Some("o1-preview".into()),
            },
        }
    }
}
