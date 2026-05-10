-- Copyright 2026 Exochain Foundation
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at:
--
--     https://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--
-- SPDX-License-Identifier: Apache-2.0

-- Dashboard persistence tables for layout templates and feedback issues.
--
-- Layout templates store per-user dashboard configurations (widget positions,
-- visibility).  Feedback issues implement the mandated reporter pattern —
-- every widget can file structured issues that get tracked to resolution.

-- User-created layout templates (built-in templates live in code).
-- `layout_json` stores the serialized LayoutItem[] array.
-- `hidden_panels` stores a JSON array of panel IDs that are hidden.
CREATE TABLE IF NOT EXISTS layout_templates (
    id              TEXT    PRIMARY KEY,
    user_did        TEXT,
    name            TEXT    NOT NULL,
    layout_json     JSONB   NOT NULL,
    hidden_panels   JSONB   NOT NULL DEFAULT '[]'::jsonb,
    is_built_in     BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      BIGINT  NOT NULL,
    updated_at      BIGINT  NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_layout_templates_user ON layout_templates(user_did);

-- Mandated reporter feedback issues filed from dashboard widgets.
-- Every issue captures the source widget, severity, category, and
-- auto-captured context for agent team triage.
CREATE TABLE IF NOT EXISTS feedback_issues (
    id                  TEXT    PRIMARY KEY,
    title               TEXT    NOT NULL,
    description         TEXT    NOT NULL DEFAULT '',
    severity            TEXT    NOT NULL DEFAULT 'medium',
    category            TEXT    NOT NULL DEFAULT 'bug',
    status              TEXT    NOT NULL DEFAULT 'open',
    source_widget_id    TEXT    NOT NULL,
    source_module_type  TEXT    NOT NULL DEFAULT '',
    reporter_did        TEXT,
    assigned_agent_team TEXT,
    widget_state        JSONB,
    browser_info        JSONB,
    resolution_notes    TEXT,
    created_at          BIGINT  NOT NULL,
    updated_at          BIGINT  NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_feedback_issues_status ON feedback_issues(status);
CREATE INDEX IF NOT EXISTS idx_feedback_issues_widget ON feedback_issues(source_widget_id);
CREATE INDEX IF NOT EXISTS idx_feedback_issues_severity ON feedback_issues(severity);
