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

//! REST endpoints for enterprise integration (SSO, ERP).

use serde::{Deserialize, Serialize};

/// Health check response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub uptime_seconds: u64,
}

/// REST API route definitions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RestRoute {
    /// GET /health
    Health,
    /// GET /ready
    Ready,
    /// GET /gateway/metrics
    GatewayMetrics,
    /// GET /health/db
    DbHealth,
    /// GET /api/v1/decisions/:id
    GetDecision,
    /// POST /api/v1/decisions
    CreateDecision,
    /// POST /api/v1/auth/token
    AuthToken,
    /// GET /api/v1/tenants/:id/constitution
    GetConstitution,
    /// POST /api/v1/ediscovery/export
    EDiscoveryExport,
    /// GET /api/v1/audit/:decision_id
    AuditTrail,
    /// POST /api/v1/auth/register
    AuthRegister,
    /// POST /api/v1/auth/login
    AuthLogin,
    /// POST /api/v1/auth/refresh
    AuthRefresh,
    /// GET /api/v1/auth/me
    AuthMe,
    /// POST /api/v1/auth/logout
    AuthLogout,
    /// POST /api/v1/agents/enroll
    AgentEnroll,
    /// GET /api/v1/agents
    ListAgents,
    /// GET /api/v1/agents/:did
    GetAgent,
    /// POST /api/v1/agents/:did/advance-pace
    AdvanceAgentPace,
    /// GET /api/v1/identity/:did/score
    GetIdentityScore,
    /// DELETE /api/v1/identity/:did
    DeleteIdentity,
    /// GET /api/v1/users
    ListUsers,
    /// POST /api/v1/users/:did/advance-pace
    AdvanceUserPace,
    /// GET /api/v1/layout-templates
    ListLayoutTemplates,
    /// PUT /api/v1/layout-templates
    PutLayoutTemplate,
    /// DELETE /api/v1/layout-templates/:id
    DeleteLayoutTemplate,
    /// GET /api/v1/feedback-issues
    ListFeedbackIssues,
    /// POST /api/v1/feedback-issues
    CreateFeedbackIssue,
    /// PATCH /api/v1/feedback-issues/:id
    UpdateFeedbackIssue,
}

impl RestRoute {
    /// Get the HTTP method for this route.
    pub fn method(&self) -> &str {
        match self {
            RestRoute::Health
            | RestRoute::Ready
            | RestRoute::GatewayMetrics
            | RestRoute::DbHealth
            | RestRoute::GetDecision
            | RestRoute::GetConstitution
            | RestRoute::AuditTrail
            | RestRoute::AuthMe
            | RestRoute::ListAgents
            | RestRoute::GetAgent
            | RestRoute::GetIdentityScore
            | RestRoute::ListUsers
            | RestRoute::ListLayoutTemplates
            | RestRoute::ListFeedbackIssues => "GET",
            RestRoute::CreateDecision
            | RestRoute::AuthToken
            | RestRoute::EDiscoveryExport
            | RestRoute::AuthRegister
            | RestRoute::AuthLogin
            | RestRoute::AuthRefresh
            | RestRoute::AuthLogout
            | RestRoute::AgentEnroll
            | RestRoute::AdvanceAgentPace
            | RestRoute::AdvanceUserPace
            | RestRoute::CreateFeedbackIssue => "POST",
            RestRoute::PutLayoutTemplate => "PUT",
            RestRoute::DeleteIdentity | RestRoute::DeleteLayoutTemplate => "DELETE",
            RestRoute::UpdateFeedbackIssue => "PATCH",
        }
    }

    /// Get the path pattern for this route.
    pub fn path(&self) -> &str {
        match self {
            RestRoute::Health => "/health",
            RestRoute::Ready => "/ready",
            RestRoute::GatewayMetrics => "/gateway/metrics",
            RestRoute::DbHealth => "/health/db",
            RestRoute::GetDecision => "/api/v1/decisions/:id",
            RestRoute::CreateDecision => "/api/v1/decisions",
            RestRoute::AuthToken => "/api/v1/auth/token",
            RestRoute::GetConstitution => "/api/v1/tenants/:id/constitution",
            RestRoute::EDiscoveryExport => "/api/v1/ediscovery/export",
            RestRoute::AuditTrail => "/api/v1/audit/:decision_id",
            RestRoute::AuthRegister => "/api/v1/auth/register",
            RestRoute::AuthLogin => "/api/v1/auth/login",
            RestRoute::AuthRefresh => "/api/v1/auth/refresh",
            RestRoute::AuthMe => "/api/v1/auth/me",
            RestRoute::AuthLogout => "/api/v1/auth/logout",
            RestRoute::AgentEnroll => "/api/v1/agents/enroll",
            RestRoute::ListAgents => "/api/v1/agents",
            RestRoute::GetAgent => "/api/v1/agents/:did",
            RestRoute::AdvanceAgentPace => "/api/v1/agents/:did/advance-pace",
            RestRoute::GetIdentityScore => "/api/v1/identity/:did/score",
            RestRoute::DeleteIdentity => "/api/v1/identity/:did",
            RestRoute::ListUsers => "/api/v1/users",
            RestRoute::AdvanceUserPace => "/api/v1/users/:did/advance-pace",
            RestRoute::ListLayoutTemplates => "/api/v1/layout-templates",
            RestRoute::PutLayoutTemplate => "/api/v1/layout-templates",
            RestRoute::DeleteLayoutTemplate => "/api/v1/layout-templates/:id",
            RestRoute::ListFeedbackIssues => "/api/v1/feedback-issues",
            RestRoute::CreateFeedbackIssue => "/api/v1/feedback-issues",
            RestRoute::UpdateFeedbackIssue => "/api/v1/feedback-issues/:id",
        }
    }

    /// All defined routes.
    pub fn all() -> Vec<RestRoute> {
        vec![
            RestRoute::Health,
            RestRoute::Ready,
            RestRoute::GatewayMetrics,
            RestRoute::DbHealth,
            RestRoute::GetDecision,
            RestRoute::CreateDecision,
            RestRoute::AuthToken,
            RestRoute::GetConstitution,
            RestRoute::EDiscoveryExport,
            RestRoute::AuditTrail,
            RestRoute::AuthRegister,
            RestRoute::AuthLogin,
            RestRoute::AuthRefresh,
            RestRoute::AuthMe,
            RestRoute::AuthLogout,
            RestRoute::AgentEnroll,
            RestRoute::ListAgents,
            RestRoute::GetAgent,
            RestRoute::AdvanceAgentPace,
            RestRoute::GetIdentityScore,
            RestRoute::DeleteIdentity,
            RestRoute::ListUsers,
            RestRoute::AdvanceUserPace,
            RestRoute::ListLayoutTemplates,
            RestRoute::PutLayoutTemplate,
            RestRoute::DeleteLayoutTemplate,
            RestRoute::ListFeedbackIssues,
            RestRoute::CreateFeedbackIssue,
            RestRoute::UpdateFeedbackIssue,
        ]
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn test_route_methods() {
        assert_eq!(RestRoute::Health.method(), "GET");
        assert_eq!(RestRoute::Ready.method(), "GET");
        assert_eq!(RestRoute::GatewayMetrics.method(), "GET");
        assert_eq!(RestRoute::DbHealth.method(), "GET");
        assert_eq!(RestRoute::CreateDecision.method(), "POST");
        assert_eq!(RestRoute::AuthRegister.method(), "POST");
        assert_eq!(RestRoute::AuthLogin.method(), "POST");
        assert_eq!(RestRoute::AuthMe.method(), "GET");
        assert_eq!(RestRoute::ListAgents.method(), "GET");
        assert_eq!(RestRoute::AgentEnroll.method(), "POST");
        assert_eq!(RestRoute::GetIdentityScore.method(), "GET");
        assert_eq!(RestRoute::DeleteIdentity.method(), "DELETE");
        assert_eq!(RestRoute::ListUsers.method(), "GET");
        assert_eq!(RestRoute::AdvanceUserPace.method(), "POST");
        assert_eq!(RestRoute::ListLayoutTemplates.method(), "GET");
        assert_eq!(RestRoute::PutLayoutTemplate.method(), "PUT");
        assert_eq!(RestRoute::DeleteLayoutTemplate.method(), "DELETE");
        assert_eq!(RestRoute::ListFeedbackIssues.method(), "GET");
        assert_eq!(RestRoute::CreateFeedbackIssue.method(), "POST");
        assert_eq!(RestRoute::UpdateFeedbackIssue.method(), "PATCH");
    }

    #[test]
    fn test_route_paths() {
        assert_eq!(RestRoute::Health.path(), "/health");
        assert_eq!(RestRoute::Ready.path(), "/ready");
        assert_eq!(RestRoute::GatewayMetrics.path(), "/gateway/metrics");
        assert_eq!(RestRoute::DbHealth.path(), "/health/db");
        assert_eq!(RestRoute::GetDecision.path(), "/api/v1/decisions/:id");
        assert_eq!(RestRoute::CreateDecision.path(), "/api/v1/decisions");
        assert_eq!(RestRoute::AuthToken.path(), "/api/v1/auth/token");
        assert_eq!(
            RestRoute::GetConstitution.path(),
            "/api/v1/tenants/:id/constitution"
        );
        assert_eq!(
            RestRoute::EDiscoveryExport.path(),
            "/api/v1/ediscovery/export"
        );
        assert_eq!(RestRoute::AuditTrail.path(), "/api/v1/audit/:decision_id");
        assert_eq!(RestRoute::AuthRegister.path(), "/api/v1/auth/register");
        assert_eq!(RestRoute::AuthLogin.path(), "/api/v1/auth/login");
        assert_eq!(RestRoute::AuthRefresh.path(), "/api/v1/auth/refresh");
        assert_eq!(RestRoute::AuthMe.path(), "/api/v1/auth/me");
        assert_eq!(RestRoute::AuthLogout.path(), "/api/v1/auth/logout");
        assert_eq!(RestRoute::AgentEnroll.path(), "/api/v1/agents/enroll");
        assert_eq!(RestRoute::ListAgents.path(), "/api/v1/agents");
        assert_eq!(RestRoute::GetAgent.path(), "/api/v1/agents/:did");
        assert_eq!(
            RestRoute::AdvanceAgentPace.path(),
            "/api/v1/agents/:did/advance-pace"
        );
        assert_eq!(
            RestRoute::GetIdentityScore.path(),
            "/api/v1/identity/:did/score"
        );
        assert_eq!(RestRoute::DeleteIdentity.path(), "/api/v1/identity/:did");
        assert_eq!(RestRoute::ListUsers.path(), "/api/v1/users");
        assert_eq!(
            RestRoute::AdvanceUserPace.path(),
            "/api/v1/users/:did/advance-pace"
        );
        assert_eq!(
            RestRoute::ListLayoutTemplates.path(),
            "/api/v1/layout-templates"
        );
        assert_eq!(
            RestRoute::PutLayoutTemplate.path(),
            "/api/v1/layout-templates"
        );
        assert_eq!(
            RestRoute::DeleteLayoutTemplate.path(),
            "/api/v1/layout-templates/:id"
        );
        assert_eq!(
            RestRoute::ListFeedbackIssues.path(),
            "/api/v1/feedback-issues"
        );
        assert_eq!(
            RestRoute::CreateFeedbackIssue.path(),
            "/api/v1/feedback-issues"
        );
        assert_eq!(
            RestRoute::UpdateFeedbackIssue.path(),
            "/api/v1/feedback-issues/:id"
        );
    }

    #[test]
    fn health_response_fields() {
        let r = HealthResponse {
            status: "ok".into(),
            version: "0.1.0".into(),
            uptime_seconds: 42,
        };
        assert_eq!(r.status, "ok");
        assert_eq!(r.version, "0.1.0");
        assert_eq!(r.uptime_seconds, 42);
    }

    #[test]
    fn test_all_routes() {
        let routes = RestRoute::all();
        assert_eq!(routes.len(), 29);
    }

    #[test]
    fn rest_route_inventory_matches_live_non_graphql_gateway_surface() {
        let routes = RestRoute::all();
        let actual: BTreeSet<(&str, &str)> = routes
            .iter()
            .map(|route| (route.method(), route.path()))
            .collect();
        let expected = BTreeSet::from([
            ("GET", "/health"),
            ("GET", "/ready"),
            ("GET", "/gateway/metrics"),
            ("GET", "/health/db"),
            ("GET", "/api/v1/decisions/:id"),
            ("POST", "/api/v1/decisions"),
            ("POST", "/api/v1/auth/token"),
            ("POST", "/api/v1/auth/register"),
            ("POST", "/api/v1/auth/login"),
            ("POST", "/api/v1/auth/refresh"),
            ("GET", "/api/v1/auth/me"),
            ("POST", "/api/v1/auth/logout"),
            ("POST", "/api/v1/agents/enroll"),
            ("GET", "/api/v1/agents"),
            ("GET", "/api/v1/agents/:did"),
            ("POST", "/api/v1/agents/:did/advance-pace"),
            ("GET", "/api/v1/identity/:did/score"),
            ("DELETE", "/api/v1/identity/:did"),
            ("GET", "/api/v1/tenants/:id/constitution"),
            ("POST", "/api/v1/ediscovery/export"),
            ("GET", "/api/v1/audit/:decision_id"),
            ("GET", "/api/v1/users"),
            ("POST", "/api/v1/users/:did/advance-pace"),
            ("GET", "/api/v1/layout-templates"),
            ("PUT", "/api/v1/layout-templates"),
            ("DELETE", "/api/v1/layout-templates/:id"),
            ("GET", "/api/v1/feedback-issues"),
            ("POST", "/api/v1/feedback-issues"),
            ("PATCH", "/api/v1/feedback-issues/:id"),
        ]);

        assert_eq!(
            actual, expected,
            "RestRoute::all must enumerate every live non-GraphQL gateway HTTP endpoint"
        );
    }
}
