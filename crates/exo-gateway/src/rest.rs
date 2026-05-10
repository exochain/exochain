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
    /// GET /api/v1/decisions/:id
    GetDecision,
    /// POST /api/v1/decisions
    CreateDecision,
    /// POST /api/v1/auth/token
    AuthToken,
    /// POST /api/v1/auth/saml/callback
    SamlCallback,
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
    /// GET /api/v1/users
    ListUsers,
    /// POST /api/v1/users/:did/advance-pace
    AdvanceUserPace,
}

impl RestRoute {
    /// Get the HTTP method for this route.
    pub fn method(&self) -> &str {
        match self {
            RestRoute::Health
            | RestRoute::GetDecision
            | RestRoute::GetConstitution
            | RestRoute::AuditTrail
            | RestRoute::AuthMe
            | RestRoute::ListAgents
            | RestRoute::GetAgent
            | RestRoute::GetIdentityScore
            | RestRoute::ListUsers => "GET",
            RestRoute::CreateDecision
            | RestRoute::AuthToken
            | RestRoute::SamlCallback
            | RestRoute::EDiscoveryExport
            | RestRoute::AuthRegister
            | RestRoute::AuthLogin
            | RestRoute::AuthRefresh
            | RestRoute::AuthLogout
            | RestRoute::AgentEnroll
            | RestRoute::AdvanceAgentPace
            | RestRoute::AdvanceUserPace => "POST",
        }
    }

    /// Get the path pattern for this route.
    pub fn path(&self) -> &str {
        match self {
            RestRoute::Health => "/health",
            RestRoute::GetDecision => "/api/v1/decisions/:id",
            RestRoute::CreateDecision => "/api/v1/decisions",
            RestRoute::AuthToken => "/api/v1/auth/token",
            RestRoute::SamlCallback => "/api/v1/auth/saml/callback",
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
            RestRoute::ListUsers => "/api/v1/users",
            RestRoute::AdvanceUserPace => "/api/v1/users/:did/advance-pace",
        }
    }

    /// All defined routes.
    pub fn all() -> Vec<RestRoute> {
        vec![
            RestRoute::Health,
            RestRoute::GetDecision,
            RestRoute::CreateDecision,
            RestRoute::AuthToken,
            RestRoute::SamlCallback,
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
            RestRoute::ListUsers,
            RestRoute::AdvanceUserPace,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_route_methods() {
        assert_eq!(RestRoute::Health.method(), "GET");
        assert_eq!(RestRoute::CreateDecision.method(), "POST");
        assert_eq!(RestRoute::AuthRegister.method(), "POST");
        assert_eq!(RestRoute::AuthLogin.method(), "POST");
        assert_eq!(RestRoute::AuthMe.method(), "GET");
        assert_eq!(RestRoute::ListAgents.method(), "GET");
        assert_eq!(RestRoute::AgentEnroll.method(), "POST");
        assert_eq!(RestRoute::GetIdentityScore.method(), "GET");
        assert_eq!(RestRoute::ListUsers.method(), "GET");
        assert_eq!(RestRoute::AdvanceUserPace.method(), "POST");
    }

    #[test]
    fn test_route_paths() {
        assert_eq!(RestRoute::Health.path(), "/health");
        assert_eq!(RestRoute::GetDecision.path(), "/api/v1/decisions/:id");
        assert_eq!(RestRoute::CreateDecision.path(), "/api/v1/decisions");
        assert_eq!(RestRoute::AuthToken.path(), "/api/v1/auth/token");
        assert_eq!(RestRoute::SamlCallback.path(), "/api/v1/auth/saml/callback");
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
        assert_eq!(RestRoute::ListUsers.path(), "/api/v1/users");
        assert_eq!(
            RestRoute::AdvanceUserPace.path(),
            "/api/v1/users/:did/advance-pace"
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
        assert_eq!(routes.len(), 20);
    }
}
