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

//! Public `GET /status` page for the node host.
//!
//! Facts come from `site/src/data/public-status.json`, which is checked
//! against the workspace version and the publication snapshot. Live
//! `/health` and `/ready` bodies are rendered as text from those responses.

use axum::{Json, Router, http::StatusCode, response::Html, routing::get};
use serde::Deserialize;

const STATUS_FACTS_JSON: &str = include_str!("../../../site/src/data/public-status.json");

#[derive(Debug, Deserialize)]
struct StatusFacts {
    maturity: String,
    maturity_summary: String,
    spec: SpecFacts,
    publication: PublicationFacts,
    gap_registry: GapRegistryFacts,
    default_off_features: Vec<FeatureFact>,
    bounded_capabilities: Vec<BoundedCapability>,
}

#[derive(Debug, Deserialize)]
struct SpecFacts {
    normative_version: String,
    normative_document: String,
    authority_record: String,
    engineering_version: String,
    engineering_document: String,
    v2_3_present_in_repository: bool,
}

#[derive(Debug, Deserialize)]
struct PublicationFacts {
    version: String,
    observed_at: String,
    github_published_at: String,
    github_url: String,
    native_archive_contents: String,
    runtime_deployment_claimed: bool,
    pypi_package: String,
}

#[derive(Debug, Deserialize)]
struct GapRegistryFacts {
    path: String,
    header_amended: String,
    header_records_release: String,
    note: String,
}

#[derive(Debug, Deserialize)]
struct FeatureFact {
    package: String,
    feature: String,
    boundary: String,
}

#[derive(Debug, Deserialize)]
struct BoundedCapability {
    name: String,
    posture: String,
}

/// Router for the public status page.
pub fn public_status_router() -> Router {
    Router::new().route("/status", get(handle_public_status))
}

async fn handle_public_status() -> Result<Html<String>, (StatusCode, Json<serde_json::Value>)> {
    render_public_status().map(Html).map_err(|reason| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "public_status_unavailable",
                "reason": reason,
            })),
        )
    })
}

fn render_public_status() -> Result<String, String> {
    let facts: StatusFacts = serde_json::from_str(STATUS_FACTS_JSON)
        .map_err(|error| format!("public status facts failed to parse: {error}"))?;
    if facts.maturity != "beta" {
        return Err(format!(
            "public status maturity must be beta, found {}",
            facts.maturity
        ));
    }
    if facts.publication.runtime_deployment_claimed {
        return Err(
            "public status must not claim runtime deployment for the published release".into(),
        );
    }
    if facts.spec.v2_3_present_in_repository {
        return Err(
            "public status must not claim a v2.3 specification is in the repository".into(),
        );
    }
    Ok(render_html(&facts))
}

fn render_html(facts: &StatusFacts) -> String {
    let mut features = String::new();
    for feature in &facts.default_off_features {
        features.push_str(&format!(
            "<li><code>{}</code> / <code>{}</code> — {}</li>",
            escape_html(&feature.package),
            escape_html(&feature.feature),
            escape_html(&feature.boundary)
        ));
    }
    let mut capabilities = String::new();
    for capability in &facts.bounded_capabilities {
        capabilities.push_str(&format!(
            "<li><strong>{}.</strong> {}</li>",
            escape_html(&capability.name),
            escape_html(&capability.posture)
        ));
    }
    let deployment = if facts.publication.runtime_deployment_claimed {
        "yes"
    } else {
        "no"
    };
    let spec_v23 = if facts.spec.v2_3_present_in_repository {
        "present"
    } else {
        "not present"
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>EXOCHAIN status</title>
<style>
  :root {{
    --bg: #0a0e17; --surface: #111827; --border: #1e293b;
    --text: #e2e8f0; --text-dim: #94a3b8; --accent: #38bdf8;
    --mono: 'SF Mono', 'Fira Code', ui-monospace, monospace;
    --sans: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  }}
  * {{ box-sizing: border-box; }}
  body {{ margin: 0; background: var(--bg); color: var(--text); font-family: var(--sans); line-height: 1.5; }}
  main {{ max-width: 880px; margin: 0 auto; padding: 2rem 1.25rem 4rem; }}
  h1 {{ font-size: 1.75rem; font-weight: 650; letter-spacing: -0.02em; }}
  h2 {{ margin-top: 2rem; font-size: 1.05rem; }}
  a {{ color: var(--accent); }}
  code, pre {{ font-family: var(--mono); }}
  pre {{ white-space: pre-wrap; background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 1rem; }}
  ul {{ padding-left: 1.2rem; }}
  li {{ margin: 0.4rem 0; }}
  .dim {{ color: var(--text-dim); }}
</style>
</head>
<body>
<main>
  <p class="dim">EXOCHAIN public status</p>
  <h1>{maturity}</h1>
  <p>{maturity_summary}</p>
  <p>Binary version compiled into this page: <code>v{binary_version}</code>.</p>

  <h2>Published release</h2>
  <p>Reviewed publication snapshot version <code>v{version}</code>, observed <code>{observed_at}</code>. GitHub Release published <code>{github_published_at}</code>: <a href="{github_url}">{github_url}</a>.</p>
  <p>Native archives contain {native_archives}. Runtime deployment claimed by that release: <strong>{deployment}</strong>.</p>
  <p>PyPI package observed with that version: <code>{pypi_package}</code>. crates.io and npm packages are listed in <code>governance/releases/published-release-snapshot.json</code>.</p>

  <h2>Specification</h2>
  <p>Normative specification: v{spec_version} (<code>{spec_document}</code>), decided in <code>{authority}</code>. Engineering elaboration: v{engineering_version} (<code>{engineering_document}</code>), subordinate to the normative specification. A v2.3 specification is {spec_v23} in this repository.</p>

  <h2>This process</h2>
  <p class="dim">The blocks below are the raw same-origin <code>/health</code> and <code>/ready</code> responses. This page does not invent validator counts, peer counts, committed height, uptime percent, or incidents. <code>/ready</code> is the exo-gateway probe and reports <code>CARGO_PKG_VERSION</code>.</p>
  <h3>/health</h3>
  <pre id="health-probe">Reading /health.</pre>
  <h3>/ready</h3>
  <pre id="ready-probe">Reading /ready.</pre>

  <h2>Default-off boundaries</h2>
  <ul>{features}</ul>

  <h2>Bounded capabilities</h2>
  <ul>{capabilities}</ul>

  <h2>Gap ledger</h2>
  <p>{gap_note}</p>
  <p class="dim"><code>{gap_path}</code> header amended {gap_amended}; that header records {gap_release}.</p>
  <p><a href="/">Node dashboard</a> · <a href="/health">/health</a> · <a href="/ready">/ready</a> · <a href="https://github.com/exochain/exochain">GitHub</a></p>
</main>
<script>
(function() {{
  'use strict';
  async function show(path, elementId) {{
    var el = document.getElementById(elementId);
    try {{
      var resp = await fetch(path);
      var body = await resp.text();
      el.textContent = 'HTTP ' + resp.status + '\n' + body;
    }} catch (err) {{
      el.textContent = 'unreachable: ' + (err && err.message ? err.message : 'fetch failed');
    }}
  }}
  show('/health', 'health-probe');
  show('/ready', 'ready-probe');
}})();
</script>
</body>
</html>
"#,
        maturity = escape_html(&facts.maturity),
        maturity_summary = escape_html(&facts.maturity_summary),
        binary_version = escape_html(env!("CARGO_PKG_VERSION")),
        version = escape_html(&facts.publication.version),
        observed_at = escape_html(&facts.publication.observed_at),
        github_published_at = escape_html(&facts.publication.github_published_at),
        github_url = escape_html(&facts.publication.github_url),
        native_archives = escape_html(&facts.publication.native_archive_contents),
        deployment = deployment,
        pypi_package = escape_html(&facts.publication.pypi_package),
        spec_version = escape_html(&facts.spec.normative_version),
        spec_document = escape_html(&facts.spec.normative_document),
        authority = escape_html(&facts.spec.authority_record),
        engineering_version = escape_html(&facts.spec.engineering_version),
        engineering_document = escape_html(&facts.spec.engineering_document),
        spec_v23 = spec_v23,
        features = features,
        capabilities = capabilities,
        gap_note = escape_html(&facts.gap_registry.note),
        gap_path = escape_html(&facts.gap_registry.path),
        gap_amended = escape_html(&facts.gap_registry.header_amended),
        gap_release = escape_html(&facts.gap_registry.header_records_release),
    )
}

fn escape_html(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for character in input.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(character),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use axum::{body::Body, http::Request};
    use serde_json::Value;
    use tower::ServiceExt;

    use super::*;

    fn facts() -> StatusFacts {
        serde_json::from_str(STATUS_FACTS_JSON).expect("status facts parse")
    }

    #[test]
    fn status_facts_match_workspace_version_and_publication_snapshot() {
        let parsed = facts();
        assert_eq!(parsed.publication.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(parsed.maturity, "beta");
        assert!(!parsed.publication.runtime_deployment_claimed);
        assert_eq!(parsed.spec.normative_version, "2.2");
        assert!(!parsed.spec.v2_3_present_in_repository);
        assert!(
            parsed
                .publication
                .native_archive_contents
                .contains("libexo_*.rlib")
        );

        let snapshot_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../governance/releases/published-release-snapshot.json");
        let snapshot: Value = serde_json::from_str(
            &fs::read_to_string(&snapshot_path).expect("publication snapshot readable"),
        )
        .expect("publication snapshot parses");
        assert_eq!(
            snapshot["version"].as_str(),
            Some(parsed.publication.version.as_str())
        );
        assert_eq!(
            snapshot["observed_at"].as_str(),
            Some(parsed.publication.observed_at.as_str())
        );
        assert_eq!(snapshot["github"]["draft"].as_bool(), Some(false));
        assert_eq!(snapshot["github"]["prerelease"].as_bool(), Some(false));
        assert_eq!(
            snapshot["github"]["url"].as_str(),
            Some(parsed.publication.github_url.as_str())
        );
    }

    #[test]
    fn default_off_features_are_absent_from_cargo_defaults() {
        let crates = [
            ("exochain-proofs", "exo-proofs"),
            ("exochain-node", "exo-node"),
            ("exochain-gateway", "exo-gateway"),
        ];
        for feature in &facts().default_off_features {
            let directory = crates
                .iter()
                .find(|(package, _)| *package == feature.package)
                .map(|(_, directory)| *directory)
                .unwrap_or_else(|| panic!("unmapped package {}", feature.package));
            let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .join(directory)
                .join("Cargo.toml");
            let manifest = fs::read_to_string(&path).expect("crate manifest readable");
            assert!(
                manifest.contains(&format!("{} =", feature.feature)),
                "{} missing from {}",
                feature.feature,
                path.display()
            );
            let default_line = manifest
                .lines()
                .find(|line| line.trim_start().starts_with("default ="))
                .unwrap_or_else(|| panic!("default feature line missing in {}", path.display()));
            assert!(
                !default_line.contains(&feature.feature),
                "{} is default-on in {}",
                feature.feature,
                path.display()
            );
        }
    }

    #[tokio::test]
    async fn status_route_renders_repository_facts_without_fictional_metrics() {
        let app = public_status_router();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(html.contains("beta"));
        assert!(html.contains(env!("CARGO_PKG_VERSION")));
        assert!(html.contains("not general availability"));
        assert!(html.contains("libexo_*.rlib"));
        assert!(html.contains("Runtime deployment claimed by that release"));
        assert!(html.contains("textContent"));
        assert!(!html.contains("innerHTML"));
        assert!(!html.contains("v0.4.2"));
        assert!(!html.contains("alpha-testnet"));
        assert!(!html.contains("99.86"));
        assert!(html.contains("id=\"health-probe\""));
        assert!(html.contains("id=\"ready-probe\""));
    }
}
