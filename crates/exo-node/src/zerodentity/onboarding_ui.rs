//! 0dentity onboarding status UI.
//!
//! Serves `GET /0dentity`. The browser route does not submit first-touch
//! claims because feature-enabled claim submission now requires caller-signed
//! canonical CBOR proof-of-possession. Default builds show the Onyx-4 R1
//! feature-gate refusal; feature-enabled builds show the proof-of-possession
//! browser-surface refusal instead of fabricating placeholder key material.
//!
//! Spec reference: §1.3, §4, §6.

use axum::{Router, response::Html, routing::get};

/// Route: `GET /0dentity`.
#[cfg(not(feature = "unaudited-zerodentity-first-touch-onboarding"))]
pub async fn zerodentity_onboarding() -> Html<&'static str> {
    Html(ONBOARDING_DISABLED_HTML)
}

/// Route: `GET /0dentity`.
#[cfg(feature = "unaudited-zerodentity-first-touch-onboarding")]
pub async fn zerodentity_onboarding() -> Html<&'static str> {
    Html(ONBOARDING_PROOF_REQUIRED_HTML)
}

/// Router for the 0dentity onboarding endpoint.
pub fn zerodentity_onboarding_router() -> Router {
    Router::new().route("/0dentity", get(zerodentity_onboarding))
}

// ---------------------------------------------------------------------------
// Self-contained onboarding HTML (§4 Gamma Flow)
// ---------------------------------------------------------------------------

#[cfg(not(feature = "unaudited-zerodentity-first-touch-onboarding"))]
const ONBOARDING_DISABLED_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>0dentity onboarding disabled</title>
<style>
  :root { --primary: #38bdf8; --bg: #0a0e17; --text: #e2e8f0; --dim: #94a3b8; --border: #1e2940; }
  * { box-sizing: border-box; }
  body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: var(--bg); color: var(--text); font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; padding: 1rem; }
  main { width: min(100%, 44rem); border: 1px solid var(--border); padding: 2rem; }
  h1 { margin: 0 0 1rem; font-size: 1.25rem; color: var(--primary); }
  p { color: var(--dim); line-height: 1.6; }
  code { color: var(--text); overflow-wrap: anywhere; }
</style>
</head>
<body>
<main>
  <h1>0dentity first-touch onboarding is disabled</h1>
  <p>POST /api/v1/0dentity/claims is refused by default while the approved proof-of-possession design is pending.</p>
  <p>Feature flag: <code>unaudited-zerodentity-first-touch-onboarding</code></p>
  <p>Initiative: <code>fix-onyx-4-r1-onboarding-auth.md</code></p>
</main>
</body>
</html>
"##;

#[cfg(feature = "unaudited-zerodentity-first-touch-onboarding")]
const ONBOARDING_PROOF_REQUIRED_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>0dentity onboarding requires proof</title>
<style>
  :root { --primary: #38bdf8; --bg: #0a0e17; --text: #e2e8f0; --dim: #94a3b8; --border: #1e2940; }
  * { box-sizing: border-box; }
  body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: var(--bg); color: var(--text); font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; padding: 1rem; }
  main { width: min(100%, 44rem); border: 1px solid var(--border); padding: 2rem; }
  h1 { margin: 0 0 1rem; font-size: 1.25rem; color: var(--primary); }
  p { color: var(--dim); line-height: 1.6; }
  code { color: var(--text); overflow-wrap: anywhere; }
</style>
</head>
<body>
<main>
  <h1>0dentity browser onboarding is disabled</h1>
  <p>The first-touch API is enabled only for clients that submit canonical CBOR claim-submission proof-of-possession signed by the subject key.</p>
  <p>This browser route refuses to submit claims and never fabricates placeholder signatures or public keys.</p>
  <p>Feature flag: <code>unaudited-zerodentity-first-touch-onboarding</code></p>
  <p>Initiative: <code>fix-zerodentity-first-touch-proof-of-possession.md</code></p>
</main>
</body>
</html>
"##;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[cfg(not(feature = "unaudited-zerodentity-first-touch-onboarding"))]
    async fn test_onboarding_refuses_when_first_touch_disabled() {
        let response = zerodentity_onboarding().await;
        let html = response.0;
        assert!(
            html.contains("unaudited-zerodentity-first-touch-onboarding"),
            "refusal page must name the feature flag"
        );
        assert!(
            html.contains("fix-onyx-4-r1-onboarding-auth.md"),
            "refusal page must name the R1 initiative"
        );
        assert!(
            !html.contains("'00'.repeat"),
            "default onboarding page must not ship placeholder key material"
        );
    }

    #[tokio::test]
    #[cfg(feature = "unaudited-zerodentity-first-touch-onboarding")]
    async fn test_feature_enabled_onboarding_refuses_legacy_placeholder_ui() {
        let response = zerodentity_onboarding().await;
        let html = response.0;
        assert!(
            html.contains("fix-zerodentity-first-touch-proof-of-possession.md"),
            "feature-enabled UI must point at the proof-of-possession initiative"
        );
        assert!(
            !html.contains("'00'.repeat"),
            "feature-enabled UI must not ship placeholder key material"
        );
        assert!(
            !html.contains("/api/v1/0dentity/claims"),
            "feature-enabled UI must not call the claim API until it can sign canonical CBOR"
        );
    }

    #[tokio::test]
    async fn test_onboarding_no_external_cdn() {
        let response = zerodentity_onboarding().await;
        let html = response.0;
        assert!(!html.contains("cdn."), "must not use external CDN");
        assert!(!html.contains("unpkg.com"), "must not use unpkg");
        assert!(!html.contains("jsdelivr"), "must not use jsdelivr");
        assert!(!html.contains("googleapis"), "must not use googleapis");
    }

    #[tokio::test]
    #[cfg(feature = "unaudited-zerodentity-first-touch-onboarding")]
    async fn test_onboarding_feature_enabled_page_names_feature_flag() {
        let response = zerodentity_onboarding().await;
        let html = response.0;
        assert!(
            html.contains("unaudited-zerodentity-first-touch-onboarding"),
            "feature-enabled refusal page must name the feature flag"
        );
    }

    #[tokio::test]
    async fn test_onboarding_contains_css_variables() {
        let response = zerodentity_onboarding().await;
        let html = response.0;
        assert!(
            html.contains("--primary"),
            "must contain --primary CSS variable"
        );
        assert!(html.contains("--bg"), "must contain --bg CSS variable");
    }

    #[test]
    fn test_onboarding_router_builds() {
        let _ = zerodentity_onboarding_router();
    }
}
