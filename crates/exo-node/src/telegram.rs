//! Telegram adjutant — agentic chief-of-staff for human operator oversight.
//!
//! A Telegram bot that acts as the operator's adjutant, presenting clear
//! choices via inline keyboard buttons for every material action.  The
//! bot receives alerts from the sentinel system and forwards them with
//! actionable options.
//!
//! ## Configuration
//!
//! Set environment variables:
//! - `TELEGRAM_BOT_TOKEN` — bot token from @BotFather
//! - `TELEGRAM_CHAT_ID`   — admin chat/group ID
//!
//! If either is unset, the adjutant logs a notice and does not start.
//!
//! ## Interactions
//!
//! | Command / Callback | Action |
//! |---------------------|--------|
//! | `/status`           | Node status with action buttons |
//! | `/receipts`         | Recent trust receipts |
//! | `/challenges`       | Active challenges with review/dismiss |
//! | `/sentinels`        | Sentinel health dashboard |
//! | Inline buttons      | Direct actions (review, dismiss, ack) |

use std::sync::{Arc, Mutex};

use exo_core::types::Did;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    challenges::SharedChallengeStore,
    reactor::SharedReactorState,
    sentinels::{AlertReceiver, SentinelAlert, SharedSentinelState, now_ms},
    store::SqliteDagStore,
    zerodentity::store::SharedZerodentityStore,
};

// ---------------------------------------------------------------------------
// Telegram API types (minimal subset)
// ---------------------------------------------------------------------------

const TELEGRAM_HTTP_TIMEOUT_SECS: u64 = 30;
const TELEGRAM_POLL_FAILURE_BACKOFF_MS: u64 = 1_000;
const MAX_TELEGRAM_UPDATE_RESPONSE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Serialize)]
struct SendMessageRequest {
    chat_id: String,
    text: String,
    parse_mode: Option<String>,
    reply_markup: Option<InlineKeyboardMarkup>,
}

#[derive(Debug, Serialize)]
struct InlineKeyboardMarkup {
    inline_keyboard: Vec<Vec<InlineKeyboardButton>>,
}

#[derive(Debug, Serialize)]
struct InlineKeyboardButton {
    text: String,
    callback_data: String,
}

#[derive(Debug, Deserialize)]
struct TelegramResponse<T> {
    ok: bool,
    result: Option<T>,
    description: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
enum TelegramUpdateParseError {
    Oversized { len: u64, max: u64 },
    Body(String),
    Json(String),
    ApiRejected { description: String },
    MissingResult,
}

impl std::fmt::Display for TelegramUpdateParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Oversized { len, max } => {
                write!(f, "telegram update response too large: {len} bytes > {max}")
            }
            Self::Body(error) => write!(f, "telegram update response body failed: {error}"),
            Self::Json(error) => write!(f, "telegram update response parse failed: {error}"),
            Self::ApiRejected { description } => {
                write!(f, "telegram API rejected update polling: {description}")
            }
            Self::MissingResult => write!(f, "telegram update response missing result field"),
        }
    }
}

fn usize_to_u64_saturating(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn checked_committed_height(committed_len: usize) -> Result<u64, String> {
    u64::try_from(committed_len).map_err(|_| {
        format!("committed height {committed_len} exceeds maximum representable u64 height")
    })
}

fn u64_to_usize_cap(value: u64, cap: usize) -> usize {
    match usize::try_from(value) {
        Ok(converted) => converted.min(cap),
        Err(_) => cap,
    }
}

async fn read_bounded_response_body(
    mut resp: reqwest::Response,
    max: usize,
) -> Result<Vec<u8>, TelegramUpdateParseError> {
    let max_u64 = usize_to_u64_saturating(max);
    if let Some(content_length) = resp.content_length() {
        if content_length > max_u64 {
            return Err(TelegramUpdateParseError::Oversized {
                len: content_length,
                max: max_u64,
            });
        }
    }

    let initial_capacity = resp
        .content_length()
        .map_or(0, |len| u64_to_usize_cap(len, max));
    let mut body = Vec::with_capacity(initial_capacity);
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|error| TelegramUpdateParseError::Body(error.to_string()))?
    {
        let next_len = usize_to_u64_saturating(body.len())
            .saturating_add(usize_to_u64_saturating(chunk.len()));
        if next_len > max_u64 {
            return Err(TelegramUpdateParseError::Oversized {
                len: next_len,
                max: max_u64,
            });
        }
        body.extend_from_slice(&chunk);
    }

    Ok(body)
}

async fn read_telegram_update_body(
    resp: reqwest::Response,
) -> Result<Vec<u8>, TelegramUpdateParseError> {
    read_bounded_response_body(resp, MAX_TELEGRAM_UPDATE_RESPONSE_BYTES).await
}

fn parse_updates_response(bytes: &[u8]) -> Result<Vec<Update>, TelegramUpdateParseError> {
    let len = usize_to_u64_saturating(bytes.len());
    let max = usize_to_u64_saturating(MAX_TELEGRAM_UPDATE_RESPONSE_BYTES);
    if len > max {
        return Err(TelegramUpdateParseError::Oversized { len, max });
    }

    let parsed: TelegramResponse<Vec<Update>> = serde_json::from_slice(bytes)
        .map_err(|error| TelegramUpdateParseError::Json(error.to_string()))?;
    if !parsed.ok {
        return Err(TelegramUpdateParseError::ApiRejected {
            description: parsed
                .description
                .unwrap_or_else(|| "ok=false without description".into()),
        });
    }

    parsed.result.ok_or(TelegramUpdateParseError::MissingResult)
}

#[derive(Debug, Deserialize)]
pub(crate) struct Update {
    update_id: i64,
    message: Option<TgMessage>,
    callback_query: Option<CallbackQuery>,
}

#[derive(Debug, Deserialize)]
struct TgMessage {
    text: Option<String>,
    chat: TgChat,
}

#[derive(Debug, Deserialize)]
struct TgChat {
    id: i64,
}

#[derive(Debug, Deserialize)]
struct CallbackQuery {
    id: String,
    data: Option<String>,
    /// The message the inline keyboard was attached to — carries the
    /// originating chat so we can filter out queries from unauthorized
    /// chats. May be absent for very old keyboards; when absent we
    /// reject by default (fail-closed).
    #[serde(default)]
    message: Option<TgMessage>,
}

/// Return true iff `msg` came from the single authorized chat.
///
/// Fail-closed: if `expected_chat_id` is `None` (misconfigured env),
/// no message is authorized.
fn is_message_authorized(expected_chat_id: Option<i64>, msg: &TgMessage) -> bool {
    expected_chat_id == Some(msg.chat.id)
}

/// Return true iff a callback query originated in the authorized chat.
///
/// Callback queries must carry their originating `message` with a
/// `chat` field. Fail-closed: missing message OR missing
/// `expected_chat_id` rejects.
fn is_callback_authorized(expected_chat_id: Option<i64>, cb: &CallbackQuery) -> bool {
    match (&cb.message, expected_chat_id) {
        (Some(m), Some(id)) => id == m.chat.id,
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Adjutant
// ---------------------------------------------------------------------------

/// Configuration for the Telegram adjutant.
#[derive(Clone)]
pub struct AdjutantConfig {
    bot_token: Zeroizing<String>,
    pub chat_id: String,
}

impl std::fmt::Debug for AdjutantConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdjutantConfig")
            .field("bot_token", &"<redacted>")
            .field("chat_id", &self.chat_id)
            .finish()
    }
}

impl AdjutantConfig {
    fn from_parts(bot_token: Zeroizing<String>, chat_id: String) -> Option<Self> {
        if bot_token.is_empty() || chat_id.is_empty() {
            return None;
        }

        Some(Self { bot_token, chat_id })
    }

    /// Load from environment variables.  Returns `None` if not configured.
    #[must_use]
    pub fn from_env() -> Option<Self> {
        let token = Zeroizing::new(std::env::var("TELEGRAM_BOT_TOKEN").ok()?);
        let chat_id = std::env::var("TELEGRAM_CHAT_ID").ok()?;
        Self::from_parts(token, chat_id)
    }
}

/// The Telegram adjutant — chief-of-staff bot.
pub struct Adjutant {
    config: AdjutantConfig,
    client: reqwest::Client,
    last_update_id: i64,
}

fn next_update_offset(last_update_id: i64) -> Option<i64> {
    last_update_id.checked_add(1)
}

impl Adjutant {
    /// Create a new adjutant.
    pub fn new(config: AdjutantConfig) -> Result<Self, String> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(TELEGRAM_HTTP_TIMEOUT_SECS))
            .build()
            .map_err(|error| format!("telegram HTTP client: {error}"))?;

        Ok(Self {
            config,
            client,
            last_update_id: 0,
        })
    }

    /// Telegram Bot API base URL.
    fn api_url(&self, method: &str) -> Zeroizing<String> {
        Zeroizing::new(format!(
            "https://api.telegram.org/bot{}/{}",
            self.config.bot_token.as_str(),
            method
        ))
    }

    /// Send a text message with optional inline keyboard.
    pub async fn send_message(
        &self,
        text: &str,
        keyboard: Option<Vec<Vec<(&str, &str)>>>,
    ) -> Result<(), String> {
        let reply_markup = keyboard.map(|rows| InlineKeyboardMarkup {
            inline_keyboard: rows
                .into_iter()
                .map(|row| {
                    row.into_iter()
                        .map(|(label, data)| InlineKeyboardButton {
                            text: label.to_string(),
                            callback_data: data.to_string(),
                        })
                        .collect()
                })
                .collect(),
        });

        let body = SendMessageRequest {
            chat_id: self.config.chat_id.clone(),
            text: text.to_string(),
            parse_mode: Some("HTML".to_string()),
            reply_markup,
        };

        let url = self.api_url("sendMessage");
        self.client
            .post(url.as_str())
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("telegram send: {e}"))?;

        Ok(())
    }

    /// Send a message, logging a warning on failure instead of silently dropping.
    pub async fn send_or_log(&self, text: &str, keyboard: Option<Vec<Vec<(&str, &str)>>>) {
        if let Err(e) = self.send_message(text, keyboard).await {
            tracing::warn!(err = %e, "Telegram message delivery failed");
        }
    }

    async fn poll_updates_result(&mut self) -> Result<Vec<Update>, String> {
        let base_url = self.api_url("getUpdates");
        let Some(offset) = next_update_offset(self.last_update_id) else {
            return Err(format!(
                "telegram update offset overflow after update id {}",
                self.last_update_id
            ));
        };
        let url = Zeroizing::new(format!(
            "{}?offset={}&timeout=10",
            base_url.as_str(),
            offset
        ));

        let resp = match self.client.get(url.as_str()).send().await {
            Ok(r) => r,
            Err(e) => return Err(format!("telegram poll failed: {e}")),
        };

        let bytes = match read_telegram_update_body(resp).await {
            Ok(bytes) => bytes,
            Err(e) => return Err(format!("telegram update body read failed: {e}")),
        };

        let updates = match parse_updates_response(bytes.as_ref()) {
            Ok(updates) => updates,
            Err(e) => return Err(format!("telegram update response rejected: {e}")),
        };

        if let Some(last) = updates.last() {
            self.last_update_id = last.update_id;
        }

        Ok(updates)
    }

    /// Acknowledge a callback query (removes the "loading" indicator).
    pub async fn answer_callback(&self, callback_id: &str) {
        let url = self.api_url("answerCallbackQuery");
        if let Err(e) = self
            .client
            .post(url.as_str())
            .json(&serde_json::json!({ "callback_query_id": callback_id }))
            .send()
            .await
        {
            tracing::debug!(err = %e, "Telegram callback acknowledgement failed");
        }
    }

    /// Send a sentinel alert with action buttons.
    pub async fn send_alert(&self, alert: &SentinelAlert) {
        let emoji = match alert.severity {
            crate::sentinels::Severity::Critical => "\u{1f6a8}", // 🚨
            crate::sentinels::Severity::Warning => "\u{26a0}\u{fe0f}", // ⚠️
            crate::sentinels::Severity::Info => "\u{2139}\u{fe0f}", // ℹ️
        };
        let check = escape_telegram_html(&alert.check.to_string());
        let message = escape_telegram_html(&alert.message);

        let text = format!(
            "{emoji} <b>SENTINEL: {}</b>\n{}\n\nSeverity: {:?}",
            check, message, alert.severity
        );

        let keyboard = vec![vec![
            ("\u{2705} Acknowledge", "sentinel:ack"),
            ("\u{1f50d} Details", "cmd:sentinels"),
        ]];

        self.send_or_log(&text, Some(keyboard)).await;
    }
}

// ---------------------------------------------------------------------------
// Message builders
// ---------------------------------------------------------------------------

/// Escape dynamic text inserted into Telegram messages sent with HTML parse mode.
fn escape_telegram_html(input: &str) -> String {
    let mut escaped = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

/// Format basis-point value as "XX.YY" (e.g. 5250 → "52.50").
fn fmt_bp(bp: u32) -> String {
    format!("{}.{:02}", bp / 100, bp % 100)
}

type TelegramKeyboard = Vec<Vec<(&'static str, &'static str)>>;
type TelegramMessage = (String, TelegramKeyboard);

/// Build the `/0dentity <did>` response.
///
/// Shows the 8-axis polar table, composite, symmetry and claim count.
/// Spec §10.5.
pub fn build_zerodentity_score_message(
    zerodentity: &SharedZerodentityStore,
    did_str: &str,
) -> (String, Vec<Vec<(&'static str, &'static str)>>) {
    let did = match Did::new(did_str) {
        Ok(d) => d,
        Err(_) => {
            let did_html = escape_telegram_html(did_str);
            return (
                format!("\u{274c} Invalid DID: <code>{did_html}</code>"),
                vec![],
            );
        }
    };
    let did_html = escape_telegram_html(did.as_str());

    let zstore = match zerodentity.lock() {
        Ok(s) => s,
        Err(_) => {
            return (
                "\u{274c} 0dentity store temporarily unavailable".to_string(),
                vec![],
            );
        }
    };
    let score = match zstore.get_score(&did) {
        Some(s) => s.clone(),
        None => {
            return (
                format!(
                    "\u{1f194} <b>0dentity Score</b>\n\
                     No score data for <code>{did_html}</code>"
                ),
                vec![],
            );
        }
    };
    drop(zstore);

    let a = &score.axes;
    let text = format!(
        "\u{1f194} <b>0dentity Score</b>\n\
         <code>{did_html}</code>\n\
         \u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\n\
         Communication:       {}\n\
         CredentialDepth:     {}\n\
         DeviceTrust:         {}\n\
         Behavioral:          {}\n\
         NetworkReputation:   {}\n\
         TemporalStability:   {}\n\
         CryptographicStr:    {}\n\
         Constitutional:      {}\n\
         \u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\n\
         Composite: <b>{}</b> | Symmetry: {}\n\
         Claims: {} verified",
        fmt_bp(a.communication),
        fmt_bp(a.credential_depth),
        fmt_bp(a.device_trust),
        fmt_bp(a.behavioral_signature),
        fmt_bp(a.network_reputation),
        fmt_bp(a.temporal_stability),
        fmt_bp(a.cryptographic_strength),
        fmt_bp(a.constitutional_standing),
        fmt_bp(score.composite),
        fmt_bp(score.symmetry),
        score.claim_count,
    );

    let keyboard = vec![vec![
        ("\u{1f504} Refresh", "cmd:sentinels"),
        ("\u{1f6e1}\u{fe0f} Sentinels", "cmd:sentinels"),
    ]];

    (text, keyboard)
}

/// Severity threshold constants for `/0dentity-alerts`.
/// Composite drop > 1500 bp (= 15.00 pts).
const ALERT_COMPOSITE_DROP_BP: u32 = 1_500;
/// Fingerprint consistency below 2000 bp (= 20.00%).
const ALERT_FINGERPRINT_LOW_BP: u32 = 2_000;
/// OTP lockout window: 24 hours in ms.
const ALERT_OTP_WINDOW_MS: u64 = 86_400_000;
/// Maximum scored DIDs scanned for one `/0dentity-alerts` request.
const MAX_ZERODENTITY_ALERT_SCAN_DIDS: usize = 1_000;

/// Build the `/0dentity-alerts` response.
///
/// Scans all scored DIDs and flags:
/// - Composite drop > 15 pts (1500 bp) since last snapshot
/// - Fingerprint consistency < 20% (2000 bp)
/// - OTP lockout in the last 24 h
///
/// Spec §10.5.
pub fn build_zerodentity_alerts_message(
    zerodentity: &SharedZerodentityStore,
) -> (String, Vec<Vec<(&'static str, &'static str)>>) {
    let zstore = match zerodentity.lock() {
        Ok(s) => s,
        Err(_) => {
            return (
                "\u{274c} 0dentity store temporarily unavailable".to_string(),
                vec![],
            );
        }
    };
    let scored_did_count = zstore.scored_did_count();
    let dids = zstore.sample_scored_dids(MAX_ZERODENTITY_ALERT_SCAN_DIDS);
    drop(zstore);

    let since_ms = now_ms().saturating_sub(ALERT_OTP_WINDOW_MS);
    let mut alerts: Vec<String> = Vec::new();

    for did in &dids {
        let (current_score, previous_score, fingerprints, has_recent_otp_lockout) = {
            let zstore = match zerodentity.lock() {
                Ok(s) => s,
                Err(_) => {
                    return (
                        "\u{274c} 0dentity store temporarily unavailable".to_string(),
                        vec![],
                    );
                }
            };
            let current_score = zstore.get_score(did).cloned();
            let previous_score = zstore.get_previous_score(did).cloned();
            let fingerprints = match zstore.get_fingerprints(did) {
                Ok(fps) => fps,
                Err(e) => {
                    let did_html = escape_telegram_html(did.as_str());
                    let error_html = escape_telegram_html(&e.to_string());
                    return (
                        format!(
                            "\u{274c} <b>0dentity Alerts</b>\n\
                             0dentity alert scan unavailable while reading fingerprints for <code>{}</code>: {}",
                            did_html, error_html
                        ),
                        vec![],
                    );
                }
            };
            let has_recent_otp_lockout = zstore.has_otp_lockout_since(did, since_ms);

            (
                current_score,
                previous_score,
                fingerprints,
                has_recent_otp_lockout,
            )
        };

        // 1. Score regression.
        if let (Some(curr), Some(prev)) = (current_score, previous_score) {
            if prev.composite > curr.composite
                && prev.composite - curr.composite > ALERT_COMPOSITE_DROP_BP
            {
                let did_html = escape_telegram_html(did.as_str());
                alerts.push(format!(
                    "\u{26a0}\u{fe0f} <code>{}</code> score dropped {} bp ({}\u{2192}{})",
                    did_html,
                    prev.composite - curr.composite,
                    fmt_bp(prev.composite),
                    fmt_bp(curr.composite),
                ));
            }
        }

        // 2. Fingerprint consistency.
        if let Some(latest) = fingerprints.last() {
            if let Some(consistency) = latest.consistency_score_bp {
                if consistency < ALERT_FINGERPRINT_LOW_BP {
                    let did_html = escape_telegram_html(did.as_str());
                    alerts.push(format!(
                        "\u{26a0}\u{fe0f} <code>{}</code> fingerprint consistency low: {}",
                        did_html,
                        fmt_bp(consistency),
                    ));
                }
            }
        }

        // 3. OTP lockout in last 24h.
        if has_recent_otp_lockout {
            let did_html = escape_telegram_html(did.as_str());
            alerts.push(format!(
                "\u{1f512} <code>{}</code> OTP lockout in last 24h",
                did_html,
            ));
        }
    }

    let scan_limit_note = if scored_did_count > dids.len() {
        format!(
            "\nScan limited to first {} of {} scored DIDs.",
            dids.len(),
            scored_did_count
        )
    } else {
        String::new()
    };

    let text = if alerts.is_empty() {
        format!(
            "\u{2705} <b>0dentity Alerts</b>\n\
             \u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\n\
             No 0dentity alerts.{scan_limit_note}",
        )
    } else {
        let count = alerts.len();
        let body = alerts.join("\n");
        format!(
            "\u{1f6a8} <b>0dentity Alerts</b>\n\
             \u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\n\
             {body}\n\
             \u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\n\
             {count} alert(s) found.{scan_limit_note}"
        )
    };

    let keyboard = vec![vec![
        ("\u{1f504} Refresh", "0d_alerts"),
        ("\u{1f6e1}\u{fe0f} Sentinels", "cmd:sentinels"),
    ]];

    (text, keyboard)
}

/// Build the /status response.
pub fn build_status_message(
    reactor: &SharedReactorState,
    store: &Arc<Mutex<SqliteDagStore>>,
) -> (String, Vec<Vec<(&'static str, &'static str)>>) {
    let (round, height, validator_count, is_validator) = match reactor.lock() {
        Ok(s) => match checked_committed_height(s.consensus.committed.len()) {
            Ok(height) => (
                s.consensus.current_round,
                height,
                s.consensus.config.validators.len(),
                s.is_validator,
            ),
            Err(e) => {
                let error_html = escape_telegram_html(&e);
                return (
                    format!("\u{274c} Reactor height unavailable: {error_html}"),
                    vec![],
                );
            }
        },
        Err(_) => {
            return (
                "\u{274c} Reactor state temporarily unavailable".to_string(),
                vec![],
            );
        }
    };

    let store_height = match store.lock() {
        Ok(st) => match st.committed_height_value() {
            Ok(height) => height,
            Err(e) => {
                let error_html = escape_telegram_html(&e.to_string());
                return (
                    format!("\u{274c} Store height unavailable: {error_html}"),
                    vec![],
                );
            }
        },
        Err(_) => {
            return (
                "\u{274c} Store state temporarily unavailable".to_string(),
                vec![],
            );
        }
    };

    let role = if is_validator {
        "Validator"
    } else {
        "Observer"
    };

    let text = format!(
        "\u{1f4ca} <b>EXOCHAIN Node Status</b>\n\
         \u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\n\
         Round: <code>{round}</code> | Height: <code>{height}</code>\n\
         Store Height: <code>{store_height}</code>\n\
         Validators: <code>{validator_count}</code> | Role: {role}",
    );

    let keyboard = vec![
        vec![
            ("\u{1f4dd} Receipts", "cmd:receipts"),
            ("\u{26a0}\u{fe0f} Challenges", "cmd:challenges"),
        ],
        vec![
            ("\u{1f6e1}\u{fe0f} Sentinels", "cmd:sentinels"),
            ("\u{1f504} Refresh", "cmd:status"),
        ],
    ];

    (text, keyboard)
}

/// Build the /sentinels response.
pub fn build_sentinels_message(
    sentinel_state: &SharedSentinelState,
) -> (String, Vec<Vec<(&'static str, &'static str)>>) {
    let statuses = match sentinel_state.lock() {
        Ok(s) => s,
        Err(_) => {
            return (
                "\u{274c} Sentinel state temporarily unavailable".to_string(),
                vec![],
            );
        }
    };

    let mut text = String::from(
        "\u{1f6e1}\u{fe0f} <b>Sentinel Status</b>\n\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\n",
    );

    if statuses.is_empty() {
        text.push_str("No sentinel data yet — checks run every 30s.");
    } else {
        for s in statuses.iter() {
            let icon = if s.healthy { "\u{2705}" } else { "\u{274c}" };
            let check = escape_telegram_html(&s.check.to_string());
            let message = escape_telegram_html(&s.message);
            text.push_str(&format!("{icon} <b>{check}</b>: {message}\n"));
        }
    }

    let keyboard = vec![vec![
        ("\u{1f504} Refresh", "cmd:sentinels"),
        ("\u{1f4ca} Status", "cmd:status"),
    ]];

    (text, keyboard)
}

/// Build the /challenges response.
pub fn build_challenges_message(
    challenge_store: &SharedChallengeStore,
) -> (String, Vec<Vec<(&'static str, &'static str)>>) {
    let st = match challenge_store.lock() {
        Ok(s) => s,
        Err(_) => {
            return (
                "\u{274c} Challenge store temporarily unavailable".to_string(),
                vec![],
            );
        }
    };
    let holds = st.list();

    let mut text = String::from(
        "\u{26a0}\u{fe0f} <b>Active Challenges</b>\n\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\n",
    );

    if holds.is_empty() {
        text.push_str("No active challenges.");
    } else {
        for h in holds {
            let id = h.id.to_string();
            let id_short = escape_telegram_html(&id[..8]);
            let ground = escape_telegram_html(&h.ground.to_string());
            let status = escape_telegram_html(h.status.as_str());
            text.push_str(&format!(
                "\u{2022} <code>{id_short}</code>\n  Ground: {ground}\n  Status: {status}\n\n",
            ));
        }
    }

    let keyboard = vec![vec![
        ("\u{1f504} Refresh", "cmd:challenges"),
        ("\u{1f4ca} Status", "cmd:status"),
    ]];

    (text, keyboard)
}

fn telegram_message_builder_failed(
    label: &'static str,
    error: tokio::task::JoinError,
) -> TelegramMessage {
    tracing::error!(%label, err = %error, "Telegram message builder task failed");
    (
        "\u{274c} Telegram message builder temporarily unavailable".to_string(),
        vec![],
    )
}

async fn status_message_blocking(
    reactor: SharedReactorState,
    store: Arc<Mutex<SqliteDagStore>>,
) -> TelegramMessage {
    tokio::task::spawn_blocking(move || build_status_message(&reactor, &store))
        .await
        .unwrap_or_else(|e| telegram_message_builder_failed("status", e))
}

async fn sentinels_message_blocking(state: SharedSentinelState) -> TelegramMessage {
    tokio::task::spawn_blocking(move || build_sentinels_message(&state))
        .await
        .unwrap_or_else(|e| telegram_message_builder_failed("sentinels", e))
}

async fn challenges_message_blocking(challenge_store: SharedChallengeStore) -> TelegramMessage {
    tokio::task::spawn_blocking(move || build_challenges_message(&challenge_store))
        .await
        .unwrap_or_else(|e| telegram_message_builder_failed("challenges", e))
}

async fn zerodentity_score_message_blocking(
    zerodentity: SharedZerodentityStore,
    did_str: String,
) -> TelegramMessage {
    tokio::task::spawn_blocking(move || build_zerodentity_score_message(&zerodentity, &did_str))
        .await
        .unwrap_or_else(|e| telegram_message_builder_failed("0dentity-score", e))
}

async fn zerodentity_alerts_message_blocking(
    zerodentity: SharedZerodentityStore,
) -> TelegramMessage {
    tokio::task::spawn_blocking(move || build_zerodentity_alerts_message(&zerodentity))
        .await
        .unwrap_or_else(|e| telegram_message_builder_failed("0dentity-alerts", e))
}

// ---------------------------------------------------------------------------
// Main adjutant loop
// ---------------------------------------------------------------------------

/// Run the Telegram adjutant as a background Tokio task.
///
/// Handles:
/// 1. Incoming commands from the operator (`/status`, `/receipts`, etc.)
/// 2. Callback queries from inline keyboard buttons
/// 3. Sentinel alerts forwarded from the alert channel
#[allow(clippy::too_many_arguments)]
pub async fn run_adjutant(
    mut adjutant: Adjutant,
    mut alert_rx: AlertReceiver,
    reactor: SharedReactorState,
    store: Arc<Mutex<SqliteDagStore>>,
    challenge_store: SharedChallengeStore,
    sentinel_state: SharedSentinelState,
    zerodentity: SharedZerodentityStore,
) {
    // Announce startup.
    adjutant
        .send_or_log(
            "\u{1f916} <b>EXOCHAIN Adjutant Online</b>\n\nType /status for node overview.",
            Some(vec![vec![
                ("\u{1f4ca} Status", "cmd:status"),
                ("\u{1f6e1}\u{fe0f} Sentinels", "cmd:sentinels"),
            ]]),
        )
        .await;

    loop {
        tokio::select! {
            // Forward sentinel alerts to Telegram.
            Some(alert) = alert_rx.recv() => {
                adjutant.send_alert(&alert).await;
            }

            // Poll for Telegram updates.
            poll_result = adjutant.poll_updates_result() => {
                let updates = match poll_result {
                    Ok(updates) => updates,
                    Err(e) => {
                        tracing::debug!(err = %e, "Telegram poll failed; backing off before retry");
                        tokio::time::sleep(std::time::Duration::from_millis(
                            TELEGRAM_POLL_FAILURE_BACKOFF_MS,
                        ))
                        .await;
                        Vec::new()
                    }
                };

                // Parse the configured authorized chat id once per batch.
                // If it fails to parse (misconfigured env), we fail-closed:
                // no commands are dispatched.
                let expected_chat_id: Option<i64> =
                    adjutant.config.chat_id.parse::<i64>().ok();
                if expected_chat_id.is_none() {
                    tracing::error!(
                        configured = %adjutant.config.chat_id,
                        "TELEGRAM_CHAT_ID is not a valid i64 — rejecting ALL inbound updates (fail-closed)"
                    );
                }

                for update in updates {
                    // Handle text commands.
                    if let Some(msg) = &update.message {
                        // GAP-015 defense: reject messages from any chat other
                        // than the configured authorized chat. Without this,
                        // any holder of the bot token could DM the bot and
                        // receive full node internal state.
                        if !is_message_authorized(expected_chat_id, msg) {
                            tracing::warn!(
                                incoming_chat = msg.chat.id,
                                expected = %adjutant.config.chat_id,
                                "Rejected Telegram message from unauthorized chat"
                            );
                        } else if let Some(text) = &msg.text {
                            handle_command(
                                &adjutant,
                                text,
                                &reactor,
                                &store,
                                &challenge_store,
                                &sentinel_state,
                                &zerodentity,
                            )
                            .await;
                        }
                    }

                    // Handle callback queries (button presses).
                    if let Some(cb) = &update.callback_query {
                        // Callback queries must carry an originating message
                        // whose chat matches. Missing chat info = reject
                        // (fail-closed).
                        if !is_callback_authorized(expected_chat_id, cb) {
                            tracing::warn!(
                                callback_id = %cb.id,
                                "Rejected Telegram callback from unauthorized or unknown chat"
                            );
                            // Still answer the callback so the user's UI
                            // clears (prevents their Telegram from showing a
                            // perpetual spinner), but don't dispatch.
                            adjutant.answer_callback(&cb.id).await;
                        } else {
                            adjutant.answer_callback(&cb.id).await;
                            if let Some(data) = &cb.data {
                                handle_callback(
                                    &adjutant,
                                    data,
                                    &reactor,
                                    &store,
                                    &challenge_store,
                                    &sentinel_state,
                                    &zerodentity,
                                )
                                .await;
                            }
                        }
                    }
                }
            }
        }
    }
}

async fn handle_command(
    adjutant: &Adjutant,
    text: &str,
    reactor: &SharedReactorState,
    store: &Arc<Mutex<SqliteDagStore>>,
    challenge_store: &SharedChallengeStore,
    sentinel_state: &SharedSentinelState,
    zerodentity: &SharedZerodentityStore,
) {
    let mut parts = text.split_whitespace();
    let cmd = parts.next().unwrap_or("");
    match cmd {
        "/status" | "/start" => {
            let (msg, kb) = status_message_blocking(Arc::clone(reactor), Arc::clone(store)).await;
            adjutant.send_or_log(&msg, Some(kb)).await;
        }
        "/sentinels" => {
            let (msg, kb) = sentinels_message_blocking(Arc::clone(sentinel_state)).await;
            adjutant.send_or_log(&msg, Some(kb)).await;
        }
        "/challenges" => {
            let (msg, kb) = challenges_message_blocking(Arc::clone(challenge_store)).await;
            adjutant.send_or_log(&msg, Some(kb)).await;
        }
        "/0dentity" => {
            let did_str = parts.next().unwrap_or("");
            if did_str.is_empty() {
                adjutant
                    .send_or_log(
                        "Usage: /0dentity &lt;did&gt;\nExample: /0dentity did:exo:alice",
                        None,
                    )
                    .await;
            } else {
                let (msg, kb) = zerodentity_score_message_blocking(
                    Arc::clone(zerodentity),
                    did_str.to_string(),
                )
                .await;
                adjutant.send_or_log(&msg, Some(kb)).await;
            }
        }
        "/0dentity-alerts" => {
            let (msg, kb) = zerodentity_alerts_message_blocking(Arc::clone(zerodentity)).await;
            adjutant.send_or_log(&msg, Some(kb)).await;
        }
        "/help" => {
            adjutant
                .send_or_log(
                    "\u{1f4d6} <b>Commands</b>\n\
                     /status — Node overview\n\
                     /sentinels — Health checks\n\
                     /challenges — Active disputes\n\
                     /0dentity &lt;did&gt; — Identity score for a DID\n\
                     /0dentity-alerts — Active 0dentity alerts\n\
                     /help — This message",
                    None,
                )
                .await;
        }
        _ => {}
    }
}

async fn handle_callback(
    adjutant: &Adjutant,
    data: &str,
    reactor: &SharedReactorState,
    store: &Arc<Mutex<SqliteDagStore>>,
    challenge_store: &SharedChallengeStore,
    sentinel_state: &SharedSentinelState,
    zerodentity: &SharedZerodentityStore,
) {
    if let Some(did_str) = data.strip_prefix("0d_score:") {
        let (msg, kb) =
            zerodentity_score_message_blocking(Arc::clone(zerodentity), did_str.to_string()).await;
        adjutant.send_or_log(&msg, Some(kb)).await;
        return;
    }
    match data {
        "cmd:status" => {
            let (msg, kb) = status_message_blocking(Arc::clone(reactor), Arc::clone(store)).await;
            adjutant.send_or_log(&msg, Some(kb)).await;
        }
        "cmd:sentinels" => {
            let (msg, kb) = sentinels_message_blocking(Arc::clone(sentinel_state)).await;
            adjutant.send_or_log(&msg, Some(kb)).await;
        }
        "cmd:challenges" => {
            let (msg, kb) = challenges_message_blocking(Arc::clone(challenge_store)).await;
            adjutant.send_or_log(&msg, Some(kb)).await;
        }
        "0d_alerts" => {
            let (msg, kb) = zerodentity_alerts_message_blocking(Arc::clone(zerodentity)).await;
            adjutant.send_or_log(&msg, Some(kb)).await;
        }
        "sentinel:ack" => {
            adjutant
                .send_or_log("\u{2705} Alert acknowledged.", None)
                .await;
        }
        _ => {
            tracing::debug!(callback_data = %data, "Unknown callback");
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::collections::BTreeSet;

    use exo_core::types::{Did, Signature};

    use super::*;
    use crate::{
        challenges::ChallengeStore,
        reactor::{ReactorConfig, create_reactor_state},
        sentinels::{SentinelCheck, SentinelStatus},
        store::SqliteDagStore,
    };

    fn make_sign_fn() -> Arc<dyn Fn(&[u8]) -> Signature + Send + Sync> {
        Arc::new(|data: &[u8]| {
            let h = blake3::hash(data);
            let mut sig = [0u8; 64];
            sig[..32].copy_from_slice(h.as_bytes());
            Signature::from_bytes(sig)
        })
    }

    async fn response_from_raw_http(raw: Vec<u8>) -> reqwest::Response {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 1024];
            let _bytes_read = tokio::io::AsyncReadExt::read(&mut stream, &mut request).await;
            tokio::io::AsyncWriteExt::write_all(&mut stream, &raw)
                .await
                .unwrap();
        });

        reqwest::Client::new()
            .get(format!("http://{addr}/updates"))
            .send()
            .await
            .unwrap()
    }

    fn score_snapshot(
        did: &Did,
        composite: u32,
        computed_ms: u64,
    ) -> crate::zerodentity::types::ZerodentityScore {
        let mut score =
            crate::zerodentity::types::ZerodentityScore::compute(did, &[], &[], &[], computed_ms);
        score.composite = composite;
        score
    }

    fn test_reactor() -> SharedReactorState {
        let validators: BTreeSet<Did> = (0..4)
            .map(|i| Did::new(&format!("did:exo:v{i}")).unwrap())
            .collect();
        let config = ReactorConfig {
            node_did: Did::new("did:exo:v0").unwrap(),
            is_validator: true,
            validators,
            validator_public_keys: std::collections::BTreeMap::new(),
            round_timeout_ms: 5000,
        };
        create_reactor_state(&config, make_sign_fn(), None)
    }

    #[test]
    fn telegram_html_escape_encodes_special_chars() {
        assert_eq!(
            escape_telegram_html("<b>owned</b>&\"'"),
            "&lt;b&gt;owned&lt;/b&gt;&amp;&quot;&#39;"
        );
    }

    #[test]
    fn zerodentity_score_message_escapes_invalid_did_html() {
        let zerodentity = crate::zerodentity::store::new_shared_store();

        let (text, keyboard) =
            build_zerodentity_score_message(&zerodentity, "did:exo:<b>owned</b>&x");

        assert!(keyboard.is_empty());
        assert!(text.contains("&lt;b&gt;owned&lt;/b&gt;&amp;x"));
        assert!(!text.contains("<b>owned</b>&x"));
    }

    #[test]
    fn sentinels_message_escapes_status_text_html() {
        let sentinel_state = Arc::new(Mutex::new(vec![SentinelStatus {
            check: SentinelCheck::Liveness,
            healthy: false,
            message: "<b>owned</b>&\"'".to_string(),
            last_run_ms: 1,
        }]));

        let (text, keyboard) = build_sentinels_message(&sentinel_state);

        assert!(!keyboard.is_empty());
        assert!(text.contains("&lt;b&gt;owned&lt;/b&gt;&amp;&quot;&#39;"));
        assert!(!text.contains("<b>owned</b>&\"'"));
    }

    #[test]
    fn zerodentity_alerts_do_not_discard_store_read_errors() {
        let source = include_str!("telegram.rs");
        let production = source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .unwrap();
        let alerts = production
            .split("pub fn build_zerodentity_alerts_message")
            .nth(1)
            .and_then(|section| section.split("/// Build the /sentinels response.").next())
            .unwrap();

        assert!(!alerts.contains(".unwrap_or_default()"));
    }

    #[test]
    fn telegram_delivery_paths_do_not_silently_discard_send_failures() {
        let source = include_str!("telegram.rs");
        let production = source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .unwrap();

        for forbidden in [
            "let _ = adjutant\n        .send_message(",
            "let _ = adjutant\n                    .send_message(",
            "let _ = adjutant.send_message(",
            "let _ = self\n            .client\n            .post(url.as_str())",
        ] {
            assert!(
                !production.contains(forbidden),
                "Telegram delivery failures must be observed or logged: {forbidden}"
            );
        }
    }

    #[test]
    fn zerodentity_alerts_do_not_request_unbounded_score_sample() {
        let source = include_str!("telegram.rs");
        let production = source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .unwrap();
        let alerts = production
            .split("pub fn build_zerodentity_alerts_message")
            .nth(1)
            .and_then(|section| section.split("/// Build the /status response.").next())
            .unwrap();

        assert!(
            !alerts.contains("sample_scored_dids(usize::MAX)"),
            "Telegram 0dentity alerts must never request an unbounded score sample"
        );
    }

    #[test]
    fn zerodentity_alerts_release_initial_store_lock_before_scanning_dids() {
        let source = include_str!("telegram.rs");
        let production = source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .unwrap();
        let alerts = production
            .split("pub fn build_zerodentity_alerts_message")
            .nth(1)
            .and_then(|section| section.split("/// Build the /status response.").next())
            .unwrap();
        let sample_index = alerts
            .find("sample_scored_dids")
            .expect("alert builder samples scored DIDs");
        let loop_index = alerts
            .find("for did in &dids")
            .expect("alert builder iterates sampled DIDs");

        assert!(
            alerts[sample_index..loop_index].contains("drop(zstore)"),
            "Telegram 0dentity alerts must drop the initial store lock before per-DID scanning"
        );
    }

    #[test]
    fn zerodentity_alerts_scan_only_bounded_prefix() {
        let zerodentity = crate::zerodentity::store::new_shared_store();
        let scan_limit = 1_000;
        {
            let mut store = zerodentity.lock().unwrap();
            for i in 0..=scan_limit {
                let did = Did::new(&format!("did:exo:alert{i:04}")).unwrap();
                store.put_score(score_snapshot(&did, 9_000, 1000));
                store.put_score(score_snapshot(&did, 7_000, 2000));
            }
        }

        let (text, keyboard) = build_zerodentity_alerts_message(&zerodentity);

        assert!(text.contains("1000 alert(s) found."));
        assert!(!text.contains("did:exo:alert1000"));
        assert!(!keyboard.is_empty());
    }

    #[test]
    fn telegram_production_uses_checked_committed_height_conversion() {
        let source = include_str!("telegram.rs");
        let production = source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .unwrap();
        let status_builder = production
            .split("pub fn build_status_message")
            .nth(1)
            .and_then(|section| section.split("/// Build the /sentinels response.").next())
            .unwrap();

        assert!(
            !production.contains("clippy::as_conversions"),
            "Telegram production code must not suppress checked conversion linting"
        );
        assert!(
            !status_builder.contains("committed.len() as u64"),
            "Telegram status height must use a checked conversion from committed length"
        );
        assert!(
            status_builder.contains("checked_committed_height"),
            "Telegram status height must route conversion through the checked helper"
        );
    }

    #[test]
    fn telegram_async_dispatch_uses_blocking_message_builders() {
        let source = include_str!("telegram.rs");
        let production = source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .unwrap();

        assert!(
            production.contains("tokio::task::spawn_blocking"),
            "Telegram async dispatch must isolate synchronous store reads from Tokio workers"
        );

        let sync_builders = [
            "build_status_message(",
            "build_sentinels_message(",
            "build_challenges_message(",
            "build_zerodentity_score_message(",
            "build_zerodentity_alerts_message(",
        ];
        let command_handler = production
            .split("async fn handle_command")
            .nth(1)
            .and_then(|section| section.split("async fn handle_callback").next())
            .unwrap();
        for builder in sync_builders {
            assert!(
                !command_handler.contains(builder),
                "Telegram command handler must not call sync builder {builder} directly"
            );
        }

        let callback_handler = production
            .split("async fn handle_callback")
            .nth(1)
            .and_then(|section| section.split("// ---------------------------------------------------------------------------\n// Tests").next())
            .unwrap();
        for builder in sync_builders {
            assert!(
                !callback_handler.contains(builder),
                "Telegram callback handler must not call sync builder {builder} directly"
            );
        }
    }

    #[test]
    fn adjutant_config_source_uses_zeroizing_token_storage() {
        let source = include_str!("telegram.rs");
        let production = source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .unwrap();
        let config_source = production
            .split("pub struct AdjutantConfig")
            .nth(1)
            .and_then(|section| section.split("impl AdjutantConfig").next())
            .unwrap();

        assert!(production.contains("use zeroize::Zeroizing;"));
        assert!(config_source.contains("bot_token: Zeroizing<String>"));
        assert!(!config_source.contains("bot_token: String"));
    }

    #[test]
    fn adjutant_config_debug_redacts_bot_token() {
        let config = AdjutantConfig::from_parts(
            zeroize::Zeroizing::new("123456:secret-token-value".to_string()),
            "42".to_string(),
        )
        .expect("valid config");

        let debug = format!("{config:?}");

        assert!(debug.contains("AdjutantConfig"));
        assert!(debug.contains("bot_token"));
        assert!(debug.contains("<redacted>"));
        assert!(debug.contains("chat_id"));
        assert!(!debug.contains("123456"));
        assert!(!debug.contains("secret-token-value"));
    }

    #[test]
    fn adjutant_config_from_parts_rejects_empty_secret_or_chat() {
        assert!(
            AdjutantConfig::from_parts(zeroize::Zeroizing::new(String::new()), "42".to_string())
                .is_none()
        );
        assert!(
            AdjutantConfig::from_parts(
                zeroize::Zeroizing::new("123456:secret-token-value".to_string()),
                String::new(),
            )
            .is_none()
        );
    }

    #[test]
    fn telegram_api_url_source_uses_zeroizing_temporary_url() {
        let source = include_str!("telegram.rs");
        let production = source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .unwrap();
        let api_url_source = production
            .split("fn api_url(&self, method: &str)")
            .nth(1)
            .and_then(|section| section.split("/// Send a text message").next())
            .unwrap();

        assert!(api_url_source.contains("-> Zeroizing<String>"));
        assert!(api_url_source.contains("Zeroizing::new(format!("));
        assert!(api_url_source.contains("self.config.bot_token.as_str()"));
    }

    #[test]
    fn adjutant_http_client_uses_timeout() {
        let source = include_str!("telegram.rs");
        let production = source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .unwrap();
        let new_adjutant = production
            .split("pub fn new(config: AdjutantConfig)")
            .nth(1)
            .and_then(|section| section.split("/// Telegram Bot API base URL.").next())
            .unwrap();

        assert!(new_adjutant.contains("reqwest::Client::builder()"));
        assert!(
            new_adjutant
                .contains(".timeout(std::time::Duration::from_secs(TELEGRAM_HTTP_TIMEOUT_SECS))")
        );
        assert!(!new_adjutant.contains("reqwest::Client::new()"));
    }

    #[test]
    fn poll_updates_uses_bounded_response_body_before_deserialization() {
        let source = include_str!("telegram.rs");
        let production = source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .unwrap();
        let poll_updates = production
            .split("async fn poll_updates_result")
            .nth(1)
            .and_then(|section| section.split("/// Acknowledge a callback query").next())
            .unwrap();

        assert!(!poll_updates.contains(".json().await"));
        assert!(!poll_updates.contains(".bytes().await"));
        assert!(poll_updates.contains("read_telegram_update_body"));
        assert!(poll_updates.contains("parse_updates_response"));
    }

    #[test]
    fn run_adjutant_backs_off_after_telegram_poll_failures() {
        let source = include_str!("telegram.rs");
        let production = source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .unwrap();
        let run_adjutant = production
            .split("pub async fn run_adjutant")
            .nth(1)
            .and_then(|section| section.split("async fn handle_command").next())
            .unwrap();

        assert!(
            run_adjutant.contains("poll_updates_result"),
            "run_adjutant must distinguish failed polls from successful empty long-poll responses"
        );
        assert!(
            run_adjutant.contains("TELEGRAM_POLL_FAILURE_BACKOFF_MS"),
            "failed Telegram polls must use a bounded backoff instead of immediate repolling"
        );
        assert!(
            run_adjutant.contains("tokio::time::sleep"),
            "Telegram poll failure backoff must sleep before the next poll attempt"
        );
    }

    #[test]
    fn next_update_offset_rejects_i64_max_without_wrapping() {
        assert_eq!(next_update_offset(41), Some(42));
        assert_eq!(next_update_offset(i64::MAX), None);
    }

    #[tokio::test]
    async fn read_bounded_response_body_rejects_oversized_content_length() {
        let max = 8;
        let raw = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", max + 1);
        let resp = response_from_raw_http(raw.into_bytes()).await;

        let err = read_bounded_response_body(resp, max)
            .await
            .expect_err("oversized content-length must fail before body read");

        assert_eq!(
            err,
            TelegramUpdateParseError::Oversized {
                len: 9,
                max: usize_to_u64_saturating(max),
            }
        );
    }

    #[tokio::test]
    async fn read_bounded_response_body_rejects_chunked_body_after_limit() {
        let resp = response_from_raw_http(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n8\r\n12345678\r\n1\r\n9\r\n0\r\n\r\n"
                .to_vec(),
        )
        .await;

        let err = read_bounded_response_body(resp, 8)
            .await
            .expect_err("streaming body exceeding the limit must fail");

        assert_eq!(err, TelegramUpdateParseError::Oversized { len: 9, max: 8 });
    }

    #[tokio::test]
    async fn read_bounded_response_body_accepts_body_within_limit() {
        let resp = response_from_raw_http(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
                .to_vec(),
        )
        .await;

        let body = read_bounded_response_body(resp, 8)
            .await
            .expect("body within limit must pass");

        assert_eq!(body, b"hello");
    }

    #[test]
    fn parse_updates_response_rejects_oversized_body() {
        let bytes = vec![b' '; MAX_TELEGRAM_UPDATE_RESPONSE_BYTES + 1];

        let err = parse_updates_response(&bytes).expect_err("oversized response must fail");

        assert_eq!(
            err,
            TelegramUpdateParseError::Oversized {
                len: usize_to_u64_saturating(MAX_TELEGRAM_UPDATE_RESPONSE_BYTES + 1),
                max: usize_to_u64_saturating(MAX_TELEGRAM_UPDATE_RESPONSE_BYTES),
            }
        );
    }

    #[test]
    fn parse_updates_response_accepts_valid_updates() {
        let updates = parse_updates_response(
            br#"{"ok":true,"result":[{"update_id":42,"message":{"text":"/status","chat":{"id":7}}}]}"#,
        )
        .expect("valid Telegram update response");

        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].update_id, 42);
        assert!(updates[0].message.is_some());
    }

    #[test]
    fn parse_updates_response_rejects_missing_result() {
        let err =
            parse_updates_response(br#"{"ok":true}"#).expect_err("missing result must fail closed");

        assert!(matches!(err, TelegramUpdateParseError::MissingResult));
    }

    #[test]
    fn parse_updates_response_rejects_api_failure() {
        let err = parse_updates_response(br#"{"ok":false,"description":"Unauthorized"}"#)
            .expect_err("Telegram API failure must fail closed");

        assert!(matches!(
            err,
            TelegramUpdateParseError::ApiRejected { description } if description == "Unauthorized"
        ));
    }

    #[test]
    fn zerodentity_alerts_fail_closed_on_fingerprint_read_error() {
        let zerodentity = crate::zerodentity::store::new_shared_store();
        {
            let did = Did::new("did:exo:alerted").unwrap();
            let mut store = zerodentity.lock().unwrap();
            store.put_score(crate::zerodentity::types::ZerodentityScore::compute(
                &did,
                &[],
                &[],
                &[],
                1000,
            ));
            store.inject_read_failure(
                crate::zerodentity::store::ZerodentityReadFailure::Fingerprints,
            );
        }

        let (text, keyboard) = build_zerodentity_alerts_message(&zerodentity);

        assert!(text.contains("0dentity alert scan unavailable"));
        assert!(text.contains("did:exo:alerted"));
        assert!(keyboard.is_empty());
    }

    #[test]
    fn config_from_env_returns_none_when_unset() {
        // Env vars are not set in test environment.
        assert!(AdjutantConfig::from_env().is_none());
    }

    #[test]
    fn status_message_contains_key_metrics() {
        let reactor = test_reactor();
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Mutex::new(SqliteDagStore::open(dir.path()).unwrap()));

        let (text, keyboard) = build_status_message(&reactor, &store);
        assert!(text.contains("Round:"));
        assert!(text.contains("Height:"));
        assert!(text.contains("Validators:"));
        assert!(text.contains("Validator")); // role
        assert!(!keyboard.is_empty());
    }

    #[test]
    fn status_message_fails_closed_on_store_height_error() {
        let reactor = test_reactor();
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteDagStore::open(dir.path()).unwrap();
        let conn = rusqlite::Connection::open(dir.path().join("dag.db")).unwrap();
        let hash = [0xA5u8; 32];
        conn.execute(
            "INSERT INTO committed (hash, height) VALUES (?1, ?2)",
            rusqlite::params![hash.as_slice(), -1_i64],
        )
        .unwrap();
        let store = Arc::new(Mutex::new(store));

        let (text, keyboard) = build_status_message(&reactor, &store);

        assert!(text.contains("Store height unavailable"));
        assert!(text.contains("committed.height"));
        assert!(keyboard.is_empty());
    }

    #[test]
    fn sentinels_message_shows_statuses() {
        let state: SharedSentinelState = Arc::new(Mutex::new(vec![SentinelStatus {
            check: SentinelCheck::Liveness,
            healthy: true,
            message: "ok".into(),
            last_run_ms: 0,
        }]));
        let (text, _) = build_sentinels_message(&state);
        assert!(text.contains("Liveness"));
        assert!(text.contains("ok"));
    }

    #[test]
    fn challenges_message_empty() {
        let store: SharedChallengeStore = Arc::new(Mutex::new(ChallengeStore::new()));
        let (text, _) = build_challenges_message(&store);
        assert!(text.contains("No active challenges"));
    }

    #[test]
    fn challenges_message_with_hold() {
        use exo_escalation::challenge::{
            self, ChallengeAdmission, SybilChallengeGround, sign_challenge_admission,
        };

        let store: SharedChallengeStore = Arc::new(Mutex::new(ChallengeStore::new()));
        {
            let mut st = store.lock().unwrap();
            let keypair = exo_core::crypto::KeyPair::from_secret_bytes([7u8; 32]).unwrap();
            let admission = ChallengeAdmission {
                hold_id: uuid::Uuid::from_bytes([1u8; 16]),
                action_id: [1u8; 32],
                ground: SybilChallengeGround::QuorumContamination,
                admitted_at: exo_core::types::Timestamp::new(1000, 0),
                admitted_by: Did::new("did:exo:reviewer").unwrap(),
                admitter_public_key: *keypair.public_key(),
                evidence_hash: [0xEEu8; 32],
                authority_chain_hash: [0xACu8; 32],
            };
            let hold = challenge::admit_challenge(
                sign_challenge_admission(admission, keypair.secret_key()).unwrap(),
            )
            .unwrap();
            st.insert(hold);
        }
        let (text, _) = build_challenges_message(&store);
        assert!(text.contains("QuorumContamination"));
        assert!(text.contains("PauseEligible"));
    }

    #[test]
    fn challenges_message_uses_stable_status_labels() {
        let source = include_str!("telegram.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production section");
        assert!(
            !production.contains("format!(\"{:?}\", h.status)"),
            "Telegram challenge status output must use explicit stable labels"
        );
        assert!(
            production.contains("h.status.as_str()"),
            "Telegram challenge status output must use ContestStatus labels"
        );
    }

    // ==== GAP-015 chat_id auth tests ==================================

    fn msg_from_chat(id: i64, text: Option<&str>) -> TgMessage {
        TgMessage {
            text: text.map(ToOwned::to_owned),
            chat: TgChat { id },
        }
    }

    #[test]
    fn is_message_authorized_matches_expected_chat() {
        let msg = msg_from_chat(42, Some("/status"));
        assert!(is_message_authorized(Some(42), &msg));
    }

    #[test]
    fn is_message_authorized_rejects_other_chat() {
        let msg = msg_from_chat(999, Some("/status"));
        assert!(!is_message_authorized(Some(42), &msg));
    }

    #[test]
    fn is_message_authorized_fails_closed_when_unconfigured() {
        // TELEGRAM_CHAT_ID misconfigured / unparseable.
        let msg = msg_from_chat(42, Some("/status"));
        assert!(!is_message_authorized(None, &msg));
    }

    #[test]
    fn is_callback_authorized_matches_expected_chat() {
        let cb = CallbackQuery {
            id: "abc".into(),
            data: Some("cmd:status".into()),
            message: Some(msg_from_chat(42, None)),
        };
        assert!(is_callback_authorized(Some(42), &cb));
    }

    #[test]
    fn is_callback_authorized_rejects_other_chat() {
        let cb = CallbackQuery {
            id: "abc".into(),
            data: Some("cmd:status".into()),
            message: Some(msg_from_chat(999, None)),
        };
        assert!(!is_callback_authorized(Some(42), &cb));
    }

    #[test]
    fn is_callback_authorized_fails_closed_without_message() {
        let cb = CallbackQuery {
            id: "abc".into(),
            data: Some("cmd:status".into()),
            message: None,
        };
        assert!(!is_callback_authorized(Some(42), &cb));
    }

    #[test]
    fn is_callback_authorized_fails_closed_when_unconfigured() {
        let cb = CallbackQuery {
            id: "abc".into(),
            data: Some("cmd:status".into()),
            message: Some(msg_from_chat(42, None)),
        };
        assert!(!is_callback_authorized(None, &cb));
    }
}
