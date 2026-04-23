//! OpenAI-shaped facade: accepts `/v1/chat/completions` and translates to a
//! canonical `FacadeRequest`.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAiChatRequest {
    pub model: String,
    pub messages: Vec<OpenAiMessage>,
    #[serde(default)]
    pub stream: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAiMessage {
    pub role: String,
    pub content: String,
}

impl OpenAiChatRequest {
    /// Flatten messages into a single prompt string for canonicalisation.
    #[must_use]
    pub fn flatten(&self) -> String {
        let mut out = String::new();
        for m in &self.messages {
            out.push_str(&m.role);
            out.push_str(": ");
            out.push_str(&m.content);
            out.push('\n');
        }
        out
    }
}
