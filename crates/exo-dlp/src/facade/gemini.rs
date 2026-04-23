//! Gemini-shaped facade: accepts `/v1/models/{model}:generateContent` and
//! translates to a canonical `FacadeRequest`.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeminiGenerateContentRequest {
    pub contents: Vec<GeminiContent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeminiContent {
    pub role: String,
    pub parts: Vec<GeminiPart>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeminiPart {
    pub text: String,
}
