use std::collections::BTreeMap;

#[derive(Debug, Clone, Default)]
pub struct MockLlmClient {
    pub responses: BTreeMap<String, String>, // model_id -> canned response
    pub default_response: String,
}

impl MockLlmClient {
    pub fn new() -> Self {
        Self {
            responses: BTreeMap::new(),
            default_response: "Mocked response".into(),
        }
    }

    pub fn with_responses(responses: BTreeMap<String, String>) -> Self {
        Self {
            responses,
            default_response: "Mocked response".into(),
        }
    }

    pub fn call(&self, model_id: &str, _prompt: &str) -> String {
        self.responses
            .get(model_id)
            .cloned()
            .unwrap_or_else(|| self.default_response.clone())
    }
}
