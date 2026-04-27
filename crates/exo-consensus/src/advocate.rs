/// Generates a prompt for the devil's advocate based on the synthesized consensus.
pub fn generate_advocate_prompt(question: &str, consensus: &str) -> String {
    format!(
        "The panel has reached a consensus on the following question:\nQuestion: {}\nConsensus: {}\n\nYour job is to find the strongest counterarguments, logical flaws, or edge cases that break this consensus. Be adversarial but strictly logical.",
        question, consensus
    )
}
