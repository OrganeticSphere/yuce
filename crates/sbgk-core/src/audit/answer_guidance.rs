//! Common normative answer instructions. Window metadata and actual kernel findings remain in the directive.
use serde_json::Value;
use std::sync::LazyLock;

static DATA: LazyLock<Value> = LazyLock::new(|| serde_json::from_str(include_str!("answer_guidance.json")).expect("built-in answer guidance"));
static TEXT: LazyLock<String> = LazyLock::new(|| {
    format!(
        "COMMON ANSWER GUIDANCE:\n{}\n{}\nTarget each claim text at most {} characters.\nEND COMMON ANSWER GUIDANCE",
        DATA["chronology"].as_str().expect("chronology instruction"),
        DATA["coverage"].as_str().expect("coverage instruction"),
        target_claim_characters()
    )
});

pub(super) fn text() -> &'static str {
    &TEXT
}

pub(super) fn target_claim_characters() -> usize {
    DATA["target_claim_characters"].as_u64().expect("claim text target") as usize
}
