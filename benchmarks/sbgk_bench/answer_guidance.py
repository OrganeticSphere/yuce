"""The same normative instructions Rust embeds; kernel data and native response schemas stay separate."""
import json
from pathlib import Path

ASSET = Path(__file__).resolve().parents[2] / "crates/sbgk-core/src/audit/answer_guidance.json"
DATA = json.loads(ASSET.read_text(encoding="utf-8"))
TARGET_CLAIM_CHARACTERS = DATA["target_claim_characters"]
TEXT = (f'COMMON ANSWER GUIDANCE:\n{DATA["chronology"]}\n{DATA["coverage"]}\n'
        f'Target each claim text at most {TARGET_CLAIM_CHARACTERS} characters.\nEND COMMON ANSWER GUIDANCE')


def append_to(rules: str) -> str:
    return rules if TEXT in rules else rules + "\n" + TEXT
