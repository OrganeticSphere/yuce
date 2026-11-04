//! Opt-in durable agent-failure attempts. Generic existing checkpoints keep the WAL format unchanged.
use super::*;
use serde_json::json;
pub const KEY: &str = "audit:agent-failures";
pub fn limit<S: AuditStore>(s: &S) -> Option<u32> {
    s.checkpoint("audit:mcp:coverage")?["context"]["agent_attempts"].as_u64().and_then(|n| u32::try_from(n).ok()).filter(|n| *n > 0)
}
pub fn state<S: AuditStore>(s: &S) -> Value {
    s.checkpoint(KEY).map(|v| v["context"].clone()).unwrap_or_else(|| json!({"format":"r2r-agent-failures/1","work":{}}))
}
pub fn entry<S: AuditStore>(s: &S, key: &str) -> Value {
    state(s)["work"][key].clone()
}
pub fn unresolved_card<S: AuditStore>(s: &S, id: &str, from: u64, to: u64) -> bool {
    if limit(s).is_none() {
        return false;
    }
    let e = entry(s, &format!("build:{id}"));
    e["unresolved"] == true && e["range"] == json!([from, to])
}
pub fn record<S: AuditStore>(s: &mut S, key: &str, attempt: &str, who: &str, reason: &str, metadata: Option<Value>) -> Result<Value, Value> {
    let max = limit(s).ok_or_else(|| json!({"code":"AGENT_FAILURE_POLICY_DISABLED"}))?;
    if key.is_empty() || attempt.is_empty() || attempt.len() > 1024 || who.is_empty() || reason.len() > 2048 {
        return Err(json!({"code":"BAD_AGENT_FAILURE"}));
    }
    let mut context = state(s);
    let mut e = context["work"][key].clone();
    if key.starts_with("rq:") && metadata.as_ref().is_some_and(|m| e["question_set_revision"] != m["question_set_revision"]) {
        e = Value::Null;
    }
    if let Some(old) = e["attempts"].as_array().and_then(|xs| xs.iter().find(|v| v["id"] == attempt)) {
        if old["subject"] != who || old["reason"] != reason {
            return Err(json!({"code":"FAILURE_ATTEMPT_CONFLICT"}));
        }
        return Ok(e);
    }
    if e["unresolved"] == true {
        return Ok(e);
    }
    if e.is_null() {
        e = json!({"attempts":[],"unresolved":false});
    }
    if let Some(meta) = metadata {
        for (k, v) in meta.as_object().ok_or_else(|| json!({"code":"BAD_FAILURE_METADATA"}))? {
            if k == "range" && !e[k].is_null() && e[k] != *v {
                return Err(json!({"code":"FAILURE_RANGE_CHANGED"}));
            }
            e[k] = v.clone();
        }
    }
    e["attempts"].as_array_mut().ok_or_else(|| json!({"code":"BAD_FAILURE_CHECKPOINT"}))?.push(json!({"id":attempt,"subject":who,"reason":reason}));
    let count = e["attempts"].as_array().unwrap().len();
    e["failures"] = json!(count);
    e["limit"] = json!(max);
    e["unresolved"] = json!(count >= max as usize);
    context["work"][key] = e.clone();
    let checkpoint = json!({"key":KEY,"from":0,"to":0,"context":context});
    let id = format!("agent-failure:{}", crate::hash::to_hex(&crate::hash::sha256(crate::jcs::to_jcs(&checkpoint).as_bytes())));
    match s.submit_operations_id(&id, "kernel", &[], Some(checkpoint)) {
        Ok(r) if r["checkpointed"] == true && r["error"].is_null() => Ok(e),
        Ok(r) => Err(r),
        Err(e) => Err(e.to_json()),
    }
}

pub fn unresolved_review<S: AuditStore>(s: &S, id: &Value) -> bool {
    limit(s).is_some()
        && state(s)["work"].as_object().into_iter().flat_map(|m| m.values()).any(|e| e["unresolved"] == true && !id.is_null() && e["review"] == *id)
}

/// Contiguous serial ranges explicitly left unresolved. A pool uses its own longest closed prefix.
pub fn serial_progress<S: AuditStore>(s: &S) -> (u64, u64, Vec<String>) {
    let from = s.checkpoint(super::builder::BUILDER_CHECKPOINT).and_then(|v| v["to"].as_u64()).unwrap_or(0);
    if limit(s).is_none() {
        return (from, from, vec![]);
    }
    let mut ranges = state(s)["work"]
        .as_object()
        .into_iter()
        .flat_map(|m| m.iter())
        .filter_map(|(k, e)| {
            (k.starts_with("build:") && e["unresolved"] == true && e["pool"] != true)
                .then(|| Some((e["range"][0].as_u64()?, e["range"][1].as_u64()?, k.clone())))?
        })
        .collect::<Vec<_>>();
    ranges.sort();
    let mut to = from;
    let mut ids = vec![];
    for (a, b, id) in ranges {
        if a <= to && to < b {
            to = b;
            ids.push(id);
        } else if a > to {
            break;
        }
    }
    (from, to, ids)
}
