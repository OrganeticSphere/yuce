//! Offline map export for a pinned explicit lineage; no models, engine run, or semantic claims.
//! Input: {documents:[{doc_id,label,text}],lineage:{lineages:[...]}}. Output: the deterministic map.
use sbgk_core::audit::versions;
use serde_json::Value;
use std::collections::BTreeMap;

fn main() {
    let path = std::env::args().nth(1).expect("input JSON path");
    let input: Value = serde_json::from_slice(&std::fs::read(path).expect("input bytes")).expect("input JSON");
    let docs = input["documents"]
        .as_array()
        .expect("documents")
        .iter()
        .map(|d| (d["doc_id"].as_str().expect("doc_id").into(), (d["label"].as_str().expect("label").into(), d["text"].as_str().expect("text").into())))
        .collect::<BTreeMap<String, (String, String)>>();
    let map = versions::compute(&docs, &input["lineage"]).expect("valid frozen inputs");
    println!("{}", sbgk_core::jcs::to_jcs(&map));
}
