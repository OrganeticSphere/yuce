//! The resident compiler (`sbgk serve`, op `directives`) against the one-shot CLI (`sbgk emit-batch-directives`) on the same
//! states. A scripted executor plays parallel rounds through ONE `serve` process (an erratum becomes visible mid-run); before
//! every round the batch is asked from the live session and, from a snapshot of that state, from the CLI. The frames must be
//! byte-identical, and so must every other field that is not a timing.

use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_sbgk");

struct Serve {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    seq: u64,
}

impl Serve {
    fn start(onto: &Path, docs: &Path) -> Serve {
        let mut child = Command::new(BIN)
            .args(["serve", "--ontology", onto.to_str().unwrap(), "--docs", docs.to_str().unwrap(), "--ack", "full"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("start sbgk serve");
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        Serve { child, stdin, stdout, seq: 0 }
    }

    /// One request line, one response line (raw text, as the process wrote it).
    fn raw(&mut self, line: &str) -> String {
        writeln!(self.stdin, "{line}").unwrap();
        self.stdin.flush().unwrap();
        let mut out = String::new();
        self.stdout.read_line(&mut out).unwrap();
        out.trim_end().to_string()
    }

    fn send(&mut self, mut ev: Value) -> bool {
        ev["seq"] = json!(self.seq + 1);
        let r: Value = serde_json::from_str(&self.raw(&ev.to_string())).unwrap();
        let ok = r["status"] == json!("ok");
        if ok {
            self.seq += 1;
        }
        ok
    }
}

impl Drop for Serve {
    fn drop(&mut self) {
        let _ = writeln!(self.stdin, "{}", json!({"op": "finish"}));
        let _ = self.stdin.flush();
        let _ = self.child.wait();
    }
}

fn onto(n: usize, apis: usize) -> String {
    let mut ents = Vec::new();
    for i in 0..n {
        ents.push(json!({"id": format!("svc_{i:03}"), "type": "Service", "aliases": [format!("service {i}")]}));
    }
    for a in 0..apis {
        ents.push(json!({"id": format!("api_{a:03}"), "type": "Api", "aliases": [format!("interface {a}")]}));
    }
    json!({
        "entities": ents,
        "predicates": [
            {"id": "uses_api", "subject": "Service", "object": "Api"},
            {"id": "api_deprecated", "subject": "Api", "object": "@literal"},
            {"id": "needs_review", "subject": "Service", "object": "@literal"}],
        "rules": [{"id": "R_depr_review@1", "mode": "AND", "body": [{"p": "uses_api"}, {"p": "api_deprecated"}],
                   "join": [["0.o", "1.s"]], "head": {"s": "0.s", "p": "needs_review", "o": {"const": "true"}}}]
    })
    .to_string()
}

/// 10 services over 4 APIs; D.0 is later withdrawn by an erratum and restated in R.0; one service has a NEG clause too.
fn world() -> (String, String, HashMap<String, Value>) {
    let mut facts = HashMap::new();
    let mut sents = vec!["The operator shall archive the access logs within 3 business days.".to_string()];
    for i in 0..10usize {
        let a = i % 4;
        let (lo, hi) = (100 + 2 * i as i64, 200 + 4 * i as i64);
        let s = format!("Clause U.{i}: service svc_{i:03} shall call interface api_{a:03} in production from t={lo} until t={hi}.");
        facts.insert(s.clone(), json!({"s": format!("svc_{i:03}"), "p": "uses_api", "o": format!("api_{a:03}"), "polarity": "POS", "t": [lo, hi]}));
        sents.push(s);
    }
    let n = "Clause N.5: service svc_005 does not call interface api_001 in production from t=130 until t=160.".to_string();
    facts.insert(n.clone(), json!({"s": "svc_005", "p": "uses_api", "o": "api_001", "polarity": "NEG", "t": [130, 160]}));
    sents.push(n);
    for (a, (lo, hi)) in [(0usize, (150i64, 300i64)), (1, (150, 300)), (2, (300, 400))] {
        let s = format!("Clause D.{a}: interface api_{a:03} is deprecated in production from t={lo} until t={hi}.");
        facts.insert(s.clone(), json!({"s": format!("api_{a:03}"), "p": "api_deprecated", "o": "true", "polarity": "POS", "t": [lo, hi]}));
        sents.push(s);
    }
    let r = "Clause R.0: from t=150 until t=300, production use of interface api_000 is deprecated (this restates clause D.0).".to_string();
    facts.insert(r.clone(), json!({"s": "api_000", "p": "api_deprecated", "o": "true", "polarity": "POS", "t": [150, 300]}));
    sents.push(r);
    sents.push("The custodian must review all change requests before the next audit window.".into());
    let erratum = "Erratum E.1: clause D.0 is withdrawn; the same statement stands in clause R.0.\n".to_string();
    (sents.join(" ") + "\n", erratum, facts)
}

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("sbgk_{name}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("docs")).unwrap();
    d
}

#[test]
fn resident_directives_are_byte_identical_to_the_cli_on_every_round() {
    let dir = scratch("serve_vs_cli");
    let (doc, erratum, facts) = world();
    std::fs::write(dir.join("docs").join("policy.txt"), &doc).unwrap();
    std::fs::write(dir.join("docs").join("erratum.txt"), &erratum).unwrap();
    std::fs::write(dir.join("onto.json"), onto(10, 4)).unwrap();
    let mut serve = Serve::start(&dir.join("onto.json"), &dir.join("docs"));
    let (state, tfile) = (dir.join("state.sbgk"), dir.join("targets.json"));
    let mut kinds_seen: Vec<String> = Vec::new();
    let mut rejected = 0;
    let mut complete = false;
    for round in 1..=12u64 {
        let docs: Vec<&str> = if round >= 3 { vec!["erratum", "policy"] } else { vec!["policy"] };
        let targets = json!({"entities": (0..10).map(|i| format!("svc_{i:03}")).collect::<Vec<_>>(), "predicate": "needs_review", "docs": docs});
        std::fs::write(&tfile, targets.to_string()).unwrap();
        // resident: the live session
        let live_text = serve.raw(&json!({"op": "directives", "targets": targets, "seats": 3, "k": 4, "round": round}).to_string());
        let live: Value = serde_json::from_str(&live_text).unwrap();
        assert_eq!(live["status"], json!("directives"), "{live_text}");
        assert_eq!(live["open_us"], json!(0.0), "no container is opened");
        // one-shot: the CLI on a snapshot of the same state
        let snap: Value = serde_json::from_str(&serve.raw(&json!({"op": "snapshot", "out": state.to_str().unwrap()}).to_string())).unwrap();
        assert_eq!(snap["status"], json!("snapshot"));
        let out = Command::new(BIN)
            .args([
                "emit-batch-directives",
                "--state",
                state.to_str().unwrap(),
                "--targets",
                tfile.to_str().unwrap(),
                "--seats",
                "3",
                "--k",
                "4",
                "--round",
                &round.to_string(),
            ])
            .output()
            .unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        let cli_text = String::from_utf8(out.stdout).unwrap();
        let cli: Value = serde_json::from_str(&cli_text).unwrap();
        // byte identity: the frames array the CLI printed appears verbatim in the line the resident compiler wrote
        let frames = serde_json::to_string(&cli["frames"]).unwrap();
        assert!(cli_text.contains(&frames), "re-serialisation is exact");
        assert!(live_text.contains(&frames), "round {round}: resident frames differ from the CLI frames");
        for k in
            ["round", "seats", "k", "complete", "gaps_total", "gaps_by_priority", "goal_states", "goal_state", "segments", "segments_covered", "auto_close"]
        {
            assert_eq!(live[k], cli[k], "round {round}: field {k}");
        }
        if live["complete"] == json!(true) {
            complete = true;
            break;
        }
        // the scripted executor does what each frame says (fact derives are left to the compiler's next round)
        for f in live["frames"].as_array().unwrap().iter().filter(|f| f["noop"] == json!(false)) {
            let pre = f["local_id_prefix"].as_str().unwrap().to_string();
            let mut n = 0;
            for g in f["gaps"].as_array().unwrap() {
                let kind = g["kind"].as_str().unwrap().to_string();
                if !kinds_seen.contains(&kind) {
                    kinds_seen.push(kind.clone());
                }
                match kind.as_str() {
                    "FORMALIZE" | "EXTRACT_PARTNER" | "RESUPPORT_FROM_RESTATEMENT" | "REPAIR_UNSUPPORTED" => {
                        for text in g["segment_texts"].as_array().unwrap() {
                            let fact = if g["resupport"].is_object() { g["resupport"].clone() } else { facts[text.as_str().unwrap()].clone() };
                            n += 1;
                            let (e, fl) = (format!("{pre}e{n}"), format!("{pre}f{n}"));
                            rejected += usize::from(!serve.send(json!({"op": "bind_evidence", "local_id": e, "doc_id": "policy", "exact_quote": text})));
                            rejected += usize::from(!serve.send(json!({"op": "assert_fact", "local_id": fl, "s": fact["s"], "p": fact["p"], "o": fact["o"],
                                "polarity": fact["polarity"], "ctx": "prod", "t": fact["t"], "evidence": [e]})));
                        }
                    }
                    "EMIT_DERIVE_ONLY" => {
                        n += 1;
                        rejected +=
                            usize::from(!serve.send(
                                json!({"op": "derive", "local_id": format!("{pre}r{n}"), "rule": g["derive"]["rule"], "premises": g["derive"]["premises"]}),
                            ));
                    }
                    "REVOKE_WITHDRAWN" | "RESOLVE_CONFLICT" => {
                        for ev in g["evidence"].as_array().unwrap() {
                            rejected += usize::from(!serve.send(json!({"op": "revoke_evidence", "target_evidence": ev})));
                        }
                    }
                    k => panic!("unexpected gap kind {k}"),
                }
            }
        }
    }
    drop(serve);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(complete, "the run reaches P4");
    assert_eq!(rejected, 0, "every event the frames asked for was accepted");
    for k in ["FORMALIZE", "EMIT_DERIVE_ONLY", "REVOKE_WITHDRAWN", "RESUPPORT_FROM_RESTATEMENT"] {
        assert!(kinds_seen.iter().any(|x| x == k), "{k} was exercised: {kinds_seen:?}");
    }
}
