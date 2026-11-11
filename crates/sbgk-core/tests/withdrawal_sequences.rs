//! Random sequences of quotes, withdrawals and new versions against a plain model of the rule: a quote stands while its document has
//! the version it was quoted from and no closed text overlaps it, and a new quote that overlaps closed text is refused. The model
//! searches whole documents with its own code, so a shortcut in the kernel's search that changed a decision would show here.

use sbgk_core::audit::onto::AuditOntology;
use sbgk_core::audit::state::AuditState;
use sbgk_core::audit::{RecordId, Scope};
use sbgk_core::hash::sha256;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

const SEEDS: u64 = 24;
const STEPS: usize = 50;
const WORDS: [&str; 7] = ["alpha", "beta", "gamma", "delta", "word", "one", "two"];
const DOCS: [&str; 2] = ["left.txt", "right.txt"];

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

struct Journal(PathBuf);

impl Drop for Journal {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn line(rng: &mut Rng) -> String {
    let words: Vec<&str> = (0..3 + rng.below(4)).map(|_| WORDS[rng.below(WORDS.len())]).collect();
    format!("{}.\n", words.join(" "))
}

fn every(hay: &[u8], needle: &[u8]) -> Vec<(usize, usize)> {
    (0..hay.len().saturating_sub(needle.len()) + 1).filter(|p| hay[*p..].starts_with(needle)).map(|p| (p, p + needle.len())).collect()
}

struct Quote {
    id: RecordId,
    doc: &'static str,
    span: (usize, usize),
    version: Vec<u8>,
}

#[derive(Default)]
struct Model {
    docs: BTreeMap<&'static str, Vec<u8>>,
    closed: BTreeMap<&'static str, BTreeSet<Vec<u8>>>,
    quotes: Vec<Quote>,
    /// A claim and the quotes it rests on, by their place in `quotes`.
    claims: Vec<(RecordId, Vec<usize>)>,
}

impl Model {
    /// The first closed occurrence that overlaps `span`: closed texts in order, places in order, as the kernel reports it.
    fn overlap(&self, doc: &str, span: (usize, usize)) -> Option<(usize, usize)> {
        let bytes = &self.docs[doc];
        let closed = self.closed.get(doc)?;
        closed.iter().flat_map(|text| every(bytes, text)).find(|o| o.0 < span.1 && span.0 < o.1)
    }

    fn stands(&self, q: &Quote) -> bool {
        self.docs[q.doc] == q.version && self.overlap(q.doc, q.span).is_none()
    }

    fn check(&self, s: &AuditState, at: &str) {
        for (n, q) in self.quotes.iter().enumerate() {
            assert_eq!(s.is_grounded(&q.id), self.stands(q), "{at}: quote {n} at {:?} of {}", q.span, q.doc);
        }
        for (id, on) in &self.claims {
            let stands = on.iter().all(|n| self.stands(&self.quotes[*n]));
            assert_eq!(s.is_grounded(id), stands, "{at}: a claim on quotes {on:?}");
        }
    }

    /// A piece of a document that begins and ends on a word.
    fn piece(&self, rng: &mut Rng, doc: &str) -> Option<String> {
        let text = std::str::from_utf8(&self.docs[doc]).unwrap();
        let start = rng.below(text.len());
        let end = (start + 4 + rng.below(40)).min(text.len());
        let piece = text[start..end].trim();
        (!piece.is_empty()).then(|| piece.to_string())
    }
}

fn scope() -> Scope {
    Scope { docs: DOCS.iter().map(|d| d.to_string()).collect(), topic: Some("words".into()), ranges: Vec::new() }
}

fn observe(local: &str, doc: &str, quote: &str) -> Value {
    json!({"kind":"observe","local_id":local,"doc_id":doc,"exact_quote":quote,"terms":["word"]})
}

/// Quote one piece, and the kernel's answer must be the model's.
fn quote(s: &mut AuditState, m: &mut Model, rng: &mut Rng, step: usize) {
    let doc = DOCS[rng.below(DOCS.len())];
    let Some(text) = m.piece(rng, doc) else { return };
    let places = every(&m.docs[doc], text.as_bytes());
    if m.quotes.iter().any(|q| q.doc == doc && q.version == m.docs[doc] && q.span == places[0]) {
        return; // the same quote again is another rule
    }
    let closing = (places.len() == 1).then(|| m.overlap(doc, places[0])).flatten();
    let local = format!("o{step}");
    let mut lines = vec![observe(&local, doc, &text)];
    let with_claim = rng.below(2) == 0;
    if with_claim {
        lines.push(
            json!({"kind":"claim","local_id":format!("c{step}"),"text":format!("Claim {step}."),"subject":"word","stance":"reported","based_on":[local]}),
        );
    }
    let r = s.submit_records_id(&format!("q{step}"), "worker", &format!("d{step}"), &scope(), &lines);
    if places.len() != 1 {
        assert_eq!(r.error.expect("a quote with two places is refused").to_json()["code"], "AMBIGUOUS_QUOTE_SPAN");
    } else if let Some(hit) = closing {
        let error = r.error.expect("a quote on closed text is refused").to_json();
        assert_eq!(error["code"], "EVIDENCE_REVOKED", "{error}");
        assert_eq!(error["expected_by_kernel"]["withdrawn_span"], json!([hit.0, hit.1]), "{error}");
        assert!(r.accepted.is_empty());
    } else {
        assert!(r.error.is_none(), "step {step}: {text:?} in {doc}: {:?}", r.error.map(|e| e.to_json()));
        m.quotes.push(Quote { id: r.accepted[0], doc, span: places[0], version: m.docs[doc].clone() });
        if with_claim {
            m.claims.push((r.accepted[1], vec![m.quotes.len() - 1]));
        }
    }
}

fn run(seed: u64) {
    static UNIQUE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nonce = format!(
        "{}-{}",
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
        UNIQUE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let journal = Journal(std::env::temp_dir().join(format!("sbgk_sequences_{}_{seed}_{nonce}.wal", std::process::id())));
    let mut rng = Rng(seed);
    let mut m = Model::default();
    let mut versions: BTreeMap<&str, Vec<Vec<u8>>> = BTreeMap::new();
    let mut docs = Vec::new();
    for doc in DOCS {
        let text: String = (0..24).map(|_| line(&mut rng)).collect();
        m.docs.insert(doc, text.clone().into_bytes());
        versions.entry(doc).or_default().push(text.clone().into_bytes());
        docs.push((doc.to_string(), text.into_bytes()));
    }
    let mut s = AuditState::create(&journal.0, &AuditOntology::base(), &docs, "sequences", sha256(b"sequences")).unwrap();
    for step in 0..STEPS {
        match rng.below(10) {
            0..=5 => quote(&mut s, &mut m, &mut rng, step),
            6 => {
                let doc = DOCS[rng.below(DOCS.len())];
                let Some(text) = m.piece(&mut rng, doc) else { continue };
                let known = m.closed.get(doc).is_some_and(|c| c.contains(text.as_bytes()));
                let places = every(&m.docs[doc], text.as_bytes());
                let going = m.quotes.iter().filter(|q| m.stands(q) && q.doc == doc && places.iter().any(|o| o.0 < q.span.1 && q.span.0 < o.1)).count();
                let answer = s.withdraw_text("owner", doc, &text);
                if known {
                    assert!(answer.is_err(), "already closed");
                } else {
                    assert_eq!(answer.unwrap(), going as u64, "seed {seed} step {step}");
                    m.closed.entry(doc).or_default().insert(text.into_bytes());
                }
            }
            7 => {
                let live: Vec<usize> = (0..m.quotes.len()).filter(|n| m.stands(&m.quotes[*n])).collect();
                if live.is_empty() {
                    continue;
                }
                let q = &m.quotes[live[rng.below(live.len())]];
                let (id, doc) = (q.id, q.doc);
                let text = q.version[q.span.0..q.span.1].to_vec();
                s.revoke_observation("owner", &id).unwrap();
                m.closed.entry(doc).or_default().insert(text);
            }
            _ => {
                let doc = DOCS[rng.below(DOCS.len())];
                let earlier = &versions[doc];
                let next = if rng.below(3) == 0 {
                    earlier[rng.below(earlier.len())].clone()
                } else {
                    let mut text = line(&mut rng).into_bytes();
                    text.extend_from_slice(&m.docs[doc]);
                    text
                };
                s.put_document("owner", doc, &next).unwrap();
                versions.get_mut(doc).unwrap().push(next.clone());
                m.docs.insert(doc, next);
            }
        }
        m.check(&s, &format!("seed {seed} step {step}"));
    }
    assert!(m.quotes.len() >= 5, "seed {seed}: a sequence with few quotes shows little");
    let roots = (s.engine_root(), s.audit_root(), s.wal_head());
    drop(s);
    let (replayed, _) = AuditState::verify(&journal.0, &mut |_, _, _, _| {}).unwrap();
    assert_eq!((replayed.engine_root(), replayed.audit_root()), (roots.0, roots.1), "seed {seed}");
    m.check(&replayed, &format!("seed {seed} replayed"));
    drop(replayed);
    let reopened = AuditState::open(&journal.0).unwrap();
    assert_eq!((reopened.engine_root(), reopened.audit_root(), reopened.wal_head()), roots, "seed {seed}");
    m.check(&reopened, &format!("seed {seed} reopened"));
}

#[test]
fn random_sequences_keep_to_the_rule_and_replay_to_the_same_roots() {
    for seed in 0..SEEDS {
        run(seed);
    }
}
