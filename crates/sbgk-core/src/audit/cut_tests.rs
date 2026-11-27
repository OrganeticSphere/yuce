use super::*;

#[test]
fn a_name_is_letters_digits_and_three_marks_and_names_a_file() {
    for name in ["a", "e1", "A-b_c.9", &"x".repeat(MAX_NAME)] {
        assert!(is_name(name), "{name}");
    }
    for name in ["", ".", "..", "a/b", "a b", "a\\b", "\u{e9}", &"x".repeat(MAX_NAME + 1)] {
        assert!(!is_name(name), "{name}");
    }
}

#[test]
fn an_export_escapes_a_backslash_and_the_two_line_ends_and_nothing_else() {
    assert_eq!(escape("a\\b\nc\rd \"e\" [f] ; \t"), "a\\\\b\\nc\\rd \"e\" [f] ; \t");
    // an escaped text holds no line end: a paragraph is one line
    assert!(!escape("x\n\ny\r\n").contains(['\n', '\r']));
}

#[test]
fn strings_sort_by_utf16_code_units() {
    // U+10000 is the surrogate pair D800 DC00 and sorts before U+E000, though its code point is the larger
    assert_eq!(utf16_order("\u{10000}", "\u{e000}"), Ordering::Less);
    assert_eq!("\u{10000}".cmp("\u{e000}"), Ordering::Greater);
}

#[test]
fn an_export_file_is_read_up_to_the_id_of_each_paragraph() {
    let id = "ab".repeat(32);
    let seal = "cd".repeat(32);
    // the run id holds the words of the header, and the paragraph the separators of its own form
    let text =
        format!("{EXPORT_FORMAT} run=r seal=x records=9 seal={seal} records=2\n\nRecord {id}: T Quotes: [d] \"q\" ; [e] \"Rests on: z\"\n\nRecord {id}: \n");
    let parsed = parse_export("e", text.as_bytes()).unwrap();
    assert_eq!((parsed.run.as_str(), to_hex(&parsed.seal_hash)), ("r seal=x records=9", seal.clone()));
    let first = text.find("Record").unwrap();
    assert_eq!(parsed.paragraphs.len(), 2);
    assert_eq!(parsed.paragraphs[0].0, first);
    assert_eq!(&text[parsed.paragraphs[0].0..parsed.paragraphs[0].1], format!("Record {id}: T Quotes: [d] \"q\" ; [e] \"Rests on: z\""));
    // the last paragraph ends before the line feed that ends the file
    assert_eq!(parsed.paragraphs[1].1, text.len() - 1);

    let empty = format!("{EXPORT_FORMAT} run=r seal={seal} records=0\n");
    assert!(parse_export("e", empty.as_bytes()).unwrap().paragraphs.is_empty());

    for (broken, why) in [
        (text.trim_end().to_string(), "no line feed at the end"),
        (text.replace("records=2", "records=3"), "another number of records"),
        (text.replace("Record ab", "Record AB"), "an id in upper case"),
        (text.replace(&format!("Record {id}: T"), &format!("Record {id}:T")), "no space after the id"),
        (text.replace(EXPORT_FORMAT, "yuce-export/2"), "another format"),
        (text.replace(&format!("seal={seal}"), "seal=12"), "a seal that is no hash"),
    ] {
        assert!(parse_export("e", broken.as_bytes()).is_err(), "{why}");
    }
}

// ---- journals the library writes

/// A manifest someone else wrote is read as it says (Codex's review of dd7f5b2f): `sound` is the manifest of the journals `a`
/// and `b` of `dir` and of the export `e1`, which passes.
fn given_manifests(dir: &Folder, sound: &Value, export: &[u8]) {
    let journal = |name: &str, file: &str| (name.to_string(), Journal::read(&dir.path(file)).unwrap(), BTreeSet::new());
    let exports = |names: &[&str]| -> Vec<(String, Vec<u8>)> { names.iter().map(|n| (n.to_string(), export.to_vec())).collect() };
    let read_it = |manifest: &Value| read(manifest, vec![journal("a", "a.wal"), journal("b", "b.wal")], exports(&["e1"]));
    let level = |refused: KResult<Cut>| refused.err().map(|e| e.message).unwrap_or_else(|| "it passes".into());
    let passed = read_it(sound).unwrap();
    assert_eq!((passed.cut_hash, passed.deliveries.len(), passed.across().len()), (cut_hash(sound), 1, 1));

    // the form of a manifest, level B0
    let changed = |change: &dyn Fn(&mut Value)| {
        let mut manifest = sound.clone();
        change(&mut manifest);
        manifest
    };
    let forms: Vec<(&str, Value)> = vec![
        ("a key more", changed(&|m| m["note"] = json!("x"))),
        ("a key less", changed(&|m| drop(m.as_object_mut().unwrap().remove("previous_cut")))),
        ("another format", changed(&|m| m["format"] = json!("yuce-cut/2"))),
        ("the reserved mode", changed(&|m| m["mode"] = json!("govern"))),
        ("a previous cut that is no hash", changed(&|m| m["previous_cut"] = json!("abc"))),
        ("journals out of order", changed(&|m| m["journals"].as_array_mut().unwrap().reverse())),
        (
            "a journal twice",
            changed(&|m| {
                let first = m["journals"][0].clone();
                m["journals"].as_array_mut().unwrap().insert(0, first)
            }),
        ),
        ("a name that is a path", changed(&|m| m["journals"][0]["name"] = json!("../a"))),
        ("the name of this folder", changed(&|m| m["exports"][0]["name"] = json!("."))),
        ("a log size that is no whole number", changed(&|m| m["journals"][0]["log_size"] = json!(7.5))),
        ("a log size past 2^53", changed(&|m| m["journals"][0]["log_size"] = json!(9_007_199_254_740_992u64))),
        ("closed as text", changed(&|m| m["journals"][0]["closed"] = json!("false"))),
        ("a seal hash in capitals", changed(&|m| m["journals"][0]["seal_hash"] = json!("A".repeat(64)))),
        ("a key more in a delivery", changed(&|m| m["deliveries"][0]["version"] = json!("x"))),
        ("an empty document name", changed(&|m| m["deliveries"][0]["doc_id"] = json!(""))),
        (
            "a delivery twice",
            changed(&|m| {
                let first = m["deliveries"][0].clone();
                m["deliveries"].as_array_mut().unwrap().push(first)
            }),
        ),
        ("an export of a journal that is not listed", changed(&|m| m["exports"][0]["journal"] = json!("c"))),
        ("a delivery of an export that is not listed", changed(&|m| m["deliveries"][0]["export"] = json!("e9"))),
    ];
    for (what, manifest) in &forms {
        assert!(manifest_form(manifest).is_err(), "{what}");
        assert!(level(read_it(manifest)).contains("at level B0:"), "{what}");
    }
    assert_eq!(manifest_form(sound).unwrap(), (vec!["a".to_string(), "b".to_string()], vec!["e1".to_string()]));

    // B1: what the manifest says of a journal is what the journal shows. `closed` is read, not looked up: neither journal is
    // closed, so `true` does not hold
    let b1: Vec<(&str, Value)> = vec![
        ("an earlier seal under the same log size", changed(&|m| m["journals"][0]["seal_hash"] = json!("0".repeat(64)))),
        ("a frame that is no seal", changed(&|m| m["journals"][0]["log_size"] = json!(2))),
        ("another head", changed(&|m| m["journals"][0]["wal_head"] = json!("1".repeat(64)))),
        ("another run id", changed(&|m| m["journals"][0]["run_id"] = json!("cut z"))),
        ("other rules", changed(&|m| m["journals"][0]["rules_version"] = json!("r2r-audit-rules/3"))),
        ("closed, with no close after the seal", changed(&|m| m["journals"][0]["closed"] = json!(true))),
    ];
    for (what, manifest) in &b1 {
        assert!(level(read_it(manifest)).contains("at level B1:"), "{what}: {}", level(read_it(manifest)));
    }
    // B2: the export is the one named, from the journal named
    let b2: Vec<(&str, Value)> = vec![
        ("other bytes than named", changed(&|m| m["exports"][0]["sha256"] = json!("2".repeat(64)))),
        ("another number of records", changed(&|m| m["exports"][0]["records"] = json!(1))),
        ("another seal than its header", changed(&|m| m["exports"][0]["seal_hash"] = m["journals"][0]["seal_hash"].clone())),
        ("the journal it was not made from", changed(&|m| m["exports"][0]["journal"] = json!("b"))),
    ];
    for (what, manifest) in &b2 {
        assert!(level(read_it(manifest)).contains("at level B2:"), "{what}: {}", level(read_it(manifest)));
    }
    // B3: a delivery is the frame it names, and every import is declared
    let moved = changed(&|m| m["deliveries"][0]["frame"] = json!(2));
    let renamed = changed(&|m| m["deliveries"][0]["doc_id"] = json!("other"));
    let dropped = changed(&|m| m["deliveries"] = json!([]));
    assert!(level(read_it(&moved)).contains("at level B3.1:"));
    assert!(level(read_it(&renamed)).contains("at level B3.1:"));
    assert!(level(read_it(&dropped)).contains("at level B3.2:"));

    // The same bytes under a second export name, with the delivery declared by that name: the manifest names the export, and
    // the reader does not pick another one of the same bytes.
    let alias = changed(&|m| {
        let mut second = m["exports"][0].clone();
        second["name"] = json!("e2");
        m["exports"].as_array_mut().unwrap().push(second);
        m["deliveries"][0]["export"] = json!("e2");
    });
    let read_alias = read(&alias, vec![journal("a", "a.wal"), journal("b", "b.wal")], exports(&["e1", "e2"])).unwrap();
    assert_eq!(read_alias.exports[read_alias.deliveries[0].export].name, "e2");
    // The same journal under a second name: the export names the journal it was made from, and two journals with its seal
    // are no ambiguity.
    let twin = changed(&|m| {
        let mut second = m["journals"][0].clone();
        second["name"] = json!("z");
        m["journals"].as_array_mut().unwrap().push(second);
    });
    let read_twin = read(&twin, vec![journal("a", "a.wal"), journal("b", "b.wal"), journal("z", "a.wal")], exports(&["e1"])).unwrap();
    assert_eq!((read_twin.parts.len(), read_twin.exports[0].journal), (3, 0));
    // the files read are those the manifest lists, in its order
    assert!(read(sound, vec![journal("b", "b.wal"), journal("a", "a.wal")], exports(&["e1"])).is_err());
    assert!(read(sound, vec![journal("a", "a.wal"), journal("b", "b.wal")], exports(&["e2"])).is_err());
}

/// The part of a journal is read as a file of its own: a frame damaged after it does not take the part away (the review of
/// 23e15cf3: one read of the whole file refused the journal for bytes outside the input).
#[test]
fn the_part_of_a_journal_is_read_without_the_frames_after_it() {
    let dir = Folder::new("prefix");
    let docs = vec![("source".to_string(), b"Alpha.\nBeta.\n".to_vec())];
    let mut s = AuditState::create_from_docs(&dir.path("a.wal"), &AuditOntology::base(), "cut a", docs).unwrap();
    submit(&mut s, json!([observe("o1", "source", "Alpha."), claim("c1", "One says alpha.", &["o1"])]));
    let first = seal(&mut s);
    submit(&mut s, json!([observe("o2", "source", "Beta."), claim("c2", "Two says beta.", &["o2"])]));
    let second = seal(&mut s);
    s.close_run().unwrap();
    drop(s);
    let none = BTreeSet::new();
    let sound = std::fs::read(dir.path("a.wal")).unwrap();
    let lines: Vec<&[u8]> = sound.split(|b| *b == b'\n').filter(|line| !line.is_empty()).collect();
    assert_eq!(lines.len(), second + 2, "the close is the last frame");
    let whole = Journal::read(&dir.path("a.wal")).unwrap();
    let of = |part: &Part| (part.seal_hash, part.wal_head, part.state.record_count(), part.closed, part.frames_after);
    let sound_first = of(&whole.part(first, Some(false), &none).unwrap());
    // the file with one of its frames replaced
    let with = |at: usize, line: &[u8]| {
        let mut out = Vec::new();
        for (i, kept) in lines.iter().enumerate() {
            out.extend_from_slice(if i == at { line } else { kept });
            out.push(b'\n');
        }
        std::fs::write(dir.path("d.wal"), out).unwrap();
    };

    // the frame right after the first seal is no JSON: the file as a whole is refused, and its part to the first seal is as it
    // was, with the same number of lines left out
    with(first + 1, b"{not json");
    assert!(Journal::read(&dir.path("d.wal")).is_err());
    for closed in [None, Some(false)] {
        let journal = Journal::read_part(&dir.path("d.wal"), first, closed).unwrap();
        assert!(!journal.close_follows(first));
        assert_eq!(of(&journal.part(first, closed, &none).unwrap()), sound_first, "{closed:?}");
    }
    assert!(Journal::read_part(&dir.path("d.wal"), first, Some(true)).is_err(), "a close that must be there is read");
    // the same frame is inside the part to the second seal
    for closed in [None, Some(false), Some(true)] {
        assert!(Journal::read_part(&dir.path("d.wal"), second, closed).is_err(), "{closed:?}");
    }
    // a frame of another journal in its place: whole JSON, and a broken chain
    with(first + 1, lines[first]);
    assert!(Journal::read(&dir.path("d.wal")).is_err());
    assert_eq!(of(&Journal::read_part(&dir.path("d.wal"), first, None).unwrap().part(first, None, &none).unwrap()), sound_first);

    // the close after the last seal cut in half: the journal is not closed there, and is no closed journal when one is asked
    with(second + 1, &lines[second + 1][..lines[second + 1].len() / 2]);
    let journal = Journal::read_part(&dir.path("d.wal"), second, None).unwrap();
    let part = journal.part(second, None, &none).unwrap();
    assert_eq!((part.closed, part.frames_after, journal.close_follows(second)), (false, 1, false));
    assert!(Journal::read_part(&dir.path("d.wal"), second, Some(true)).is_err());
    // the sound file: the close is read when it may be, and left unread when the part is asked open
    let journal = Journal::read_part(&dir.path("a.wal"), second, None).unwrap();
    let part = journal.part(second, None, &none).unwrap();
    assert_eq!((part.closed, part.frames_after, journal.close_follows(second)), (true, 0, true));
    let journal = Journal::read_part(&dir.path("a.wal"), second, Some(false)).unwrap();
    let part = journal.part(second, Some(false), &none).unwrap();
    assert_eq!((part.closed, part.frames_after, journal.close_follows(second)), (false, 1, false));
    // a seal past the end of the file, and a frame that is no seal
    assert!(Journal::read_part(&dir.path("a.wal"), lines.len() + 3, None).is_err());
    assert!(Journal::read_part(&dir.path("a.wal"), first + 1, None).unwrap().part(first + 1, None, &none).is_err());
    // a genesis document is asked of what was supplied with the journal
    let part = whole.part(second, None, &none).unwrap();
    assert_eq!(part.missing_document(&BTreeSet::new()), Some("source"));
    assert_eq!(part.missing_document(&BTreeSet::from([sha256(b"Alpha.\nBeta.\n")])), None);
}

/// A caller that names no seal takes the last seal of the file, and the whole file is its input: the frames after that seal
/// replay too, and a torn tail is no whole file (Codex's review of c64809bb).
#[test]
fn the_frames_after_a_part_replay_when_no_seal_was_named_and_a_torn_tail_is_refused() {
    let dir = Folder::new("rest");
    let docs = vec![("source".to_string(), b"Alpha.\nBeta.\n".to_vec())];
    let mut s = AuditState::create_from_docs(&dir.path("a.wal"), &AuditOntology::base(), "cut a", docs).unwrap();
    submit(&mut s, json!([observe("o1", "source", "Alpha."), claim("c1", "One says alpha.", &["o1"])]));
    let first = seal(&mut s);
    submit(&mut s, json!([observe("o2", "source", "Beta."), claim("c2", "Two says beta.", &["o2"])]));
    let second = seal(&mut s);
    s.close_run().unwrap();
    drop(s);
    let none = BTreeSet::new();
    let journal = Journal::read(&dir.path("a.wal")).unwrap();
    assert_eq!(journal.torn_tail_bytes(), 0);
    // from either seal the rest of the sound file replays: the frames between the seals and the close
    for (seal, closed) in [(first, None), (second, None), (second, Some(false))] {
        let part = journal.part(seal, closed, &none).unwrap();
        assert!(part.rest_replays().is_ok(), "{seal} {closed:?}");
    }
    // a frame after the first seal that the chain takes and the kernel does not: the close, moved to follow the first seal,
    // cannot be written by hand, so the same is shown on the file of the vectors (`boundary/nested-seal.wal`) by the command
    // tests. Here: a torn tail. The file read whole says so, and a cut that is told no seal refuses it.
    let sound = std::fs::read(dir.path("a.wal")).unwrap();
    std::fs::write(dir.path("t.wal"), [sound.as_slice(), b"{\"body\":"].concat()).unwrap();
    let torn = || Journal::read(&dir.path("t.wal")).unwrap();
    assert_eq!(torn().torn_tail_bytes(), 8);
    let refused = cut(vec![("a".to_string(), torn(), None)], Vec::new(), None).err().expect("a torn file is no whole input");
    assert!(refused.message.contains("8 bytes") && refused.message.contains("no seal named"), "{}", refused.message);
    // with the seal named the tail is outside the input: the cut is the cut of the sound file
    let named = cut(vec![("a".to_string(), torn(), Some(second))], Vec::new(), None).unwrap();
    let whole = cut(vec![("a".to_string(), Journal::read(&dir.path("a.wal")).unwrap(), None)], Vec::new(), None).unwrap();
    assert_eq!(named.manifest, whole.manifest);
    assert!(whole.rests_replay().is_ok());
    // a part read up to its seal has no tail to speak of
    assert_eq!(Journal::read_part(&dir.path("t.wal"), second, None).unwrap().torn_tail_bytes(), 0);
}

/// A part ends with its seal, or with the close after it, as it is asked: a manifest may name a journal open at a seal though
/// the file goes on to its close.
#[test]
fn a_part_takes_the_close_after_its_seal_as_it_is_asked_and_a_document_of_the_genesis_is_asked_of_the_bundle() {
    let dir = Folder::new("closed");
    let docs = vec![("source".to_string(), b"Alpha.\nBeta.\n".to_vec())];
    let mut s = AuditState::create_from_docs(&dir.path("a.wal"), &AuditOntology::base(), "cut a", docs).unwrap();
    submit(&mut s, json!([observe("o1", "source", "Alpha."), claim("c1", "One says alpha.", &["o1"])]));
    let sealed = seal(&mut s);
    s.close_run().unwrap();
    drop(s);
    let journal = Journal::read(&dir.path("a.wal")).unwrap();
    let none = BTreeSet::new();
    // by default the close belongs to the part; asked for an open part, the part ends with the seal and one frame is left
    let (with, open, asked) =
        (journal.part(sealed, None, &none).unwrap(), journal.part(sealed, Some(false), &none).unwrap(), journal.part(sealed, Some(true), &none).unwrap());
    assert_eq!((with.closed, with.frames_after, open.closed, open.frames_after, asked.closed), (true, 0, false, 1, true));
    assert_eq!((open.seal_hash, open.wal_head), (with.seal_hash, with.wal_head));

    // a made manifest says closed; the same manifest with closed false is the open prefix of the same journal, and passes too
    let made = cut(vec![("a".to_string(), Journal::read(&dir.path("a.wal")).unwrap(), None)], Vec::new(), None).unwrap();
    assert_eq!(made.manifest["journals"][0]["closed"], true);
    let sha_of_source = sha256(b"Alpha.\nBeta.\n");
    let bundle =
        |documents: &[Hash]| vec![("a".to_string(), Journal::read(&dir.path("a.wal")).unwrap(), documents.iter().copied().collect::<BTreeSet<Hash>>())];
    let mut open_manifest = made.manifest.clone();
    open_manifest["journals"][0]["closed"] = json!(false);
    for manifest in [&made.manifest, &open_manifest] {
        let read_it = read(manifest, bundle(&[sha_of_source]), Vec::new()).unwrap();
        assert_eq!(read_it.parts[0].1.closed, manifest["journals"][0]["closed"] == true);
        // without the document of its genesis record in its folder the journal cannot be checked from outside: level B1
        let missing = read(manifest, bundle(&[]), Vec::new()).err().unwrap();
        assert!(missing.message.contains("at level B1:") && missing.message.contains("\"source\""), "{}", missing.message);
        assert!(read(manifest, bundle(&[sha256(b"other bytes")]), Vec::new()).is_err());
    }
}

use crate::audit::onto::AuditOntology;
use crate::audit::state::GenesisSpec;
use std::path::PathBuf;

struct Folder(PathBuf);

impl Folder {
    fn new(tag: &str) -> Folder {
        static UNIQUE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let n = UNIQUE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("r2r_cut_{tag}_{}_{nanos}-{n}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        Folder(root)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Folder {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A journal that starts without a document, under the rules 4, as `audit-stream start` writes it.
fn start(path: &Path, run: &str) -> AuditState {
    let mut s = AuditState::prepare_from_docs(&AuditOntology::base(), run, Vec::new()).unwrap();
    s.start_journal(path, &GenesisSpec::default()).unwrap();
    s
}

fn submit(s: &mut AuditState, lines: Value) -> Vec<RecordId> {
    let lines = lines.as_array().unwrap().clone();
    let scope = s.scope_of_lines("owner", "read", &lines);
    let id = format!("t-{}", s.entries().unwrap());
    let report = s.submit_records_id(&id, "owner", "read", &scope, &lines);
    assert!(report.error.is_none(), "{:?}", report.error);
    report.accepted
}

fn seal(s: &mut AuditState) -> usize {
    s.seal().unwrap();
    s.entries().unwrap() - 1
}

fn observe(local: &str, doc: &str, quote: &str) -> Value {
    json!({"kind": "observe", "local_id": local, "doc_id": doc, "exact_quote": quote, "terms": []})
}

fn claim(local: &str, text: &str, based_on: &[&str]) -> Value {
    json!({"kind": "claim", "local_id": local, "text": text, "subject": local, "object": "said", "stance": "reported", "based_on": based_on})
}

/// Journal `a`: a source, two quotes, a claim on the first quote named twice, a claim on that claim named twice and on the second
/// quote; a seal; a third claim; the first quote withdrawn; a seal. Returns the records and the frames of the two seals.
fn journal_a(path: &Path) -> (Vec<RecordId>, usize, usize) {
    let mut s = start(path, "cut a");
    s.put_document("owner", "source", b"Alpha.\nBeta.\n").unwrap();
    let mut ids = submit(
        &mut s,
        json!([
            observe("o1", "source", "Alpha."),
            observe("o2", "source", "Beta."),
            claim("c1", "One \"says\" alpha.", &["o1", "o1"]),
            claim("c2", "Two rests on one;\nand on beta.", &["c1", "c1", "o2"])
        ]),
    );
    let first = seal(&mut s);
    ids.extend(submit(&mut s, json!([observe("o3", "source", "Beta."), claim("c3", "Three says beta.", &["o3"])])));
    s.revoke_observation("owner", &ids[0]).unwrap();
    let second = seal(&mut s);
    (ids, first, second)
}

#[test]
fn an_export_carries_the_standing_claims_of_its_seal_in_record_order_each_ground_once() {
    let dir = Folder::new("export");
    let (ids, first, second) = journal_a(&dir.path("a.wal"));
    let (o1, c1, c2, c3) = (ids[0], ids[2], ids[3], ids[5]);
    let journal = Journal::read(&dir.path("a.wal")).unwrap();
    assert_eq!(journal.seals().iter().map(|s| s.0).collect::<Vec<_>>(), [first, second]);
    let part = journal.part(second, None, &BTreeSet::from([first])).unwrap();
    assert_eq!((part.log_size, part.closed, part.seals.len()), (second, false, 2));

    // at the first seal both claims stand: a ground named twice is written once, a line end in a text is escaped
    let all = part.export(first, None).unwrap();
    let seal_hash = to_hex(&journal.seals()[0].1);
    let want = format!(
        "{EXPORT_FORMAT} run=cut a seal={seal_hash} records=2\n\nRecord {}: One \"says\" alpha. Quotes: [source] \"Alpha.\"\n\n\
         Record {}: Two rests on one;\\nand on beta. Rests on: {} Quotes: [source] \"Beta.\"\n",
        to_hex(&c1.0),
        to_hex(&c2.0),
        to_hex(&c1.0)
    );
    assert_eq!(String::from_utf8(all.bytes.clone()).unwrap(), want);
    assert_eq!(all.records, [c1, c2]);
    // the order of the list does not show: the paragraphs come in record order
    assert_eq!(part.export(first, Some(&[c2, c1])).unwrap().bytes, all.bytes);
    assert!(part.export(first, Some(&[c2])).unwrap().bytes.ends_with(b"Quotes: [source] \"Beta.\"\n"));

    // at the second seal the first quote is withdrawn: the claim on it fell, the claim on that claim with it, and the third stands
    let later = part.export(second, None).unwrap();
    assert_eq!(later.records, [c3]);
    let refusal = |seal: usize, claims: &[RecordId]| part.export(seal, Some(claims)).err().map(|e| e.message).unwrap_or_default();
    assert!(refusal(second, &[c1]).contains("does not stand at that seal"));
    assert!(refusal(second, &[c2]).contains("does not stand at that seal"));
    assert!(refusal(first, &[o1]).contains("is no claim"));
    assert!(refusal(first, &[c1, c1]).contains("named twice"));
    // a record the journal accepted after the seal is no record of an export at it
    assert!(refusal(first, &[c3]).contains("before that seal"));
    assert!(refusal(first, &[RecordId([7; 32])]).contains("before that seal"));
    // an export with no paragraph is its header alone
    let none = part.export(first, Some(&[])).unwrap();
    assert_eq!(String::from_utf8(none.bytes).unwrap(), format!("{EXPORT_FORMAT} run=cut a seal={seal_hash} records=0\n"));
    // a seal the part was not read at, and a frame that is no seal
    assert!(journal.part(second, None, &BTreeSet::new()).unwrap().export(first, None).is_err());
    assert!(journal.part(first + 1, None, &BTreeSet::new()).is_err());
}

#[test]
fn a_cut_finds_a_delivery_by_a_put_of_its_own_and_refuses_one_inside_a_batch() {
    let dir = Folder::new("batch");
    let (ids, first, second) = journal_a(&dir.path("a.wal"));
    let journal = Journal::read(&dir.path("a.wal")).unwrap();
    let export = journal.part(second, None, &BTreeSet::from([first])).unwrap().export(first, None).unwrap();
    let text = String::from_utf8(export.bytes.clone()).unwrap();

    // `b` takes the export in by a put_document frame of its own, and quotes the paragraph of the claim that fell later
    let mut b = start(&dir.path("b.wal"), "cut b");
    b.put_document("owner", "inbound", &export.bytes).unwrap();
    let paragraph = text.split("\n\n").nth(1).unwrap();
    let quoted = submit(&mut b, json!([observe("o", "inbound", paragraph), claim("c", "B relies on one.", &["o"])]));
    seal(&mut b);
    drop(b);
    let read = |name: &str| (name.to_string(), Journal::read(&dir.path(&format!("{name}.wal"))).unwrap(), None);
    let made = cut(vec![read("b"), read("a")], vec![("e1".to_string(), export.bytes.clone())], None).unwrap();
    assert_eq!(made.manifest["journals"].as_array().unwrap().iter().map(|j| j["name"].as_str().unwrap()).collect::<Vec<_>>(), ["a", "b"]);
    assert_eq!(made.manifest["deliveries"], json!([{"export": "e1", "journal": "b", "doc_id": "inbound", "frame": 1}]));
    assert_eq!(made.manifest["exports"][0]["sha256"], to_hex(&sha256(&export.bytes)));
    assert_eq!(made.manifest["previous_cut"], Value::Null);
    assert_eq!(made.cut_hash, cut_hash(&made.manifest));
    // the claim of the first paragraph fell in `a` after the export, and the quote of it in `b` still stands
    let across = made.across();
    assert_eq!(across.len(), 1);
    assert_eq!((across[0].record, across[0].record_stands, across[0].observation, across[0].observation_stands), (ids[2], false, quoted[0], true));
    // so the journals show the cut failing the bundle check at B4: the report of such a cut is not made
    assert_eq!(made.unmet_level(), Some("B4"));
    // with the withdrawal brought to `b`, nothing is left unmet
    let mut b = AuditState::open(&dir.path("b.wal")).unwrap();
    b.withdraw_text("owner", "inbound", paragraph).unwrap();
    seal(&mut b);
    drop(b);
    let made = cut(vec![read("b"), read("a")], vec![("e1".to_string(), export.bytes.clone())], None).unwrap();
    assert_eq!((made.unmet_level(), made.across()[0].observation_stands), (None, false));
    given_manifests(&dir, &made.manifest, &export.bytes);
    // a delivered name put again fails at B3.3, whatever its quotes do
    let mut b = AuditState::open(&dir.path("b.wal")).unwrap();
    b.put_document("owner", "inbound", b"Other bytes.\n").unwrap();
    seal(&mut b);
    drop(b);
    let made = cut(vec![read("b"), read("a")], vec![("e1".to_string(), export.bytes.clone())], None).unwrap();
    assert_eq!(made.unmet_level(), Some("B3.3"));

    // `c` takes the same bytes in by an operation of a batch: no delivery can declare it, and the cut is refused
    let mut c = start(&dir.path("c.wal"), "cut c");
    let report = c.submit_operations_id("batch", "owner", &[json!({"kind": "put_document", "doc_id": "inbound", "text": text})], None).unwrap();
    assert_eq!(report["accepted_operations"], 1, "{report}");
    seal(&mut c);
    drop(c);
    let refused = cut(vec![read("a"), read("c")], vec![("e1".to_string(), export.bytes.clone())], None).err().unwrap();
    assert_eq!(refused.field.as_deref(), Some("delivery"));
    assert!(refused.message.contains("frame 1 of the journal c is a batch"), "{}", refused.message);

    // an export of another run, a changed byte, a name that is none and a name given twice are refused too
    let other = text.replace("run=cut a", "run=cut z");
    assert!(cut(vec![read("a")], vec![("e1".to_string(), other.into_bytes())], None).err().unwrap().message.contains("names no seal of a journal of the cut"));
    let changed = text.replace("One \"says\" alpha.", "One \"said\" alpha.");
    assert!(cut(vec![read("a")], vec![("e1".to_string(), changed.into_bytes())], None)
        .err()
        .unwrap()
        .message
        .contains("a paragraph is not the one made from its record"));
    assert!(cut(vec![read("a")], vec![("..".to_string(), export.bytes.clone())], None).err().unwrap().message.contains("is no name"));
    let twice = vec![("e1".to_string(), export.bytes.clone()), ("e1".to_string(), export.bytes.clone())];
    assert!(cut(vec![read("a")], twice, None).err().unwrap().message.contains("given twice"));
    // an export names a seal at or before its journal's seal in the cut: `a` cut at its first seal has no export of its second
    let late = journal.part(second, None, &BTreeSet::new()).unwrap().export(second, None).unwrap();
    let early = (String::from("a"), Journal::read(&dir.path("a.wal")).unwrap(), Some(first));
    assert!(cut(vec![early], vec![("e2".to_string(), late.bytes)], None).is_err());
}
