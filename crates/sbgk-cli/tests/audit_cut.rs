//! `sbgk audit-cut` and `sbgk audit-observation` on the vectors published with their specifications (`verifier/inputs/cut`,
//! `verifier/inputs/obs`): the exports and the manifests of the cut vectors come out byte for byte from their journals, and the
//! observation reports equal the expected reports that were published before this code. The vectors were written by scripts
//! over `sbgk` 0.3.0; here the command makes them from the journals alone.

use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_sbgk");

struct Folder(PathBuf);

impl Folder {
    fn new(tag: &str) -> Folder {
        static UNIQUE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let n = UNIQUE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("sbgk_cut_{tag}_{}_{nanos}-{n}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        Folder(root)
    }
}

impl Drop for Folder {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn text(path: &Path) -> &str {
    path.to_str().unwrap()
}

fn inputs() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../verifier/inputs")
}

fn json_file(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))).unwrap()
}

/// One command: its exit code and the JSON document it printed, on stdout or, for a usage error, on stderr.
fn sbgk(args: &[&str]) -> (i32, Value) {
    let out = Command::new(BIN).args(args).output().unwrap();
    let printed = if out.stdout.is_empty() { &out.stderr } else { &out.stdout };
    let printed = String::from_utf8_lossy(printed);
    let value = serde_json::from_str(printed.trim()).unwrap_or_else(|e| panic!("{args:?}: {e}: {printed}"));
    (out.status.code().unwrap_or(-1), value)
}

/// The journals of a vector, copied into a new bundle folder: neither its exports nor its manifest.
fn journals_of(vector: &Path, manifest: &Value, tag: &str) -> Folder {
    let work = Folder::new(tag);
    for journal in manifest["journals"].as_array().unwrap() {
        let name = journal["name"].as_str().unwrap();
        std::fs::create_dir_all(work.0.join(name)).unwrap();
        std::fs::copy(vector.join(name).join("run.wal"), work.0.join(name).join("run.wal")).unwrap();
    }
    work
}

/// `--at` for the seals a manifest names.
fn at(manifest: &Value) -> String {
    let pairs: Vec<String> = manifest["journals"].as_array().unwrap().iter().map(|j| format!("{}={}", j["name"].as_str().unwrap(), j["log_size"])).collect();
    pairs.join(",")
}

/// The export `entry` of a manifest, made again in `work` from its journal: at the seal the entry names, of the records the
/// paragraphs of the published file name. Returns the answer of the command.
fn export_again(vector: &Path, work: &Path, entry: &Value) -> (i32, Value) {
    let name = entry["name"].as_str().unwrap();
    let wal = work.join(entry["journal"].as_str().unwrap()).join("run.wal");
    let (_, status) = sbgk(&["audit-read", "status", "--wal", text(&wal)]);
    let seal = status["projections"]["seals"].as_array().unwrap().iter().find(|s| s["seal_hash"] == entry["seal_hash"]).expect("a seal of the journal");
    let published = String::from_utf8(std::fs::read(vector.join(format!("{name}.txt"))).unwrap()).unwrap();
    let ids: Vec<&str> = published.split("\n\n").skip(1).map(|p| &p["Record ".len().."Record ".len() + 64]).collect();
    let list = work.join(format!("{name}.ids.json"));
    std::fs::write(&list, json!(ids).to_string()).unwrap();
    let out = work.join(format!("{name}.txt"));
    let answer = sbgk(&["audit-cut", "export", "--wal", text(&wal), "--seal", &seal["log_size"].to_string(), "--records", text(&list), "--out", text(&out)]);
    std::fs::remove_file(&list).unwrap();
    answer
}

/// The vectors whose manifest says what their journals show: the five that pass, and three that fail for what the journals
/// did, not for what the manifest says of them. Every export and every manifest comes out byte for byte.
#[test]
fn the_exports_and_the_manifests_of_the_cut_vectors_are_made_again_byte_for_byte() {
    for vector in ["V-CUT-1", "V-CUT-2", "V-CUT-11", "V-CUT-12", "V-CUT-13", "V-CUT-15", "V-CUT-16", "V-CUT-18", "V-CUT-20"] {
        let dir = inputs().join("cut").join(vector);
        let published = std::fs::read(dir.join("cut.json")).unwrap();
        let manifest: Value = serde_json::from_slice(&published).unwrap();
        let expected = json_file(&dir.join("expected.json"));
        let work = journals_of(&dir, &manifest, vector);
        for entry in manifest["exports"].as_array().unwrap() {
            let (code, answer) = export_again(&dir, &work.0, entry);
            assert_eq!((code, answer["status"].as_str()), (0, Some("EXPORT")), "{vector}: {answer}");
            let name = entry["name"].as_str().unwrap();
            assert_eq!(std::fs::read(work.0.join(format!("{name}.txt"))).unwrap(), std::fs::read(dir.join(format!("{name}.txt"))).unwrap(), "{vector} {name}");
            assert_eq!(
                (&answer["sha256"], &answer["records"], &answer["seal"]["seal_hash"]),
                (&entry["sha256"], &entry["records"], &entry["seal_hash"]),
                "{vector}"
            );
        }
        let (code, answer) = sbgk(&["audit-cut", "manifest", "--bundle", text(&work.0), "--at", &at(&manifest)]);
        assert_eq!((code, answer["status"].as_str()), (0, Some("CUT")), "{vector}: {answer}");
        assert_eq!(std::fs::read(work.0.join("cut.json")).unwrap(), published, "{vector}: the manifest");
        assert_eq!(answer["cut_hash"], expected["cut_hash"], "{vector}");
        assert_eq!(answer["manifest"], manifest, "{vector}");
        // the answer says what the journals show, and no verdict on the bundle: that is the verifier's
        assert_eq!((answer.get("expected_failures"), answer.get("across"), answer.get("verdict")), (None, None, None), "{vector}: {answer}");
        // a journal that goes on after the seal the cut names (V-CUT-13, journal `b`): its later frames are not read, and the
        // answer says how many they are
        let after = if vector == "V-CUT-13" { json!({"b": 2}) } else { Value::Null };
        assert_eq!(answer["frames_after_the_seal"], after, "{vector}: {answer}");
    }
}

/// A vector with a forged manifest or a forged export: the command makes the manifest the journals show, or refuses the export.
#[test]
fn a_manifest_is_made_of_what_the_journals_show_and_a_forged_export_is_refused() {
    let cut = inputs().join("cut");
    let bundle = |vector: &str, with_exports: bool| {
        let dir = cut.join(vector);
        let manifest = json_file(&dir.join("cut.json"));
        let work = journals_of(&dir, &manifest, vector);
        for entry in manifest["exports"].as_array().unwrap().iter().filter(|_| with_exports) {
            let file = format!("{}.txt", entry["name"].as_str().unwrap());
            std::fs::copy(dir.join(&file), work.0.join(&file)).unwrap();
        }
        (work, manifest)
    };
    let made = |vector: &str| {
        let (work, manifest) = bundle(vector, true);
        let (code, answer) = sbgk(&["audit-cut", "manifest", "--bundle", text(&work.0), "--at", &at(&manifest)]);
        (code, answer, std::fs::read(work.0.join("cut.json")).ok())
    };
    // no delivery declared (V-CUT-9, V-CUT-14), a wrong frame (V-CUT-4), a delivery listed twice (V-CUT-8, V-CUT-19), a wrong head
    // or seal (V-CUT-6, V-CUT-7): the manifest made from the same journals is the one of the vector that declares them as they are
    for (forged, sound) in [
        ("V-CUT-9", "V-CUT-2"),
        ("V-CUT-14", "V-CUT-15"),
        ("V-CUT-4", "V-CUT-1"),
        ("V-CUT-8", "V-CUT-1"),
        ("V-CUT-6", "V-CUT-1"),
        ("V-CUT-7", "V-CUT-1"),
        ("V-CUT-19", "V-CUT-18"),
        // a key written twice in the manifest (V-CUT-22), another layout of it (V-CUT-23)
        ("V-CUT-22", "V-CUT-1"),
        ("V-CUT-23", "V-CUT-1"),
    ] {
        let (code, answer, written) = made(forged);
        assert_eq!(code, 0, "{forged}: {answer}");
        assert_eq!(written.unwrap(), std::fs::read(cut.join(sound).join("cut.json")).unwrap(), "{forged} is made as {sound}");
    }
    // the receiving journal refused the put (V-CUT-10): nothing was brought in, and no delivery is found
    let (code, answer, _) = made("V-CUT-10");
    assert_eq!((code, &answer["manifest"]["deliveries"]), (0, &json!([])), "{answer}");
    // one byte of the export changed (V-CUT-3), its paragraphs swapped (V-CUT-17), a claim that did not stand at the seal (V-CUT-5)
    for (vector, why) in [
        ("V-CUT-3", "a paragraph is not the one made from its record"),
        ("V-CUT-17", "its paragraphs are not in record order"),
        ("V-CUT-5", "does not stand at that seal"),
    ] {
        let (code, answer, written) = made(vector);
        assert_eq!((code, answer["status"].as_str(), written), (1, Some("REFUSED"), None), "{vector}: {answer}");
        assert!(answer["error"]["message"].as_str().unwrap().contains(why), "{vector}: {answer}");
    }
    // the receiving journal took the bytes of the export in by an operation of a batch (V-CUT-25, V-CUT-26: written by the
    // library): no delivery can declare it, whether the manifest names the frame or not, and no manifest is made
    // The published manifests get no report either: the one without a delivery leaves an import undeclared, the one that names
    // the frame of the batch names no put_document frame.
    for (vector, level) in [("V-CUT-25", "B3.2"), ("V-CUT-26", "B3.1")] {
        let (code, answer, written) = made(vector);
        assert_eq!((code, answer["status"].as_str(), written), (1, Some("REFUSED"), None), "{vector}: {answer}");
        assert!(answer["error"]["message"].as_str().unwrap().contains("frame 1 of the journal b is a batch"), "{vector}: {answer}");
        let (code, answer) = sbgk(&["audit-observation", "--bundle", text(&cut.join(vector))]);
        assert_eq!((code, answer["status"].as_str()), (1, Some("REFUSED")), "{vector}: {answer}");
        assert!(answer["error"]["message"].as_str().unwrap().contains(&format!("at level {level}:")), "{vector}: {answer}");
    }
    // and the export of a claim that did not stand at the seal is not made at all
    let (work, manifest) = bundle("V-CUT-5", false);
    let (code, answer) = export_again(&cut.join("V-CUT-5"), &work.0, &manifest["exports"][0]);
    assert_eq!((code, answer["status"].as_str()), (1, Some("REFUSED")), "{answer}");
    assert!(answer["error"]["message"].as_str().unwrap().contains("an export carries standing claims only"), "{answer}");
    assert!(!work.0.join("e1.txt").exists());
}

#[test]
fn an_export_without_a_list_carries_every_claim_that_stands_at_its_seal() {
    let dir = inputs().join("cut").join("V-CUT-1");
    let work = Folder::new("default");
    let wal = dir.join("a").join("run.wal");
    let out = work.0.join("made").join("e.txt");
    // at the first seal of `a` both claims stand: the export is the published one, and the folder of --out is made
    let (code, answer) = sbgk(&["audit-cut", "export", "--wal", text(&wal), "--seal", "3", "--out", text(&out)]);
    assert_eq!((code, answer["records"].as_u64()), (0, Some(2)), "{answer}");
    assert_eq!(std::fs::read(&out).unwrap(), std::fs::read(dir.join("e1.txt")).unwrap());
    // at its last seal, the default, the quote under the first claim is withdrawn: one claim stands
    let (code, answer) = sbgk(&["audit-cut", "export", "--wal", text(&wal), "--out", text(&out)]);
    assert_eq!((code, answer["records"].as_u64(), answer["seal"]["log_size"].as_u64()), (0, Some(1), Some(6)), "{answer}");
    let made = String::from_utf8(std::fs::read(&out).unwrap()).unwrap();
    assert!(
        made.starts_with("yuce-export/1 run=cut-a seal=a3d875044679a891ba07391570030ed44024e2afd37e87e7748ad7d399edb241 records=1\n\nRecord f5331d89"),
        "{made}"
    );

    // a frame that is no seal, a record that is no claim, and an export written over its journal
    let (code, answer) = sbgk(&["audit-cut", "export", "--wal", text(&wal), "--seal", "2", "--out", text(&out)]);
    assert_eq!((code, answer["status"].as_str()), (1, Some("REFUSED")), "{answer}");
    let list = work.0.join("ids.json");
    std::fs::write(&list, json!(["@7bac51987ee2cc09"]).to_string()).unwrap();
    let (code, answer) = sbgk(&["audit-cut", "export", "--wal", text(&wal), "--seal", "3", "--records", text(&list), "--out", text(&out)]);
    assert_eq!(code, 1, "{answer}");
    assert!(answer["error"]["message"].as_str().unwrap().contains("is no claim"), "{answer}");
    let copy = work.0.join("run.wal");
    std::fs::copy(&wal, &copy).unwrap();
    let before = std::fs::read(&copy).unwrap();
    let (code, answer) = sbgk(&["audit-cut", "export", "--wal", text(&copy), "--out", text(&copy)]);
    assert_eq!((code, answer["status"].as_str()), (1, Some("REFUSED")), "{answer}");
    assert_eq!(std::fs::read(&copy).unwrap(), before);
    // usage errors exit 2
    assert_eq!(sbgk(&["audit-cut", "exports", "--wal", text(&wal)]).0, 2);
    assert_eq!(sbgk(&["audit-cut", "manifest", "--bundle", text(&work.0.join("made"))]).0, 2);
    assert_eq!(sbgk(&["audit-cut", "manifest", "--bundle", text(&dir), "--at", "z=3", "--out", text(&work.0.join("cut.json"))]).0, 2);
}

/// The documents folder of a journal of the inputs: `<name>.docs` beside it, or `docs` in its folder.
fn docs_of(journal: &Path) -> PathBuf {
    let beside = journal.with_extension("docs");
    if beside.is_dir() {
        beside
    } else {
        journal.parent().unwrap().join("docs")
    }
}

/// The expected reports of the specification, published before the code: each comes out byte for byte.
#[test]
fn the_observation_reports_of_the_vectors_come_out_byte_for_byte() {
    let work = Folder::new("obs");
    for vector in ["V-OBS-1", "V-OBS-2", "V-OBS-3", "V-OBS-6", "V-OBS-8"] {
        let dir = inputs().join("obs").join(vector);
        let input = json_file(&dir.join("input.json"));
        let out = work.0.join(format!("{vector}.json"));
        let source: Vec<String> = match input["input"].as_str() {
            Some("cut") => vec!["--bundle".into(), text(&inputs().join(input["cut"].as_str().unwrap())).into()],
            _ => {
                let journal = inputs().join(input["journal"].as_str().unwrap());
                vec!["--wal".into(), text(&journal).into(), "--seal".into(), input["seal_frame"].to_string(), "--docs".into(), text(&docs_of(&journal)).into()]
            }
        };
        let mut args: Vec<&str> = vec!["audit-observation"];
        args.extend(source.iter().map(String::as_str));
        let published = std::fs::read(dir.join("report.json")).unwrap();
        // without --out the report is the answer, in the same bytes and a line end
        let printed = Command::new(BIN).args(&args).output().unwrap();
        assert_eq!(printed.status.code(), Some(0), "{vector}");
        assert_eq!(printed.stdout.strip_suffix(b"\n").unwrap(), published, "{vector}: the report printed");
        args.extend(["--out", text(&out)]);
        let (code, answer) = sbgk(&args);
        assert_eq!((code, answer["status"].as_str()), (0, Some("OBSERVATION_REPORT")), "{vector}: {answer}");
        assert_eq!(std::fs::read(&out).unwrap(), published, "{vector}: the report written");
        let report: Value = serde_json::from_slice(&published).unwrap();
        assert_eq!((&answer["report_hash"], &answer["debt"]), (&report["report_hash"], &report["debt"]["total"]), "{vector}");
    }
    // two observations of the same bytes of one version are two grounds of a claim and one entry of its `quotes`: no array of the
    // report holds a duplicate (the independent verifier found the repeat on this journal, 27.11.2026)
    let k017 = inputs().join("valid/k017-oracle-v3.wal");
    let (code, report) = sbgk(&["audit-observation", "--wal", text(&k017), "--docs", text(&docs_of(&k017))]);
    assert_eq!(code, 0);
    let claims = report["claims"].as_array().unwrap();
    let twice = claims.iter().find(|c| c["id"] == "96dbc269ab11e642384243c7e2d376045c90f9e8b6b83b07ff777d0eab3b7e79").expect("the claim of k017");
    assert_eq!(twice["quotes"].as_array().map(Vec::len), Some(2), "{twice}");
    for claim in claims {
        for list in ["quotes", "rests_on", "rests_on_across", "questions", "root_causes", "dispute_links", "time_links"] {
            let entries = claim[list].as_array().unwrap();
            let distinct: std::collections::BTreeSet<String> = entries.iter().map(Value::to_string).collect();
            assert_eq!(distinct.len(), entries.len(), "{list} of {}", claim["id"]);
        }
    }
    // the last seal of a journal is the default: V-OBS-6 is the journal of V-OBS-3 at its last seal
    let journal = inputs().join("j4a/set-d/d6-relation-link-lifecycle.wal");
    let printed = Command::new(BIN).args(["audit-observation", "--wal", text(&journal)]).output().unwrap();
    assert_eq!(printed.stdout.strip_suffix(b"\n").unwrap(), std::fs::read(inputs().join("obs/V-OBS-6/report.json")).unwrap());
    assert!(printed.stderr.is_empty(), "{}", String::from_utf8_lossy(&printed.stderr));
    // at an earlier seal the frames after it are not read: the report is of the part, and the answer says what was left out
    let (code, answer) = sbgk(&["audit-observation", "--wal", text(&journal), "--seal", "11", "--out", text(&work.0.join("part.json"))]);
    assert_eq!((code, &answer["frames_after_the_seal"]), (0, &json!({"axis-d6": 3})), "{answer}");
    let printed = Command::new(BIN).args(["audit-observation", "--wal", text(&journal), "--seal", "11"]).output().unwrap();
    let note: Value = serde_json::from_slice(&printed.stderr).unwrap();
    assert_eq!((printed.status.code(), &note["frames_after_the_seal"]), (Some(0), &json!({"axis-d6": 3})), "{note}");
    assert_eq!(printed.stdout.strip_suffix(b"\n").unwrap(), std::fs::read(inputs().join("obs/V-OBS-3/report.json")).unwrap());
    // so a journal whose frame after its seal the kernel refuses still has the report of its part, when the seal is named
    // (`audit-verify` refuses the file as a whole); and a journal without a seal has none
    let nested = inputs().join("boundary/nested-seal.wal");
    assert_eq!(sbgk(&["audit-verify", "--wal", text(&nested)]).0, 1);
    let (code, answer) =
        sbgk(&["audit-observation", "--wal", text(&nested), "--seal", "1", "--docs", text(&docs_of(&nested)), "--out", text(&work.0.join("nested.json"))]);
    assert_eq!((code, answer["claims"].as_u64(), answer["frames_after_the_seal"].as_object().map(|o| o.len())), (0, Some(0), Some(1)), "{answer}");
    assert_eq!(sbgk(&["audit-observation", "--wal", text(&inputs().join("valid/gap-primary-exhausted.wal"))]).0, 2);
    // a journal the kernel refuses inside the part gets no report
    let (code, answer) = sbgk(&["audit-observation", "--wal", text(&inputs().join("j4a/set-c/forged-cascade.wal"))]);
    assert_eq!((code, answer["status"].as_str()), (1, Some("REFUSED")), "{answer}");
}

/// The report of one journal is of the journal with its documents, up to the seal and no further (the specification of the
/// report, section 1): what the independent verifier asks of a single journal, no more and no less.
#[test]
fn the_report_of_a_journal_asks_for_its_documents_and_reads_no_frame_after_its_seal() {
    let work = Folder::new("single");
    let report = |args: &[&str]| {
        let mut all = vec!["audit-observation"];
        all.extend(args);
        Command::new(BIN).args(&all).output().unwrap()
    };
    let refusal = |printed: &std::process::Output| -> Value { serde_json::from_slice(&printed.stdout).unwrap() };

    // journal `b` of V-CUT-18: `inbound` and `second` are documents of its genesis record, `notice` came by a put; sealed at
    // frame 4 and closed
    let b = inputs().join("cut/V-CUT-18/b");
    let (wal, docs) = (b.join("run.wal"), b.join("docs"));
    let sound = report(&["--wal", text(&wal), "--seal", "4", "--docs", text(&docs)]);
    assert_eq!(sound.status.code(), Some(0));
    assert!(sound.stderr.is_empty(), "a well-formed close after the seal is no frame left out: {}", String::from_utf8_lossy(&sound.stderr));
    // without its documents, or with those of another journal: no report
    for other in [None, Some(inputs().join("cut/V-CUT-18/a/docs"))] {
        let printed = match &other {
            None => report(&["--wal", text(&wal), "--seal", "4"]),
            Some(folder) => report(&["--wal", text(&wal), "--seal", "4", "--docs", text(folder)]),
        };
        let answer = refusal(&printed);
        assert_eq!((printed.status.code(), answer["status"].as_str(), answer["error"]["field"].as_str()), (Some(1), Some("REFUSED"), Some("docs")), "{answer}");
        assert!(answer["error"]["message"].as_str().unwrap().contains("of its genesis record"), "{answer}");
    }
    // a document is known by its bytes: under other names and deeper in the folder it is the same document; the one that came
    // by a put is in its frame, and its file is not asked for
    let moved = work.0.join("moved");
    std::fs::create_dir_all(moved.join("deeper")).unwrap();
    std::fs::copy(docs.join("inbound"), moved.join("deeper").join("x.bin")).unwrap();
    std::fs::copy(docs.join("second"), moved.join("y")).unwrap();
    assert_eq!(report(&["--wal", text(&wal), "--seal", "4", "--docs", text(&moved)]).stdout, sound.stdout);
    std::fs::remove_file(moved.join("y")).unwrap();
    assert_eq!(report(&["--wal", text(&wal), "--seal", "4", "--docs", text(&moved)]).status.code(), Some(1));
    // a journal whose genesis record names no document needs none (journal `a` of V-CUT-1 took its source by a put)
    assert_eq!(report(&["--wal", text(&inputs().join("cut/V-CUT-1/a/run.wal")), "--seal", "3"]).status.code(), Some(0));
    // --docs is a folder, and goes with --wal
    assert_eq!(report(&["--wal", text(&wal), "--docs", text(&wal)]).status.code(), Some(2));
    assert_eq!(report(&["--bundle", text(&inputs().join("cut/V-CUT-18")), "--docs", text(&docs)]).status.code(), Some(2));

    // The close after the seal broken: it is no part of the input, and the report is the same; the note says one frame was
    // left out. Named closed in a manifest, the same journal fails the check of its bundle.
    let lines = |file: &Path| -> Vec<Vec<u8>> { std::fs::read(file).unwrap().split(|b| *b == b'\n').filter(|l| !l.is_empty()).map(<[u8]>::to_vec).collect() };
    let write = |file: &Path, lines: &[Vec<u8>]| std::fs::write(file, lines.iter().flat_map(|l| l.iter().copied().chain(*b"\n")).collect::<Vec<u8>>()).unwrap();
    let bundle = work.0.join("closebroken");
    copy_folder(&inputs().join("cut/V-CUT-18"), &bundle);
    let mut frames = lines(&bundle.join("b/run.wal"));
    assert_eq!(frames.len(), 6);
    frames[5] = b"{not json".to_vec();
    write(&bundle.join("b/run.wal"), &frames);
    let printed = report(&["--wal", text(&bundle.join("b/run.wal")), "--seal", "4", "--docs", text(&docs)]);
    assert_eq!((printed.status.code(), &printed.stdout), (Some(0), &sound.stdout));
    let note: Value = serde_json::from_slice(&printed.stderr).unwrap();
    assert_eq!(note["frames_after_the_seal"].as_object().and_then(|o| o.values().next()), Some(&json!(1)), "{note}");
    assert_eq!(report(&["--wal", text(&bundle.join("b/run.wal")), "--docs", text(&docs)]).status.code(), Some(1), "with no seal named the whole file is read");
    let printed = report(&["--bundle", text(&bundle)]);
    assert_eq!(printed.status.code(), Some(1));
    assert!(refusal(&printed)["error"]["message"].as_str().unwrap().contains("at level B1:"));

    // Journal `b` of V-CUT-13 goes on for two frames after the seal of its cut. Its last frame broken, or cut in half: the
    // report of the bundle, the report of the journal and an export at that seal are what the sound files give.
    let cut13 = inputs().join("cut/V-CUT-13");
    let sound_bundle = report(&["--bundle", text(&cut13)]);
    let sound_journal = report(&["--wal", text(&cut13.join("b/run.wal")), "--seal", "5", "--docs", text(&cut13.join("b/docs"))]);
    assert_eq!((sound_bundle.status.code(), sound_journal.status.code()), (Some(0), Some(0)));
    let export = |wal: &Path, out: &Path| sbgk(&["audit-cut", "export", "--wal", text(wal), "--seal", "5", "--out", text(out)]);
    assert_eq!(export(&cut13.join("b/run.wal"), &work.0.join("sound.txt")).0, 0);
    for (tag, torn) in [("nojson", false), ("torn", true)] {
        let damaged = work.0.join(tag);
        copy_folder(&cut13, &damaged);
        let file = damaged.join("b/run.wal");
        let mut frames = lines(&file);
        assert_eq!(frames.len(), 8);
        frames[7] = if torn { frames[7][..frames[7].len() / 2].to_vec() } else { b"{not json".to_vec() };
        write(&file, &frames);
        assert_eq!(sbgk(&["audit-verify", "--wal", text(&file)]).0, 1, "{tag}: the file as a whole is refused");
        let printed = report(&["--bundle", text(&damaged)]);
        assert_eq!((printed.status.code(), &printed.stdout), (Some(0), &sound_bundle.stdout), "{tag}");
        let printed = report(&["--wal", text(&file), "--seal", "5", "--docs", text(&damaged.join("b/docs"))]);
        assert_eq!((printed.status.code(), &printed.stdout), (Some(0), &sound_journal.stdout), "{tag}");
        assert_eq!(export(&file, &work.0.join(format!("{tag}.txt"))).0, 0, "{tag}");
        assert_eq!(std::fs::read(work.0.join(format!("{tag}.txt"))).unwrap(), std::fs::read(work.0.join("sound.txt")).unwrap(), "{tag}");
        // a frame broken inside the part takes the report away
        frames[2] = b"{not json".to_vec();
        write(&file, &frames);
        assert_eq!(report(&["--bundle", text(&damaged)]).status.code(), Some(1), "{tag}");
        assert_eq!(report(&["--wal", text(&file), "--seal", "5", "--docs", text(&damaged.join("b/docs"))]).status.code(), Some(1), "{tag}");
    }
}

/// Every file of a folder, at any depth, with its bytes.
fn snapshot(dir: &Path) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
    let mut files = std::collections::BTreeMap::new();
    let mut folders = vec![dir.to_path_buf()];
    while let Some(dir) = folders.pop() {
        for entry in std::fs::read_dir(&dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                folders.push(path);
            } else {
                files.insert(path.clone(), std::fs::read(&path).unwrap());
            }
        }
    }
    files
}

/// An output is written over no file of its input (Codex's review of c64809bb: a report replaced a document it had just
/// hashed, and the next check of the same input failed on both sides). Every file of the input of each of the four commands
/// is tried as `--out`: the command refuses, and the folder is as it was.
#[test]
fn an_output_is_written_over_no_file_of_its_input() {
    // V-CUT-18: two journals, each with documents, two exports and the manifest. The verifier's expected answer is no file of
    // the bundle.
    let work = bundle_of("V-CUT-18", "guard", |_| ());
    let dir = work.0.clone();
    std::fs::remove_file(dir.join("expected.json")).unwrap();
    // a list of records, and a second documents folder of journal `b`, both outside the bundle
    let aside = Folder::new("guardaside");
    let list = aside.0.join("ids.json");
    std::fs::write(&list, json!(["fc7e632f2db912c9c610c8a8f294440361675d9084798b171eae63307653ab7e"]).to_string()).unwrap();
    let moved = aside.0.join("moved");
    std::fs::create_dir_all(moved.join("deeper")).unwrap();
    std::fs::copy(dir.join("b/docs/inbound"), moved.join("deeper").join("x.bin")).unwrap();
    std::fs::copy(dir.join("b/docs/second"), moved.join("y")).unwrap();
    let (before, before_aside) = (snapshot(&dir), snapshot(&aside.0));
    let under = |part: &str| -> Vec<PathBuf> { before.keys().filter(|path| path.starts_with(dir.join(part))).cloned().collect() };
    assert_eq!((before.len(), under("a").len(), under("b").len()), (10, 3, 4), "{:?}", before.keys().collect::<Vec<_>>());
    let (a, b) = (dir.join("a/run.wal"), dir.join("b/run.wal"));

    // each command with the files of its input
    let all: Vec<PathBuf> = before.keys().cloned().collect();
    let commands: Vec<(&str, Vec<String>, Vec<PathBuf>)> = vec![
        (
            "export",
            ["audit-cut", "export", "--wal", text(&a), "--seal", "3", "--records", text(&list)].map(String::from).to_vec(),
            under("a").into_iter().chain([list.clone()]).collect(),
        ),
        (
            "manifest",
            ["audit-cut", "manifest", "--bundle", text(&dir)].map(String::from).to_vec(),
            all.iter().filter(|path| path.file_name().unwrap() != "cut.json").cloned().collect(),
        ),
        (
            "report of a journal",
            ["audit-observation", "--wal", text(&b), "--seal", "4", "--docs", text(&dir.join("b/docs"))].map(String::from).to_vec(),
            under("b"),
        ),
        (
            "report of a journal, its documents elsewhere",
            ["audit-observation", "--wal", text(&b), "--seal", "4", "--docs", text(&moved)].map(String::from).to_vec(),
            under("b").into_iter().chain([moved.join("deeper").join("x.bin"), moved.join("y")]).collect(),
        ),
        ("report of a bundle", ["audit-observation", "--bundle", text(&dir)].map(String::from).to_vec(), all.clone()),
    ];
    let mut tried = 0;
    for (what, command, files) in &commands {
        // the command itself is sound: to a file of its own it writes
        let own = aside.0.join("out").join(format!("{}.out", tried));
        let mut args: Vec<&str> = command.iter().map(String::as_str).collect();
        args.extend(["--out", text(&own)]);
        assert_eq!(sbgk(&args).0, 0, "{what}");
        std::fs::remove_file(&own).unwrap();
        for file in files {
            // the path as it is, and written another way
            let dotted = file.parent().unwrap().join(".").join(file.file_name().unwrap());
            let mut spellings = vec![file.clone(), dotted];
            if cfg!(windows) {
                spellings.push(PathBuf::from(file.to_string_lossy().to_uppercase()));
            }
            for out in spellings {
                let mut args: Vec<&str> = command.iter().map(String::as_str).collect();
                args.extend(["--out", text(&out)]);
                let (code, answer) = sbgk(&args);
                assert_eq!((code, answer["status"].as_str()), (1, Some("REFUSED")), "{what} over {}: {answer}", out.display());
                assert!(answer["error"].as_str().is_some_and(|e| e.contains("would be written over")), "{what} over {}: {answer}", out.display());
                tried += 1;
            }
            assert!(snapshot(&dir) == before && snapshot(&aside.0) == before_aside, "{what} over {}: a file changed", file.display());
        }
    }
    assert!(tried >= 2 * (4 + 9 + 4 + 6 + 10), "{tried}");
    // and the input still gives its report
    assert_eq!(report_of(&dir).0, 0);
}

/// With no seal named a command takes the last seal of the file itself, and the whole file is then its input: it answers only
/// where `audit-verify` verifies the file (Codex's review of c64809bb: a torn tail was neither refused nor named). With the
/// seal named the bytes after the part are outside the input.
#[test]
fn with_no_seal_named_the_whole_file_is_the_input_as_audit_verify_reads_it() {
    let work = Folder::new("whole");
    let lines = |file: &Path| -> Vec<Vec<u8>> { std::fs::read(file).unwrap().split(|b| *b == b'\n').filter(|l| !l.is_empty()).map(<[u8]>::to_vec).collect() };
    let joined = |lines: &[Vec<u8>]| -> Vec<u8> { lines.iter().flat_map(|l| l.iter().copied().chain(*b"\n")).collect() };

    // k017 up to its seal of frame 3, and the same with eight bytes of a frame that was never finished
    let k017 = inputs().join("valid/k017-oracle-v3.wal");
    let docs = docs_of(&k017);
    let (clean, torn) = (work.0.join("clean.wal"), work.0.join("torn.wal"));
    let prefix = joined(&lines(&k017)[..4]);
    std::fs::write(&clean, &prefix).unwrap();
    std::fs::write(&torn, [prefix.as_slice(), b"{\"body\":"].concat()).unwrap();
    let (code, verified) = sbgk(&["audit-verify", "--wal", text(&torn)]);
    assert_eq!((code, verified["status"].as_str(), verified["torn_tail_bytes"].as_u64()), (1, Some("TORN_TAIL"), Some(8)), "{verified}");
    let report = |wal: &Path, seal: Option<&str>, out: &Path| {
        let mut args = vec!["audit-observation", "--wal", text(wal), "--docs", text(&docs), "--out", text(out)];
        args.extend(seal.into_iter().flat_map(|n| ["--seal", n]));
        sbgk(&args)
    };
    let export = |wal: &Path, seal: Option<&str>, out: &Path| {
        let mut args = vec!["audit-cut", "export", "--wal", text(wal), "--out", text(out)];
        args.extend(seal.into_iter().flat_map(|n| ["--seal", n]));
        sbgk(&args)
    };
    let out = |name: &str| work.0.join(name);
    assert_eq!(report(&clean, None, &out("clean.json")).0, 0);
    assert_eq!(export(&clean, None, &out("clean.txt")).0, 0);
    for (what, answer) in [("report", report(&torn, None, &out("no.json"))), ("export", export(&torn, None, &out("no.txt")))] {
        let (code, answer) = answer;
        assert_eq!(
            (code, answer["status"].as_str(), answer["torn_tail_bytes"].as_u64(), answer["last_seal"].as_u64()),
            (1, Some("TORN_TAIL"), Some(8), Some(3)),
            "{what}: {answer}"
        );
        let message = answer["error"]["message"].as_str().unwrap();
        assert!(message.contains("--seal 3") && message.contains("audit-verify"), "{what}: {answer}");
    }
    assert!(!out("no.json").exists() && !out("no.txt").exists(), "nothing is written");
    // the seal named: the tail is outside the input, and the answers are those of the clean file
    assert_eq!(report(&torn, Some("3"), &out("torn.json")).0, 0);
    assert_eq!(export(&torn, Some("3"), &out("torn.txt")).0, 0);
    assert_eq!(std::fs::read(out("torn.json")).unwrap(), std::fs::read(out("clean.json")).unwrap());
    assert_eq!(std::fs::read(out("torn.txt")).unwrap(), std::fs::read(out("clean.txt")).unwrap());

    // a frame after the last seal that the kernel refuses (`audit-verify` refuses the file): no answer without the seal
    let nested = inputs().join("boundary/nested-seal.wal");
    assert_eq!(sbgk(&["audit-verify", "--wal", text(&nested)]).0, 1);
    let nested_docs = docs_of(&nested);
    let (code, answer) = sbgk(&["audit-observation", "--wal", text(&nested), "--docs", text(&nested_docs), "--out", text(&out("nested.json"))]);
    assert_eq!((code, answer["status"].as_str(), answer["last_seal"].as_u64()), (1, Some("REFUSED"), Some(1)), "{answer}");
    let message = answer["error"]["message"].as_str().unwrap();
    assert!(message.contains("frame 2") && message.contains("--seal 1") && message.contains("audit-verify"), "{answer}");
    let (code, answer) = export(&nested, None, &out("nested.txt"));
    assert_eq!((code, answer["status"].as_str()), (1, Some("REFUSED")), "{answer}");
    assert!(!out("nested.json").exists() && !out("nested.txt").exists(), "nothing is written");
    assert_eq!(export(&nested, Some("1"), &out("nested.txt")).0, 0);
    // the same journal as the one journal of a bundle: the manifest is made only with its seal named
    let lone = work.0.join("lone");
    std::fs::create_dir_all(lone.join("n")).unwrap();
    std::fs::copy(&nested, lone.join("n/run.wal")).unwrap();
    let (code, answer) = sbgk(&["audit-cut", "manifest", "--bundle", text(&lone)]);
    assert_eq!((code, answer["status"].as_str()), (1, Some("REFUSED")), "{answer}");
    assert!(answer["error"]["message"].as_str().unwrap().contains("--at n=1"), "{answer}");
    assert!(!lone.join("cut.json").exists());
    assert_eq!(sbgk(&["audit-cut", "manifest", "--bundle", text(&lone), "--at", "n=1"]).0, 0);

    // Frames after the last seal that are sound are no refusal: journal `b` of V-CUT-13 goes on for two frames, and the answer
    // counts them. With its tail torn, the manifest of the bundle is made only with the seal of `b` named, and is then the
    // published one.
    let bundle = work.0.join("cut13");
    copy_folder(&inputs().join("cut/V-CUT-13"), &bundle);
    let b = bundle.join("b/run.wal");
    assert_eq!(sbgk(&["audit-verify", "--wal", text(&b)]).0, 0);
    let (code, answer) = sbgk(&["audit-observation", "--wal", text(&b), "--docs", text(&bundle.join("b/docs")), "--out", text(&out("b.json"))]);
    assert_eq!((code, answer["frames_after_the_seal"].as_object().and_then(|o| o.values().next())), (0, Some(&json!(2))), "{answer}");
    let published = json_file(&bundle.join("cut.json"));
    std::fs::write(&b, [std::fs::read(&b).unwrap().as_slice(), b"{\"body\":"].concat()).unwrap();
    let made = out("made.json");
    let (code, answer) = sbgk(&["audit-cut", "manifest", "--bundle", text(&bundle), "--out", text(&made)]);
    assert_eq!((code, answer["status"].as_str(), answer["torn_tail_bytes"].as_u64()), (1, Some("TORN_TAIL"), Some(8)), "{answer}");
    assert!(answer["error"]["message"].as_str().unwrap().contains("--at b=5"), "{answer}");
    assert!(!made.exists());
    let (code, answer) = sbgk(&["audit-cut", "manifest", "--bundle", text(&bundle), "--at", "b=5", "--out", text(&made)]);
    assert_eq!((code, &answer["manifest"]), (0, &published), "{answer}");
    // and the report of the bundle reads the manifest, which names the seal: the torn tail is outside its input
    assert_eq!(report_of(&bundle).0, 0);
}

fn copy_folder(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap().flatten() {
        let (source, target) = (entry.path(), to.join(entry.file_name()));
        if source.is_dir() {
            copy_folder(&source, &target);
        } else {
            std::fs::copy(&source, &target).unwrap();
        }
    }
}

/// A vector copied whole into a new folder, with its manifest changed.
fn bundle_of(vector: &str, tag: &str, change: impl FnOnce(&mut Value)) -> Folder {
    let work = Folder::new(tag);
    copy_folder(&inputs().join("cut").join(vector), &work.0);
    let mut manifest = json_file(&work.0.join("cut.json"));
    change(&mut manifest);
    std::fs::write(work.0.join("cut.json"), manifest.to_string()).unwrap();
    work
}

fn report_of(bundle: &Path) -> (i32, Value) {
    sbgk(&["audit-observation", "--bundle", text(bundle)])
}

/// A manifest someone else wrote is read as it says, and the bundle is asked what the independent verifier asks of it: the
/// four boundaries of Codex's review of dd7f5b2f. On each the verifier's answer is the one checked here (the gate compares the
/// two sides on these and on variants of every vector).
#[test]
fn a_given_manifest_is_read_as_it_says_and_the_bundle_is_asked_what_the_verifier_asks() {
    let published: Value = json_file(&inputs().join("obs/V-OBS-1/report.json"));
    let same_claims = |report: &Value| assert_eq!(report["claims"], published["claims"], "{report}");

    // 1. `closed: false` at a seal, though the file goes on to its close: the close is outside the part, and the cut passes.
    //    The reader took `closed` from the frame after the seal and answered that the journals differ.
    let open = bundle_of("V-CUT-1", "open", |m| m["journals"][0]["closed"] = json!(false));
    let (code, report) = report_of(&open.0);
    assert_eq!(code, 0, "{report}");
    same_claims(&report);
    assert_ne!(report["cut_hash"], published["cut_hash"], "another manifest is another cut");
    // and `closed: true` where no close follows the seal does not hold (journal `b` of V-CUT-13 goes on unclosed)
    let not_closed = bundle_of("V-CUT-13", "notclosed", |m| m["journals"][1]["closed"] = json!(true));
    let (code, answer) = report_of(&not_closed.0);
    assert_eq!(code, 1, "{answer}");
    assert!(answer["error"]["message"].as_str().unwrap().contains("at level B1:"), "{answer}");

    // 2. The manifest names the export of a delivery and the journal of an export: neither is looked up again.
    //    The same bytes as `e2`, the one delivery declared as `e2`: the reader chose `e1` and answered that the deliveries differ.
    let alias = bundle_of("V-CUT-1", "alias", |m| {
        let mut second = m["exports"][0].clone();
        second["name"] = json!("e2");
        m["exports"].as_array_mut().unwrap().push(second);
        m["deliveries"][0]["export"] = json!("e2");
    });
    std::fs::copy(alias.0.join("e1.txt"), alias.0.join("e2.txt")).unwrap();
    let (code, report) = report_of(&alias.0);
    assert_eq!(code, 0, "{report}");
    same_claims(&report);
    //    Journal `a` also in the bundle as `z`, the export still of `a`: the reader refused two journals with the seal.
    let twin = bundle_of("V-CUT-1", "twin", |m| {
        let mut second = m["journals"][0].clone();
        second["name"] = json!("z");
        m["journals"].as_array_mut().unwrap().push(second);
    });
    copy_folder(&twin.0.join("a"), &twin.0.join("z"));
    let (code, report) = report_of(&twin.0);
    assert_eq!(code, 0, "{report}");
    assert_eq!(report["journals"].as_array().map(Vec::len), Some(3));
    assert_eq!(report["claims"].as_array().unwrap().iter().find(|c| c["journal"] == "b").unwrap()["rests_on_across"][0]["journal"], "a");

    // 3. A document of a genesis record that is not in the bundle: the journal cannot be checked from outside, and the reader
    //    wrote a report all the same. A document that came by a put is in its frame, and its file is not needed.
    let whole = bundle_of("V-CUT-18", "whole", |_| ());
    assert_eq!(report_of(&whole.0).0, 0);
    std::fs::remove_file(whole.0.join("b/docs/notice")).unwrap();
    assert_eq!(report_of(&whole.0).0, 0, "the notice came by a put");
    std::fs::remove_file(whole.0.join("b/docs/inbound")).unwrap();
    let (code, answer) = report_of(&whole.0);
    assert_eq!((code, answer["status"].as_str()), (1, Some("REFUSED")), "{answer}");
    assert!(answer["error"]["message"].as_str().unwrap().contains("at level B1:"), "{answer}");
    assert!(answer["error"]["message"].as_str().unwrap().contains("inbound"), "{answer}");
    // a journal or an export the manifest lists and the bundle does not hold
    let gone = bundle_of("V-CUT-1", "gone", |_| ());
    std::fs::remove_file(gone.0.join("e1.txt")).unwrap();
    assert_eq!(report_of(&gone.0).0, 1);
    std::fs::remove_dir_all(gone.0.join("b")).unwrap();
    assert_eq!(report_of(&gone.0).0, 1);
}

/// 4. An export is written over neither file it was made from: the journal, and the list of its records.
#[test]
fn an_export_is_not_written_over_the_list_of_its_records() {
    let work = Folder::new("list");
    let wal = inputs().join("cut/V-CUT-1/a/run.wal");
    let list = work.0.join("ids.json");
    let ids = json!(["fc7e632f2db912c9c610c8a8f294440361675d9084798b171eae63307653ab7e"]).to_string();
    std::fs::write(&list, &ids).unwrap();
    let (code, answer) = sbgk(&["audit-cut", "export", "--wal", text(&wal), "--seal", "3", "--records", text(&list), "--out", text(&list)]);
    assert_eq!((code, answer["status"].as_str()), (1, Some("REFUSED")), "{answer}");
    assert_eq!(std::fs::read_to_string(&list).unwrap(), ids, "the list is as it was");
    // the same file by another spelling of its path
    let other = work.0.join(".").join("ids.json");
    assert_eq!(sbgk(&["audit-cut", "export", "--wal", text(&wal), "--seal", "3", "--records", text(&list), "--out", text(&other)]).0, 1);
    assert_eq!(std::fs::read_to_string(&list).unwrap(), ids);
    // and to a file of its own it is written
    let out = work.0.join("e.txt");
    let (code, answer) = sbgk(&["audit-cut", "export", "--wal", text(&wal), "--seal", "3", "--records", text(&list), "--out", text(&out)]);
    assert_eq!((code, answer["records"].as_u64()), (0, Some(1)), "{answer}");
}

/// The report of a cut reads the deliveries of its manifest: a manifest that is not the cut of its bundle gets no report.
#[test]
fn a_manifest_that_is_not_the_cut_of_its_bundle_gets_no_report() {
    let cut = inputs().join("cut");
    // a wrong frame (V-CUT-4), a delivery twice (V-CUT-8), no delivery (V-CUT-9), a wrong head or seal (V-CUT-6, V-CUT-7), an
    // export named `.` (V-CUT-21): each is refused at the level of the bundle check it fails
    for (vector, differs) in [("V-CUT-4", "B3.1"), ("V-CUT-8", "B0"), ("V-CUT-9", "B3.2"), ("V-CUT-6", "B1"), ("V-CUT-7", "B1"), ("V-CUT-21", "B0")] {
        let (code, answer) = sbgk(&["audit-observation", "--bundle", text(&cut.join(vector))]);
        assert_eq!((code, answer["status"].as_str()), (1, Some("REFUSED")), "{vector}: {answer}");
        assert!(answer["error"]["message"].as_str().unwrap().contains(&format!("at level {differs}:")), "{vector}: {answer}");
    }
    // a changed export, and a manifest that names a journal by a path
    let (code, answer) = sbgk(&["audit-observation", "--bundle", text(&cut.join("V-CUT-3"))]);
    assert_eq!((code, answer["status"].as_str()), (1, Some("REFUSED")), "{answer}");
    let work = Folder::new("path");
    let mut manifest = json_file(&cut.join("V-CUT-1/cut.json"));
    manifest["journals"][0]["name"] = json!("../a");
    let file = work.0.join("cut.json");
    std::fs::write(&file, manifest.to_string()).unwrap();
    assert_eq!(sbgk(&["audit-observation", "--bundle", text(&cut.join("V-CUT-1")), "--cut", text(&file)]).0, 1);
    // a report is of a checked input: a cut the journals show failing the bundle check gets none. A withdrawal that has not
    // reached the other side (V-CUT-2, V-CUT-15) and a delivered document put again (V-CUT-11); the failure is the verifier's to name
    for (vector, level) in [("V-CUT-2", "B4"), ("V-CUT-15", "B4"), ("V-CUT-11", "B3.3")] {
        let (code, answer) = sbgk(&["audit-observation", "--bundle", text(&cut.join(vector))]);
        assert_eq!((code, answer["status"].as_str()), (1, Some("REFUSED")), "{vector}: {answer}");
        assert!(answer["error"]["message"].as_str().unwrap().contains(&format!("at level {level}:")), "{vector}: {answer}");
    }
    // a manifest file is one JSON object without a key written twice: a key twice (V-CUT-22) and `null` (V-CUT-24) are none,
    // and so is a file with a byte-order mark; another layout of the same object (V-CUT-23) is the same cut
    for vector in ["V-CUT-22", "V-CUT-24"] {
        let (code, answer) = sbgk(&["audit-observation", "--bundle", text(&cut.join(vector))]);
        assert_eq!((code, answer["status"].as_str()), (1, Some("REFUSED")), "{vector}: {answer}");
    }
    let mut marked = vec![0xEF, 0xBB, 0xBF];
    marked.extend(std::fs::read(cut.join("V-CUT-1/cut.json")).unwrap());
    std::fs::write(&file, marked).unwrap();
    assert_eq!(sbgk(&["audit-observation", "--bundle", text(&cut.join("V-CUT-1")), "--cut", text(&file)]).0, 1);
    let nested = r#"{"journals":[{"name":"a","log_size":6,"x":{"k":1,"\u006b":2}}],"exports":[]}"#;
    std::fs::write(&file, nested).unwrap();
    let (code, answer) = sbgk(&["audit-observation", "--bundle", text(&cut.join("V-CUT-1")), "--cut", text(&file)]);
    assert_eq!(code, 1, "{answer}");
    assert!(answer["error"]["message"].as_str().unwrap().contains("without a key written twice"), "{answer}");
    let same = Command::new(BIN).args(["audit-observation", "--bundle", text(&cut.join("V-CUT-23"))]).output().unwrap();
    assert_eq!(same.stdout.strip_suffix(b"\n").unwrap(), std::fs::read(inputs().join("obs/V-OBS-1/report.json")).unwrap());
    // one journal or one bundle, not both
    assert_eq!(sbgk(&["audit-observation", "--bundle", text(&cut.join("V-CUT-1")), "--wal", text(&cut.join("V-CUT-1/a/run.wal"))]).0, 2);
    assert_eq!(sbgk(&["audit-observation"]).0, 2);
}
