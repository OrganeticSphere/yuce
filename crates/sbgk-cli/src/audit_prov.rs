//! `sbgk audit-prov`: the journal as W3C PROV-O, one JSON-LD file rebuilt from it at any time (`sbgk_core::audit::prov`). The truth
//! stays in the journal: the file is a reading of it, and the same journal always gives the same bytes.

use super::audit_index::same_file;
use super::{fail, Args};
use sbgk_core::audit::prov;
use sbgk_core::hash::to_hex;
use serde_json::json;
use std::path::{Path, PathBuf};

pub fn cmd_audit_prov(a: &Args) {
    let wal = a.req("wal");
    let out = PathBuf::from(a.get("out").map_or(format!("{wal}.prov.jsonld"), str::to_string));
    let refuse = |error: &str| -> ! {
        println!("{}", json!({"status": "REFUSED", "out": out.display().to_string(), "wal": wal, "error": error}));
        std::process::exit(1)
    };
    // a path that names the journal would put the export over it (`audit-proof --out` once wrote a quittance over its journal)
    if same_file(&out, Path::new(&wal)) {
        refuse("the export would be written over its own journal: give --out another path");
    }
    let upto = a.get("upto").map(|n| n.parse::<usize>().unwrap_or_else(|_| fail("--upto is a number of frames, the genesis included")));
    super::audit_mcp::refuse_locked_whole(&wal);
    let export = match prov::export_at(Path::new(&wal), upto) {
        Ok(export) => export,
        Err(e) => {
            println!("{}", json!({"status": "REFUSED", "wal": wal, "error": e.to_json()}));
            std::process::exit(1);
        }
    };
    if let Err(e) = write_beside(&out, &export.text()) {
        refuse(&format!("cannot write the export: {e}"));
    }
    let mut summary = json!({"status": "EXPORTED", "format": prov::FORMAT, "out": out.display().to_string(), "wal": wal, "run_id": export.run_id,
        "frames": export.frames, "wal_head": to_hex(&export.wal_head), "nodes": export.nodes, "content_hash": to_hex(&export.content_hash)});
    if export.live {
        summary["live"] = super::audit_mcp::live_read(export.frames, None);
    }
    println!("{summary}");
}

/// Writes `text` to a file of its own beside `out`, then moves it over `out`: a reader never finds half a file. The file beside is
/// created new, under a name no file has: an existing file is never opened, so a name that is another link to the journal, or a
/// file someone keeps, is never written (Codex review of 32aff362, PROV-01: `<out>.partial`, a hard link to the journal, was
/// truncated and the journal lost). On a failure only the file this call created is removed. A move over `out` replaces the name
/// `out`, never the bytes of a file another name holds.
fn write_beside(out: &Path, text: &str) -> std::io::Result<()> {
    use std::io::Write;
    let folder = out.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let name = out.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "export".to_string());
    for attempt in 0..1000u32 {
        let partial = folder.join(format!(".{name}.{}-{attempt}.partial", std::process::id()));
        let mut file = match std::fs::OpenOptions::new().write(true).create_new(true).open(&partial) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        };
        let written = file.write_all(text.as_bytes()).and_then(|()| file.sync_all());
        drop(file);
        let moved = written.and_then(|()| std::fs::rename(&partial, out));
        if moved.is_err() {
            let _ = std::fs::remove_file(&partial);
        }
        return moved;
    }
    Err(std::io::Error::new(std::io::ErrorKind::AlreadyExists, "no free name for the file written beside the export"))
}
