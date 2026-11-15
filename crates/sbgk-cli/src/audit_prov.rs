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
    // written beside it first, then moved over it: a reader never finds half a file
    let partial = PathBuf::from(format!("{}.partial", out.display()));
    if same_file(&partial, Path::new(&wal)) {
        refuse("the export's partial file would be written over the journal: give --out another path");
    }
    if let Err(e) = std::fs::write(&partial, export.text()).and_then(|_| std::fs::rename(&partial, &out)) {
        let _ = std::fs::remove_file(&partial);
        refuse(&format!("cannot write the export: {e}"));
    }
    let mut summary = json!({"status": "EXPORTED", "format": prov::FORMAT, "out": out.display().to_string(), "wal": wal, "run_id": export.run_id,
        "frames": export.frames, "wal_head": to_hex(&export.wal_head), "nodes": export.nodes, "content_hash": to_hex(&export.content_hash)});
    if export.live {
        summary["live"] = super::audit_mcp::live_read(export.frames, None);
    }
    println!("{summary}");
}
