//! The coverage table of a recorded run held against the report of its gap pass, offline ($0, no model). The journal is read and
//! never written: it is checked as `sbgk audit-verify` checks it, the coverage table is drawn from its last state
//! (`directives::coverage`, from the journal alone), and a dispatcher with the settings the journal pins is recovered on that state
//! and gives the report of the pass as a live server would (`Dispatcher::gap_pass_report`). Every number of the report is a count
//! of rows of the table; the check prints both and exits 1 where they differ.
//!
//!     cargo run --release -p sbgk-core --example coverage_check -- <run.wal> [<run.wal> ...]
use sbgk_core::audit::directives::{by_status, coverage, DispatchConfig, Dispatcher, GapProfile};
use sbgk_core::audit::state::AuditState;
use serde_json::{json, Value};
use std::path::Path;

fn check(path: &Path) -> Value {
    let (state, read) = AuditState::verify_states(path, &mut |_, _, _| {}).unwrap_or_else(|e| panic!("{}: {}", path.display(), e.to_json()));
    let table = coverage(&state);
    let pinned = state.checkpoint("audit:mcp:coverage").unwrap_or(Value::Null);
    let context = &pinned["context"];
    let mut out = json!({"wal": path.display().to_string(), "wal_bytes": read.bytes, "available": table.unavailable.is_none(),
                         "gap_pass": table.gap_pass, "units": table.units.len(), "packs": table.packs.len(), "by_status": by_status(&table.units)});
    if let Some(reason) = &table.unavailable {
        out["reason"] = json!(reason);
        out["same"] = json!(true);
        return out;
    }
    // the dispatcher of the run: the section size, the gap pass and the bound of attempts its journal pins
    let gap = if context["gap_pass"].is_null() { GapProfile::default() } else { GapProfile::from_json(&context["gap_pass"]).expect("the pinned gap pass") };
    let config = DispatchConfig {
        section_bytes: context["section_bytes"].as_u64().expect("the pinned section size") as usize,
        gap,
        agent_attempts: context["agent_attempts"].as_u64().map(|n| n as u32),
        ..Default::default()
    };
    let mut dispatcher = Dispatcher::new(config, Vec::new());
    dispatcher.recover(&state);
    let report = dispatcher.gap_pass_report(&state);
    // without a pass the table gives the units read, quoted and left, and the dispatcher counts the same three
    let same = if table.gap_pass.is_some() {
        table.summary == report
    } else {
        ["units_read", "units_quoted", "gap_units"].iter().all(|k| table.summary[*k] == report[*k])
    };
    // and the counts by status add up to the units read
    let counts = by_status(&table.units);
    let read_units: usize = counts.iter().filter(|(status, _)| status.as_str() != "unread").map(|(_, n)| n).sum();
    out["table"] = table.summary;
    out["report"] = report.clone();
    out["same"] = json!(same && json!(read_units) == report["units_read"]);
    out
}

fn main() {
    let mut differ = false;
    for path in std::env::args().skip(1) {
        let out = check(Path::new(&path));
        differ |= out["same"] != true;
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
    }
    if differ {
        std::process::exit(1);
    }
}
