//! Offline only: invoke on a dedicated closed WAL copy, never a running journal.
#[cfg(feature = "audit-root-profile")]
fn main() {
    use sbgk_core::{
        audit::{state::AuditState, AuditStore},
        hash::{sha256, to_hex},
    };
    let args = std::env::args().collect::<Vec<_>>();
    assert!(args.len() == 3 && matches!(args[1].as_str(), "legacy" | "cached"), "legacy|cached CLOSED_COPY.wal");
    let path = std::path::Path::new(&args[2]);
    let before = std::fs::read(path).unwrap();
    AuditState::root_profile_begin(args[1] == "legacy");
    let start = std::time::Instant::now();
    let state = AuditState::open(path).unwrap();
    let wall = start.elapsed();
    let (calls, ns) = AuditState::root_profile_snapshot();
    let transactions = state.transaction_sequence().unwrap();
    let root = to_hex(&state.audit_root());
    let engine = to_hex(&state.engine_root());
    let head = state.head();
    drop(state);
    assert_eq!(before, std::fs::read(path).unwrap(), "closed archive changed");
    println!(
        "{}",
        serde_json::json!({"mode":args[1],"path":args[2],"bytes":before.len(),"sha256":to_hex(&sha256(&before)),"transactions":transactions,"records":head,"root_calls":calls,"root_ns":ns,"root_ns_per_transaction":ns as f64/transactions as f64,"open_wall_ns":wall.as_nanos(),"audit_root":root,"engine_root":engine,"verify_feature":cfg!(feature="audit-root-verify")})
    );
}
#[cfg(not(feature = "audit-root-profile"))]
fn main() {
    eprintln!("requires --features audit-root-profile; closed copies only");
    std::process::exit(2);
}
