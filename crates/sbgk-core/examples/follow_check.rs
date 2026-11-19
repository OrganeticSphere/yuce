//! Reads journals two ways and compares them at every frame: whole, as `sbgk audit-verify` reads a journal, and in steps, as
//! `sbgk audit-watch` follows one (`audit::follow`). At each frame both must reach the same audit root, engine root, session root
//! and frame hash, and at the end the same provenance export, byte for byte.
//!
//!   cargo run --release -p sbgk-core --example follow_check -- <run.wal> [<run.wal> ...] [--step <frames>]
//!
//! `--step` is how many frames a step of the follower takes (default 7). Exit 0 when every journal agrees, 1 otherwise.

use sbgk_core::audit::follow::Follower;
use sbgk_core::audit::prov::{self, Tracker};
use sbgk_core::audit::state::AuditState;
use sbgk_core::hash::Hash;
use std::path::Path;
use std::time::Instant;

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut step = 7usize;
    if let Some(i) = args.iter().position(|a| a == "--step") {
        step = args.get(i + 1).and_then(|n| n.parse().ok()).filter(|n| *n > 0).expect("--step <frames>");
        args.drain(i..=i + 1);
    }
    if args.is_empty() {
        eprintln!("usage: follow_check <run.wal> [<run.wal> ...] [--step <frames>]");
        std::process::exit(2);
    }
    let mut failed = false;
    for wal in &args {
        match check(Path::new(wal), step) {
            Ok(line) => println!("OK      {wal}: {line}"),
            Err(why) => {
                failed = true;
                println!("DIFFERS {wal}: {why}");
            }
        }
    }
    std::process::exit(i32::from(failed));
}

fn check(wal: &Path, step: usize) -> Result<String, String> {
    // whole: the roots after each frame
    let started = Instant::now();
    let mut whole: Vec<(Hash, Hash, Hash)> = Vec::new();
    let mut sessions: Vec<Hash> = Vec::new();
    AuditState::verify_states(wal, &mut |_, state, head| {
        whole.push((state.audit_root(), state.engine_root(), head));
        sessions.push(state.session_root());
    })
    .map_err(|e| format!("read whole: {}", e.message))?;
    let whole_time = started.elapsed();

    // in steps of `step` frames
    let started = Instant::now();
    let mut follower = Follower::new(wal);
    let mut tracker = Tracker::new();
    let mut differ = None;
    let mut steps = 0;
    loop {
        let mut taken = 0;
        let tail = follower
            .advance(&mut |f| {
                let n = f.number;
                let here = (f.state.audit_root(), f.state.engine_root(), f.head);
                if differ.is_none() && (whole.get(n) != Some(&here) || sessions.get(n) != Some(&f.state.session_root())) {
                    differ = Some(n);
                }
                tracker.frame(f.state, f.payload, f.head);
                taken += 1;
                taken < step
            })
            .map_err(|e| format!("read in steps: {e:?}"))?;
        steps += 1;
        if !tail.more {
            break;
        }
    }
    let stepped_time = started.elapsed();
    if let Some(n) = differ {
        return Err(format!("the roots differ at frame {n}"));
    }
    if follower.frames() != whole.len() {
        return Err(format!("{} frames whole, {} in steps", whole.len(), follower.frames()));
    }
    let stepped = tracker.document(follower.state().ok_or("no state")?, false).map_err(|e| e.message)?;
    let export = prov::export(wal).map_err(|e| e.message)?;
    if stepped.text() != export.text() {
        return Err("the provenance exports differ".to_string());
    }
    Ok(format!(
        "{} frames, the same roots at every frame and the same export ({} bytes); whole {:.2} s, in {steps} steps {:.2} s",
        whole.len(),
        export.text().len(),
        whole_time.as_secs_f64(),
        stepped_time.as_secs_f64()
    ))
}
