//! A mistyped flag is refused before the command runs: it must not switch a check or a limit off in silence.

use std::process::Command;

fn run(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_sbgk")).args(args).output().unwrap();
    (out.status.code().unwrap(), String::from_utf8_lossy(&out.stdout).into_owned(), String::from_utf8_lossy(&out.stderr).into_owned())
}

#[test]
fn a_mistyped_flag_is_refused_and_named() {
    for (args, flag) in [
        (&["audit-verify", "--wal", "x.wal", "--expct", "r.json"][..], "--expct"),
        (&["mcp-bridge", "--connect", "127.0.0.1:1", "--agent-id", "owner", "--allow-tool", "audit_status"][..], "--allow-tool"),
        (&["audit-serve", "--wal", "x.wal", "--build-scop", "full"][..], "--build-scop"),
        (&["verify", "x.sbgk", "--strict", "yes"][..], "--strict"),
        (&["root", "x.sbgk", "--foo", "bar"][..], "--foo"),
    ] {
        let (code, stdout, stderr) = run(args);
        assert_eq!(code, 2, "{args:?}: {stdout} {stderr}");
        assert!(stderr.contains(flag) && stdout.is_empty(), "{args:?}: {stderr}");
    }
}

#[test]
fn a_flag_with_one_dash_a_long_dash_or_no_dash_is_refused_too() {
    for (args, stray) in [
        (&["audit-verify", "--wal", "x.wal", "-expect", "r.json"][..], "-expect"),
        (&["audit-verify", "--wal", "x.wal", "r.json"][..], "r.json"),
        (&["audit-verify", "--wal", "x.wal", "\u{2014}expect", "r.json"][..], "expect"),
        (&["mcp-bridge", "--connect", "127.0.0.1:1", "--agent-id", "owner", "-allow-tools", "audit_status"][..], "-allow-tools"),
        (&["audit-serve", "--wal", "x.wal", "--allow-remote", "false"][..], "false"),
        (&["verify", "a.sbgk", "b.sbgk"][..], "b.sbgk"),
    ] {
        let (code, stdout, stderr) = run(args);
        assert_eq!(code, 2, "{args:?}: {stdout} {stderr}");
        assert!(stderr.contains(stray) && stdout.is_empty(), "{args:?}: {stderr}");
    }
}

#[test]
fn a_switch_of_another_command_is_refused_too() {
    let (code, _, stderr) = run(&["verify", "x.sbgk", "--allow-remote"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("--allow-remote"), "{stderr}");
}

#[test]
fn help_and_version_still_work() {
    assert_eq!(run(&["--help"]).0, 0);
    assert_eq!(run(&["verify", "--help"]).0, 0);
    assert_eq!(run(&["--version"]).0, 0);
}
