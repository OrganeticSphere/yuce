//! The command line explains itself: `--help` (also after a command), `--version`, and the usage on an empty call.

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_sbgk");
const YUCE: &str = env!("CARGO_BIN_EXE_yuce");

fn run(bin: &str, args: &[&str]) -> (i32, String, String) {
    let out = Command::new(bin).args(args).output().expect("the binary starts");
    (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stdout).into_owned(), String::from_utf8_lossy(&out.stderr).into_owned())
}

#[test]
fn help_is_printed_on_stdout_with_exit_zero_also_after_a_command() {
    for args in [&["--help"][..], &["-h"], &["help"], &["audit-serve", "--help"], &["apply", "--stream", "x.jsonl", "-h"]] {
        let (code, out, err) = run(BIN, args);
        assert_eq!(code, 0, "{args:?}: {err}");
        assert!(out.starts_with("usage: sbgk (or yuce) <command>"), "{args:?}: {out}");
        for command in ["audit-serve", "mcp-bridge", "audit-verify", "apply", "verify", "--profile custom"] {
            assert!(out.contains(command), "{args:?} lacks {command}");
        }
    }
    let (code, out, _) = run(YUCE, &["--help"]);
    assert_eq!(code, 0);
    assert!(out.starts_with("usage: sbgk (or yuce)"));
}

#[test]
fn an_empty_call_prints_the_usage_on_stderr_and_fails() {
    let (code, out, err) = run(BIN, &[]);
    assert_eq!(code, 2);
    assert!(out.is_empty());
    assert!(err.starts_with("usage: sbgk"), "{err}");
}

#[test]
fn version_names_the_package_version() {
    for flag in ["--version", "-V"] {
        let (code, out, _) = run(BIN, &[flag]);
        assert_eq!(code, 0);
        assert_eq!(out.trim(), format!("sbgk {}", env!("CARGO_PKG_VERSION")));
    }
}

#[test]
fn an_unknown_command_points_to_the_help() {
    let (code, _, err) = run(BIN, &["no-such-command"]);
    assert_eq!(code, 2);
    assert!(err.contains("unknown command 'no-such-command'") && err.contains("sbgk --help"), "{err}");
}
