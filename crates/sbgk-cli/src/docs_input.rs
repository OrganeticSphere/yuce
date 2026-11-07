//! The text files of a folder as the sources of a run (`sbgk audit-serve --docs`).
//!
//! A document's name is its path inside the folder, with `/` on every system, so nothing of the machine reaches the journal. What
//! a journal takes it keeps for good and hands to whoever checks it, so a walk leaves out what nobody meant to give: hidden files
//! such as `.env`, service folders, links, the server's own files. A file that is no text stops the start, by name: leaving
//! it out quietly would look like a reviewed folder with a contract missing. `--select` names the files instead of walking.

use sbgk_core::audit::state::MAX_DOC_BYTES;
use std::path::{Component, Path, PathBuf};

const SERVICE_FOLDERS: [&str; 3] = ["__pycache__", "node_modules", "target"];

pub struct Taken {
    /// Sorted by name.
    pub docs: Vec<(String, Vec<u8>)>,
    /// What was left out, with the reason.
    pub skipped: Vec<(String, &'static str)>,
}

fn hidden(name: &str, meta: &std::fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_HIDDEN: u32 = 2;
        if meta.file_attributes() & FILE_ATTRIBUTE_HIDDEN != 0 {
            return true;
        }
    }
    #[cfg(not(windows))]
    let _ = meta;
    name.starts_with('.')
}

fn walk(dir: &Path, prefix: &str, own: &[PathBuf], files: &mut Vec<(String, PathBuf)>, skipped: &mut Vec<(String, &'static str)>) -> Result<(), String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
        let path = entry.path();
        let name = entry.file_name().into_string().map_err(|n| format!("a name in {} is not UTF-8: {n:?}", dir.display()))?;
        let id = format!("{prefix}{name}");
        let meta = std::fs::symlink_metadata(&path).map_err(|e| format!("cannot read {id}: {e}"))?;
        if meta.file_type().is_symlink() {
            skipped.push((id, "a link: links are not followed"));
        } else if hidden(&name, &meta) {
            skipped.push((id, "hidden"));
        } else if meta.is_dir() {
            if SERVICE_FOLDERS.contains(&name.as_str()) {
                skipped.push((id, "a service folder"));
            } else {
                walk(&path, &format!("{id}/"), own, files, skipped)?;
            }
        } else if !meta.is_file() {
            skipped.push((id, "not a regular file"));
        } else if std::fs::canonicalize(&path).is_ok_and(|p| own.contains(&p)) {
            skipped.push((id, "a file of this server's own command"));
        } else {
            files.push((id, path));
        }
    }
    Ok(())
}

/// The files of a `--select` list: one path inside the folder per line, as in a repository's list, `#` for a comment.
fn named(folder: &Path, list: &str, files: &mut Vec<(String, PathBuf)>) -> Result<(), String> {
    for line in list.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let mut parts = Vec::new();
        let plain = line.replace('\\', "/");
        for part in Path::new(&plain).components() {
            match part {
                Component::Normal(p) => parts.push(p.to_str().ok_or_else(|| format!("--select: {line} is not UTF-8"))?),
                Component::CurDir => {}
                _ => return Err(format!("--select: {line} is not a path inside the folder")),
            }
        }
        if parts.is_empty() {
            return Err(format!("--select: {line} names no file"));
        }
        let id = parts.join("/");
        let path = folder.join(&id);
        files.push((id, path));
    }
    Ok(())
}

/// The documents of a run on `folder`. `own` holds the canonical paths of the server's own files, which a walk leaves out.
pub fn collect(folder: &Path, select: Option<&str>, own: &[PathBuf]) -> Result<Taken, String> {
    if !folder.is_dir() {
        return Err(format!("--docs: {} is not a folder", folder.display()));
    }
    let (mut files, mut skipped) = (Vec::new(), Vec::new());
    match select {
        Some(list) => named(folder, list, &mut files)?,
        None => walk(folder, "", own, &mut files, &mut skipped)?,
    }
    files.sort();
    if let Some(twice) = files.windows(2).find(|w| w[0].0 == w[1].0) {
        return Err(format!("--select names {} twice", twice[0].0));
    }
    let (mut docs, mut refused) = (Vec::new(), Vec::new());
    for (id, path) in files {
        let size = std::fs::metadata(&path).map_err(|e| format!("cannot read {id}: {e}"))?.len();
        if size > MAX_DOC_BYTES as u64 {
            refused.push(format!("{id} (larger than 16 MiB)"));
            continue;
        }
        let bytes = std::fs::read(&path).map_err(|e| format!("cannot read {id}: {e}"))?;
        if bytes.is_empty() {
            skipped.push((id, "empty"));
        } else if bytes.contains(&0) || std::str::from_utf8(&bytes).is_err() {
            refused.push(format!("{id} (not UTF-8 text)"));
        } else {
            docs.push((id, bytes));
        }
    }
    if !refused.is_empty() {
        return Err(format!(
            "--docs takes UTF-8 text files, and these are not: {}. Convert PDF and Word files to text first, or name the files to take with --select",
            refused.join(", ")
        ));
    }
    if docs.is_empty() {
        return Err(format!("--docs: no text file to take in {}", folder.display()));
    }
    skipped.sort();
    Ok(Taken { docs, skipped })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Folder(PathBuf);

    impl Folder {
        fn new(tag: &str, files: &[(&str, &[u8])]) -> Folder {
            let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
            let root = std::env::temp_dir().join(format!("sbgk_docs_{tag}_{}_{nonce}", std::process::id()));
            for (name, bytes) in files {
                let path = root.join(name);
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(path, bytes).unwrap();
            }
            Folder(root)
        }
    }

    impl Drop for Folder {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn ids(t: &Taken) -> Vec<&str> {
        t.docs.iter().map(|(id, _)| id.as_str()).collect()
    }

    #[test]
    fn a_walk_names_files_by_their_path_and_leaves_out_what_nobody_meant_to_give() {
        let f = Folder::new(
            "walk",
            &[
                ("b.txt", b"two\n"),
                ("sub/a.md", b"# one\n"),
                ("sub/deep/c.py", b"# three\n"),
                (".env", b"KEY=secret\n"),
                (".git/config", b"x\n"),
                ("node_modules/m/index.js", b"x\n"),
                ("target/out.txt", b"x\n"),
                ("sub/__pycache__/c.txt", b"x\n"),
                ("sub/empty.txt", b""),
            ],
        );
        let t = collect(&f.0, None, &[]).unwrap();
        assert_eq!(ids(&t), ["b.txt", "sub/a.md", "sub/deep/c.py"]);
        let left: Vec<&str> = t.skipped.iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(left, [".env", ".git", "node_modules", "sub/__pycache__", "sub/empty.txt", "target"]);
        assert!(t.skipped.iter().all(|(_, why)| !why.is_empty()));
    }

    #[test]
    fn the_servers_own_files_are_no_sources() {
        let f = Folder::new("own", &[("a.txt", b"one\n"), ("subjects.json", b"{\"token\":\"t\"}\n")]);
        let own = vec![std::fs::canonicalize(f.0.join("subjects.json")).unwrap()];
        let t = collect(&f.0, None, &own).unwrap();
        assert_eq!(ids(&t), ["a.txt"]);
        assert_eq!(t.skipped[0].0, "subjects.json");
    }

    #[test]
    fn a_file_that_is_no_text_stops_the_start_and_every_one_is_named() {
        let f = Folder::new("binary", &[("a.txt", b"one\n"), ("b.pdf", b"%PDF\x00\x01"), ("c.txt", b"\xcf\xf0\xe8\xe2\xe5\xf2\n")]);
        let error = collect(&f.0, None, &[]).err().unwrap();
        assert!(error.contains("b.pdf") && error.contains("c.txt") && !error.contains("a.txt"), "{error}");
        assert!(error.contains("--select"), "{error}");
    }

    #[test]
    fn a_list_names_files_beside_ones_that_are_no_text() {
        let f = Folder::new("list", &[("a.txt", b"one\n"), ("sub/b.txt", b"two\n"), ("c.pdf", b"%PDF\x00"), (".notes", b"named on purpose\n")]);
        let t = collect(&f.0, Some("# the two that count\na.txt\n./sub/b.txt\n.notes\n"), &[]).unwrap();
        assert_eq!(ids(&t), [".notes", "a.txt", "sub/b.txt"]);
    }

    #[test]
    fn a_list_stays_inside_the_folder_and_names_a_file_once() {
        let f = Folder::new("outside", &[("a.txt", b"one\n")]);
        for list in ["../a.txt\n", "sub/../../a.txt\n", "/etc/hosts\n"] {
            assert!(collect(&f.0, Some(list), &[]).err().unwrap().contains("inside the folder"), "{list}");
        }
        assert!(collect(&f.0, Some("a.txt\n./a.txt\n"), &[]).err().unwrap().contains("twice"));
    }

    #[test]
    fn nothing_to_take_is_said() {
        let f = Folder::new("nothing", &[(".env", b"KEY=secret\n"), ("empty.txt", b"")]);
        assert!(collect(&f.0, None, &[]).err().unwrap().contains("no text file"));
        assert!(collect(&f.0.join("absent"), None, &[]).err().unwrap().contains("not a folder"));
    }

    #[cfg(unix)]
    #[test]
    fn a_link_is_not_followed() {
        let outside = Folder::new("outside_link", &[("secret.txt", b"not yours\n")]);
        let f = Folder::new("link", &[("a.txt", b"one\n")]);
        std::os::unix::fs::symlink(outside.0.join("secret.txt"), f.0.join("b.txt")).unwrap();
        let t = collect(&f.0, None, &[]).unwrap();
        assert_eq!(ids(&t), ["a.txt"]);
        assert_eq!(t.skipped[0].0, "b.txt");
    }
}
