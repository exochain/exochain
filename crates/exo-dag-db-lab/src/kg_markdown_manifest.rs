use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    ffi::{OsStr, OsString},
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::{
    ambient_authority,
    fs::{Dir, OpenOptions},
};
use same_file::Handle;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MANIFEST_SCHEMA_VERSION: &str = "dagdb_markdown_kg_manifest_v1";
pub const MAX_MANIFEST_DEPTH: usize = 64;
pub const MAX_MANIFEST_FILES: usize = 4_096;
/// All child entries inspected, including directories and ignored files.
pub const MAX_MANIFEST_ENTRIES: usize = MAX_MANIFEST_FILES * 2;
/// Shared aggregate ceiling for each variable-count semantic collection.
///
/// Each of headings, frontmatter entries, and wikilinks may retain at most
/// sixteen items per maximum-sized manifest file across the whole manifest.
/// This keeps all three collections finite before allocation while preserving
/// the existing wikilink edge budget in full.
pub const MAX_MANIFEST_SEMANTIC_ITEMS: usize = MAX_MANIFEST_FILES * 16;
/// The importer emits one candidate edge for every manifest wikilink.
pub const MAX_MANIFEST_WIKILINKS: usize = MAX_MANIFEST_SEMANTIC_ITEMS;
pub const MAX_MANIFEST_HEADINGS: usize = MAX_MANIFEST_SEMANTIC_ITEMS;
pub const MAX_MANIFEST_FRONTMATTER_ENTRIES: usize = MAX_MANIFEST_SEMANTIC_ITEMS;
pub const MAX_MARKDOWN_FILE_BYTES: usize = 4_194_304;
pub const MAX_MARKDOWN_TOTAL_BYTES: usize = 67_108_864;
pub const MAX_JSON_FILE_BYTES: usize = 16_777_216;
const BOUNDED_JSON_GROWTH_FLOOR: usize = 65_536;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Manifest {
    pub schema_version: String,
    pub graph_root: String,
    pub file_count: usize,
    pub files: Vec<ManifestFile>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ManifestFile {
    pub path: String,
    pub sha256: String,
    pub byte_length: usize,
    pub frontmatter: BTreeMap<String, String>,
    pub title: String,
    pub headings: Vec<Heading>,
    pub wikilinks: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Heading {
    pub level: usize,
    pub text: String,
}

struct BoundedJsonOutput {
    bytes: Vec<u8>,
    max_bytes: usize,
    label: String,
}

impl BoundedJsonOutput {
    fn new(max_bytes: usize, label: &str) -> Self {
        Self {
            bytes: Vec::new(),
            max_bytes,
            label: label.to_owned(),
        }
    }

    fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl Write for BoundedJsonOutput {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let next_len = self
            .bytes
            .len()
            .checked_add(buffer.len())
            .ok_or_else(|| io::Error::other(format!("{} size overflow", self.label)))?;
        if next_len > self.max_bytes {
            return Err(io::Error::other(format!(
                "{} exceeds {} bytes",
                self.label, self.max_bytes
            )));
        }
        if next_len > self.bytes.capacity() {
            let doubled = self
                .bytes
                .capacity()
                .checked_mul(2)
                .unwrap_or(self.max_bytes);
            let target_capacity = doubled
                .max(BOUNDED_JSON_GROWTH_FLOOR)
                .max(next_len)
                .min(self.max_bytes);
            self.bytes
                .try_reserve_exact(target_capacity - self.bytes.len())
                .map_err(|error| {
                    io::Error::other(format!("reserve {} output: {error}", self.label))
                })?;
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Serialize pretty JSON plus its trailing newline without ever growing the
/// output buffer beyond `max_bytes`.
pub fn serialize_pretty_json_bounded<T: Serialize>(
    value: &T,
    max_bytes: usize,
    label: &str,
) -> Result<Vec<u8>, String> {
    let mut output = BoundedJsonOutput::new(max_bytes, label);
    serde_json::to_writer_pretty(&mut output, value)
        .map_err(|error| format!("serialize {label}: {error}"))?;
    output
        .write_all(b"\n")
        .map_err(|error| format!("serialize {label}: {error}"))?;
    Ok(output.into_bytes())
}

#[derive(Debug)]
struct ManifestDirectory {
    capability: Dir,
    relative_path: PathBuf,
}

#[derive(Default)]
struct ManifestBuildBudget {
    entry_count: usize,
    total_bytes: usize,
    total_wikilinks: usize,
    total_headings: usize,
    total_frontmatter_entries: usize,
}

fn open_root_directory_capability(root: &Path) -> Result<(ManifestDirectory, PathBuf), String> {
    open_root_directory_capability_with(root, |path| fs::canonicalize(path))
}

fn open_root_directory_capability_with<F>(
    root: &Path,
    resolve: F,
) -> Result<(ManifestDirectory, PathBuf), String>
where
    F: FnOnce(&Path) -> std::io::Result<PathBuf>,
{
    let root_metadata = match fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(format!("graph root does not exist: {}", root.display()));
        }
        Err(error) => return Err(format!("inspect graph root: {error}")),
    };
    if root_metadata.file_type().is_symlink() {
        return Err(format!("graph root symlink rejected: {}", root.display()));
    }
    if !root_metadata.is_dir() {
        return Err(format!("graph root is not a directory: {}", root.display()));
    }

    let expected = Handle::from_path(root)
        .map_err(|error| format!("inspect graph root {}: {error}", root.display()))?;
    let resolved =
        resolve(root).map_err(|error| format!("resolve graph root {}: {error}", root.display()))?;
    let mut anchor = PathBuf::new();
    let mut names = Vec::<OsString>::new();
    for component in resolved.components() {
        match component {
            std::path::Component::Prefix(prefix) => anchor.push(prefix.as_os_str()),
            std::path::Component::RootDir => anchor.push(component.as_os_str()),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if names.pop().is_none() {
                    return Err("graph root escapes its filesystem anchor".to_owned());
                }
            }
            std::path::Component::Normal(name) => names.push(name.to_owned()),
        }
    }
    if anchor.as_os_str().is_empty() {
        return Err("graph root has no filesystem anchor".to_owned());
    }

    let mut capability = Dir::open_ambient_dir(&anchor, ambient_authority())
        .map_err(|error| format!("open graph root anchor {}: {error}", anchor.display()))?;
    for name in names {
        capability = capability
            .open_dir_nofollow(&name)
            .map_err(|error| format!("open resolved graph root component {:?}: {error}", name))?;
    }
    if !capability
        .dir_metadata()
        .map_err(|error| format!("inspect opened graph root: {error}"))?
        .is_dir()
    {
        return Err(format!("graph root is not a directory: {}", root.display()));
    }

    let opened = Handle::from_file(
        capability
            .try_clone()
            .map_err(|error| format!("inspect opened graph root: {error}"))?
            .into_std_file(),
    )
    .map_err(|error| format!("inspect opened graph root: {error}"))?;
    let after_metadata = fs::symlink_metadata(root)
        .map_err(|error| format!("inspect graph root after open: {error}"))?;
    if after_metadata.file_type().is_symlink() || !after_metadata.is_dir() {
        return Err("graph root changed during capability open".to_owned());
    }
    let after = Handle::from_path(root)
        .map_err(|error| format!("inspect graph root after open: {error}"))?;
    if expected != opened || opened != after {
        return Err("graph root changed during capability open".to_owned());
    }

    Ok((
        ManifestDirectory {
            capability,
            relative_path: PathBuf::new(),
        },
        resolved,
    ))
}

fn open_child_directory_capability(
    parent: &ManifestDirectory,
    name: &OsStr,
    relative_path: PathBuf,
) -> Result<ManifestDirectory, String> {
    let capability = parent
        .capability
        .open_dir_nofollow(name)
        .map_err(|error| format!("open manifest directory {:?}: {error}", relative_path))?;
    if !capability
        .dir_metadata()
        .map_err(|error| format!("inspect manifest directory {:?}: {error}", relative_path))?
        .is_dir()
    {
        return Err(format!(
            "manifest entry is not a directory: {}",
            relative_path.display()
        ));
    }
    Ok(ManifestDirectory {
        capability,
        relative_path,
    })
}

pub fn build_manifest(root: &Path) -> Result<Manifest, String> {
    let (root_directory, canonical_root) = open_root_directory_capability(root)?;
    let mut visited = BTreeSet::new();
    let mut budget = ManifestBuildBudget::default();
    let mut files = Vec::new();
    collect_markdown_files(&root_directory, 0, &mut visited, &mut budget, &mut files)?;
    files.sort_by(|left, right| left.path.cmp(&right.path));

    Ok(Manifest {
        schema_version: MANIFEST_SCHEMA_VERSION.to_owned(),
        graph_root: display_root(&canonical_root),
        file_count: files.len(),
        files,
    })
}

fn collect_markdown_files(
    directory: &ManifestDirectory,
    depth: usize,
    visited: &mut BTreeSet<PathBuf>,
    budget: &mut ManifestBuildBudget,
    out: &mut Vec<ManifestFile>,
) -> Result<(), String> {
    if depth > MAX_MANIFEST_DEPTH {
        return Err(format!(
            "manifest directory depth exceeds {MAX_MANIFEST_DEPTH}"
        ));
    }
    if !visited.insert(directory.relative_path.clone()) {
        return Err(format!(
            "manifest directory cycle rejected: {}",
            directory.relative_path.display()
        ));
    }

    let opened_entries = directory
        .capability
        .entries()
        .map_err(|error| format!("read manifest directory: {error}"))?;
    let mut entries = Vec::new();
    for entry in opened_entries {
        let entry = entry.map_err(|error| format!("read directory entry: {error}"))?;
        budget.entry_count = budget
            .entry_count
            .checked_add(1)
            .ok_or_else(|| "manifest entry count overflow".to_owned())?;
        if budget.entry_count > MAX_MANIFEST_ENTRIES {
            return Err(format!(
                "manifest entry count exceeds {MAX_MANIFEST_ENTRIES}"
            ));
        }
        entries
            .try_reserve(1)
            .map_err(|error| format!("reserve manifest directory entries: {error}"))?;
        entries.push((entry.file_name(), entry));
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0));

    for (name, entry) in entries {
        let relative_path = directory.relative_path.join(&name);
        let file_type = entry
            .file_type()
            .map_err(|error| format!("inspect manifest entry: {error}"))?;
        if file_type.is_symlink() {
            return Err(format!(
                "manifest symlink rejected: {}",
                relative_path.display()
            ));
        }
        if file_type.is_dir() {
            let child = open_child_directory_capability(directory, &name, relative_path.clone())?;
            collect_markdown_files(
                &child,
                depth
                    .checked_add(1)
                    .ok_or_else(|| "manifest directory depth overflow".to_owned())?,
                visited,
                budget,
                out,
            )?;
        } else if file_type.is_file()
            && relative_path
                .extension()
                .and_then(|extension| extension.to_str())
                == Some("md")
        {
            if out.len() >= MAX_MANIFEST_FILES {
                return Err(format!("manifest file count exceeds {MAX_MANIFEST_FILES}"));
            }
            let mut options = OpenOptions::new();
            options.read(true).follow(FollowSymlinks::No);
            let file = directory
                .capability
                .open_with(&name, &options)
                .map_err(|error| format!("open markdown file {:?}: {error}", relative_path))?;
            let metadata = file
                .metadata()
                .map_err(|error| format!("inspect opened markdown file: {error}"))?;
            if !metadata.is_file() {
                return Err(format!(
                    "markdown path is not a regular file: {}",
                    relative_path.display()
                ));
            }
            if metadata.len()
                > u64::try_from(MAX_MARKDOWN_FILE_BYTES)
                    .map_err(|_| "markdown file limit invalid".to_owned())?
            {
                return Err(format!(
                    "markdown file size exceeds {MAX_MARKDOWN_FILE_BYTES} bytes"
                ));
            }
            let data = read_at_most(file, MAX_MARKDOWN_FILE_BYTES, "markdown file")?;
            budget.total_bytes = budget
                .total_bytes
                .checked_add(data.len())
                .ok_or_else(|| "markdown aggregate size overflow".to_owned())?;
            if budget.total_bytes > MAX_MARKDOWN_TOTAL_BYTES {
                return Err(format!(
                    "markdown aggregate exceeds {MAX_MARKDOWN_TOTAL_BYTES} bytes"
                ));
            }
            let text = String::from_utf8(data)
                .map_err(|error| format!("markdown file is not UTF-8: {error}"))?;
            let remaining_wikilinks = MAX_MANIFEST_WIKILINKS
                .checked_sub(budget.total_wikilinks)
                .ok_or_else(|| "manifest wikilink count overflow".to_owned())?;
            let wikilinks = extract_wikilinks(&text, remaining_wikilinks)?;
            budget.total_wikilinks = budget
                .total_wikilinks
                .checked_add(wikilinks.len())
                .ok_or_else(|| "manifest wikilink count overflow".to_owned())?;
            let remaining_headings = MAX_MANIFEST_HEADINGS
                .checked_sub(budget.total_headings)
                .ok_or_else(|| "manifest heading count overflow".to_owned())?;
            let headings = extract_headings(&text, remaining_headings)?;
            budget.total_headings = budget
                .total_headings
                .checked_add(headings.len())
                .ok_or_else(|| "manifest heading count overflow".to_owned())?;
            let remaining_frontmatter_entries = MAX_MANIFEST_FRONTMATTER_ENTRIES
                .checked_sub(budget.total_frontmatter_entries)
                .ok_or_else(|| "manifest frontmatter entry count overflow".to_owned())?;
            let frontmatter = parse_frontmatter(&text, remaining_frontmatter_entries)?;
            budget.total_frontmatter_entries = budget
                .total_frontmatter_entries
                .checked_add(frontmatter.len())
                .ok_or_else(|| "manifest frontmatter entry count overflow".to_owned())?;
            let path = relative_path
                .to_str()
                .ok_or_else(|| "manifest path is not valid UTF-8".to_owned())?
                .replace('\\', "/");
            out.try_reserve(1)
                .map_err(|error| format!("reserve manifest files: {error}"))?;
            out.push(ManifestFile {
                path,
                sha256: sha256_hex(text.as_bytes()),
                byte_length: text.len(),
                frontmatter,
                title: headings
                    .first()
                    .map(|heading| heading.text.clone())
                    .unwrap_or_default(),
                headings,
                wikilinks,
            });
        }
    }
    Ok(())
}

pub fn read_bounded_file(path: &Path, max_bytes: usize, label: &str) -> Result<Vec<u8>, String> {
    read_bounded_file_with_open(path, max_bytes, label, |opened_path| {
        fs::File::open(opened_path)
    })
}

fn inspect_bounded_path(
    path: &Path,
    max_bytes: usize,
    label: &str,
) -> Result<fs::Metadata, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| format!("read {label}: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!("{label} must be a regular non-symlink file"));
    }
    if metadata.len() > u64::try_from(max_bytes).map_err(|_| format!("{label} limit invalid"))? {
        return Err(format!("{label} file size exceeds {max_bytes} bytes"));
    }
    Ok(metadata)
}

fn read_bounded_file_with_open<F>(
    path: &Path,
    max_bytes: usize,
    label: &str,
    open: F,
) -> Result<Vec<u8>, String>
where
    F: FnOnce(&Path) -> std::io::Result<fs::File>,
{
    inspect_bounded_path(path, max_bytes, label)?;
    let before = Handle::from_path(path).map_err(|error| format!("read {label}: {error}"))?;
    inspect_bounded_path(path, max_bytes, label)?;

    let file = open(path).map_err(|error| format!("read {label}: {error}"))?;
    let opened_metadata = file
        .metadata()
        .map_err(|error| format!("inspect opened {label}: {error}"))?;
    if !opened_metadata.is_file()
        || opened_metadata.len()
            > u64::try_from(max_bytes).map_err(|_| format!("{label} limit invalid"))?
    {
        return Err(format!("opened {label} is not a bounded regular file"));
    }
    let opened = Handle::from_file(
        file.try_clone()
            .map_err(|error| format!("inspect opened {label}: {error}"))?,
    )
    .map_err(|error| format!("inspect opened {label}: {error}"))?;

    inspect_bounded_path(path, max_bytes, label)?;
    let after = Handle::from_path(path).map_err(|error| format!("read {label}: {error}"))?;
    if before != opened || opened != after {
        return Err(format!("{label} changed during open"));
    }
    read_at_most(file, max_bytes, label)
}

fn read_at_most(reader: impl Read, max_bytes: usize, label: &str) -> Result<Vec<u8>, String> {
    let authoritative_limit = max_bytes
        .checked_add(1)
        .ok_or_else(|| format!("{label} limit overflow"))?;
    let mut bounded = reader
        .take(u64::try_from(authoritative_limit).map_err(|_| format!("{label} limit invalid"))?);
    let mut bytes = Vec::new();
    bounded
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read {label}: {error}"))?;
    if bytes.len() > max_bytes {
        return Err(format!("{label} exceeds {max_bytes} bytes"));
    }
    Ok(bytes)
}

#[cfg(test)]
fn repo_relative_to(path: &Path, root: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn display_root(root: &Path) -> String {
    let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    match root.strip_prefix(cwd.canonicalize().unwrap_or(cwd)) {
        Ok(relative) => relative.to_string_lossy().replace('\\', "/"),
        Err(_) => root.to_string_lossy().replace('\\', "/"),
    }
}

fn parse_frontmatter(
    text: &str,
    max_unique_entries: usize,
) -> Result<BTreeMap<String, String>, String> {
    let mut frontmatter = BTreeMap::new();
    let Some(rest) = text.strip_prefix("---\n") else {
        return Ok(frontmatter);
    };
    let Some(end) = rest.find("\n---\n") else {
        return Ok(frontmatter);
    };
    for raw_line in rest[..end].lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || !line.contains(':') {
            continue;
        }
        let mut parts = line.splitn(2, ':');
        let key = parts.next().unwrap_or_default().trim();
        let value = parts
            .next()
            .unwrap_or_default()
            .trim()
            .trim_matches('"')
            .trim_matches('\'');
        if !key.is_empty() {
            if !frontmatter.contains_key(key) && frontmatter.len() >= max_unique_entries {
                return Err(format!(
                    "manifest frontmatter entry count exceeds {MAX_MANIFEST_FRONTMATTER_ENTRIES}"
                ));
            }
            frontmatter.insert(key.to_owned(), value.to_owned());
        }
    }
    Ok(frontmatter)
}

fn extract_headings(text: &str, max_headings: usize) -> Result<Vec<Heading>, String> {
    let mut headings = Vec::new();
    for line in text.lines() {
        let hashes = line.chars().take_while(|ch| *ch == '#').count();
        if !(1..=6).contains(&hashes) {
            continue;
        }
        let rest = &line[hashes..];
        if !rest.starts_with(char::is_whitespace) {
            continue;
        }
        let title = rest.trim();
        if !title.is_empty() {
            if headings.len() >= max_headings {
                return Err(format!(
                    "manifest heading count exceeds {MAX_MANIFEST_HEADINGS}"
                ));
            }
            headings
                .try_reserve(1)
                .map_err(|error| format!("reserve manifest headings: {error}"))?;
            headings.push(Heading {
                level: hashes,
                text: title.to_owned(),
            });
        }
    }
    Ok(headings)
}

fn extract_wikilinks(text: &str, max_unique: usize) -> Result<Vec<String>, String> {
    let text = strip_inline_code(&strip_fenced_code(text));
    let mut links = BTreeSet::new();
    let bytes = text.as_bytes();
    let mut index = 0;
    while index + 3 < bytes.len() {
        if &bytes[index..index + 2] != b"[[" {
            index += 1;
            continue;
        }
        let Some(end) = text[index + 2..].find("]]") else {
            break;
        };
        let raw = &text[index + 2..index + 2 + end];
        if !raw.contains('\n') {
            let without_alias = raw.split_once('|').map(|(left, _)| left).unwrap_or(raw);
            let target = without_alias
                .split_once('#')
                .map(|(left, _)| left)
                .unwrap_or(without_alias)
                .trim();
            if !target.is_empty() && !links.contains(target) {
                if links.len() >= max_unique {
                    return Err(format!(
                        "manifest wikilink count exceeds {MAX_MANIFEST_WIKILINKS}"
                    ));
                }
                links.insert(target.to_owned());
            }
        }
        index += end + 4;
    }
    Ok(links.into_iter().collect())
}

fn strip_fenced_code(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut in_fence = false;
    for line in text.lines() {
        if line.starts_with("```") {
            in_fence = !in_fence;
            output.push('\n');
            continue;
        }
        if !in_fence {
            output.push_str(line);
        }
        output.push('\n');
    }
    output
}

fn strip_inline_code(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut in_code = false;
    for ch in text.chars() {
        if ch == '`' {
            in_code = !in_code;
            continue;
        }
        if !in_code {
            output.push(ch);
        }
    }
    output
}

fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use std::{fmt::Write as _, io::Cursor};

    use super::*;

    fn fixture_dir(name: &str) -> PathBuf {
        env::temp_dir()
            .join("exo_dagdb_kg_markdown_manifest_tests")
            .join(format!("{name}_{}", std::process::id()))
    }

    fn reset_dir(path: &Path) {
        let _ = fs::remove_dir_all(path);
        fs::create_dir_all(path).expect("test manifest dir");
    }

    fn create_sized_file(path: &Path, len: u64) {
        let file = fs::File::create(path).expect("create sized fixture");
        file.set_len(len).expect("size fixture");
    }

    #[test]
    fn kg_markdown_manifest_builds_sorted_manifest_from_markdown_tree() {
        let root = fixture_dir("sorted_tree");
        reset_dir(&root);
        fs::create_dir_all(root.join("nested")).expect("nested dir");

        let alpha = concat!(
            "---\n",
            "frontmatter_title: \"Alpha Frontmatter\"\n",
            "owner: 'dagdb'\n",
            "ignored line without colon\n",
            "---\n",
            "# Alpha Title\n",
            "Links [[b-beta|Beta alias]] and [[nested/c-gamma#Details]].\n",
            "Duplicate [[b-beta]] and empty [[#Only Heading]].\n",
            "`inline [[ignored-inline]] code`\n",
            "```rust\n",
            "[[ignored-fence]]\n",
            "```\n",
            "## Details\n",
            "#### Deep Cut\n",
        );
        let beta = "# Beta Title\nBody [[a-alpha]]\n";
        let gamma = "preamble\n#### Gamma Deep\n";

        fs::write(root.join("a-alpha.md"), alpha).expect("alpha markdown");
        fs::write(root.join("b-beta.md"), beta).expect("beta markdown");
        fs::write(root.join("nested").join("c-gamma.md"), gamma).expect("gamma markdown");
        fs::write(root.join("ignored.txt"), "# Ignored\n").expect("ignored text");

        let first = build_manifest(&root).expect("manifest");
        let second = build_manifest(&root).expect("manifest again");

        assert_eq!(
            serde_json::to_value(&first).expect("first json"),
            serde_json::to_value(&second).expect("second json")
        );
        assert_eq!(first.schema_version, MANIFEST_SCHEMA_VERSION);
        assert_eq!(first.file_count, 3);
        assert!(
            first
                .graph_root
                .ends_with(root.file_name().unwrap().to_str().unwrap())
        );
        assert_eq!(
            first
                .files
                .iter()
                .map(|file| file.path.as_str())
                .collect::<Vec<_>>(),
            vec!["a-alpha.md", "b-beta.md", "nested/c-gamma.md"]
        );

        let alpha_file = &first.files[0];
        assert_eq!(alpha_file.byte_length, alpha.len());
        assert_eq!(alpha_file.sha256, sha256_hex(alpha.as_bytes()));
        assert_eq!(
            alpha_file.frontmatter.get("frontmatter_title"),
            Some(&"Alpha Frontmatter".to_owned())
        );
        assert_eq!(
            alpha_file.frontmatter.get("owner"),
            Some(&"dagdb".to_owned())
        );
        assert!(
            !alpha_file
                .frontmatter
                .contains_key("ignored line without colon")
        );
        assert_eq!(alpha_file.title, "Alpha Title");
        assert_eq!(
            alpha_file
                .headings
                .iter()
                .map(|heading| (heading.level, heading.text.as_str()))
                .collect::<Vec<_>>(),
            vec![(1, "Alpha Title"), (2, "Details"), (4, "Deep Cut")]
        );
        assert_eq!(
            alpha_file.wikilinks,
            vec!["b-beta".to_owned(), "nested/c-gamma".to_owned()]
        );

        assert_eq!(first.files[1].title, "Beta Title");
        assert_eq!(first.files[1].wikilinks, vec!["a-alpha".to_owned()]);
        assert_eq!(first.files[2].title, "Gamma Deep");

        fs::remove_dir_all(root).expect("cleanup manifest dir");
    }

    #[cfg(unix)]
    #[test]
    fn graph_root_display_remains_canonical_through_parent_symlink_and_dotdot_alias() {
        use std::os::unix::fs::symlink;

        let fixture = tempfile::tempdir().expect("fixture");
        let actual_parent = fixture.path().join("actual-parent");
        let actual_root = actual_parent.join("graph");
        let alias_parent = fixture.path().join("alias-parent");
        fs::create_dir_all(&actual_root).expect("actual graph root");
        fs::write(actual_root.join("entry.md"), b"# Entry\n").expect("markdown");
        symlink(&actual_parent, &alias_parent).expect("parent symlink");
        let aliased_root = alias_parent.join("graph").join("..").join("graph");
        let noncanonical = std::path::absolute(&aliased_root).expect("absolute alias");
        let canonical = fs::canonicalize(&aliased_root).expect("canonical graph root");
        assert_ne!(noncanonical, canonical);

        let manifest = build_manifest(&aliased_root).expect("manifest through parent alias");
        assert_eq!(manifest.graph_root, display_root(&canonical));
        assert_ne!(manifest.graph_root, display_root(&noncanonical));
    }

    #[test]
    fn kg_markdown_manifest_reports_invalid_roots_and_non_utf8_markdown() {
        let missing_root = fixture_dir("missing_root");
        let _ = fs::remove_dir_all(&missing_root);
        let missing_error = build_manifest(&missing_root).expect_err("missing root");
        assert!(missing_error.contains("graph root does not exist"));

        let file_root = fixture_dir("file_root");
        let _ = fs::remove_file(&file_root);
        fs::create_dir_all(file_root.parent().expect("file root parent")).expect("parent dir");
        fs::write(&file_root, b"not a directory").expect("file root");
        let file_error = build_manifest(&file_root).expect_err("file root");
        assert!(file_error.contains("graph root is not a directory"));
        fs::remove_file(&file_root).expect("cleanup file root");

        let invalid_utf8_root = fixture_dir("invalid_utf8");
        reset_dir(&invalid_utf8_root);
        fs::write(invalid_utf8_root.join("bad.md"), [0xff]).expect("bad markdown");
        let utf8_error = build_manifest(&invalid_utf8_root).expect_err("utf8 markdown");
        assert!(utf8_error.contains("markdown file is not UTF-8"));
        fs::remove_dir_all(invalid_utf8_root).expect("cleanup invalid utf8 root");
    }

    #[test]
    fn kg_markdown_manifest_parses_frontmatter_headings_and_wikilink_edges() {
        let frontmatter = parse_frontmatter(
            concat!(
                "---\n",
                "title: 'Quoted Title'\n",
                "owner: \"DAG DB\"\n",
                "# comment\n",
                "no colon\n",
                ": missing key\n",
                "spaced : value: with colon\n",
                "---\n",
                "# Body\n",
            ),
            MAX_MANIFEST_FRONTMATTER_ENTRIES,
        )
        .expect("frontmatter");
        assert_eq!(frontmatter.get("title"), Some(&"Quoted Title".to_owned()));
        assert_eq!(frontmatter.get("owner"), Some(&"DAG DB".to_owned()));
        assert_eq!(
            frontmatter.get("spaced"),
            Some(&"value: with colon".to_owned())
        );
        assert!(!frontmatter.contains_key("no colon"));
        assert!(!frontmatter.contains_key(""));
        assert!(
            parse_frontmatter("# Body\n", MAX_MANIFEST_FRONTMATTER_ENTRIES)
                .expect("no frontmatter")
                .is_empty()
        );
        assert!(
            parse_frontmatter(
                "---\ntitle: missing end\n# Body\n",
                MAX_MANIFEST_FRONTMATTER_ENTRIES
            )
            .expect("unterminated frontmatter")
            .is_empty()
        );

        let headings = extract_headings(
            concat!(
                "preamble\n",
                "# One\n",
                "#### Four\n",
                "####### Too Many\n",
                "#NoSpace\n",
                "##   \n",
            ),
            MAX_MANIFEST_HEADINGS,
        )
        .expect("headings");
        assert_eq!(
            headings
                .iter()
                .map(|heading| (heading.level, heading.text.as_str()))
                .collect::<Vec<_>>(),
            vec![(1, "One"), (4, "Four")]
        );

        let wikilinks = extract_wikilinks(
            concat!(
                "[[Alpha]] [[Alpha|alias]] [[Beta#Section]] [[ spaced ]] [[ ]] ",
                "[[\n",
                "nope]] `[[Code]]`\n",
                "```\n",
                "[[Fence]]\n",
                "```\n",
                "[[NoClose",
            ),
            MAX_MANIFEST_WIKILINKS,
        )
        .expect("wikilinks");
        assert_eq!(
            wikilinks,
            vec!["Alpha".to_owned(), "Beta".to_owned(), "spaced".to_owned()]
        );
        assert_eq!(strip_inline_code("a `hidden [[Link]]` b"), "a  b");
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            repo_relative_to(Path::new("outside.md"), &fixture_dir("root")),
            "outside.md"
        );
        assert!(!display_root(Path::new(".")).contains('\\'));
    }

    #[cfg(unix)]
    #[test]
    fn kg_markdown_manifest_rejects_root_file_and_directory_symlinks() {
        use std::os::unix::fs::symlink;

        let fixture = tempfile::tempdir().expect("fixture");
        let root = fixture.path().join("root");
        let outside = fixture.path().join("outside");
        fs::create_dir_all(&root).expect("root");
        fs::create_dir_all(&outside).expect("outside");
        fs::write(outside.join("outside.md"), b"# Outside\n").expect("outside markdown");

        let root_link = fixture.path().join("root-link");
        symlink(&root, &root_link).expect("root symlink");
        assert!(
            build_manifest(&root_link)
                .expect_err("root symlink must be rejected")
                .contains("symlink")
        );

        let file_link = root.join("outside-file.md");
        symlink(outside.join("outside.md"), &file_link).expect("file symlink");
        assert!(
            build_manifest(&root)
                .expect_err("outbound file symlink must be rejected")
                .contains("symlink")
        );
        fs::remove_file(file_link).expect("remove file symlink");

        let directory_link = root.join("outside-directory");
        symlink(&outside, &directory_link).expect("directory symlink");
        assert!(
            build_manifest(&root)
                .expect_err("outbound directory symlink must be rejected")
                .contains("symlink")
        );
    }

    #[cfg(unix)]
    #[test]
    fn root_directory_capability_cannot_be_redirected_by_swap_back() {
        use std::os::unix::fs::symlink;

        let fixture = tempfile::tempdir().expect("fixture");
        let root = fixture.path().join("root");
        let parked = fixture.path().join("parked-root");
        let outside = fixture.path().join("outside");
        fs::create_dir(&root).expect("root");
        fs::create_dir(&outside).expect("outside");
        fs::write(root.join("inside.md"), b"# Inside\n").expect("inside markdown");
        fs::write(outside.join("outside.md"), b"# Outside\n").expect("outside markdown");

        let (opened, _) = open_root_directory_capability(&root).expect("opened root capability");
        fs::rename(&root, &parked).expect("park root");
        symlink(&outside, &root).expect("redirect root path");
        let entries = opened.capability.entries().expect("enumerate opened root");
        fs::remove_file(&root).expect("remove redirect");
        fs::rename(&parked, &root).expect("swap original root back");

        let names = entries
            .map(|entry| entry.expect("entry").file_name())
            .collect::<Vec<_>>();
        assert_eq!(names, vec![std::ffi::OsString::from("inside.md")]);
    }

    #[cfg(unix)]
    #[test]
    fn root_resolution_swap_back_cannot_redefine_trusted_root() {
        use std::os::unix::fs::symlink;

        let fixture = tempfile::tempdir().expect("fixture");
        let root = fixture.path().join("root");
        let parked = fixture.path().join("parked-root");
        let outside = fixture.path().join("outside");
        fs::create_dir(&root).expect("root");
        fs::create_dir(&outside).expect("outside");

        let error = open_root_directory_capability_with(&root, |path| {
            fs::rename(path, &parked)?;
            symlink(&outside, path)?;
            let redirected = fs::canonicalize(path)?;
            fs::remove_file(path)?;
            fs::rename(&parked, path)?;
            Ok(redirected)
        })
        .expect_err("swap-back during resolution must be rejected");
        assert!(error.contains("changed"));
    }

    #[cfg(unix)]
    #[test]
    fn child_directory_capability_cannot_be_redirected_by_swap_back() {
        use std::os::unix::fs::symlink;

        let fixture = tempfile::tempdir().expect("fixture");
        let root = fixture.path().join("root");
        let child = root.join("child");
        let parked = root.join("parked-child");
        let outside = fixture.path().join("outside");
        fs::create_dir_all(&child).expect("child");
        fs::create_dir(&outside).expect("outside");
        fs::write(child.join("inside.md"), b"# Inside\n").expect("inside markdown");
        fs::write(outside.join("outside.md"), b"# Outside\n").expect("outside markdown");

        let (opened_root, _) =
            open_root_directory_capability(&root).expect("opened root capability");
        let opened_child = open_child_directory_capability(
            &opened_root,
            std::ffi::OsStr::new("child"),
            PathBuf::from("child"),
        )
        .expect("opened child capability");
        fs::rename(&child, &parked).expect("park child");
        symlink(&outside, &child).expect("redirect child path");
        let entries = opened_child
            .capability
            .entries()
            .expect("enumerate opened child");
        fs::remove_file(&child).expect("remove redirect");
        fs::rename(&parked, &child).expect("swap original child back");

        let names = entries
            .map(|entry| entry.expect("entry").file_name())
            .collect::<Vec<_>>();
        assert_eq!(names, vec![std::ffi::OsString::from("inside.md")]);
    }

    #[test]
    fn kg_markdown_manifest_rejects_revisited_canonical_directory() {
        let fixture = tempfile::tempdir().expect("fixture");
        let (opened_root, _) =
            open_root_directory_capability(fixture.path()).expect("opened root capability");
        let mut visited = BTreeSet::from([PathBuf::new()]);
        let mut budget = ManifestBuildBudget::default();
        let mut files = Vec::new();
        let error = collect_markdown_files(&opened_root, 0, &mut visited, &mut budget, &mut files)
            .expect_err("revisited directory must be rejected");
        assert!(error.contains("cycle"));
    }

    #[test]
    fn kg_markdown_manifest_accepts_depth_64_and_rejects_depth_65() {
        let fixture = tempfile::tempdir().expect("fixture");
        let mut deepest = fixture.path().to_path_buf();
        for depth in 1..=64 {
            deepest = deepest.join(format!("d{depth}"));
            fs::create_dir(&deepest).expect("nested directory");
        }
        fs::write(deepest.join("accepted.md"), b"# Accepted\n").expect("depth 64 file");
        assert_eq!(
            build_manifest(fixture.path()).expect("depth 64").file_count,
            1
        );

        let too_deep = deepest.join("d65");
        fs::create_dir(&too_deep).expect("depth 65 directory");
        fs::write(too_deep.join("rejected.md"), b"# Rejected\n").expect("depth 65 file");
        assert!(
            build_manifest(fixture.path())
                .expect_err("depth 65 must be rejected")
                .contains("depth")
        );
    }

    #[test]
    fn kg_markdown_manifest_accepts_4096_files_and_rejects_4097() {
        let fixture = tempfile::tempdir().expect("fixture");
        for index in 0..4_096 {
            fs::write(fixture.path().join(format!("{index:04}.md")), []).expect("markdown");
        }
        assert_eq!(
            build_manifest(fixture.path())
                .expect("4,096 files")
                .file_count,
            4_096
        );

        fs::write(fixture.path().join("4096.md"), []).expect("extra markdown");
        assert!(
            build_manifest(fixture.path())
                .expect_err("4,097 files must be rejected")
                .contains("file count")
        );
    }

    #[test]
    fn kg_markdown_manifest_bounds_all_directory_entries() {
        let fixture = tempfile::tempdir().expect("fixture");
        for index in 0..4_096 {
            fs::create_dir(fixture.path().join(format!("directory-{index:04}")))
                .expect("empty directory");
            fs::write(fixture.path().join(format!("ignored-{index:04}.txt")), [])
                .expect("ignored file");
        }
        assert_eq!(
            build_manifest(fixture.path())
                .expect("8,192 directory entries")
                .file_count,
            0
        );

        fs::write(fixture.path().join("ignored-extra.txt"), []).expect("extra ignored file");
        assert!(
            build_manifest(fixture.path())
                .expect_err("8,193 directory entries must be rejected")
                .contains("entry count")
        );
    }

    #[test]
    fn kg_markdown_manifest_accepts_65536_unique_wikilinks_and_rejects_65537() {
        let fixture = tempfile::tempdir().expect("fixture");
        let markdown = fixture.path().join("links.md");
        let exact = (0..MAX_MANIFEST_WIKILINKS)
            .map(|index| format!("[[target-{index}]]\n"))
            .collect::<String>();
        assert!(exact.len() < MAX_MARKDOWN_FILE_BYTES);
        fs::write(&markdown, &exact).expect("exact wikilink budget");

        let manifest = build_manifest(fixture.path()).expect("65,536 unique wikilinks");
        assert_eq!(manifest.files[0].wikilinks.len(), MAX_MANIFEST_WIKILINKS);

        fs::write(&markdown, format!("{exact}[[one-too-many]]\n"))
            .expect("wikilink budget plus one");
        assert!(
            build_manifest(fixture.path())
                .expect_err("65,537 unique wikilinks must be rejected")
                .contains("wikilink")
        );
    }

    #[test]
    fn kg_markdown_manifest_accepts_65536_headings_and_rejects_65537() {
        assert_eq!(MAX_MANIFEST_HEADINGS, 65_536);
        let fixture = tempfile::tempdir().expect("fixture");
        let first_path = fixture.path().join("first.md");
        let second_path = fixture.path().join("second.md");
        let first = "# x\n".repeat(MAX_MANIFEST_HEADINGS / 2);
        let second = "# x\n".repeat(MAX_MANIFEST_HEADINGS - (MAX_MANIFEST_HEADINGS / 2));
        assert!(first.len() < MAX_MARKDOWN_FILE_BYTES);
        assert!(second.len() < MAX_MARKDOWN_FILE_BYTES);
        fs::write(&first_path, &first).expect("first exact heading fixture");
        fs::write(&second_path, &second).expect("second exact heading fixture");

        let manifest = build_manifest(fixture.path()).expect("65,536 headings");
        assert_eq!(
            manifest
                .files
                .iter()
                .map(|file| file.headings.len())
                .sum::<usize>(),
            MAX_MANIFEST_HEADINGS
        );

        fs::write(&second_path, format!("{second}# one-too-many\n"))
            .expect("heading budget plus one");
        assert!(
            build_manifest(fixture.path())
                .expect_err("65,537 headings must be rejected")
                .contains("heading")
        );
    }

    #[test]
    fn kg_markdown_manifest_accepts_65536_frontmatter_entries_and_rejects_65537() {
        assert_eq!(MAX_MANIFEST_FRONTMATTER_ENTRIES, 65_536);
        let fixture = tempfile::tempdir().expect("fixture");
        let first_path = fixture.path().join("first.md");
        let second_path = fixture.path().join("second.md");
        let make_frontmatter = |start: usize, count: usize| {
            let mut text = String::from("---\n");
            for index in start..start + count {
                writeln!(&mut text, "key-{index}: value").expect("write frontmatter fixture");
            }
            text.push_str("---\n");
            text
        };
        let first_count = MAX_MANIFEST_FRONTMATTER_ENTRIES / 2;
        let first = make_frontmatter(0, first_count);
        let second = make_frontmatter(first_count, MAX_MANIFEST_FRONTMATTER_ENTRIES - first_count);
        assert!(first.len() < MAX_MARKDOWN_FILE_BYTES);
        assert!(second.len() < MAX_MARKDOWN_FILE_BYTES);
        fs::write(&first_path, &first).expect("first exact frontmatter fixture");
        fs::write(&second_path, &second).expect("second exact frontmatter fixture");

        let manifest = build_manifest(fixture.path()).expect("65,536 frontmatter entries");
        assert_eq!(
            manifest
                .files
                .iter()
                .map(|file| file.frontmatter.len())
                .sum::<usize>(),
            MAX_MANIFEST_FRONTMATTER_ENTRIES
        );

        let closing = second
            .strip_suffix("---\n")
            .expect("frontmatter closing delimiter");
        fs::write(&second_path, format!("{closing}one-too-many: value\n---\n"))
            .expect("frontmatter budget plus one");
        assert!(
            build_manifest(fixture.path())
                .expect_err("65,537 frontmatter entries must be rejected")
                .contains("frontmatter")
        );
    }

    #[test]
    fn manifest_output_accepts_exact_16_mib_and_rejects_plus_one() {
        let mut manifest = Manifest {
            schema_version: MANIFEST_SCHEMA_VERSION.to_owned(),
            graph_root: String::new(),
            file_count: 0,
            files: Vec::new(),
        };
        let baseline =
            serialize_pretty_json_bounded(&manifest, MAX_JSON_FILE_BYTES, "manifest output")
                .expect("baseline manifest output");
        let content_bytes = MAX_JSON_FILE_BYTES
            .checked_sub(baseline.len())
            .expect("baseline fits output boundary");
        let escaped_count = content_bytes / 6;
        let literal_count = content_bytes % 6;
        manifest
            .graph_root
            .extend(std::iter::repeat_n('\0', escaped_count));
        manifest
            .graph_root
            .extend(std::iter::repeat_n('x', literal_count));

        let output =
            serialize_pretty_json_bounded(&manifest, MAX_JSON_FILE_BYTES, "manifest output")
                .expect("exact 16 MiB manifest output");
        assert_eq!(output.len(), MAX_JSON_FILE_BYTES);
        let fixture = tempfile::tempdir().expect("manifest output fixture");
        let output_path = fixture.path().join("manifest.json");
        fs::write(&output_path, &output).expect("write exact manifest output");
        let consumer_input = read_bounded_file(&output_path, MAX_JSON_FILE_BYTES, "manifest input")
            .expect("consumer accepts exact manifest output");
        serde_json::from_slice::<Manifest>(&consumer_input)
            .expect("exact output remains valid JSON");

        manifest.graph_root.push('x');
        assert!(
            serialize_pretty_json_bounded(&manifest, MAX_JSON_FILE_BYTES, "manifest output")
                .expect_err("manifest output limit plus one must be rejected")
                .contains("exceeds")
        );
    }

    #[test]
    fn kg_markdown_manifest_accepts_4_mib_file_and_rejects_one_more_byte() {
        let fixture = tempfile::tempdir().expect("fixture");
        let markdown = fixture.path().join("bounded.md");
        create_sized_file(&markdown, 4_194_304);
        assert_eq!(
            build_manifest(fixture.path()).expect("4 MiB file").files[0].byte_length,
            4_194_304
        );

        create_sized_file(&markdown, 4_194_305);
        assert!(
            build_manifest(fixture.path())
                .expect_err("4 MiB plus one byte must be rejected")
                .contains("file size")
        );
    }

    #[test]
    fn kg_markdown_manifest_accepts_64_mib_total_and_rejects_one_more_byte() {
        let fixture = tempfile::tempdir().expect("fixture");
        for index in 0..16 {
            create_sized_file(&fixture.path().join(format!("{index:02}.md")), 4_194_304);
        }
        let accepted = build_manifest(fixture.path()).expect("64 MiB aggregate");
        assert_eq!(
            accepted
                .files
                .iter()
                .map(|file| file.byte_length)
                .sum::<usize>(),
            67_108_864
        );

        fs::write(fixture.path().join("extra.md"), b"x").expect("aggregate plus one");
        assert!(
            build_manifest(fixture.path())
                .expect_err("64 MiB plus one byte must be rejected")
                .contains("aggregate")
        );
    }

    #[test]
    fn bounded_reader_accepts_limit_and_rejects_limit_plus_one() {
        assert_eq!(
            read_at_most(Cursor::new(vec![0_u8; 16]), 16, "fixture").expect("exact limit"),
            vec![0_u8; 16]
        );
        assert!(
            read_at_most(Cursor::new(vec![0_u8; 17]), 16, "fixture")
                .expect_err("limit plus one")
                .contains("exceeds")
        );
    }

    #[cfg(unix)]
    #[test]
    fn bounded_reader_rejects_path_swaps_between_inspection_and_open() {
        use std::os::unix::fs::symlink;

        let fixture = tempfile::tempdir().expect("fixture");
        let path = fixture.path().join("input.json");
        let outside = fixture.path().join("outside.json");
        fs::write(&path, b"original").expect("original input");
        fs::write(&outside, b"external").expect("outside input");

        let replacement_error = read_bounded_file_with_open(
            &path,
            16,
            "fixture",
            |opened_path| -> std::io::Result<fs::File> {
                fs::remove_file(opened_path)?;
                fs::write(opened_path, b"replaced")?;
                fs::File::open(opened_path)
            },
        )
        .expect_err("regular-file replacement must be rejected");
        assert!(replacement_error.contains("changed"));

        fs::remove_file(&path).expect("remove replacement");
        fs::write(&path, b"original").expect("restore input");
        let symlink_error = read_bounded_file_with_open(
            &path,
            16,
            "fixture",
            |opened_path| -> std::io::Result<fs::File> {
                fs::remove_file(opened_path)?;
                symlink(&outside, opened_path)?;
                fs::File::open(opened_path)
            },
        )
        .expect_err("symlink replacement must be rejected");
        assert!(symlink_error.contains("symlink") || symlink_error.contains("changed"));
    }
}
