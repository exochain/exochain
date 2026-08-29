use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

use exo_dag_db_lab::kg_markdown_manifest::{
    Heading, MANIFEST_SCHEMA_VERSION, MAX_JSON_FILE_BYTES, MAX_MANIFEST_FILES,
    MAX_MANIFEST_FRONTMATTER_ENTRIES, MAX_MANIFEST_HEADINGS, MAX_MANIFEST_WIKILINKS, Manifest,
    ManifestFile, build_manifest, read_bounded_file, serialize_pretty_json_bounded,
};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{DeserializeSeed, Error as _, IgnoredAny, MapAccess, SeqAccess, Visitor},
};
use sha2::{Digest, Sha256};

const SCHEMA_VERSION: &str = "dagdb_markdown_kg_import_candidates_v1";
/// Candidate in-memory construction receives a bounded 64 MiB work budget.
const MAX_CANDIDATE_CONSTRUCTION_WORK_BYTES: usize = MAX_JSON_FILE_BYTES * 4;
/// Candidate output must fit the same boundary consumed by import-persist.
const MAX_CANDIDATE_OUTPUT_BYTES: usize = MAX_JSON_FILE_BYTES;
/// Covers fixed node/vector/map allocation work not represented by string bytes.
const CANDIDATE_FILE_FIXED_WORK: usize = 1_024;
/// Conservatively covers a `Vec<String>` slot plus one small string allocation.
const CANDIDATE_CATALOG_COMPONENT_WORK: usize = 128;
/// Conservatively covers a cloned BTreeMap entry/node plus allocator overhead.
const CANDIDATE_FRONTMATTER_ENTRY_WORK: usize = 512;
/// Covers reserved edge/unresolved slots and fixed IDs/status strings per edge.
const CANDIDATE_EDGE_FIXED_WORK: usize = 512;

fn main() {
    if let Err(error) = run() {
        eprintln!("dagdb_kg_import_candidates_error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = parse_args(env::args().skip(1).collect())?;
    let manifest = load_manifest(&args)?;
    let candidates = build_candidates(manifest)?;
    let encoded = serialize_candidates_bounded(&candidates)?;

    if let Some(output) = args.output {
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("create output directory: {error}"))?;
        }
        fs::write(&output, &encoded).map_err(|error| format!("write output: {error}"))?;
    } else {
        io::stdout()
            .write_all(&encoded)
            .map_err(|error| format!("write stdout: {error}"))?;
    }
    Ok(())
}

fn serialize_candidates_bounded(candidates: &CandidateReport) -> Result<Vec<u8>, String> {
    serialize_pretty_json_bounded(candidates, MAX_CANDIDATE_OUTPUT_BYTES, "candidate output")
}

struct Args {
    root: PathBuf,
    manifest: Option<PathBuf>,
    output: Option<PathBuf>,
}

#[derive(Deserialize)]
#[serde(field_identifier, rename_all = "snake_case")]
enum ManifestField {
    SchemaVersion,
    GraphRoot,
    FileCount,
    Files,
    #[serde(other)]
    Other,
}

#[derive(Deserialize)]
#[serde(field_identifier, rename_all = "snake_case")]
enum ManifestFileField {
    Path,
    Sha256,
    ByteLength,
    Frontmatter,
    Title,
    Headings,
    Wikilinks,
    #[serde(other)]
    Other,
}

#[derive(Default)]
struct ImportSemanticBudget {
    headings: usize,
    frontmatter_entries: usize,
    wikilinks: usize,
}

/// Import-only seed that bounds collections during deserialization. Candidate
/// generation never consumes headings, so valid heading objects are streamed,
/// counted, and discarded instead of being retained in the imported manifest.
struct BoundedManifestSeed;

impl<'de> DeserializeSeed<'de> for BoundedManifestSeed {
    type Value = Manifest;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_struct(
            "Manifest",
            &["schema_version", "graph_root", "file_count", "files"],
            BoundedManifestVisitor,
        )
    }
}

struct BoundedManifestVisitor;

impl<'de> Visitor<'de> for BoundedManifestVisitor {
    type Value = Manifest;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a bounded DAG DB Markdown manifest")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let schema_version = sequence
            .next_element()?
            .ok_or_else(|| A::Error::custom("manifest is missing schema_version"))?;
        let graph_root = sequence
            .next_element()?
            .ok_or_else(|| A::Error::custom("manifest is missing graph_root"))?;
        let file_count = sequence
            .next_element()?
            .ok_or_else(|| A::Error::custom("manifest is missing file_count"))?;
        let files = sequence
            .next_element_seed(BoundedManifestFilesSeed)?
            .ok_or_else(|| A::Error::custom("manifest is missing files"))?;
        if sequence.next_element::<IgnoredAny>()?.is_some() {
            return Err(A::Error::custom(
                "manifest contains unexpected trailing fields",
            ));
        }
        Ok(Manifest {
            schema_version,
            graph_root,
            file_count,
            files,
        })
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut schema_version = None;
        let mut graph_root = None;
        let mut file_count = None;
        let mut files = None;
        while let Some(field) = map.next_key::<ManifestField>()? {
            match field {
                ManifestField::SchemaVersion => {
                    if schema_version.is_some() {
                        return Err(A::Error::duplicate_field("schema_version"));
                    }
                    schema_version = Some(map.next_value()?);
                }
                ManifestField::GraphRoot => {
                    if graph_root.is_some() {
                        return Err(A::Error::duplicate_field("graph_root"));
                    }
                    graph_root = Some(map.next_value()?);
                }
                ManifestField::FileCount => {
                    if file_count.is_some() {
                        return Err(A::Error::duplicate_field("file_count"));
                    }
                    file_count = Some(map.next_value()?);
                }
                ManifestField::Files => {
                    if files.is_some() {
                        return Err(A::Error::duplicate_field("files"));
                    }
                    files = Some(map.next_value_seed(BoundedManifestFilesSeed)?);
                }
                ManifestField::Other => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(Manifest {
            schema_version: schema_version
                .ok_or_else(|| A::Error::missing_field("schema_version"))?,
            graph_root: graph_root.ok_or_else(|| A::Error::missing_field("graph_root"))?,
            file_count: file_count.ok_or_else(|| A::Error::missing_field("file_count"))?,
            files: files.ok_or_else(|| A::Error::missing_field("files"))?,
        })
    }
}

struct BoundedManifestFilesSeed;

impl<'de> DeserializeSeed<'de> for BoundedManifestFilesSeed {
    type Value = Vec<ManifestFile>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(BoundedManifestFilesVisitor)
    }
}

struct BoundedManifestFilesVisitor;

impl<'de> Visitor<'de> for BoundedManifestFilesVisitor {
    type Value = Vec<ManifestFile>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a bounded manifest file array")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut files = Vec::new();
        let mut budget = ImportSemanticBudget::default();
        loop {
            if files.len() >= MAX_MANIFEST_FILES {
                return match sequence.next_element::<IgnoredAny>()? {
                    Some(_) => Err(A::Error::custom(format!(
                        "manifest file count exceeds {MAX_MANIFEST_FILES}"
                    ))),
                    None => Ok(files),
                };
            }
            let Some(file) = sequence.next_element_seed(BoundedManifestFileSeed {
                budget: &mut budget,
            })?
            else {
                return Ok(files);
            };
            files
                .try_reserve(1)
                .map_err(|error| A::Error::custom(format!("reserve manifest files: {error}")))?;
            files.push(file);
        }
    }
}

struct BoundedManifestFileSeed<'a> {
    budget: &'a mut ImportSemanticBudget,
}

impl<'de> DeserializeSeed<'de> for BoundedManifestFileSeed<'_> {
    type Value = ManifestFile;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_struct(
            "ManifestFile",
            &[
                "path",
                "sha256",
                "byte_length",
                "frontmatter",
                "title",
                "headings",
                "wikilinks",
            ],
            BoundedManifestFileVisitor {
                budget: self.budget,
            },
        )
    }
}

struct BoundedManifestFileVisitor<'a> {
    budget: &'a mut ImportSemanticBudget,
}

impl<'de> Visitor<'de> for BoundedManifestFileVisitor<'_> {
    type Value = ManifestFile;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a bounded manifest file")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let path = sequence
            .next_element()?
            .ok_or_else(|| A::Error::custom("manifest file is missing path"))?;
        let sha256 = sequence
            .next_element()?
            .ok_or_else(|| A::Error::custom("manifest file is missing sha256"))?;
        let byte_length = sequence
            .next_element()?
            .ok_or_else(|| A::Error::custom("manifest file is missing byte_length"))?;
        let frontmatter = sequence
            .next_element_seed(BoundedFrontmatterSeed {
                observed: &mut self.budget.frontmatter_entries,
            })?
            .ok_or_else(|| A::Error::custom("manifest file is missing frontmatter"))?;
        let title = sequence
            .next_element()?
            .ok_or_else(|| A::Error::custom("manifest file is missing title"))?;
        sequence
            .next_element_seed(BoundedDiscardedHeadingsSeed {
                observed: &mut self.budget.headings,
            })?
            .ok_or_else(|| A::Error::custom("manifest file is missing headings"))?;
        let wikilinks = sequence
            .next_element_seed(BoundedWikilinksSeed {
                observed: &mut self.budget.wikilinks,
            })?
            .ok_or_else(|| A::Error::custom("manifest file is missing wikilinks"))?;
        if sequence.next_element::<IgnoredAny>()?.is_some() {
            return Err(A::Error::custom(
                "manifest file contains unexpected trailing fields",
            ));
        }
        Ok(ManifestFile {
            path,
            sha256,
            byte_length,
            frontmatter,
            title,
            headings: Vec::new(),
            wikilinks,
        })
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut path = None;
        let mut sha256 = None;
        let mut byte_length = None;
        let mut frontmatter = None;
        let mut title = None;
        let mut headings_seen = false;
        let mut wikilinks = None;
        while let Some(field) = map.next_key::<ManifestFileField>()? {
            match field {
                ManifestFileField::Path => {
                    if path.is_some() {
                        return Err(A::Error::duplicate_field("path"));
                    }
                    path = Some(map.next_value()?);
                }
                ManifestFileField::Sha256 => {
                    if sha256.is_some() {
                        return Err(A::Error::duplicate_field("sha256"));
                    }
                    sha256 = Some(map.next_value()?);
                }
                ManifestFileField::ByteLength => {
                    if byte_length.is_some() {
                        return Err(A::Error::duplicate_field("byte_length"));
                    }
                    byte_length = Some(map.next_value()?);
                }
                ManifestFileField::Frontmatter => {
                    if frontmatter.is_some() {
                        return Err(A::Error::duplicate_field("frontmatter"));
                    }
                    frontmatter = Some(map.next_value_seed(BoundedFrontmatterSeed {
                        observed: &mut self.budget.frontmatter_entries,
                    })?);
                }
                ManifestFileField::Title => {
                    if title.is_some() {
                        return Err(A::Error::duplicate_field("title"));
                    }
                    title = Some(map.next_value()?);
                }
                ManifestFileField::Headings => {
                    if headings_seen {
                        return Err(A::Error::duplicate_field("headings"));
                    }
                    map.next_value_seed(BoundedDiscardedHeadingsSeed {
                        observed: &mut self.budget.headings,
                    })?;
                    headings_seen = true;
                }
                ManifestFileField::Wikilinks => {
                    if wikilinks.is_some() {
                        return Err(A::Error::duplicate_field("wikilinks"));
                    }
                    wikilinks = Some(map.next_value_seed(BoundedWikilinksSeed {
                        observed: &mut self.budget.wikilinks,
                    })?);
                }
                ManifestFileField::Other => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        if !headings_seen {
            return Err(A::Error::missing_field("headings"));
        }
        Ok(ManifestFile {
            path: path.ok_or_else(|| A::Error::missing_field("path"))?,
            sha256: sha256.ok_or_else(|| A::Error::missing_field("sha256"))?,
            byte_length: byte_length.ok_or_else(|| A::Error::missing_field("byte_length"))?,
            frontmatter: frontmatter.ok_or_else(|| A::Error::missing_field("frontmatter"))?,
            title: title.ok_or_else(|| A::Error::missing_field("title"))?,
            headings: Vec::new(),
            wikilinks: wikilinks.ok_or_else(|| A::Error::missing_field("wikilinks"))?,
        })
    }
}

struct BoundedDiscardedHeadingsSeed<'a> {
    observed: &'a mut usize,
}

impl<'de> DeserializeSeed<'de> for BoundedDiscardedHeadingsSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(BoundedDiscardedHeadingsVisitor {
            observed: self.observed,
        })
    }
}

struct BoundedDiscardedHeadingsVisitor<'a> {
    observed: &'a mut usize,
}

impl<'de> Visitor<'de> for BoundedDiscardedHeadingsVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a bounded heading array")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        loop {
            if *self.observed >= MAX_MANIFEST_HEADINGS {
                return match sequence.next_element::<IgnoredAny>()? {
                    Some(_) => Err(A::Error::custom(format!(
                        "manifest heading count exceeds {MAX_MANIFEST_HEADINGS}"
                    ))),
                    None => Ok(()),
                };
            }
            let Some(_heading) = sequence.next_element::<Heading>()? else {
                return Ok(());
            };
            *self.observed = self
                .observed
                .checked_add(1)
                .ok_or_else(|| A::Error::custom("manifest heading count overflow"))?;
        }
    }
}

struct BoundedFrontmatterSeed<'a> {
    observed: &'a mut usize,
}

impl<'de> DeserializeSeed<'de> for BoundedFrontmatterSeed<'_> {
    type Value = BTreeMap<String, String>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(BoundedFrontmatterVisitor {
            observed: self.observed,
        })
    }
}

struct BoundedFrontmatterVisitor<'a> {
    observed: &'a mut usize,
}

impl<'de> Visitor<'de> for BoundedFrontmatterVisitor<'_> {
    type Value = BTreeMap<String, String>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a bounded frontmatter map")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut frontmatter = BTreeMap::new();
        loop {
            if *self.observed >= MAX_MANIFEST_FRONTMATTER_ENTRIES {
                return match map.next_key::<IgnoredAny>()? {
                    Some(_) => Err(A::Error::custom(format!(
                        "manifest frontmatter entry count exceeds {MAX_MANIFEST_FRONTMATTER_ENTRIES}"
                    ))),
                    None => Ok(frontmatter),
                };
            }
            let Some(key) = map.next_key::<String>()? else {
                return Ok(frontmatter);
            };
            let value = map.next_value::<String>()?;
            *self.observed = self
                .observed
                .checked_add(1)
                .ok_or_else(|| A::Error::custom("manifest frontmatter entry count overflow"))?;
            frontmatter.insert(key, value);
        }
    }
}

struct BoundedWikilinksSeed<'a> {
    observed: &'a mut usize,
}

impl<'de> DeserializeSeed<'de> for BoundedWikilinksSeed<'_> {
    type Value = Vec<String>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(BoundedWikilinksVisitor {
            observed: self.observed,
        })
    }
}

struct BoundedWikilinksVisitor<'a> {
    observed: &'a mut usize,
}

impl<'de> Visitor<'de> for BoundedWikilinksVisitor<'_> {
    type Value = Vec<String>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a bounded wikilink array")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut wikilinks = Vec::new();
        loop {
            if *self.observed >= MAX_MANIFEST_WIKILINKS {
                return match sequence.next_element::<IgnoredAny>()? {
                    Some(_) => Err(A::Error::custom(format!(
                        "manifest wikilink count exceeds {MAX_MANIFEST_WIKILINKS}"
                    ))),
                    None => Ok(wikilinks),
                };
            }
            let Some(wikilink) = sequence.next_element::<String>()? else {
                return Ok(wikilinks);
            };
            *self.observed = self
                .observed
                .checked_add(1)
                .ok_or_else(|| A::Error::custom("manifest wikilink count overflow"))?;
            wikilinks.try_reserve(1).map_err(|error| {
                A::Error::custom(format!("reserve manifest wikilinks: {error}"))
            })?;
            wikilinks.push(wikilink);
        }
    }
}

fn deserialize_manifest_bounded(bytes: &[u8]) -> Result<Manifest, String> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let manifest = BoundedManifestSeed
        .deserialize(&mut deserializer)
        .map_err(|error| format!("parse manifest: {error}"))?;
    deserializer
        .end()
        .map_err(|error| format!("parse manifest: {error}"))?;
    Ok(manifest)
}

fn parse_args(raw: Vec<String>) -> Result<Args, String> {
    let mut root = PathBuf::from("KnowledgeGraphs/dag-db");
    let mut manifest = None;
    let mut output = None;
    let mut index = 0;
    while index < raw.len() {
        match raw[index].as_str() {
            "--root" => {
                index += 1;
                root = PathBuf::from(
                    raw.get(index)
                        .ok_or_else(|| "--root requires a value".to_owned())?,
                );
            }
            "--manifest" => {
                index += 1;
                manifest = Some(PathBuf::from(
                    raw.get(index)
                        .ok_or_else(|| "--manifest requires a value".to_owned())?,
                ));
            }
            "--output" => {
                index += 1;
                output = Some(PathBuf::from(
                    raw.get(index)
                        .ok_or_else(|| "--output requires a value".to_owned())?,
                ));
            }
            "-h" | "--help" => {
                println!(
                    "usage: dagdb_kg_import_candidates [--root <path>] [--manifest <path>] [--output <path>]"
                );
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
        index += 1;
    }
    Ok(Args {
        root,
        manifest,
        output,
    })
}

fn load_manifest(args: &Args) -> Result<Manifest, String> {
    let manifest = if let Some(path) = &args.manifest {
        let bytes = read_bounded_file(path, MAX_JSON_FILE_BYTES, "manifest")?;
        deserialize_manifest_bounded(&bytes)?
    } else {
        build_manifest(&args.root)?
    };
    if manifest.schema_version != MANIFEST_SCHEMA_VERSION {
        return Err(format!(
            "unsupported manifest schema: {:?}",
            manifest.schema_version
        ));
    }
    if manifest.file_count > MAX_MANIFEST_FILES || manifest.files.len() > MAX_MANIFEST_FILES {
        return Err(format!("manifest file count exceeds {MAX_MANIFEST_FILES}"));
    }
    if manifest.file_count != manifest.files.len() {
        return Err(format!(
            "manifest declared file count {} does not match {} file entries",
            manifest.file_count,
            manifest.files.len()
        ));
    }
    Ok(manifest)
}

#[derive(Debug, Serialize)]
struct CandidateReport {
    schema_version: &'static str,
    source_manifest_schema_version: String,
    graph_root: String,
    node_count: usize,
    edge_count: usize,
    unresolved_wikilink_count: usize,
    nodes: Vec<NodeCandidate>,
    edges: Vec<EdgeCandidate>,
    unresolved_wikilinks: Vec<UnresolvedWikilink>,
}

#[derive(Debug, Serialize)]
struct NodeCandidate {
    candidate_id: String,
    path: String,
    title: String,
    document_type: String,
    status: String,
    project_id: String,
    content_sha256: String,
    byte_length: usize,
    catalog_path: Vec<String>,
    frontmatter: BTreeMap<String, String>,
}

#[derive(Debug, Serialize)]
struct EdgeCandidate {
    candidate_id: String,
    edge_kind: &'static str,
    source_candidate_id: String,
    source_path: String,
    target_wikilink: String,
    target_candidate_id: String,
    target_path: String,
    resolution_status: String,
}

#[derive(Debug, Serialize)]
struct UnresolvedWikilink {
    source_path: String,
    target_wikilink: String,
    resolution_status: String,
}

fn build_candidates(mut manifest: Manifest) -> Result<CandidateReport, String> {
    let edge_work = validate_manifest_semantics(&manifest.files)?;
    manifest
        .files
        .sort_by(|left, right| left.path.cmp(&right.path));
    let link_index = build_link_index(&manifest.files);

    let mut nodes = Vec::new();
    nodes
        .try_reserve_exact(manifest.files.len())
        .map_err(|error| format!("reserve candidate nodes: {error}"))?;
    let mut path_to_node_id = BTreeMap::new();
    for file_entry in &manifest.files {
        let candidate_id = stable_id("kg_node", &[&file_entry.path]);
        path_to_node_id.insert(file_entry.path.clone(), candidate_id.clone());
        nodes.push(NodeCandidate {
            candidate_id,
            path: file_entry.path.clone(),
            title: file_entry.title.clone(),
            document_type: document_type_for(&file_entry.path, &file_entry.frontmatter),
            status: file_entry
                .frontmatter
                .get("status")
                .cloned()
                .unwrap_or_else(|| "unknown".to_owned()),
            project_id: file_entry
                .frontmatter
                .get("project_id")
                .cloned()
                .unwrap_or_default(),
            content_sha256: file_entry.sha256.clone(),
            byte_length: file_entry.byte_length,
            catalog_path: catalog_path(&file_entry.path),
            frontmatter: file_entry.frontmatter.clone(),
        });
    }

    let mut edges = Vec::new();
    let mut unresolved = Vec::new();
    edges
        .try_reserve_exact(edge_work)
        .map_err(|error| format!("reserve candidate edges: {error}"))?;
    unresolved
        .try_reserve_exact(edge_work)
        .map_err(|error| format!("reserve unresolved wikilinks: {error}"))?;
    for file_entry in &manifest.files {
        let source_id = path_to_node_id
            .get(&file_entry.path)
            .ok_or_else(|| format!("missing node id for {}", file_entry.path))?
            .clone();
        for target in &file_entry.wikilinks {
            let matched_paths = link_matches(&link_index, target);
            let (resolution_status, target_path, target_id) = match matched_paths {
                [path] => (
                    "resolved".to_owned(),
                    path.clone(),
                    path_to_node_id
                        .get(path)
                        .ok_or_else(|| format!("missing node id for {path}"))?
                        .clone(),
                ),
                [] => ("unresolved".to_owned(), String::new(), String::new()),
                _ => ("ambiguous".to_owned(), String::new(), String::new()),
            };
            edges.push(EdgeCandidate {
                candidate_id: stable_id("kg_edge", &[&file_entry.path, target]),
                edge_kind: "wikilink",
                source_candidate_id: source_id.clone(),
                source_path: file_entry.path.clone(),
                target_wikilink: target.clone(),
                target_candidate_id: target_id,
                target_path,
                resolution_status: resolution_status.clone(),
            });
            if resolution_status != "resolved" {
                unresolved.push(UnresolvedWikilink {
                    source_path: file_entry.path.clone(),
                    target_wikilink: target.clone(),
                    resolution_status,
                });
            }
        }
    }
    edges.sort_by(|left, right| {
        (left.source_path.as_str(), left.target_wikilink.as_str())
            .cmp(&(right.source_path.as_str(), right.target_wikilink.as_str()))
    });
    unresolved.sort_by(|left, right| {
        (left.source_path.as_str(), left.target_wikilink.as_str())
            .cmp(&(right.source_path.as_str(), right.target_wikilink.as_str()))
    });

    Ok(CandidateReport {
        schema_version: SCHEMA_VERSION,
        source_manifest_schema_version: manifest.schema_version,
        graph_root: manifest.graph_root,
        node_count: nodes.len(),
        edge_count: edges.len(),
        unresolved_wikilink_count: unresolved.len(),
        nodes,
        edges,
        unresolved_wikilinks: unresolved,
    })
}

fn validate_manifest_semantics(files: &[ManifestFile]) -> Result<usize, String> {
    if files.len() > MAX_MANIFEST_FILES {
        return Err(format!("manifest file count exceeds {MAX_MANIFEST_FILES}"));
    }

    let max_path_bytes = files
        .iter()
        .map(|file_entry| file_entry.path.len())
        .max()
        .unwrap_or(0);
    let mut total_wikilinks = 0_usize;
    let mut generated_byte_work = 0_usize;
    for file_entry in files {
        total_wikilinks = total_wikilinks
            .checked_add(file_entry.wikilinks.len())
            .ok_or_else(|| "manifest wikilink count overflow".to_owned())?;
        if total_wikilinks > MAX_MANIFEST_WIKILINKS {
            return Err(format!(
                "manifest wikilink edge work exceeds {MAX_MANIFEST_WIKILINKS}"
            ));
        }

        // This conservatively covers node/path-index/frontmatter string clones.
        // Pretty-JSON bytes are enforced independently by BoundedOutput.
        let frontmatter_bytes =
            file_entry
                .frontmatter
                .iter()
                .try_fold(0_usize, |total, (key, value)| {
                    total
                        .checked_add(key.len())
                        .and_then(|next| next.checked_add(value.len()))
                        .ok_or_else(|| "candidate generated byte work overflow".to_owned())
                })?;
        for (bytes, copies) in [
            (file_entry.path.len(), 12_usize),
            (file_entry.title.len(), 3_usize),
            (file_entry.sha256.len(), 2_usize),
            (frontmatter_bytes, 3_usize),
        ] {
            let projected = bytes
                .checked_mul(copies)
                .ok_or_else(|| "candidate generated byte work overflow".to_owned())?;
            generated_byte_work =
                checked_candidate_generated_bytes(generated_byte_work, projected)?;
        }
        let catalog_components = file_entry
            .path
            .split('/')
            .filter(|component| !component.is_empty())
            .count();
        for (elements, work_per_element) in [
            (catalog_components, CANDIDATE_CATALOG_COMPONENT_WORK),
            (
                file_entry.frontmatter.len(),
                CANDIDATE_FRONTMATTER_ENTRY_WORK,
            ),
        ] {
            let projected = elements
                .checked_mul(work_per_element)
                .ok_or_else(|| "candidate generated byte work overflow".to_owned())?;
            generated_byte_work =
                checked_candidate_generated_bytes(generated_byte_work, projected)?;
        }
        generated_byte_work =
            checked_candidate_generated_bytes(generated_byte_work, CANDIDATE_FILE_FIXED_WORK)?;

        for target in &file_entry.wikilinks {
            // Worst case includes the edge plus unresolved row, stable-ID input,
            // and a resolved target path as long as the longest manifest path.
            for (bytes, copies) in [
                (file_entry.path.len(), 3_usize),
                (target.len(), 3_usize),
                (max_path_bytes, 1_usize),
            ] {
                let projected = bytes
                    .checked_mul(copies)
                    .ok_or_else(|| "candidate generated byte work overflow".to_owned())?;
                generated_byte_work =
                    checked_candidate_generated_bytes(generated_byte_work, projected)?;
            }
            generated_byte_work =
                checked_candidate_generated_bytes(generated_byte_work, CANDIDATE_EDGE_FIXED_WORK)?;
        }
    }

    // Uniqueness allocations happen only after count and byte work are bounded.
    let mut paths = BTreeSet::new();
    for file_entry in files {
        if !paths.insert(file_entry.path.as_str()) {
            return Err(format!(
                "duplicate manifest path rejected: {}",
                file_entry.path
            ));
        }
        let mut unique_wikilinks = BTreeSet::new();
        for target in &file_entry.wikilinks {
            if !unique_wikilinks.insert(target.as_str()) {
                return Err(format!(
                    "duplicate wikilink rejected for {}: {target}",
                    file_entry.path
                ));
            }
        }
    }
    Ok(total_wikilinks)
}

fn checked_candidate_generated_bytes(current: usize, additional: usize) -> Result<usize, String> {
    let next = current
        .checked_add(additional)
        .ok_or_else(|| "candidate generated byte work overflow".to_owned())?;
    if next > MAX_CANDIDATE_CONSTRUCTION_WORK_BYTES {
        return Err(format!(
            "candidate generated byte work exceeds {MAX_CANDIDATE_CONSTRUCTION_WORK_BYTES} bytes"
        ));
    }
    Ok(next)
}

fn link_matches<'a>(index: &'a BTreeMap<String, Vec<String>>, target: &str) -> &'a [String] {
    index.get(target).map(Vec::as_slice).unwrap_or(&[])
}

fn build_link_index(files: &[ManifestFile]) -> BTreeMap<String, Vec<String>> {
    let mut index: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for file_entry in files {
        for key in link_keys_for_file(file_entry) {
            index.entry(key).or_default().push(file_entry.path.clone());
        }
    }
    for paths in index.values_mut() {
        paths.sort();
    }
    index
}

fn link_keys_for_file(file_entry: &ManifestFile) -> Vec<String> {
    let path = file_entry.path.as_str();
    let path_without_ext = path.strip_suffix(".md").unwrap_or(path);
    let basename_without_ext = Path::new(path)
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or_default();
    let mut keys = BTreeSet::from([
        path.to_owned(),
        path_without_ext.to_owned(),
        basename_without_ext.to_owned(),
    ]);
    if !file_entry.title.trim().is_empty() {
        keys.insert(file_entry.title.clone());
    }
    keys.into_iter()
        .map(|key| key.trim().to_owned())
        .filter(|key| !key.is_empty())
        .collect()
}

fn catalog_path(path: &str) -> Vec<String> {
    let without_ext = path.strip_suffix(".md").unwrap_or(path);
    without_ext
        .split('/')
        .filter(|part| !part.is_empty())
        .map(str::to_owned)
        .collect()
}

fn document_type_for(path: &str, frontmatter: &BTreeMap<String, String>) -> String {
    if let Some(explicit) = frontmatter.get("type").map(|value| value.trim()) {
        if !explicit.is_empty() && explicit != "unknown" {
            return explicit.to_owned();
        }
    }

    let stem = Path::new(path)
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or_default();
    let lower_path = path.to_ascii_lowercase();
    let basename = Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    if stem == "00_Index" {
        "index"
    } else if stem == "01_Project_Brief" {
        "project_brief"
    } else if stem == "00_Pinned_Mission" || lower_path.contains("pinned_mission") {
        "pinned_mission"
    } else if path.ends_with(".plan.md") {
        "plan"
    } else if path.ends_with(".schema.md") {
        "export_contract"
    } else if basename.ends_with("-status.md") {
        "batch_report"
    } else if basename.ends_with("-contract.md") {
        "requirement"
    } else if lower_path.contains("/03_decisions/") || stem.eq_ignore_ascii_case("decision log") {
        "decision"
    } else if lower_path.contains("/08_open_questions/") || lower_path.contains("open-question") {
        "open_question"
    } else if lower_path.contains("milestone") && lower_path.contains("ladder") {
        "milestone_ladder"
    } else if lower_path.contains("/09_exports/") || lower_path.starts_with("09_exports/") {
        "export"
    } else {
        "technical_note"
    }
    .to_owned()
}

fn stable_id(prefix: &str, parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(parts.join("\0").as_bytes());
    let digest = hasher.finalize();
    let hex = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("{prefix}_{}", &hex[..24])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest_file(path: String) -> ManifestFile {
        ManifestFile {
            path,
            sha256: String::new(),
            byte_length: 0,
            frontmatter: BTreeMap::new(),
            title: String::new(),
            headings: Vec::new(),
            wikilinks: Vec::new(),
        }
    }

    fn manifest_with(files: Vec<ManifestFile>) -> Manifest {
        Manifest {
            schema_version: MANIFEST_SCHEMA_VERSION.to_owned(),
            graph_root: String::new(),
            file_count: files.len(),
            files,
        }
    }

    fn args_for(path: PathBuf) -> Args {
        Args {
            root: PathBuf::new(),
            manifest: Some(path),
            output: None,
        }
    }

    #[test]
    fn imported_manifest_accepts_16_mib_and_rejects_plus_one() -> Result<(), String> {
        let fixture = tempfile::tempdir().map_err(|error| error.to_string())?;
        let path = fixture.path().join("manifest.json");
        let mut manifest = Manifest {
            schema_version: MANIFEST_SCHEMA_VERSION.to_owned(),
            graph_root: String::new(),
            file_count: 0,
            files: Vec::new(),
        };
        let base = serde_json::to_vec(&manifest).map_err(|error| error.to_string())?;
        manifest.graph_root = "x".repeat(16_777_216 - base.len());
        let exact = serde_json::to_vec(&manifest).map_err(|error| error.to_string())?;
        assert_eq!(exact.len(), 16_777_216);
        fs::write(&path, &exact).map_err(|error| error.to_string())?;

        let args = args_for(path.clone());
        assert_eq!(load_manifest(&args)?.files.len(), 0);

        let mut oversized = exact;
        oversized.push(b' ');
        fs::write(&path, oversized).map_err(|error| error.to_string())?;
        let error = match load_manifest(&args) {
            Err(error) => error,
            Ok(_) => return Err("limit plus one was accepted".to_owned()),
        };
        assert!(error.contains("exceeds"));
        Ok(())
    }

    #[test]
    fn bounded_manifest_export_is_candidate_import_readable() -> Result<(), String> {
        let fixture = tempfile::tempdir().map_err(|error| error.to_string())?;
        let path = fixture.path().join("manifest.json");
        let mut source = manifest_file("source.md".to_owned());
        source.title = "Source".to_owned();
        source.headings.push(Heading {
            level: 1,
            text: "Source".to_owned(),
        });
        source.wikilinks.push("target".to_owned());
        let manifest = manifest_with(vec![source]);
        let output =
            serialize_pretty_json_bounded(&manifest, MAX_JSON_FILE_BYTES, "manifest output")?;
        fs::write(&path, &output).map_err(|error| error.to_string())?;

        let imported = load_manifest(&args_for(path))?;
        assert_eq!(imported.file_count, 1);
        assert_eq!(imported.files[0].path, "source.md");
        assert_eq!(imported.files[0].title, "Source");
        assert_eq!(imported.files[0].wikilinks, vec!["target".to_owned()]);
        assert!(imported.files[0].headings.is_empty());
        Ok(())
    }

    #[test]
    fn bounded_manifest_import_preserves_legacy_sequence_wire_shape() -> Result<(), String> {
        let wire = serde_json::json!([
            MANIFEST_SCHEMA_VERSION,
            "root",
            1,
            [["source.md", "digest", 12, {"owner": "dagdb"}, "Source", [[1, "Source"]], ["target"]]]
        ]);
        let baseline: Manifest =
            serde_json::from_value(wire.clone()).map_err(|error| error.to_string())?;
        assert_eq!(baseline.files[0].headings.len(), 1);

        let encoded = serde_json::to_vec(&wire).map_err(|error| error.to_string())?;
        let imported = deserialize_manifest_bounded(&encoded)?;
        assert_eq!(imported.schema_version, MANIFEST_SCHEMA_VERSION);
        assert_eq!(imported.files[0].path, "source.md");
        assert_eq!(imported.files[0].frontmatter["owner"], "dagdb");
        assert_eq!(imported.files[0].wikilinks, vec!["target".to_owned()]);
        assert!(imported.files[0].headings.is_empty());
        Ok(())
    }

    #[test]
    fn imported_manifest_accepts_exact_file_count_limit() -> Result<(), String> {
        let fixture = tempfile::tempdir().map_err(|error| error.to_string())?;
        let path = fixture.path().join("manifest.json");
        let manifest = manifest_with(
            (0..MAX_MANIFEST_FILES)
                .map(|index| manifest_file(format!("{index}.md")))
                .collect(),
        );
        fs::write(
            &path,
            serde_json::to_vec(&manifest).map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        assert_eq!(
            load_manifest(&args_for(path))?.files.len(),
            MAX_MANIFEST_FILES
        );
        Ok(())
    }

    #[test]
    fn imported_manifest_rejects_declared_file_count_limit_plus_one() -> Result<(), String> {
        let fixture = tempfile::tempdir().map_err(|error| error.to_string())?;
        let path = fixture.path().join("manifest.json");
        let mut manifest = manifest_with(Vec::new());
        manifest.file_count = MAX_MANIFEST_FILES + 1;
        fs::write(
            &path,
            serde_json::to_vec(&manifest).map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        let error = match load_manifest(&args_for(path)) {
            Err(error) => error,
            Ok(_) => return Err("declared count plus one was accepted".to_owned()),
        };
        assert!(error.contains("file count"));
        Ok(())
    }

    #[test]
    fn imported_manifest_rejects_declared_actual_file_count_mismatch() -> Result<(), String> {
        let fixture = tempfile::tempdir().map_err(|error| error.to_string())?;
        let path = fixture.path().join("manifest.json");
        let mut manifest = manifest_with(vec![manifest_file("one.md".to_owned())]);
        manifest.file_count = 0;
        fs::write(
            &path,
            serde_json::to_vec(&manifest).map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        let error = match load_manifest(&args_for(path)) {
            Err(error) => error,
            Ok(_) => return Err("declared/actual mismatch was accepted".to_owned()),
        };
        assert!(error.contains("does not match"));
        Ok(())
    }

    #[test]
    fn imported_manifest_rejects_actual_file_count_limit_plus_one() -> Result<(), String> {
        let fixture = tempfile::tempdir().map_err(|error| error.to_string())?;
        let path = fixture.path().join("manifest.json");
        let manifest = manifest_with(
            (0..=MAX_MANIFEST_FILES)
                .map(|index| manifest_file(format!("{index}.md")))
                .collect(),
        );
        fs::write(
            &path,
            serde_json::to_vec(&manifest).map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        let error = match load_manifest(&args_for(path)) {
            Err(error) => error,
            Ok(_) => return Err("actual count plus one was accepted".to_owned()),
        };
        assert!(error.contains("file count"));
        Ok(())
    }

    #[test]
    fn imported_manifest_validates_but_does_not_retain_dense_headings() -> Result<(), String> {
        let fixture = tempfile::tempdir().map_err(|error| error.to_string())?;
        let path = fixture.path().join("manifest.json");
        let mut source = manifest_file("source.md".to_owned());
        let heading = Heading {
            level: 1,
            text: String::new(),
        };
        source.headings = vec![heading.clone(); MAX_MANIFEST_HEADINGS];
        let mut exact = manifest_with(vec![source.clone()]);
        let baseline = serde_json::to_vec(&exact).map_err(|error| error.to_string())?;
        exact.graph_root = "x".repeat(MAX_JSON_FILE_BYTES - baseline.len());
        let encoded = serde_json::to_vec(&exact).map_err(|error| error.to_string())?;
        assert_eq!(encoded.len(), MAX_JSON_FILE_BYTES);
        fs::write(&path, encoded).map_err(|error| error.to_string())?;

        let imported = load_manifest(&args_for(path.clone()))?;
        assert!(
            imported.files[0].headings.is_empty(),
            "candidate import must stream-validate and discard unused headings"
        );

        source.headings.push(heading);
        let plus_one =
            serde_json::to_vec(&manifest_with(vec![source])).map_err(|error| error.to_string())?;
        assert!(plus_one.len() < MAX_JSON_FILE_BYTES);
        fs::write(&path, plus_one).map_err(|error| error.to_string())?;
        let error = match load_manifest(&args_for(path)) {
            Err(error) => error,
            Ok(_) => return Err("heading limit plus one was accepted".to_owned()),
        };
        assert!(error.contains("heading"));
        Ok(())
    }

    #[test]
    fn imported_manifest_bounds_frontmatter_during_deserialization() -> Result<(), String> {
        let fixture = tempfile::tempdir().map_err(|error| error.to_string())?;
        let path = fixture.path().join("manifest.json");
        let mut source = manifest_file("source.md".to_owned());
        source.frontmatter = (0..MAX_MANIFEST_FRONTMATTER_ENTRIES)
            .map(|index| (format!("key-{index}"), String::new()))
            .collect();
        let mut exact = manifest_with(vec![source.clone()]);
        let baseline = serde_json::to_vec(&exact).map_err(|error| error.to_string())?;
        exact.graph_root = "x".repeat(MAX_JSON_FILE_BYTES - baseline.len());
        let encoded = serde_json::to_vec(&exact).map_err(|error| error.to_string())?;
        assert_eq!(encoded.len(), MAX_JSON_FILE_BYTES);
        fs::write(&path, encoded).map_err(|error| error.to_string())?;
        assert_eq!(
            load_manifest(&args_for(path.clone()))?.files[0]
                .frontmatter
                .len(),
            MAX_MANIFEST_FRONTMATTER_ENTRIES
        );

        source
            .frontmatter
            .insert("one-too-many".to_owned(), String::new());
        let plus_one =
            serde_json::to_vec(&manifest_with(vec![source])).map_err(|error| error.to_string())?;
        assert!(plus_one.len() < MAX_JSON_FILE_BYTES);
        fs::write(&path, plus_one).map_err(|error| error.to_string())?;
        let error = match load_manifest(&args_for(path)) {
            Err(error) => error,
            Ok(_) => return Err("frontmatter limit plus one was accepted".to_owned()),
        };
        assert!(error.contains("frontmatter"));
        Ok(())
    }

    #[test]
    fn imported_manifest_bounds_wikilinks_during_deserialization() -> Result<(), String> {
        let fixture = tempfile::tempdir().map_err(|error| error.to_string())?;
        let path = fixture.path().join("manifest.json");
        let mut source = manifest_file("source.md".to_owned());
        source.wikilinks = (0..MAX_MANIFEST_WIKILINKS)
            .map(|index| format!("target-{index}"))
            .collect();
        let exact = manifest_with(vec![source.clone()]);
        let encoded = serde_json::to_vec(&exact).map_err(|error| error.to_string())?;
        assert!(encoded.len() < MAX_JSON_FILE_BYTES);
        fs::write(&path, encoded).map_err(|error| error.to_string())?;
        assert_eq!(
            load_manifest(&args_for(path.clone()))?.files[0]
                .wikilinks
                .len(),
            MAX_MANIFEST_WIKILINKS
        );

        source.wikilinks.push("one-too-many".to_owned());
        let plus_one =
            serde_json::to_vec(&manifest_with(vec![source])).map_err(|error| error.to_string())?;
        assert!(plus_one.len() < MAX_JSON_FILE_BYTES);
        fs::write(&path, plus_one).map_err(|error| error.to_string())?;
        let error = match load_manifest(&args_for(path)) {
            Err(error) => error,
            Ok(_) => return Err("wikilink limit plus one was accepted".to_owned()),
        };
        assert!(error.contains("wikilink"));
        Ok(())
    }

    #[test]
    fn candidate_edge_budget_accepts_65536_and_rejects_65537() -> Result<(), String> {
        assert_eq!(MAX_MANIFEST_WIKILINKS, 65_536);
        let mut source = manifest_file("source.md".to_owned());
        source.wikilinks = (0..65_536).map(|index| format!("target-{index}")).collect();
        let report = build_candidates(manifest_with(vec![source.clone()]))?;
        assert_eq!(report.edge_count, 65_536);

        source.wikilinks.push("one-too-many".to_owned());
        let error = match build_candidates(manifest_with(vec![source])) {
            Err(error) => error,
            Ok(_) => return Err("65,537 candidate edges were accepted".to_owned()),
        };
        assert!(error.contains("wikilink"));
        Ok(())
    }

    #[test]
    fn imported_manifest_rejects_duplicate_paths_and_wikilinks() -> Result<(), String> {
        let duplicate_path_error = match build_candidates(manifest_with(vec![
            manifest_file("duplicate.md".to_owned()),
            manifest_file("duplicate.md".to_owned()),
        ])) {
            Err(error) => error,
            Ok(_) => return Err("duplicate manifest paths were accepted".to_owned()),
        };
        assert!(duplicate_path_error.contains("duplicate manifest path"));

        let mut source = manifest_file("source.md".to_owned());
        source.wikilinks = vec!["duplicate".to_owned(), "duplicate".to_owned()];
        let error = match build_candidates(manifest_with(vec![source])) {
            Err(error) => error,
            Ok(_) => return Err("duplicate wikilinks were accepted".to_owned()),
        };
        assert!(error.contains("duplicate wikilink"));
        Ok(())
    }

    #[test]
    fn ambiguous_link_resolution_borrows_the_index_match_slice() -> Result<(), String> {
        let mut files = (0..MAX_MANIFEST_FILES)
            .map(|index| {
                let mut file = manifest_file(format!("directory-{index}/collision.md"));
                file.title = "collision".to_owned();
                file
            })
            .collect::<Vec<_>>();
        files[0].wikilinks.push("collision".to_owned());
        let index = build_link_index(&files);
        let stored = index
            .get("collision")
            .ok_or_else(|| "missing collision index".to_owned())?;
        let borrowed = link_matches(&index, "collision");
        assert_eq!(borrowed.len(), MAX_MANIFEST_FILES);
        assert!(std::ptr::eq(borrowed.as_ptr(), stored.as_ptr()));

        let report = build_candidates(manifest_with(files))?;
        assert_eq!(report.edge_count, 1);
        assert_eq!(report.unresolved_wikilink_count, 1);
        Ok(())
    }

    #[test]
    fn repeated_long_source_and_targets_accept_exact_64_mib_work_and_reject_plus_one()
    -> Result<(), String> {
        assert_eq!(MAX_CANDIDATE_CONSTRUCTION_WORK_BYTES, 67_108_864);

        const SOURCE_PATH_BYTES: usize = 800_000;
        const TARGET_COUNT: usize = 16;
        const SHORT_TARGET_BYTES: usize = 100_000;
        const SHA_BYTES: usize = 3;
        let bytes_without_targets = SOURCE_PATH_BYTES * (12 + 4 * TARGET_COUNT)
            + SHA_BYTES * 2
            + CANDIDATE_CATALOG_COMPONENT_WORK
            + CANDIDATE_FILE_FIXED_WORK
            + TARGET_COUNT * CANDIDATE_EDGE_FIXED_WORK;
        let target_byte_work = MAX_CANDIDATE_CONSTRUCTION_WORK_BYTES - bytes_without_targets;
        assert_eq!(target_byte_work % 3, 0);
        let total_target_bytes = target_byte_work / 3;
        let final_target_bytes = total_target_bytes - SHORT_TARGET_BYTES * (TARGET_COUNT - 1);

        let mut targets = (0..TARGET_COUNT - 1)
            .map(|index| long_tagged_string(SHORT_TARGET_BYTES, index))
            .collect::<Vec<_>>();
        targets.push(long_tagged_string(final_target_bytes, TARGET_COUNT - 1));
        let exact = ManifestFile {
            path: format!("{}.md", "s".repeat(SOURCE_PATH_BYTES - 3)),
            title: String::new(),
            sha256: "x".repeat(SHA_BYTES),
            byte_length: 0,
            frontmatter: BTreeMap::new(),
            headings: Vec::new(),
            wikilinks: targets,
        };
        assert_eq!(
            validate_manifest_semantics(std::slice::from_ref(&exact))?,
            TARGET_COUNT
        );

        let mut plus_one = exact;
        plus_one.wikilinks[TARGET_COUNT - 1].push('x');
        let error = match validate_manifest_semantics(&[plus_one]) {
            Err(error) => error,
            Ok(_) => return Err("generated byte work limit plus one was accepted".to_owned()),
        };
        assert!(error.contains("exceeds"));
        Ok(())
    }

    #[test]
    fn slash_dense_path_component_storage_is_bounded_before_construction() -> Result<(), String> {
        let component_count = MAX_CANDIDATE_CONSTRUCTION_WORK_BYTES
            .checked_div(CANDIDATE_CATALOG_COMPONENT_WORK)
            .ok_or_else(|| "invalid catalog component work".to_owned())?
            + 1;
        let mut source = manifest_file(format!("{}a.md", "a/".repeat(component_count - 1)));
        source.title.clear();
        source.sha256.clear();
        let manifest = manifest_with(vec![source]);
        let encoded = serde_json::to_vec(&manifest).map_err(|error| error.to_string())?;
        assert!(encoded.len() < MAX_JSON_FILE_BYTES);

        let error = match build_candidates(manifest) {
            Err(error) => error,
            Ok(_) => return Err("slash-dense catalog allocation was accepted".to_owned()),
        };
        assert!(error.contains("generated byte work"));
        Ok(())
    }

    #[test]
    fn tiny_frontmatter_entry_storage_is_bounded_before_construction() -> Result<(), String> {
        let entry_count = MAX_CANDIDATE_CONSTRUCTION_WORK_BYTES
            .checked_div(CANDIDATE_FRONTMATTER_ENTRY_WORK)
            .ok_or_else(|| "invalid frontmatter entry work".to_owned())?
            + 1;
        let mut source = manifest_file("source.md".to_owned());
        source.title.clear();
        source.sha256.clear();
        source.frontmatter = (0..entry_count)
            .map(|index| (format!("k{index:06x}"), String::new()))
            .collect();
        let manifest = manifest_with(vec![source]);
        let encoded = serde_json::to_vec(&manifest).map_err(|error| error.to_string())?;
        assert!(encoded.len() < MAX_JSON_FILE_BYTES);

        let error = match build_candidates(manifest) {
            Err(error) => error,
            Ok(_) => return Err("frontmatter entry allocation was accepted".to_owned()),
        };
        assert!(error.contains("generated byte work"));
        Ok(())
    }

    fn long_tagged_string(len: usize, index: usize) -> String {
        let tag = format!("target-{index:02}-");
        assert!(tag.len() <= len);
        format!("{tag}{}", "t".repeat(len - tag.len()))
    }

    #[test]
    fn bounded_candidate_output_preserves_pretty_json_shape() -> Result<(), String> {
        let report = build_candidates(manifest_with(vec![manifest_file("source.md".to_owned())]))?;
        let actual = serialize_candidates_bounded(&report)?;
        let mut expected = serde_json::to_vec_pretty(&report).map_err(|error| error.to_string())?;
        expected.push(b'\n');
        assert_eq!(actual, expected);
        Ok(())
    }

    #[test]
    fn candidate_output_exact_16_mib_is_persist_readable_and_plus_one_is_rejected()
    -> Result<(), String> {
        assert_eq!(MAX_CANDIDATE_OUTPUT_BYTES, 16_777_216);
        assert_eq!(MAX_CANDIDATE_OUTPUT_BYTES, MAX_JSON_FILE_BYTES);
        let mut report =
            build_candidates(manifest_with(vec![manifest_file("source.md".to_owned())]))?;
        report.graph_root.clear();
        let baseline = serialize_candidates_bounded(&report)?;
        let content_bytes = MAX_CANDIDATE_OUTPUT_BYTES
            .checked_sub(baseline.len())
            .ok_or_else(|| "candidate baseline exceeds output limit".to_owned())?;
        let escaped_count = content_bytes / 6;
        let literal_count = content_bytes % 6;
        report
            .graph_root
            .try_reserve(escaped_count + literal_count)
            .map_err(|error| error.to_string())?;
        report
            .graph_root
            .extend(std::iter::repeat_n('\0', escaped_count));
        report
            .graph_root
            .extend(std::iter::repeat_n('x', literal_count));

        let output = serialize_candidates_bounded(&report)?;
        assert_eq!(output.len(), MAX_CANDIDATE_OUTPUT_BYTES);

        let fixture = tempfile::tempdir().map_err(|error| error.to_string())?;
        let report_path = fixture.path().join("candidate-report.json");
        fs::write(&report_path, &output).map_err(|error| error.to_string())?;
        let persist_input =
            read_bounded_file(&report_path, MAX_JSON_FILE_BYTES, "KG import report")?;
        assert_eq!(persist_input, output);
        serde_json::from_slice::<serde_json::Value>(&persist_input)
            .map_err(|error| format!("parse persisted candidate report: {error}"))?;

        report.graph_root.push('x');
        let error = match serialize_candidates_bounded(&report) {
            Err(error) => error,
            Ok(_) => return Err("bounded output plus one was accepted".to_owned()),
        };
        assert!(error.contains("exceeds"));
        Ok(())
    }

    #[test]
    fn repeated_long_source_and_targets_are_rejected_before_candidate_construction()
    -> Result<(), String> {
        let long_component = "x".repeat(262_144);
        let mut source = manifest_file(format!("{long_component}.md"));
        source.wikilinks = (0..36)
            .map(|index| format!("{long_component}-{index}"))
            .collect();
        let manifest = manifest_with(vec![source]);
        let encoded = serde_json::to_vec(&manifest).map_err(|error| error.to_string())?;
        assert!(encoded.len() < MAX_JSON_FILE_BYTES);

        let error = match build_candidates(manifest) {
            Err(error) => error,
            Ok(_) => return Err("amplifying candidate strings were accepted".to_owned()),
        };
        assert!(error.contains("generated byte work"));
        Ok(())
    }
}
