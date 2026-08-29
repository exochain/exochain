use std::{
    env, fs,
    io::{self, Write},
    path::PathBuf,
};

use exo_dag_db_lab::kg_markdown_manifest::{
    MAX_JSON_FILE_BYTES, build_manifest, serialize_pretty_json_bounded,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("dagdb_kg_export_manifest_error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = parse_args(env::args().skip(1).collect())?;
    let manifest = build_manifest(&args.root)?;
    let encoded = serialize_pretty_json_bounded(&manifest, MAX_JSON_FILE_BYTES, "manifest output")?;

    if let Some(output) = args.output {
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("create output directory: {error}"))?;
        }
        fs::write(&output, encoded).map_err(|error| format!("write output: {error}"))?;
    } else {
        io::stdout()
            .write_all(&encoded)
            .map_err(|error| format!("write stdout: {error}"))?;
    }
    Ok(())
}

struct Args {
    root: PathBuf,
    output: Option<PathBuf>,
}

fn parse_args(raw: Vec<String>) -> Result<Args, String> {
    let mut root = PathBuf::from("KnowledgeGraphs/dag-db");
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
            "--output" => {
                index += 1;
                output = Some(PathBuf::from(
                    raw.get(index)
                        .ok_or_else(|| "--output requires a value".to_owned())?,
                ));
            }
            "-h" | "--help" => {
                println!("usage: dagdb_kg_export_manifest [--root <path>] [--output <path>]");
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
        index += 1;
    }
    Ok(Args { root, output })
}
