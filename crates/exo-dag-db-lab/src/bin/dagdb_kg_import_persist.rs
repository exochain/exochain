//! Persist a validated KG dry-run import report into Postgres.
//!
//! Reads report JSON from a file path argument and writes a persisted import
//! summary JSON to stdout. Uses `DATABASE_URL` when set, otherwise
//! `EXO_DAGDB_TEST_DATABASE_URL`.

use std::{env, path::Path, process};

use exo_dag_db_exchange::kg_import::KG_IMPORT_DATABASE_URL_ENV;
use exo_dag_db_lab::kg_markdown_manifest::{MAX_JSON_FILE_BYTES, read_bounded_file};
use exo_dag_db_postgres::postgres::{
    DAGDB_GRAPH_SCHEMA_SQL, DAGDB_SCHEMA_SQL, kg_import::persist_kg_import_report,
};
use sqlx::postgres::PgPoolOptions;

#[tokio::main]
async fn main() {
    let report_path = match env::args().nth(1) {
        Some(path) => path,
        None => {
            eprintln!("usage: dagdb_kg_import_persist <report.json>");
            process::exit(2);
        }
    };

    let report_json = match read_report_json(Path::new(&report_path)) {
        Ok(text) => text,
        Err(error) => {
            eprintln!("kg_import_report_read_failed: {error}");
            process::exit(1);
        }
    };

    let database_url = env::var("DATABASE_URL")
        .or_else(|_| env::var(KG_IMPORT_DATABASE_URL_ENV))
        .unwrap_or_else(|_| {
            eprintln!("gateway database unavailable");
            process::exit(1);
        });

    let pool = match PgPoolOptions::new()
        .max_connections(2)
        .connect(database_url.as_str())
        .await
    {
        Ok(pool) => pool,
        Err(error) => {
            eprintln!("kg_import_postgres_connect_failed: {error}");
            process::exit(1);
        }
    };

    if let Err(error) = sqlx::raw_sql(DAGDB_SCHEMA_SQL).execute(&pool).await {
        eprintln!("kg_import_schema_apply_failed: {error}");
        process::exit(1);
    }
    if let Err(error) = sqlx::raw_sql(DAGDB_GRAPH_SCHEMA_SQL).execute(&pool).await {
        eprintln!("kg_import_graph_schema_apply_failed: {error}");
        process::exit(1);
    }

    match persist_kg_import_report(&pool, &report_json).await {
        Ok(summary) => {
            let output = serde_json::to_string(&summary).unwrap_or_else(|error| {
                eprintln!("kg_import_summary_encode_failed: {error}");
                process::exit(1);
            });
            pool.close().await;
            println!("{output}");
        }
        Err(error) => {
            pool.close().await;
            eprintln!("{error}");
            process::exit(1);
        }
    }
}

fn read_report_json(path: &Path) -> Result<String, String> {
    let bytes = read_bounded_file(path, MAX_JSON_FILE_BYTES, "KG import report")?;
    String::from_utf8(bytes).map_err(|error| format!("KG import report is not UTF-8: {error}"))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn persisted_import_report_accepts_16_mib_and_rejects_plus_one() -> Result<(), String> {
        let fixture = tempfile::tempdir().map_err(|error| error.to_string())?;
        let path = fixture.path().join("report.json");
        let mut exact = b"{}".to_vec();
        exact.resize(16_777_216, b' ');
        fs::write(&path, &exact).map_err(|error| error.to_string())?;
        assert_eq!(read_report_json(&path)?.len(), 16_777_216);

        exact.push(b' ');
        fs::write(&path, exact).map_err(|error| error.to_string())?;
        let error = match read_report_json(&path) {
            Err(error) => error,
            Ok(_) => return Err("limit plus one was accepted".to_owned()),
        };
        assert!(error.contains("exceeds"));
        Ok(())
    }
}
