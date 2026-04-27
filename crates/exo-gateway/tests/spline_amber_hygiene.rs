#![allow(clippy::expect_used)]

use std::{fs, path::Path};

fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("repo root")
}

fn collect_rs_files(dir: &Path, files: &mut Vec<std::path::PathBuf>) {
    for entry in fs::read_dir(dir).expect("read source dir") {
        let entry = entry.expect("read source entry");
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, files);
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
            files.push(path);
        }
    }
}

#[test]
fn spline_compiled_rust_sources_do_not_use_float_or_wall_clock_time() {
    let root = repo_root();
    let source_dirs = [
        root.join("crates/exo-api/src"),
        root.join("crates/exo-gateway/src"),
        root.join("crates/exo-messaging/src"),
    ];
    let forbidden = [
        ("f32", "floating-point score or arithmetic"),
        ("f64", "floating-point score or arithmetic"),
        ("SystemTime::now", "wall-clock time"),
        ("chrono::Utc::now", "wall-clock time"),
    ];

    let mut rust_files = Vec::new();
    for dir in source_dirs {
        collect_rs_files(&dir, &mut rust_files);
    }

    let mut violations = Vec::new();
    for file in rust_files {
        let source = fs::read_to_string(&file).expect("read source file");
        for (line_index, line) in source.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with("#[cfg(test)]") {
                continue;
            }

            for (needle, reason) in forbidden {
                if line.contains(needle) {
                    violations.push(format!(
                        "{}:{} contains {} ({})",
                        file.strip_prefix(root).expect("relative path").display(),
                        line_index + 1,
                        needle,
                        reason
                    ));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "Spline determinism hygiene violations:\n{}",
        violations.join("\n")
    );
}

#[test]
fn livesafe_and_notifications_orphans_are_removed_until_audited() {
    let gateway_src = repo_root().join("crates/exo-gateway/src");
    let orphan_files = [
        gateway_src.join("livesafe.rs"),
        gateway_src.join("notifications.rs"),
    ];

    let present: Vec<_> = orphan_files
        .iter()
        .filter(|path| path.exists())
        .map(|path| {
            path.strip_prefix(repo_root())
                .expect("relative path")
                .display()
                .to_string()
        })
        .collect();

    assert!(
        present.is_empty(),
        "unwired gateway orphan files must stay removed until audited: {}",
        present.join(", ")
    );
}

#[test]
fn livesafe_schema_uses_integer_basis_points() {
    let root = repo_root();
    let migration =
        fs::read_to_string(root.join(
            "crates/exo-gateway/migrations/20260426000001_livesafe_composite_basis_points.sql",
        ))
        .expect("read LiveSafe basis-points migration");

    assert!(
        migration.contains(
            "ADD COLUMN IF NOT EXISTS odentity_composite_basis_points INTEGER NOT NULL DEFAULT 0"
        ),
        "LiveSafe migration must add integer basis-points storage"
    );
    assert!(
        migration.contains("DROP COLUMN IF EXISTS odentity_composite"),
        "LiveSafe migration must remove the legacy floating-point score column"
    );
}

#[cfg(feature = "production-db")]
#[tokio::test]
async fn livesafe_basis_points_roundtrip_uses_integer_column() {
    use exo_gateway::db::{get_livesafe_identity, insert_livesafe_identity};
    use sqlx::{Row, postgres::PgPoolOptions};

    let url = match std::env::var("DATABASE_URL") {
        Ok(url) => url,
        Err(_) => return,
    };
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("connect test database");
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("run migrations");

    let did = "did:exo:spline-amber-hygiene";
    insert_livesafe_identity(
        &pool,
        did,
        7250,
        "Verified",
        "Issued",
        1_000,
        Some("anchor-spline-amber-hygiene"),
    )
    .await
    .expect("insert basis-points score");

    let row = get_livesafe_identity(&pool, did)
        .await
        .expect("fetch basis-points score")
        .expect("row exists");
    assert_eq!(row.odentity_composite_basis_points, 7250);

    let column = sqlx::query(
        "SELECT data_type FROM information_schema.columns \
         WHERE table_schema = 'public' \
           AND table_name = 'livesafe_identities' \
           AND column_name = 'odentity_composite_basis_points'",
    )
    .fetch_one(&pool)
    .await
    .expect("basis-points column exists");
    let data_type: String = column.get("data_type");
    assert_eq!(data_type, "integer");

    let legacy_count = sqlx::query(
        "SELECT COUNT(*) AS count FROM information_schema.columns \
         WHERE table_schema = 'public' \
           AND table_name = 'livesafe_identities' \
           AND column_name = 'odentity_composite'",
    )
    .fetch_one(&pool)
    .await
    .expect("legacy column check");
    let count: i64 = legacy_count.get("count");
    assert_eq!(count, 0);
}
