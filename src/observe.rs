//! Read-only observation of the existing OpenSnitch GUI database; no daemon RPCs.
use crate::{
    approvals::{self, ApprovalSource, Review},
    config::{self, Config},
    model::{self, Action, Connection, Entry},
    protocol, providers,
};
use anyhow::{Context, Result, ensure};
use clap::Args;
use rusqlite::{Connection as Sqlite, OpenFlags, params};
use serde::Serialize;
use std::{
    collections::{HashMap, HashSet},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Debug, Args)]
pub struct Options {
    #[arg(long)]
    pub config: PathBuf,
    /// Explicit GUI database; otherwise discovers the active ui*.sqlite3 file.
    #[arg(long)]
    pub db: Option<PathBuf>,
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
    #[arg(long, default_value_t=60, value_parser=clap::value_parser!(u64).range(1..=3600))]
    pub seconds: u64,
    /// Hard total classification budget for this invocation.
    #[arg(long, default_value_t=20, value_parser=clap::value_parser!(u32).range(1..=1000))]
    pub max_classifications: u32,
    /// Also sample this many recent rows on first opening a database.
    #[arg(long, default_value_t=0, value_parser=clap::value_parser!(u32).range(0..=1000))]
    pub recent: u32,
}

fn readonly(path: &Path) -> Result<Sqlite> {
    let db = Sqlite::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    db.busy_timeout(Duration::from_millis(100))?;
    Ok(db)
}

pub fn active_database(dir: &Path) -> Result<PathBuf> {
    let mut candidates = vec![];
    for file in std::fs::read_dir(dir)?.take(128) {
        let path = file?.path();
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if !name.starts_with("ui") || !name.ends_with(".sqlite3") || !path.is_file() {
            continue;
        }
        let latest = readonly(&path).and_then(|db| {
            Ok(db.query_row(
                "SELECT time FROM connections ORDER BY rowid DESC LIMIT 1",
                [],
                |r| r.get::<_, String>(0),
            )?)
        });
        if let Ok(time) = latest {
            candidates.push((time, path));
        }
    }
    candidates.sort();
    candidates
        .pop()
        .map(|(_, path)| path)
        .context("no readable OpenSnitch GUI database found")
}

pub struct ObservationStore {
    db: Sqlite,
}
impl ObservationStore {
    pub fn open(path: &Path) -> Result<Self> {
        let db = approvals::private_database(path)?;
        db.execute_batch("CREATE TABLE IF NOT EXISTS observations(id TEXT PRIMARY KEY, entry TEXT NOT NULL, review INTEGER NOT NULL, source_db TEXT NOT NULL, source_rowid INTEGER NOT NULL, original_action TEXT NOT NULL, action TEXT, actor TEXT, answered_at INTEGER);")?;
        Ok(Self { db })
    }
    fn record(
        &self,
        entry: &Entry,
        needs_review: bool,
        path: &Path,
        row: i64,
        original_action: &str,
    ) -> Result<()> {
        self.db.execute("INSERT INTO observations(id,entry,review,source_db,source_rowid,original_action) VALUES(?1,?2,?3,?4,?5,?6)", params![entry.id, serde_json::to_string(entry)?, needs_review, path.to_string_lossy(), row, original_action])?;
        self.db.execute("DELETE FROM observations WHERE rowid NOT IN (SELECT rowid FROM observations ORDER BY rowid DESC LIMIT 10000)", [])?;
        Ok(())
    }
}
#[tonic::async_trait]
impl ApprovalSource for ObservationStore {
    async fn pending(&mut self) -> Result<Vec<Review>> {
        let mut query = self.db.prepare("SELECT entry FROM observations WHERE review=1 AND action IS NULL ORDER BY rowid DESC LIMIT 1000")?;
        let rows = query.query_map([], |r| r.get::<_, String>(0))?;
        let mut reviews = vec![];
        for row in rows {
            let entry: Entry = serde_json::from_str(&row?)?;
            if entry.deadline > model::now() {
                reviews.push(Review {
                    entry,
                    dry_run: true,
                });
            }
        }
        Ok(reviews)
    }
    async fn decide(&mut self, id: &str, action: Action, actor: &str) -> Result<()> {
        let changed = self.db.execute("UPDATE observations SET action=?1,actor=?2,answered_at=?3 WHERE id=?4 AND action IS NULL AND review=1 AND CAST(json_extract(entry,'$.deadline') AS INTEGER)>?3", params![action.as_str(), actor, model::now(), id])?;
        ensure!(changed == 1, "observation expired or already answered");
        Ok(())
    }
}

/// Fetch only whitelisted fields. Arguments and working directory never enter memory.
fn read_rows(path: &Path, cursor: &mut i64) -> Result<Vec<(i64, Connection, String)>> {
    let db = readonly(path)?;
    let mut query = db.prepare("SELECT rowid, CASE WHEN length(process)<=4096 THEN process END, pid, uid, protocol, dst_ip, CASE WHEN length(dst_host)<=253 THEN dst_host END, dst_port, action FROM connections WHERE rowid>?1 ORDER BY rowid LIMIT 512")?;
    let mut rows = query.query([*cursor])?;
    let mut events = vec![];
    while let Some(row) = rows.next()? {
        *cursor = row.get(0)?;
        let parsed = (|| -> Result<_> {
            let protocol: String = row.get(4)?;
            let normalized = match protocol.as_str() {
                "tcp6" => "tcp",
                "udp6" => "udp",
                other => other,
            };
            let raw = protocol::Connection {
                process_path: row.get(1)?,
                process_id: row.get::<_, String>(2)?.parse()?,
                user_id: row.get::<_, String>(3)?.parse()?,
                protocol: normalized.into(),
                dst_ip: row.get(5)?,
                dst_host: row.get(6)?,
                dst_port: row.get::<_, String>(7)?.parse()?,
                ..Default::default()
            };
            let action: String = row.get(8)?;
            ensure!(
                matches!(action.as_str(), "allow" | "deny"),
                "unknown observed action"
            );
            Ok((*cursor, Connection::try_from(raw)?, action))
        })();
        if let Ok(event) = parsed {
            events.push(event);
        }
    }
    Ok(events)
}

#[derive(Default, Serialize)]
struct Summary {
    classified: u32,
    review_needed: u32,
    jev_failed: u32,
    explanation_failed: u32,
    duplicates: u32,
    self_connections_skipped: u32,
    dry_run: bool,
}

pub async fn run(args: Options) -> Result<()> {
    let config = Config::load(Some(&args.config))?;
    ensure!(
        config.jev.enabled,
        "enable [jev] in the configuration before observing"
    );
    let state = args.state_dir.map(Ok).unwrap_or_else(config::state_dir)?;
    let store = ObservationStore::open(&state.join("observations.sqlite3"))?;
    let jev = providers::client_with_socket(config.jev.unix_socket.as_deref())?;
    let ollama = providers::client_with_socket(config.ollama.unix_socket.as_deref())?;
    let data = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".local/share")
        })
        .join("opensnitch");
    let mut cursors: HashMap<(PathBuf, u64), i64> = HashMap::new();
    let mut seen = HashSet::new();
    let mut summary = Summary {
        dry_run: true,
        ..Default::default()
    };
    let end = tokio::time::Instant::now() + Duration::from_secs(args.seconds);
    eprintln!(
        "Dry-run observer: read-only GUI events, at most {} classifications; firewall decisions remain with OpenSnitch. Private results: {}",
        args.max_classifications,
        state.join("observations.sqlite3").display()
    );
    while tokio::time::Instant::now() < end && summary.classified < args.max_classifications {
        let path = match &args.db {
            Some(path) => path.clone(),
            None => active_database(&data)?,
        };
        let identity = (path.clone(), std::fs::metadata(&path)?.ino());
        if !cursors.contains_key(&identity) {
            let last: i64 = readonly(&path)?.query_row(
                "SELECT COALESCE((SELECT rowid FROM connections ORDER BY rowid DESC LIMIT 1),0)",
                [],
                |r| r.get(0),
            )?;
            cursors.insert(
                identity.clone(),
                last.saturating_sub(i64::from(args.recent)),
            );
        }
        let events = read_rows(&path, cursors.get_mut(&identity).expect("cursor"))?;
        for (row, connection, original_action) in events {
            if tokio::time::Instant::now() >= end || summary.classified >= args.max_classifications
            {
                break;
            }
            if connection.process.ends_with("/snitchgate")
                || connection.process == "/usr/bin/ollama"
            {
                summary.self_connections_skipped += 1;
                continue;
            }
            let key = format!(
                "{}\0{}\0{}\0{}\0{}\0{}",
                connection.process,
                connection.uid,
                connection.protocol,
                connection.ip,
                connection.host,
                connection.port
            );
            if !seen.insert(key) {
                summary.duplicates += 1;
                continue;
            }
            let mut entry = Entry {
                id: uuid::Uuid::new_v4().to_string(),
                connection,
                received: model::now(),
                deadline: 0,
                assessment: None,
                classifier_status: "Jev failed; manual review".into(),
                verdict: None,
                finished: None,
            };
            match tokio::time::timeout_at(
                end,
                providers::classify(&jev, &config.jev, &entry.connection),
            )
            .await
            {
                Ok(Ok(mut assessment)) => {
                    entry.classifier_status = "classified".into();
                    if config.ollama.enabled {
                        match tokio::time::timeout_at(
                            end,
                            providers::explain(
                                &ollama,
                                &config.ollama,
                                &entry.connection,
                                &assessment,
                            ),
                        )
                        .await
                        {
                            Ok(Ok((explanation, model))) => {
                                assessment.explanation = explanation;
                                assessment.llm_model = Some(model);
                            }
                            _ => {
                                summary.explanation_failed += 1;
                                entry.classifier_status =
                                    "classified; explanation unavailable".into();
                            }
                        }
                    }
                    entry.assessment = Some(assessment);
                }
                _ => summary.jev_failed += 1,
            }
            entry.deadline = model::now() + config.approvals.review_ttl_seconds;
            let review = approvals::needs_review(
                entry.assessment.as_ref(),
                config.approvals.review_below_confidence,
            );
            store.record(&entry, review, &path, row, &original_action)?;
            summary.classified += 1;
            summary.review_needed += u32::from(review);
            eprintln!(
                "Observed {}/{}; {} need review (dry run).",
                summary.classified, args.max_classifications, summary.review_needed
            );
        }
        tokio::select! { _ = tokio::time::sleep_until(end.min(tokio::time::Instant::now() + Duration::from_secs(1))) => {}, _ = tokio::signal::ctrl_c() => break }
    }
    println!("{}", serde_json::to_string_pretty(&summary)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(path: &Path, time: &str) {
        let db = Sqlite::open(path).unwrap();
        db.execute_batch("CREATE TABLE connections(time TEXT,process TEXT,pid TEXT,uid TEXT,protocol TEXT,dst_ip TEXT,dst_host TEXT,dst_port TEXT,action TEXT,process_args TEXT,process_cwd TEXT);").unwrap();
        db.execute("INSERT INTO connections VALUES(?1,'/usr/bin/firefox','123','1000','tcp6','::1','localhost','443','allow','SECRET_TOKEN','PRIVATE_CWD')", [time]).unwrap();
    }
    #[test]
    fn discovers_rotated_database_reads_whitelist_and_keeps_source_unchanged() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(
            root.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let old = root.path().join("ui.sqlite3");
        let active = root.path().join("ui-rotated.sqlite3");
        fixture(&old, "2026-10-01 12:00:00");
        fixture(&active, "2026-10-22 12:00:00");
        assert_eq!(active_database(root.path()).unwrap(), active);
        let before = std::fs::read(&active).unwrap();
        let mut cursor = 0;
        let rows = read_rows(&active, &mut cursor).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].1.protocol, "tcp");
        assert_eq!(rows[0].1.uid, 1000);
        assert!(
            !serde_json::to_string(&rows)
                .unwrap()
                .contains("SECRET_TOKEN")
        );
        assert!(
            !serde_json::to_string(&rows)
                .unwrap()
                .contains("PRIVATE_CWD")
        );
        assert!(read_rows(&active, &mut cursor).unwrap().is_empty());
        assert!(
            readonly(&active)
                .unwrap()
                .execute("DELETE FROM connections", [])
                .is_err()
        );
        assert_eq!(std::fs::read(&active).unwrap(), before);
        let db = Sqlite::open(&active).unwrap();
        db.execute("UPDATE connections SET uid=''", []).unwrap();
        assert!(read_rows(&active, &mut 0).unwrap().is_empty()); // Missing identity is never root.
    }
    #[tokio::test]
    async fn dry_run_feedback_is_durable_one_shot_and_cannot_touch_source() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(
            root.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let source = root.path().join("ui.sqlite3");
        fixture(&source, "2026-10-22 12:00:00");
        let before = std::fs::read(&source).unwrap();
        let path = root.path().join("observations.sqlite3");
        let mut store = ObservationStore::open(&path).unwrap();
        let entry = Entry {
            id: "fixture".into(),
            connection: read_rows(&source, &mut 0).unwrap()[0].1.clone(),
            received: model::now(),
            deadline: model::now() + 90,
            assessment: None,
            classifier_status: "failed; review".into(),
            verdict: None,
            finished: None,
        };
        store.record(&entry, true, &source, 1, "deny").unwrap();
        assert_eq!(store.pending().await.unwrap().len(), 1);
        store
            .decide("fixture", Action::Allow, "slack:T1:U1")
            .await
            .unwrap();
        assert!(
            store
                .decide("fixture", Action::Deny, "slack:T1:U1")
                .await
                .is_err()
        );
        drop(store);
        let mut store = ObservationStore::open(&path).unwrap();
        assert!(store.pending().await.unwrap().is_empty());
        let result: (String, String, String) = store
            .db
            .query_row(
                "SELECT action,actor,original_action FROM observations",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            result,
            ("allow".into(), "slack:T1:U1".into(), "deny".into())
        );
        assert_eq!(std::fs::read(&source).unwrap(), before);
    }
}
