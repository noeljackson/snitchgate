//! Transport-independent review contracts and a durable, one-shot approval inbox.
use crate::{
    config::ApprovalConfig,
    ipc,
    model::{self, Action, Assessment, Category, Entry},
};
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection as Sqlite, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};
use uuid::Uuid;

pub fn private_database(path: &Path) -> Result<Sqlite> {
    ipc::private_dir(path.parent().context("database needs a parent")?)?;
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "database must be a regular file"
        );
        ensure!(
            metadata.uid() == std::fs::metadata("/proc/self")?.uid()
                && metadata.mode() & 0o077 == 0,
            "database must be private and owned by this user"
        );
    }
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)?;
    let db = Sqlite::open(path)?;
    db.busy_timeout(std::time::Duration::from_secs(3))?;
    db.execute_batch("PRAGMA journal_mode=WAL;")?;
    Ok(db)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct SourceState {
        pending: Vec<Review>,
        decisions: Vec<(String, Action, String)>,
    }
    struct Source(Arc<Mutex<SourceState>>);
    #[tonic::async_trait]
    impl ApprovalSource for Source {
        async fn pending(&mut self) -> Result<Vec<Review>> {
            Ok(self.0.lock().unwrap().pending.clone())
        }
        async fn decide(&mut self, id: &str, action: Action, actor: &str) -> Result<()> {
            let mut state = self.0.lock().unwrap();
            let position = state
                .pending
                .iter()
                .position(|r| r.entry.id == id && r.entry.deadline > model::now())
                .context("stale")?;
            state.pending.remove(position);
            state.decisions.push((id.into(), action, actor.into()));
            Ok(())
        }
    }
    #[derive(Default, Clone)]
    struct Adapter {
        posts: Arc<Mutex<Vec<(String, String)>>>,
        fail: bool,
    }
    #[tonic::async_trait]
    impl ApprovalAdapter for Adapter {
        async fn post(&self, channel: &str, _review: &Review, nonce: &str) -> Result<String> {
            self.posts
                .lock()
                .unwrap()
                .push((channel.into(), nonce.into()));
            ensure!(!self.fail, "ambiguous delivery failure");
            Ok("100.000001".into())
        }
        async fn update(&self, _: &str, _: &str, _: &Review, _: &str) -> Result<()> {
            Ok(())
        }
    }
    fn review() -> Review {
        Review {
            entry: Entry {
                id: Uuid::new_v4().to_string(),
                connection: crate::broker::demo_connection("/usr/bin/curl", "", "127.0.0.1", 8000),
                received: model::now(),
                deadline: model::now() + 120,
                assessment: None,
                classifier_status: "fixture".into(),
                verdict: None,
                finished: None,
            },
            dry_run: true,
        }
    }
    fn config() -> ApprovalConfig {
        let mut config = ApprovalConfig::default();
        config.slack.approvers = vec!["U1".into()];
        config
    }
    fn reply(nonce: Option<String>) -> Reply {
        Reply {
            namespace: "slack:T1".into(),
            actor: "U1".into(),
            channel: "C1".into(),
            message: "100.000001".into(),
            nonce,
            action: Action::Allow,
        }
    }
    #[tokio::test]
    async fn approval_is_bound_authorized_one_shot_and_survives_restart() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(
            root.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let path = root.path().join("inbox.sqlite3");
        let source = Arc::new(Mutex::new(SourceState {
            pending: vec![review()],
            ..Default::default()
        }));
        let adapter = Adapter::default();
        let mut inbox = Inbox::new(
            adapter.clone(),
            Box::new(Source(source.clone())),
            &path,
            "slack:T1".into(),
            &config(),
        )
        .unwrap();
        assert!(inbox.register("OTHER", "C1", 1).is_err());
        assert!(inbox.register("U1", "C1", 2).unwrap());
        assert!(!inbox.register("U1", "OTHER", 1).unwrap());
        inbox.tick().await.unwrap();
        let nonce = adapter.posts.lock().unwrap()[0].1.clone();
        drop(inbox);
        let mut inbox = Inbox::new(
            adapter.clone(),
            Box::new(Source(source.clone())),
            &path,
            "slack:T1".into(),
            &config(),
        )
        .unwrap();
        inbox.tick().await.unwrap();
        assert_eq!(adapter.posts.lock().unwrap().len(), 1);
        let mut invalid = reply(Some(nonce.clone()));
        invalid.actor = "OTHER".into();
        assert!(!inbox.reply(invalid).await.unwrap());
        let mut invalid = reply(Some(nonce.clone()));
        invalid.channel = "OTHER".into();
        assert!(!inbox.reply(invalid).await.unwrap());
        let mut invalid = reply(Some(nonce.clone()));
        invalid.namespace = "slack:OTHER".into();
        assert!(!inbox.reply(invalid).await.unwrap());
        assert!(
            !inbox
                .reply(reply(Some("wrong nonce".into())))
                .await
                .unwrap()
        );
        assert!(inbox.reply(reply(None)).await.unwrap());
        assert!(!inbox.reply(reply(Some(nonce))).await.unwrap());
        assert_eq!(source.lock().unwrap().decisions.len(), 1);
        assert_eq!(source.lock().unwrap().decisions[0].2, "slack:T1:U1");
    }
    #[tokio::test]
    async fn expired_requests_and_ambiguous_posts_never_decide_or_repost() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(
            root.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let source = Arc::new(Mutex::new(SourceState {
            pending: vec![review()],
            ..Default::default()
        }));
        let adapter = Adapter {
            fail: true,
            ..Default::default()
        };
        let mut inbox = Inbox::new(
            adapter.clone(),
            Box::new(Source(source.clone())),
            &root.path().join("inbox.sqlite3"),
            "slack:T1".into(),
            &config(),
        )
        .unwrap();
        inbox.register("U1", "C1", 1).unwrap();
        inbox.tick().await.unwrap();
        inbox.tick().await.unwrap();
        assert_eq!(adapter.posts.lock().unwrap().len(), 1);
        assert!(!inbox.reply(reply(None)).await.unwrap());
        let adapter = Adapter::default();
        let mut inbox = Inbox::new(
            adapter,
            Box::new(Source(source.clone())),
            &root.path().join("other.sqlite3"),
            "slack:T1".into(),
            &config(),
        )
        .unwrap();
        inbox.register("U1", "C1", 1).unwrap();
        inbox.tick().await.unwrap();
        let mut expired = source.lock().unwrap().pending[0].clone();
        expired.entry.deadline = model::now() - 1;
        inbox
            .db
            .execute(
                "UPDATE deliveries SET review=?1",
                [serde_json::to_string(&expired).unwrap()],
            )
            .unwrap();
        assert!(!inbox.reply(reply(None)).await.unwrap());
        source.lock().unwrap().pending.clear();
        inbox.tick().await.unwrap();
        assert!(!inbox.reply(reply(None)).await.unwrap());
        assert!(source.lock().unwrap().decisions.is_empty());
    }
    #[test]
    fn unknown_suspicious_invalid_and_failed_classification_always_need_review() {
        assert!(needs_review(None, 0.9));
        let mut a = Assessment {
            category: Category::Unknown,
            confidence: 0.999,
            model: "fixture".into(),
            explanation: String::new(),
            llm_model: None,
        };
        assert!(needs_review(Some(&a), 0.9));
        a.category = Category::Suspicious;
        assert!(needs_review(Some(&a), 0.9));
        a.category = Category::Expected;
        assert!(!needs_review(Some(&a), 0.9));
        a.confidence = 0.8;
        assert!(needs_review(Some(&a), 0.9));
        a.confidence = f64::NAN;
        assert!(needs_review(Some(&a), 0.9));
    }
}

pub fn needs_review(assessment: Option<&Assessment>, threshold: f64) -> bool {
    assessment.is_none_or(|a| {
        !a.confidence.is_finite()
            || a.confidence < threshold
            || matches!(a.category, Category::Unknown | Category::Suspicious)
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Review {
    pub entry: Entry,
    pub dry_run: bool,
}

/// Sources own deadlines and final authority. A transport cannot widen a decision.
#[tonic::async_trait]
pub trait ApprovalSource: Send {
    async fn pending(&mut self) -> Result<Vec<Review>>;
    async fn decide(&mut self, id: &str, action: Action, actor: &str) -> Result<()>;
}

/// Telegram or another messenger implements this contract and normalizes replies.
#[tonic::async_trait]
pub trait ApprovalAdapter: Send {
    async fn post(&self, channel: &str, review: &Review, nonce: &str) -> Result<String>;
    async fn update(
        &self,
        channel: &str,
        message: &str,
        review: &Review,
        outcome: &str,
    ) -> Result<()>;
}

pub struct BrokerSource {
    pub socket: PathBuf,
}
#[tonic::async_trait]
impl ApprovalSource for BrokerSource {
    async fn pending(&mut self) -> Result<Vec<Review>> {
        let snapshot = ipc::request(&self.socket, ipc::Command::Snapshot)
            .await?
            .snapshot
            .context("missing snapshot")?;
        Ok(snapshot
            .pending
            .into_iter()
            .filter(|e| {
                !matches!(
                    e.classifier_status.as_str(),
                    "queued" | "classifying" | "explaining"
                )
            })
            .map(|entry| Review {
                entry,
                dry_run: false,
            })
            .collect())
    }
    async fn decide(&mut self, id: &str, action: Action, actor: &str) -> Result<()> {
        ipc::request(
            &self.socket,
            ipc::Command::RemoteDecide {
                id: id.into(),
                action,
                actor: actor.into(),
            },
        )
        .await?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct Reply {
    pub namespace: String,
    pub actor: String,
    pub channel: String,
    pub message: String,
    /// Buttons carry an opaque nonce; threaded replies are bound by message ID.
    pub nonce: Option<String>,
    pub action: Action,
}

pub struct Inbox<A> {
    pub adapter: A,
    source: Box<dyn ApprovalSource>,
    db: Sqlite,
    namespace: String,
    approvers: Vec<String>,
    threshold: f64,
}

impl<A: ApprovalAdapter> Inbox<A> {
    pub fn new(
        adapter: A,
        source: Box<dyn ApprovalSource>,
        path: &Path,
        namespace: String,
        config: &ApprovalConfig,
    ) -> Result<Self> {
        ensure!(
            !config.slack.approvers.is_empty(),
            "configure at least one trusted Slack approver ID"
        );
        let db = private_database(path)?;
        db.execute_batch("CREATE TABLE IF NOT EXISTS routes(namespace TEXT PRIMARY KEY, channel TEXT NOT NULL, event_micros INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS deliveries(namespace TEXT NOT NULL, id TEXT NOT NULL, channel TEXT NOT NULL, message TEXT, nonce TEXT NOT NULL, review TEXT NOT NULL, status TEXT NOT NULL, created INTEGER NOT NULL, PRIMARY KEY(namespace,id));")?;
        Ok(Self {
            adapter,
            source,
            db,
            namespace,
            approvers: config.slack.approvers.clone(),
            threshold: config.review_below_confidence,
        })
    }
    pub fn trusted(&self, actor: &str) -> bool {
        self.approvers.iter().any(|id| id == actor)
    }
    pub fn register(&self, actor: &str, channel: &str, event_micros: u64) -> Result<bool> {
        ensure!(self.trusted(actor), "untrusted approver");
        ensure!(
            event_micros > 0 && event_micros <= i64::MAX as u64,
            "invalid registration timestamp"
        );
        let changed = self.db.execute("INSERT INTO routes VALUES(?1,?2,?3) ON CONFLICT(namespace) DO UPDATE SET channel=excluded.channel,event_micros=excluded.event_micros WHERE excluded.event_micros>routes.event_micros", params![self.namespace, channel, event_micros])?;
        Ok(changed == 1)
    }
    pub async fn reply(&mut self, reply: Reply) -> Result<bool> {
        if reply.namespace != self.namespace || !self.trusted(&reply.actor) {
            return Ok(false);
        }
        let row: Option<(String, String, String)> = self.db.query_row("SELECT id,nonce,review FROM deliveries WHERE namespace=?1 AND channel=?2 AND message=?3 AND status='pending'", params![self.namespace, reply.channel, reply.message], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).optional()?;
        let Some((id, nonce, json)) = row else {
            return Ok(false);
        };
        let review: Review = serde_json::from_str(&json)?;
        if review.entry.deadline <= model::now()
            || reply.nonce.as_ref().is_some_and(|value| value != &nonce)
        {
            return Ok(false);
        }
        // The source independently checks its deadline and atomically rejects duplicates.
        self.source
            .decide(
                &id,
                reply.action,
                &format!("{}:{}", self.namespace, reply.actor),
            )
            .await?;
        let outcome = format!(
            "{} {} by {}",
            if review.dry_run {
                "Dry-run feedback:"
            } else {
                "Broker decision submitted (once):"
            },
            reply.action.as_str(),
            reply.actor
        );
        self.db.execute(
            "UPDATE deliveries SET status=?1 WHERE namespace=?2 AND id=?3",
            params![outcome, self.namespace, id],
        )?;
        // A Slack update failing cannot undo or retry a source decision.
        let _ = self
            .adapter
            .update(&reply.channel, &reply.message, &review, &outcome)
            .await;
        Ok(true)
    }
    pub async fn tick(&mut self) -> Result<()> {
        let pending: HashMap<_, _> = self
            .source
            .pending()
            .await?
            .into_iter()
            .map(|review| (review.entry.id.clone(), review))
            .collect();
        let receipts: Vec<(String, String, String, String)> = {
            let mut query = self.db.prepare("SELECT id,channel,message,review FROM deliveries WHERE namespace=?1 AND status='pending' AND message IS NOT NULL")?;
            query
                .query_map([&self.namespace], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
                })?
                .collect::<rusqlite::Result<_>>()?
        };
        for (id, channel, message, json) in receipts {
            let review: Review = serde_json::from_str(&json)?;
            if review.entry.deadline <= model::now() || !pending.contains_key(&id) {
                self.db.execute("UPDATE deliveries SET status='expired or settled elsewhere' WHERE namespace=?1 AND id=?2", params![self.namespace, id])?;
                let _ = self
                    .adapter
                    .update(
                        &channel,
                        &message,
                        &review,
                        "Expired or settled elsewhere; replies no longer apply.",
                    )
                    .await;
            }
        }
        let channel: Option<String> = self
            .db
            .query_row(
                "SELECT channel FROM routes WHERE namespace=?1",
                [&self.namespace],
                |r| r.get(0),
            )
            .optional()?;
        let Some(channel) = channel else {
            return Ok(());
        };
        let count: u32 = self.db.query_row(
            "SELECT COUNT(*) FROM deliveries WHERE namespace=?1 AND created>?2",
            params![self.namespace, model::now().saturating_sub(60)],
            |r| r.get(0),
        )?;
        if count >= 10 {
            return Ok(());
        }
        let mut pending: Vec<_> = pending.into_values().collect();
        pending.sort_by_key(|r| r.entry.deadline);
        for review in pending {
            if review.entry.deadline <= model::now() + 5
                || (review.dry_run
                    && !needs_review(review.entry.assessment.as_ref(), self.threshold))
            {
                continue;
            }
            let nonce = Uuid::new_v4().to_string();
            // Reserve before HTTP. An ambiguous POST failure is never blindly reposted.
            let claimed = self.db.execute(
                "INSERT OR IGNORE INTO deliveries VALUES(?1,?2,?3,NULL,?4,?5,'submitting',?6)",
                params![
                    self.namespace,
                    review.entry.id,
                    channel,
                    nonce,
                    serde_json::to_string(&review)?,
                    model::now()
                ],
            )?;
            if claimed == 0 {
                continue;
            }
            match self.adapter.post(&channel, &review, &nonce).await {
                Ok(message) => {
                    self.db.execute("UPDATE deliveries SET message=?1,status='pending' WHERE namespace=?2 AND id=?3", params![message, self.namespace, review.entry.id])?;
                }
                Err(_) => {
                    self.db.execute("UPDATE deliveries SET status='delivery failed; no automatic retry' WHERE namespace=?1 AND id=?2", params![self.namespace, review.entry.id])?;
                    eprintln!("Approval delivery failed; recorded locally, no decision made.");
                }
            }
            break; // At most one new message per tick, and ten per minute.
        }
        Ok(())
    }
}
