use crate::{
    config::Config,
    model::{Action, Assessment, Connection, Duration, Entry, Health, Snapshot, Verdict, now},
    policy, providers,
    store::Store,
};
use anyhow::{Result, anyhow, ensure};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration as StdDuration,
};
use tokio::sync::{Semaphore, oneshot};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

struct Pending {
    entry: Entry,
    reply: oneshot::Sender<Verdict>,
    cancellation: CancellationToken,
}
struct State {
    pending: BTreeMap<String, Pending>,
    store: Store,
    health: Health,
    closing: bool,
}
pub struct Broker {
    state: Mutex<State>,
    config: Config,
    jev_client: reqwest::Client,
    ollama_client: reqwest::Client,
    classifiers: Arc<Semaphore>,
    demo: bool,
}

impl Broker {
    pub fn new(config: Config, store: Store, demo: bool) -> Result<Arc<Self>> {
        config.validate()?;
        Ok(Arc::new(Self {
            classifiers: Arc::new(Semaphore::new(config.classifier_concurrency)),
            state: Mutex::new(State {
                pending: BTreeMap::new(),
                store,
                health: Health::default(),
                closing: false,
            }),
            jev_client: providers::client_with_socket(config.jev.unix_socket.as_deref())?,
            ollama_client: providers::client_with_socket(config.ollama.unix_socket.as_deref())?,
            config,
            demo,
        }))
    }

    /// Admission and timeout ownership live outside the cancellable RPC future.
    /// A cancelled gRPC client cannot leave an immortal inbox row behind.
    pub fn submit(self: &Arc<Self>, connection: Connection) -> Result<oneshot::Receiver<Verdict>> {
        let id = Uuid::new_v4().to_string();
        let received = now();
        let (reply, receiver) = oneshot::channel();
        let cancellation = CancellationToken::new();
        let entry = Entry {
            id: id.clone(),
            connection,
            received,
            deadline: received + self.config.request_timeout_seconds,
            assessment: None,
            classifier_status: if self.config.jev.enabled {
                "queued"
            } else {
                "disabled"
            }
            .into(),
            verdict: None,
            finished: None,
        };
        {
            let mut state = self.state.lock().expect("broker lock");
            ensure!(!state.closing, "broker shutting down");
            ensure!(
                state.pending.len() < self.config.max_pending,
                "pending queue full"
            );
            state.pending.insert(
                id.clone(),
                Pending {
                    entry,
                    reply,
                    cancellation: cancellation.clone(),
                },
            );
        }
        let broker = Arc::clone(self);
        let timeout_id = id.clone();
        let timeout_cancellation = cancellation.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = timeout_cancellation.cancelled() => {},
                _ = tokio::time::sleep(StdDuration::from_secs(broker.config.request_timeout_seconds)) => {
                    let _ = broker.finish(&timeout_id, policy::fallback("Request deadline expired"));
                }
            }
        });
        if self.config.jev.enabled {
            let broker = Arc::clone(self);
            tokio::spawn(async move {
                tokio::select! { _ = cancellation.cancelled() => {}, _ = broker.assess(id) => {} }
            });
        }
        Ok(receiver)
    }

    fn finish(&self, id: &str, verdict: Verdict) -> Result<()> {
        let mut state = self.state.lock().expect("broker lock");
        let pending = state
            .pending
            .get_mut(id)
            .ok_or_else(|| anyhow!("request expired or already decided"))?;
        ensure!(
            now() < pending.entry.deadline || verdict.source == "fallback",
            "request deadline expired"
        );
        pending.entry.verdict = Some(verdict.clone());
        pending.entry.finished = Some(now());
        let entry = pending.entry.clone();
        // Do not grant traffic when the audit write fails. Keep the request
        // pending so a later retry or timeout can settle it.
        if let Err(error) = state.store.record(&entry) {
            let pending = state.pending.get_mut(id).expect("pending");
            pending.entry.verdict = None;
            pending.entry.finished = None;
            if verdict.source == "fallback" {
                let pending = state.pending.remove(id).expect("pending");
                pending.cancellation.cancel();
                let _ = pending
                    .reply
                    .send(policy::fallback("Audit storage failed; deny once"));
            }
            return Err(error);
        }
        let pending = state.pending.remove(id).expect("pending");
        pending.cancellation.cancel();
        let _ = pending.reply.send(verdict);
        Ok(())
    }

    pub fn decide(&self, id: &str, action: Action, duration: Duration) -> Result<()> {
        if duration != Duration::Once {
            let state = self.state.lock().expect("broker lock");
            let entry = &state
                .pending
                .get(id)
                .ok_or_else(|| anyhow!("request expired or already decided"))?
                .entry;
            ensure!(
                !entry.connection.process.is_empty(),
                "unattributed requests support once only"
            );
        }
        self.finish(
            id,
            Verdict {
                action,
                duration,
                source: "human".into(),
                reason: "Explicit user decision".into(),
            },
        )
    }

    pub fn snapshot(&self) -> Result<Snapshot> {
        let state = self.state.lock().expect("broker lock");
        let mut pending: Vec<_> = state.pending.values().map(|p| p.entry.clone()).collect();
        pending.sort_by_key(|e| (e.received, e.id.clone()));
        Ok(Snapshot {
            pending,
            history: state.store.recent(200)?,
            health: state.health.clone(),
            mode: if self.demo {
                "demo"
            } else if self.config.automation.is_empty() {
                "manual / classification only"
            } else {
                "bounded automation"
            }
            .into(),
            classifier_enabled: self.config.jev.enabled,
            automation_scopes: self.config.automation.len(),
        })
    }

    pub fn ping(&self) {
        self.state.lock().expect("broker lock").health.last_ping = Some(now());
    }
    pub fn subscribe(&self, name: String, rules: usize) {
        let mut state = self.state.lock().expect("broker lock");
        state.health.daemon = Some(crate::model::display_text(&name));
        state.health.rule_count = rules;
        state.health.last_ping = Some(now());
    }
    pub fn alert(&self) {
        self.state.lock().expect("broker lock").health.alerts += 1;
    }
    pub fn shutdown(&self) {
        let ids: Vec<_> = {
            let mut state = self.state.lock().expect("broker lock");
            state.closing = true;
            state.pending.keys().cloned().collect()
        };
        for id in ids {
            let _ = self.finish(&id, policy::fallback("Broker shutting down"));
        }
    }
    pub fn entry(&self, id: &str) -> Result<Entry> {
        let snapshot = self.snapshot()?;
        snapshot
            .pending
            .into_iter()
            .chain(snapshot.history)
            .find(|e| e.id == id)
            .ok_or_else(|| anyhow!("request not found in recent history"))
    }

    fn classifier_status(&self, id: &str, status: &str, assessment: Option<Assessment>) {
        let mut state = self.state.lock().expect("broker lock");
        if let Some(pending) = state.pending.get_mut(id) {
            pending.entry.classifier_status = status.into();
            if let Some(assessment) = assessment {
                pending.entry.assessment = Some(assessment);
            }
        }
    }

    async fn assess(self: Arc<Self>, id: String) {
        // Never queue paid work: backpressure is visible and goes to manual review.
        let Ok(_permit) = self.classifiers.clone().try_acquire_owned() else {
            self.classifier_status(&id, "busy; manual review", None);
            return;
        };
        let Ok(entry) = self.entry(&id) else {
            return;
        };
        self.classifier_status(&id, "classifying", None);
        let mut assessment = match providers::classify(
            &self.jev_client,
            &self.config.jev,
            &entry.connection,
        )
        .await
        {
            Ok(assessment) => assessment,
            Err(_) => {
                self.classifier_status(&id, "Jev failed; manual review", None);
                return;
            }
        };
        let verdict = policy::automatic(&entry.connection, &assessment, &self.config.automation);
        let explain = self.config.ollama.enabled
            && (verdict.is_none()
                || assessment.confidence < self.config.ollama.explain_below_confidence);
        self.classifier_status(
            &id,
            if explain { "explaining" } else { "classified" },
            Some(assessment.clone()),
        );
        if let Some(verdict) = verdict {
            let _ = self.finish(&id, verdict);
            return;
        }
        if explain {
            match providers::explain(
                &self.ollama_client,
                &self.config.ollama,
                &entry.connection,
                &assessment,
            )
            .await
            {
                Ok((explanation, model)) => {
                    assessment.explanation = explanation;
                    assessment.llm_model = Some(model);
                }
                Err(_) => {
                    self.classifier_status(&id, "Ollama failed; manual review", None);
                    return;
                }
            }
        }
        self.classifier_status(&id, "classified; manual review", Some(assessment));
    }
}

pub fn demo_connection(process: &str, host: &str, ip: &str, port: u16) -> Connection {
    Connection {
        process: process.into(),
        pid: 4200,
        uid: 1000,
        protocol: "tcp".into(),
        ip: ip.parse().expect("fixture IP"),
        host: host.into(),
        port,
    }
}

pub fn seed_demo(broker: &Arc<Broker>) -> Result<()> {
    for connection in [
        demo_connection("/usr/bin/firefox", "example.org", "93.184.215.14", 443),
        demo_connection("/usr/bin/curl", "", "127.0.0.1", 8000),
        demo_connection(
            "/tmp/unknown-worker",
            "metrics.example.org",
            "192.0.2.10",
            443,
        ),
    ] {
        let _receiver = broker.submit(connection)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test(start_paused = true)]
    async fn deadlines_and_duplicate_decisions_are_safe() {
        let broker = Broker::new(Config::default(), Store::memory(100).unwrap(), true).unwrap();
        let response = broker
            .submit(demo_connection("/usr/bin/curl", "", "127.0.0.1", 8000))
            .unwrap();
        tokio::time::advance(StdDuration::from_secs(91)).await;
        assert_eq!(response.await.unwrap().action, Action::Deny);
        let snapshot = broker.snapshot().unwrap();
        assert!(snapshot.pending.is_empty());
        assert_eq!(
            snapshot.history[0].verdict.as_ref().unwrap().duration,
            Duration::Once
        );
        assert!(
            broker
                .decide(&snapshot.history[0].id, Action::Allow, Duration::Once)
                .is_err()
        );
    }
    #[tokio::test]
    async fn decisions_survive_reopen_and_queue_is_bounded() {
        let temp = tempfile::tempdir().unwrap();
        let db = temp.path().join("history.sqlite3");
        let config = Config {
            max_pending: 1,
            ..Config::default()
        };
        let broker = Broker::new(config, Store::open(&db, 100).unwrap(), false).unwrap();
        let receiver = broker
            .submit(demo_connection("/usr/bin/curl", "", "127.0.0.1", 8000))
            .unwrap();
        assert!(
            broker
                .submit(demo_connection("/usr/bin/curl", "", "127.0.0.1", 8001))
                .is_err()
        );
        let id = broker.snapshot().unwrap().pending[0].id.clone();
        broker.decide(&id, Action::Allow, Duration::Once).unwrap();
        assert_eq!(receiver.await.unwrap().action, Action::Allow);
        assert_eq!(Store::open(&db, 100).unwrap().recent(10).unwrap()[0].id, id);
    }
}
