use crate::{
    broker::Broker,
    model::{Action, Duration, Snapshot},
    policy,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    path::Path,
    sync::Arc,
    time::Duration as StdDuration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    sync::Semaphore,
};

const MAX_MESSAGE: usize = 16 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    Snapshot,
    Decide {
        id: String,
        action: Action,
        duration: Duration,
    },
    Propose {
        id: String,
        description: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Response {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<Snapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proposal: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub fn private_dir(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure!(
                metadata.is_dir() && !metadata.file_type().is_symlink(),
                "private directory must be a real directory"
            );
            // A directory created by this user must already have private permissions.
            ensure!(
                metadata.uid() == current_uid()? && metadata.mode() & 0o077 == 0,
                "directory must be owned by the current user with mode 0700"
            );
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(path)?;
        }
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

fn current_uid() -> Result<u32> {
    // /proc/self is a kernel-owned view; no subprocess or ambient SSH/GPG state.
    Ok(std::fs::metadata("/proc/self")?.uid())
}

pub fn bind(path: &Path) -> Result<UnixListener> {
    let parent = path.parent().context("socket needs a parent")?;
    private_dir(parent)?;
    // Never unlink an existing socket: it may belong to an active service.
    let listener = UnixListener::bind(path)
        .context("bind socket (remove stale socket only after verifying no service owns it)")?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

pub fn remove_socket(path: &Path) {
    if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_socket()) {
        let _ = std::fs::remove_file(path);
    }
}

pub async fn serve(listener: UnixListener, broker: Arc<Broker>) -> Result<()> {
    let slots = Arc::new(Semaphore::new(32));
    let uid = current_uid()?;
    loop {
        let (stream, _) = listener.accept().await?;
        if stream.peer_cred()?.uid() != uid {
            continue;
        }
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            continue;
        };
        let broker = broker.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _ = tokio::time::timeout(StdDuration::from_secs(3), handle(stream, broker)).await;
        });
    }
}

async fn read_message(stream: &mut BufReader<UnixStream>) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    // fill_buf bounds memory before extending; read_until alone would not.
    loop {
        let buf = stream.fill_buf().await?;
        ensure!(!buf.is_empty(), "peer closed before a complete message");
        let end = buf.iter().position(|b| *b == b'\n').map(|i| i + 1);
        let count = end.unwrap_or(buf.len());
        ensure!(bytes.len() + count <= MAX_MESSAGE, "IPC message too large");
        bytes.extend_from_slice(&buf[..count]);
        stream.consume(count);
        if end.is_some() {
            return Ok(bytes);
        }
    }
}

async fn handle(stream: UnixStream, broker: Arc<Broker>) -> Result<()> {
    let mut stream = BufReader::new(stream);
    let command: Command = serde_json::from_slice(&read_message(&mut stream).await?)?;
    let result: Result<Response> = (|| {
        let mut response = Response {
            snapshot: None,
            proposal: None,
            error: None,
        };
        match command {
            Command::Snapshot => response.snapshot = Some(broker.snapshot()?),
            Command::Decide {
                id,
                action,
                duration,
            } => broker.decide(&id, action, duration)?,
            Command::Propose { id, description } => {
                let entry = broker.entry(&id)?;
                let verdict = entry
                    .verdict
                    .context("decide a request before proposing a durable rule")?;
                ensure!(
                    verdict.source == "human",
                    "durable proposals require an explicit human decision"
                );
                response.proposal = Some(policy::proposal(
                    &id,
                    &entry.connection,
                    &verdict,
                    &description,
                )?);
            }
        }
        Ok(response)
    })();
    let response = result.unwrap_or_else(|_| Response {
        snapshot: None,
        proposal: None,
        error: Some("Request rejected: stale ID, invalid operation, or storage failure".into()),
    });
    let mut bytes = serde_json::to_vec(&response)?;
    bytes.push(b'\n');
    stream.write_all(&bytes).await?;
    Ok(())
}

pub async fn request(path: &Path, command: Command) -> Result<Response> {
    tokio::time::timeout(StdDuration::from_secs(3), async {
        let mut stream = BufReader::new(
            UnixStream::connect(path)
                .await
                .context("connect to Snitchgate service")?,
        );
        let mut bytes = serde_json::to_vec(&command)?;
        bytes.push(b'\n');
        stream.write_all(&bytes).await?;
        let response: Response = serde_json::from_slice(&read_message(&mut stream).await?)?;
        if let Some(error) = &response.error {
            anyhow::bail!("{error}");
        }
        Ok(response)
    })
    .await
    .context("Snitchgate service did not respond")?
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn refuses_socket_takeover_and_roundtrips_decisions() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("private/control.sock");
        let listener = bind(&path).unwrap();
        assert!(bind(&path).is_err());
        let broker = Broker::new(
            crate::config::Config::default(),
            crate::store::Store::memory(100).unwrap(),
            false,
        )
        .unwrap();
        let verdict = broker
            .submit(crate::broker::demo_connection(
                "/usr/bin/curl",
                "",
                "127.0.0.1",
                8000,
            ))
            .unwrap();
        let task = tokio::spawn(serve(listener, broker));
        let snapshot = request(&path, Command::Snapshot)
            .await
            .unwrap()
            .snapshot
            .unwrap();
        request(
            &path,
            Command::Decide {
                id: snapshot.pending[0].id.clone(),
                action: Action::Allow,
                duration: Duration::Once,
            },
        )
        .await
        .unwrap();
        assert_eq!(verdict.await.unwrap().action, Action::Allow);
        assert!(
            request(
                &path,
                Command::Decide {
                    id: snapshot.pending[0].id.clone(),
                    action: Action::Allow,
                    duration: Duration::Once
                }
            )
            .await
            .is_err()
        );
        task.abort();
    }
}
