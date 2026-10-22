use serde_json::{Value, json};
use snitchgate::{
    ipc::{self, Command as IpcCommand},
    model::{Action, Duration},
};
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration as StdDuration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    process::{Child, Command},
};

const BIN: &str = env!("CARGO_BIN_EXE_snitchgate");

async fn cli(args: &[&str]) -> String {
    let output = Command::new(BIN).args(args).output().await.unwrap();
    assert!(
        output.status.success(),
        "CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

async fn start(root: &Path, config: Option<&Path>) -> (Child, PathBuf, PathBuf) {
    start_mode(root, config, false).await
}

async fn start_mode(root: &Path, config: Option<&Path>, manual: bool) -> (Child, PathBuf, PathBuf) {
    let runtime = root.join("runtime");
    let state = root.join("state");
    let mut command = Command::new(BIN);
    command
        .args(["serve", "--runtime-dir"])
        .arg(&runtime)
        .arg("--state-dir")
        .arg(state)
        .env("TYPESAFE_API_KEY", "fixture-key")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    if let Some(config) = config {
        command.arg("--config").arg(config);
    }
    if manual {
        command.arg("--manual");
    }
    let child = command.spawn().unwrap();
    let control = runtime.join("control.sock");
    let grpc = runtime.join("opensnitch.sock");
    tokio::time::timeout(StdDuration::from_secs(5), async {
        while !control.exists() {
            tokio::time::sleep(StdDuration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    (child, control, grpc)
}

#[tokio::test]
async fn binary_manual_mode_disables_an_explicit_matching_automation_scope() {
    let root = tempfile::tempdir().unwrap();
    let jev = root.path().join("jev.sock");
    let provider = mock_provider(&jev, json!({"model":"jev-fixture","answers":{"category":{"type":"choice","choice":"development","confidence":0.99}}})).await;
    let config = root.path().join("manual.toml");
    std::fs::write(&config, format!("[jev]\nenabled=true\nendpoint='http://127.0.0.1/api'\nunix_socket={jev:?}\n[[automation]]\nprocess='/usr/bin/curl'\nuid=1000\nip='127.0.0.1'\nport=8000\nprotocol='tcp'\ncategory='development'\naction='allow'\nmin_confidence=0.9\n")).unwrap();
    let (mut service, control, grpc) = start_mode(root.path(), Some(&config), true).await;
    let mut mock = Command::new(BIN);
    mock.arg("mock").arg("--socket").arg(&grpc);
    let response = tokio::spawn(async move { mock.output().await.unwrap() });
    provider.await.unwrap();
    let snapshot = tokio::time::timeout(StdDuration::from_secs(3), async {
        loop {
            let snapshot = ipc::request(&control, IpcCommand::Snapshot)
                .await
                .unwrap()
                .snapshot
                .unwrap();
            if snapshot
                .pending
                .first()
                .is_some_and(|e| e.assessment.is_some())
            {
                break snapshot;
            }
            tokio::time::sleep(StdDuration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(snapshot.automation_scopes, 0);
    assert!(snapshot.history.is_empty());
    assert!(snapshot.pending[0].verdict.is_none());
    ipc::request(
        &control,
        IpcCommand::Decide {
            id: snapshot.pending[0].id.clone(),
            action: Action::Deny,
            duration: Duration::Once,
        },
    )
    .await
    .unwrap();
    assert!(
        String::from_utf8(response.await.unwrap().stdout)
            .unwrap()
            .contains("deny / once")
    );
    stop(&mut service, &control, &grpc).await;
}

async fn stop(child: &mut Child, control: &Path, grpc: &Path) {
    let status = Command::new("kill")
        .args(["-TERM", &child.id().unwrap().to_string()])
        .status()
        .await
        .unwrap();
    assert!(status.success());
    assert!(
        tokio::time::timeout(StdDuration::from_secs(5), child.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
    assert!(!control.exists() && !grpc.exists());
}

async fn pending(control: &Path, explained: bool) -> snitchgate::model::Entry {
    let mut status = String::new();
    let result = tokio::time::timeout(StdDuration::from_secs(5), async {
        loop {
            let snapshot = ipc::request(control, IpcCommand::Snapshot)
                .await
                .unwrap()
                .snapshot
                .unwrap();
            status = snapshot
                .pending
                .iter()
                .map(|entry| entry.classifier_status.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            if let Some(entry) = snapshot.pending.into_iter().find(|e| {
                !explained || e.assessment.as_ref().is_some_and(|a| a.llm_model.is_some())
            }) {
                return entry;
            }
            tokio::time::sleep(StdDuration::from_millis(10)).await;
        }
    })
    .await;
    result.unwrap_or_else(|_| panic!("pending request wait expired; classifier states: {status}"))
}

async fn mock_provider(path: &Path, body: Value) -> tokio::task::JoinHandle<Value> {
    let listener = tokio::net::UnixListener::bind(path).unwrap();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = BufReader::new(stream);
        let mut length = 0;
        let mut authorization = None;
        loop {
            let mut line = String::new();
            stream.read_line(&mut line).await.unwrap();
            if line == "\r\n" {
                break;
            }
            if let Some(value) = line.to_lowercase().strip_prefix("content-length:") {
                length = value.trim().parse().unwrap();
            }
            if let Some(value) = line.to_lowercase().strip_prefix("authorization:") {
                authorization = Some(value.trim().to_owned());
            }
        }
        if body["model"] == "jev-fixture" {
            assert_eq!(authorization.as_deref(), Some("bearer fixture-key"));
        }
        let mut request = vec![0; length];
        stream.read_exact(&mut request).await.unwrap();
        let body = body.to_string();
        stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
        serde_json::from_slice(&request).unwrap()
    })
}

#[tokio::test]
async fn binary_manual_decision_export_restart_and_shutdown() {
    let root = tempfile::tempdir().unwrap();
    let (mut service, control, grpc) = start(root.path(), None).await;
    let mut mock = Command::new(BIN);
    mock.arg("mock").arg("--socket").arg(&grpc);
    let response = tokio::spawn(async move { mock.output().await.unwrap() });
    let entry = pending(&control, false).await;
    cli(&[
        "decide",
        &entry.id,
        "allow",
        "--socket",
        control.to_str().unwrap(),
    ])
    .await;
    let output = response.await.unwrap();
    assert!(output.status.success());
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("allow / once")
    );
    let proposals = root.path().join("proposals");
    std::fs::create_dir(&proposals).unwrap();
    cli(&[
        "propose",
        &entry.id,
        "--description",
        "Owner: test. Local HTTP development fixture.",
        "--output-dir",
        proposals.to_str().unwrap(),
        "--socket",
        control.to_str().unwrap(),
    ])
    .await;
    let path = std::fs::read_dir(&proposals)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let proposal: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(proposal["duration"], "always");
    assert_eq!(
        path.file_stem().unwrap().to_str().unwrap(),
        proposal["name"].as_str().unwrap()
    );
    assert_eq!(proposal["operator"]["list"].as_array().unwrap().len(), 5);
    stop(&mut service, &control, &grpc).await;
    let (mut service, control, grpc) = start(root.path(), None).await;
    let snapshot: Value =
        serde_json::from_str(&cli(&["status", "--socket", control.to_str().unwrap()]).await)
            .unwrap();
    assert_eq!(snapshot["history"][0]["id"], entry.id);
    stop(&mut service, &control, &grpc).await;
}

#[tokio::test]
async fn binary_jev_classification_and_ollama_explanation_require_manual_review() {
    let root = tempfile::tempdir().unwrap();
    let jev = root.path().join("jev.sock");
    let ollama = root.path().join("ollama.sock");
    let jev_task = mock_provider(&jev, json!({"model":"jev-fixture", "answers":{"category":{"type":"choice","choice":"development","confidence":0.95}}})).await;
    let llm_task = mock_provider(&ollama, json!({"model":"llm-fixture","done":true,"done_reason":"stop","message":{"content":"{\"explanation\":\"A loopback HTTP request; intent is uncertain.\"}"}})).await;
    let config = root.path().join("config.toml");
    std::fs::write(&config, format!("[jev]\nenabled = true\nendpoint = \"http://127.0.0.1/api\"\nunix_socket = {jev:?}\n[ollama]\nenabled = true\nendpoint = \"http://127.0.0.1/api\"\nunix_socket = {ollama:?}\nmodel = \"llm-fixture\"\n")).unwrap();
    let (mut service, control, grpc) = start(root.path(), Some(&config)).await;
    let mut mock = Command::new(BIN);
    mock.arg("mock").arg("--socket").arg(&grpc);
    let response = tokio::spawn(async move { mock.output().await.unwrap() });
    let entry = pending(&control, true).await;
    assert_eq!(
        entry.assessment.unwrap().llm_model.as_deref(),
        Some("llm-fixture")
    );
    assert!(entry.verdict.is_none());
    ipc::request(
        &control,
        IpcCommand::Decide {
            id: entry.id,
            action: Action::Deny,
            duration: Duration::Once,
        },
    )
    .await
    .unwrap();
    assert!(
        String::from_utf8(response.await.unwrap().stdout)
            .unwrap()
            .contains("deny / once")
    );
    assert_eq!(
        jev_task.await.unwrap()["questions"]["category"]["type"],
        "choice"
    );
    assert_eq!(llm_task.await.unwrap()["stream"], false);
    stop(&mut service, &control, &grpc).await;
}

#[tokio::test]
async fn binary_automation_uses_configured_scope_and_denies_pending_on_shutdown() {
    let root = tempfile::tempdir().unwrap();
    let jev = root.path().join("jev.sock");
    let jev_task = mock_provider(&jev, json!({"model":"jev-fixture", "answers":{"category":{"type":"choice","choice":"development","confidence":0.95}}})).await;
    let config = root.path().join("config.toml");
    std::fs::write(&config, format!("[jev]\nenabled = true\nendpoint = \"http://127.0.0.1/api\"\nunix_socket = {jev:?}\n[[automation]]\nprocess = \"/usr/bin/curl\"\nuid = 1000\nip = \"127.0.0.1\"\nport = 8000\nprotocol = \"tcp\"\ncategory = \"development\"\naction = \"allow\"\nmin_confidence = 0.9\n")).unwrap();
    let (mut service, control, grpc) = start(root.path(), Some(&config)).await;
    let output = tokio::time::timeout(
        StdDuration::from_secs(5),
        cli(&["mock", "--socket", grpc.to_str().unwrap()]),
    )
    .await
    .unwrap();
    assert!(output.contains("allow / once"));
    jev_task.await.unwrap();
    let snapshot = ipc::request(&control, IpcCommand::Snapshot)
        .await
        .unwrap()
        .snapshot
        .unwrap();
    assert_eq!(
        snapshot.history[0].verdict.as_ref().unwrap().source,
        "automation"
    );
    // The fixture provider has closed. Its next failure must leave a request
    // pending; shutdown must return a temporary denial over the wire.
    let mut mock = Command::new(BIN);
    mock.arg("mock").arg("--socket").arg(&grpc);
    let response = tokio::spawn(async move { mock.output().await.unwrap() });
    pending(&control, false).await;
    stop(&mut service, &control, &grpc).await;
    let output = response.await.unwrap();
    assert!(output.status.success());
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("deny / once")
    );
}

#[tokio::test]
async fn binary_live_observer_redacts_metadata_and_records_only_dry_run() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("ui.sqlite3");
    let db = rusqlite::Connection::open(&source).unwrap();
    db.execute_batch("CREATE TABLE connections(process TEXT,pid TEXT,uid TEXT,protocol TEXT,dst_ip TEXT,dst_host TEXT,dst_port TEXT,action TEXT,process_args TEXT,process_cwd TEXT);
        INSERT INTO connections VALUES('/usr/bin/curl','123','1000','tcp6','::1','localhost','8000','deny','SECRET_TOKEN','PRIVATE_CWD');
        INSERT INTO connections SELECT * FROM connections;").unwrap();
    drop(db);
    let before = std::fs::read(&source).unwrap();
    let jev = root.path().join("jev.sock");
    let ollama = root.path().join("ollama.sock");
    let j=mock_provider(&jev,json!({"model":"jev-fixture","answers":{"category":{"type":"choice","choice":"unknown","confidence":0.99}}})).await;
    let q=mock_provider(&ollama,json!({"model":"qwen-fixture","done":true,"done_reason":"stop","message":{"content":"{\"explanation\":\"Intent is uncertain.\"}"}})).await;
    let config = root.path().join("config.toml");
    std::fs::write(&config,format!("[jev]\nenabled=true\nendpoint='http://127.0.0.1/api'\nunix_socket={jev:?}\n[ollama]\nenabled=true\nendpoint='http://127.0.0.1/api'\nunix_socket={ollama:?}\nmodel='qwen-fixture'\n")).unwrap();
    let state = root.path().join("state");
    let credential = root.path().join("jev-credential");
    std::fs::write(&credential, "fixture-key").unwrap();
    std::fs::set_permissions(
        &credential,
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )
    .unwrap();
    let output = Command::new(BIN)
        .args(["observe", "--config"])
        .arg(config)
        .arg("--db")
        .arg(&source)
        .arg("--state-dir")
        .arg(&state)
        .args([
            "--seconds",
            "2",
            "--recent",
            "10",
            "--max-classifications",
            "2",
        ])
        .env("TYPESAFE_API_KEY", "wrong-ambient-key")
        .env("TYPESAFE_API_KEY_FILE", &credential)
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(summary["dry_run"], true);
    assert_eq!(summary["classified"], 1);
    assert_eq!(summary["duplicates"], 1);
    assert_eq!(summary["review_needed"], 1);
    for request in [j.await.unwrap(), q.await.unwrap()] {
        let text = request.to_string();
        assert!(!text.contains("SECRET_TOKEN") && !text.contains("PRIVATE_CWD"));
    }
    assert_eq!(std::fs::read(source).unwrap(), before);
    let db = rusqlite::Connection::open(state.join("observations.sqlite3")).unwrap();
    let entry: String = db
        .query_row("SELECT entry FROM observations", [], |r| r.get(0))
        .unwrap();
    let entry: snitchgate::model::Entry = serde_json::from_str(&entry).unwrap();
    assert!(entry.verdict.is_none());
    assert_eq!(
        entry.assessment.unwrap().llm_model.as_deref(),
        Some("qwen-fixture")
    );
}

#[tokio::test]
async fn binary_remote_decision_is_once_audited_and_cannot_be_replayed() {
    let root = tempfile::tempdir().unwrap();
    let (mut service, control, grpc) = start(root.path(), None).await;
    let mut mock = Command::new(BIN);
    mock.arg("mock").arg("--socket").arg(&grpc);
    let response = tokio::spawn(async move { mock.output().await.unwrap() });
    let entry = pending(&control, false).await;
    ipc::request(
        &control,
        IpcCommand::RemoteDecide {
            id: entry.id.clone(),
            action: Action::Allow,
            actor: "slack:T1:U1".into(),
        },
    )
    .await
    .unwrap();
    assert!(
        ipc::request(
            &control,
            IpcCommand::RemoteDecide {
                id: entry.id,
                action: Action::Deny,
                actor: "slack:T1:U1".into()
            }
        )
        .await
        .is_err()
    );
    assert!(
        String::from_utf8(response.await.unwrap().stdout)
            .unwrap()
            .contains("allow / once")
    );
    let snapshot = ipc::request(&control, IpcCommand::Snapshot)
        .await
        .unwrap()
        .snapshot
        .unwrap();
    let verdict = snapshot.history[0].verdict.as_ref().unwrap();
    assert_eq!(verdict.source, "human");
    assert!(verdict.reason.contains("slack:T1:U1"));
    stop(&mut service, &control, &grpc).await;
}
