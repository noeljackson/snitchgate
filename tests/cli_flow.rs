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
        loop {
            let mut line = String::new();
            stream.read_line(&mut line).await.unwrap();
            if line == "\r\n" {
                break;
            }
            if let Some(value) = line.to_lowercase().strip_prefix("content-length:") {
                length = value.trim().parse().unwrap();
            }
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
