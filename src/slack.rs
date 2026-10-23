//! Slack Socket Mode adapter. Credentials and WebSocket ticket URLs are never logged.
use crate::{
    approvals::{ApprovalAdapter, ApprovalSource, BrokerSource, Inbox, Reply, Review},
    config::{self, Config},
    model::{Action, display_text},
    observe::ObservationStore,
    providers,
};
use anyhow::{Context, Result, anyhow, ensure};
use clap::Args;
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use std::{path::PathBuf, time::Duration};
use tokio::sync::mpsc;
use tokio_tungstenite::{
    connect_async_with_config,
    tungstenite::{Message, protocol::WebSocketConfig},
};

#[derive(Debug, Args)]
pub struct Options {
    #[arg(long)]
    pub config: PathBuf,
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
    /// Explicit opt-in: reply to actual pending broker requests instead of dry-run feedback.
    #[arg(long)]
    pub live: bool,
    #[arg(long, requires = "live")]
    pub socket: Option<PathBuf>,
}

pub struct Slack {
    client: reqwest::Client,
    api_root: String,
    bot_token: String,
    app_token: String,
}
impl Slack {
    async fn api(&self, method: &str, body: Value, app: bool) -> Result<Value> {
        let response = self
            .client
            .post(format!("{}{method}", self.api_root))
            .bearer_auth(if app {
                &self.app_token
            } else {
                &self.bot_token
            })
            .json(&body)
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(|_| anyhow!("Slack API request failed"))?;
        let value = providers::response_json(response)
            .await
            .map_err(|_| anyhow!("Slack API response failed"))?;
        ensure!(
            value["ok"] == true,
            "Slack API rejected request (check app scopes, credentials and membership)"
        );
        Ok(value)
    }
    async fn connection(&self, events: mpsc::Sender<Value>) -> Result<()> {
        let connection = self.api("apps.connections.open", json!({}), true).await?;
        let url = connection["url"]
            .as_str()
            .context("Slack did not provide a socket URL")?;
        let parsed = reqwest::Url::parse(url).map_err(|_| anyhow!("invalid Slack socket URL"))?;
        ensure!(
            parsed.scheme() == "wss"
                && parsed.username().is_empty()
                && parsed.password().is_none()
                && parsed.port_or_known_default() == Some(443)
                && parsed
                    .host_str()
                    .is_some_and(|h| h == "slack.com" || h.ends_with(".slack.com")),
            "untrusted Slack socket endpoint"
        );
        let limits = WebSocketConfig::default()
            .max_message_size(Some(64 * 1024))
            .max_frame_size(Some(64 * 1024));
        let (mut socket, _) = tokio::time::timeout(
            Duration::from_secs(10),
            connect_async_with_config(url, Some(limits), true),
        )
        .await
        .map_err(|_| anyhow!("Slack socket connection timed out"))?
        .map_err(|_| anyhow!("Slack socket connection failed"))?;
        eprintln!("Slack Socket Mode connected.");
        crate::service::notify("READY=1\nSTATUS=Slack connected")?;
        forward_socket(&mut socket, events).await
    }
}

async fn forward_socket<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    socket: &mut tokio_tungstenite::WebSocketStream<S>,
    events: mpsc::Sender<Value>,
) -> Result<()> {
    loop {
        let message = tokio::time::timeout(Duration::from_secs(90), socket.next())
            .await
            .map_err(|_| anyhow!("Slack socket idle timeout"))?
            .context("Slack socket closed")?
            .map_err(|_| anyhow!("Slack socket read failed"))?;
        match message {
            Message::Text(text) => {
                let envelope: Value = serde_json::from_str(&text)
                    .map_err(|_| anyhow!("invalid Slack socket JSON"))?;
                if let Some(id) = envelope["envelope_id"].as_str() {
                    ensure!(id.len() <= 128, "invalid Slack envelope ID");
                    // Ack in the reader, independently of classifier/storage/HTTP latency.
                    tokio::time::timeout(
                        Duration::from_secs(2),
                        socket.send(Message::Text(json!({"envelope_id":id}).to_string().into())),
                    )
                    .await
                    .map_err(|_| anyhow!("Slack acknowledgement timed out"))?
                    .map_err(|_| anyhow!("Slack acknowledgement failed"))?;
                    if events.try_send(envelope).is_err() {
                        eprintln!("Slack event queue full; no decision made. Retry the reply.");
                    }
                } else if envelope["type"] == "disconnect" {
                    return Ok(());
                }
            }
            Message::Ping(data) => {
                socket
                    .send(Message::Pong(data))
                    .await
                    .map_err(|_| anyhow!("Slack socket heartbeat failed"))?;
            }
            Message::Close(_) => return Ok(()),
            _ => {}
        }
    }
}

fn clipped(value: &str, limit: usize) -> String {
    display_text(value).chars().take(limit).collect()
}
fn card(review: &Review, nonce: Option<&str>, outcome: Option<&str>) -> Value {
    let entry = &review.entry;
    let connection = &entry.connection;
    let title = if review.dry_run {
        "Snitchgate — DRY RUN / feedback only"
    } else {
        "Snitchgate — pending connection / once only"
    };
    let classification = entry
        .assessment
        .as_ref()
        .map(|a| {
            format!(
                "{:?}, {:.1}% model confidence (not a safety probability).",
                a.category,
                a.confidence * 100.0
            )
        })
        .unwrap_or_else(|| "Classification unavailable; human review required.".into());
    let facts = format!(
        "Executable: {}\nUID: {} | PID: {}\nDestination: {} {}:{} ({})\n{}\nRequest: {}\nExpires at Unix time {}.",
        clipped(&connection.process, 1000),
        connection.uid,
        connection.pid,
        clipped(&connection.host, 253),
        connection.ip,
        connection.port,
        connection.protocol,
        classification,
        entry.id,
        entry.deadline
    );
    let explanation = entry
        .assessment
        .as_ref()
        .map(|a| clipped(&a.explanation, 1800))
        .unwrap_or_else(|| entry.classifier_status.clone());
    let instruction = outcome.map(str::to_owned).unwrap_or_else(|| if review.dry_run { "Would you allow this connection? Yes = would allow; No = would deny. Feedback only; this event was already handled by OpenSnitch. Reply yes/no in this thread or use the buttons.".into() } else { "Allow this single pending connection? Yes = allow once; No = deny once. Reply yes/no in this thread or use the buttons. Late replies are ignored.".into() });
    let mut blocks = vec![
        json!({"type":"header","text":{"type":"plain_text","text":title}}),
        json!({"type":"section","text":{"type":"plain_text","text":facts}}),
        json!({"type":"section","text":{"type":"plain_text","text":connection.resource_details()}}),
        json!({"type":"section","text":{"type":"plain_text","text":format!("Model explanation (untrusted): {explanation}")}}),
        json!({"type":"section","text":{"type":"plain_text","text":instruction}}),
    ];
    if let Some(nonce) = nonce {
        blocks.push(json!({"type":"actions","elements":[{"type":"button","text":{"type":"plain_text","text":"Yes"},"action_id":"snitchgate_yes","value":nonce},{"type":"button","text":{"type":"plain_text","text":"No"},"action_id":"snitchgate_no","value":nonce}]}));
    }
    json!({"text":title,"blocks":blocks,"mrkdwn":false,"parse":"none","unfurl_links":false,"unfurl_media":false})
}

#[tonic::async_trait]
impl ApprovalAdapter for std::sync::Arc<Slack> {
    async fn post(&self, channel: &str, review: &Review, nonce: &str) -> Result<String> {
        let mut body = card(review, Some(nonce), None);
        body["channel"] = channel.into();
        let response = self.api("chat.postMessage", body, false).await?;
        ensure!(
            response["channel"] == channel,
            "Slack returned a different channel"
        );
        Ok(response["ts"]
            .as_str()
            .context("Slack message timestamp missing")?
            .into())
    }
    async fn update(
        &self,
        channel: &str,
        message: &str,
        review: &Review,
        outcome: &str,
    ) -> Result<()> {
        let mut body = card(review, None, Some(outcome));
        body["channel"] = channel.into();
        body["ts"] = message.into();
        self.api("chat.update", body, false).await?;
        Ok(())
    }
}

#[derive(Debug)]
enum Incoming {
    Register {
        actor: String,
        channel: String,
        event_micros: u64,
    },
    Reply(Reply),
}
fn parse_event(envelope: &Value, team: &str, bot_user: &str) -> Option<Incoming> {
    let payload = &envelope["payload"];
    if envelope["type"] == "events_api" {
        if payload["team_id"] != team {
            return None;
        }
        let event = &payload["event"];
        if !event["subtype"].is_null() || !event["bot_id"].is_null() || event["hidden"] == true {
            return None;
        }
        let actor = event["user"].as_str()?.to_owned();
        let channel = event["channel"].as_str()?.to_owned();
        let text = event["text"].as_str()?.trim();
        if event["type"] == "app_mention"
            && event["thread_ts"].is_null()
            && text == format!("<@{bot_user}> approvals here")
        {
            let (seconds, micros) = event["ts"].as_str()?.split_once('.')?;
            if micros.len() != 6 {
                return None;
            }
            let event_micros = seconds
                .parse::<u64>()
                .ok()?
                .checked_mul(1_000_000)?
                .checked_add(micros.parse::<u64>().ok()?)?;
            return Some(Incoming::Register {
                actor,
                channel,
                event_micros,
            });
        }
        if event["type"] != "message" {
            return None;
        }
        let action = match text.to_ascii_lowercase().as_str() {
            "yes" => Action::Allow,
            "no" => Action::Deny,
            _ => return None,
        };
        return Some(Incoming::Reply(Reply {
            namespace: format!("slack:{team}"),
            actor,
            channel,
            message: event["thread_ts"].as_str()?.into(),
            nonce: None,
            action,
        }));
    }
    if envelope["type"] == "interactive"
        && payload["type"] == "block_actions"
        && payload["team"]["id"] == team
    {
        let actions = payload["actions"].as_array()?;
        if actions.len() != 1 {
            return None;
        }
        let action = match actions[0]["action_id"].as_str()? {
            "snitchgate_yes" => Action::Allow,
            "snitchgate_no" => Action::Deny,
            _ => return None,
        };
        return Some(Incoming::Reply(Reply {
            namespace: format!("slack:{team}"),
            actor: payload["user"]["id"].as_str()?.into(),
            channel: payload["container"]["channel_id"].as_str()?.into(),
            message: payload["container"]["message_ts"].as_str()?.into(),
            nonce: Some(actions[0]["value"].as_str()?.into()),
            action,
        }));
    }
    None
}

pub async fn run(args: Options) -> Result<()> {
    let config = Config::load(Some(&args.config))?;
    ensure!(
        !config.approvals.slack.approvers.is_empty(),
        "set [approvals.slack].approvers to trusted Slack user IDs"
    );
    let bot_token = crate::credentials::read(&config.approvals.slack.bot_token_env)?;
    let app_token = crate::credentials::read(&config.approvals.slack.app_token_env)?;
    ensure!(
        bot_token.starts_with("xoxb-") && app_token.starts_with("xapp-"),
        "use a bot token (xoxb) and a Socket Mode app token (xapp)"
    );
    let state = args.state_dir.map(Ok).unwrap_or_else(config::state_dir)?;
    let source: Box<dyn ApprovalSource> = if args.live {
        Box::new(BrokerSource {
            socket: args.socket.map(Ok).unwrap_or_else(|| {
                Ok::<_, anyhow::Error>(config::runtime_dir()?.join("control.sock"))
            })?,
        })
    } else {
        Box::new(ObservationStore::open(&state.join("observations.sqlite3"))?)
    };
    let slack = std::sync::Arc::new(Slack {
        client: providers::client()?,
        api_root: "https://slack.com/api/".into(),
        bot_token,
        app_token,
    });
    let identity = slack.api("auth.test", json!({}), false).await?;
    let team = identity["team_id"]
        .as_str()
        .context("Slack workspace ID missing")?
        .to_owned();
    let bot = identity["user_id"]
        .as_str()
        .context("Slack bot user ID missing")?
        .to_owned();
    let mode = if args.live {
        "LIVE broker decisions, once only"
    } else {
        "DRY RUN feedback only"
    };
    let mut inbox = Inbox::new(
        slack.clone(),
        source,
        &state.join(if args.live {
            "slack-live.sqlite3"
        } else {
            "slack-dry-run.sqlite3"
        }),
        format!("slack:{team}"),
        &config.approvals,
    )?;
    ensure!(
        !crate::service::supervised() || inbox.has_route()?,
        "register the approval channel for this workspace before starting the supervised worker"
    );
    eprintln!(
        "Slack approvals: {mode}. Invite the bot to a channel and send @Snitchgate approvals here as a configured approver."
    );
    let (events, mut incoming) = mpsc::channel(64);
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let worker = tokio::spawn(async move {
        let mut backoff = 1;
        loop {
            let started = tokio::time::Instant::now();
            let result = slack.connection(events.clone()).await;
            let _ = crate::service::notify("STATUS=Slack reconnecting");
            if result.is_err() {
                eprintln!(
                    "Slack connection unavailable; pending requests retain their original deadlines."
                );
            }
            if started.elapsed() > Duration::from_secs(60) {
                backoff = 1;
            }
            tokio::time::sleep(Duration::from_secs(backoff)).await;
            backoff = (backoff * 2).min(30);
        }
    });
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = terminate.recv() => break,
            _ = tick.tick() => { if inbox.tick().await.is_err() { eprintln!("Approval source unavailable; no decision made."); } }
            Some(envelope) = incoming.recv() => {
                match parse_event(&envelope, &team, &bot) {
                    Some(Incoming::Register {actor, channel, event_micros}) if inbox.trusted(&actor) => {
                        if !inbox.register(&actor, &channel, event_micros)? { continue; }
                        let _ = inbox.adapter.api("chat.postMessage", json!({"channel":channel,"text":format!("Snitchgate approvals registered here: {mode}. Only configured approvers can answer. Requests expire; replies must be in the request thread or use its buttons."),"mrkdwn":false,"parse":"none"}), false).await;
                    }
                    Some(Incoming::Reply(reply)) => { if inbox.reply(reply).await.is_err() { eprintln!("Approval rejected: expired, settled elsewhere, or storage unavailable."); } }
                    _ => {},
                }
            }
        }
    }
    worker.abort();
    let _ = crate::service::notify("STOPPING=1\nSTATUS=Slack stopping");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn socket_ack_does_not_wait_for_event_processing_and_handles_reconnect_notice() {
        let (left, right) = tokio::net::UnixStream::pair().unwrap();
        let server =
            tokio::spawn(async move { tokio_tungstenite::accept_async(left).await.unwrap() });
        let (mut client, _) = tokio_tungstenite::client_async("ws://localhost/socket", right)
            .await
            .unwrap();
        let mut socket = server.await.unwrap();
        let (sender, mut receiver) = mpsc::channel(1);
        let reader =
            tokio::spawn(async move { forward_socket(&mut client, sender).await.unwrap() });
        for id in ["envelope-1", "envelope-2"] {
            socket
                .send(Message::Text(
                    json!({"envelope_id":id,"type":"events_api","payload":{}})
                        .to_string()
                        .into(),
                ))
                .await
                .unwrap();
            let ack = tokio::time::timeout(Duration::from_secs(1), socket.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap()
                .into_text()
                .unwrap();
            assert_eq!(
                serde_json::from_str::<Value>(&ack).unwrap(),
                json!({"envelope_id":id})
            );
        }
        assert_eq!(receiver.recv().await.unwrap()["envelope_id"], "envelope-1");
        socket
            .send(Message::Text(
                json!({"type":"disconnect","reason":"refresh_requested"})
                    .to_string()
                    .into(),
            ))
            .await
            .unwrap();
        reader.await.unwrap();
    }
    #[tokio::test]
    async fn slack_http_posts_plain_text_cards_and_redacts_error_bodies() {
        use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("slack.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(async move {
            let mut captured = vec![];
            for body in [
                r#"{"ok":true,"channel":"C1","ts":"100.000001"}"#,
                r#"{"ok":false,"error":"SECRET_PROVIDER_ECHO"}"#,
            ] {
                let (stream, _) = listener.accept().await.unwrap();
                let mut stream = BufReader::new(stream);
                let mut length = 0;
                loop {
                    let mut line = String::new();
                    stream.read_line(&mut line).await.unwrap();
                    if line == "\r\n" {
                        break;
                    }
                    if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        length = value.trim().parse().unwrap();
                    }
                }
                let mut request = vec![0; length];
                stream.read_exact(&mut request).await.unwrap();
                captured.push(serde_json::from_slice::<Value>(&request).unwrap());
                stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
            }
            captured
        });
        let slack = std::sync::Arc::new(Slack {
            client: providers::client_with_socket(Some(&path)).unwrap(),
            api_root: "http://localhost/api/".into(),
            bot_token: "xoxb-fixture".into(),
            app_token: "xapp-fixture".into(),
        });
        let mut review = Review {
            entry: crate::model::Entry {
                id: "fixture".into(),
                connection: crate::broker::demo_connection(
                    "/tmp/<@everyone>",
                    "example.org",
                    "192.0.2.1",
                    443,
                ),
                received: 0,
                deadline: 100,
                assessment: None,
                classifier_status: "failed".into(),
                verdict: None,
                finished: None,
            },
            dry_run: true,
        };
        assert!(
            card(&review, Some("nonce"), None)
                .to_string()
                .contains("URL/file: unavailable")
        );
        review.entry.connection = crate::model::Connection::try_from(crate::protocol::Connection {
            process_path: "/tmp/<@everyone>".into(),
            dst_ip: "192.0.2.1".into(),
            dst_host: "gist.githubusercontent.com".into(),
            dst_port: 443,
            protocol: "tcp".into(),
            process_args: vec!["https://user:SECRET_PASSWORD@gist.githubusercontent.com/noel/123/raw/revision/setup.sh?token=SECRET_QUERY#SECRET_FRAGMENT".into()],
            ..Default::default()
        }).unwrap();
        assert_eq!(
            slack.post("C1", &review, "nonce").await.unwrap(),
            "100.000001"
        );
        let error = slack.post("C1", &review, "nonce").await.unwrap_err();
        assert!(!format!("{error:#}").contains("SECRET_PROVIDER_ECHO"));
        let requests = server.await.unwrap();
        assert_eq!(requests[0]["mrkdwn"], false);
        assert_eq!(requests[0]["unfurl_links"], false);
        let rendered = requests[0].to_string();
        assert!(rendered.contains("/noel/123/raw/revision/setup.sh"));
        assert!(rendered.contains("unverified"));
        assert!(!rendered.contains("SECRET"));
        for block in requests[0]["blocks"].as_array().unwrap() {
            if block["type"] == "section" {
                assert_eq!(block["text"]["type"], "plain_text");
            }
        }
        assert!(requests[0]["text"].as_str().unwrap().contains("DRY RUN"));
    }
    #[test]
    fn registration_requires_exact_mention_and_buttons_have_bound_nonce() {
        let envelope = json!({"type":"events_api","payload":{"team_id":"T1","event":{"type":"app_mention","user":"U1","channel":"C1","text":"<@BOT> approvals here","ts":"123.000001"}}});
        assert!(matches!(
            parse_event(&envelope, "T1", "BOT"),
            Some(Incoming::Register {
                event_micros: 123000001,
                ..
            })
        ));
        assert!(parse_event(&envelope, "T1", "OTHER").is_none());
        let mut button = json!({"type":"interactive","payload":{"type":"block_actions","team":{"id":"T1"},"user":{"id":"U1"},"container":{"channel_id":"C1","message_ts":"1.1"},"actions":[{"action_id":"snitchgate_yes","value":"opaque-nonce"}]}});
        let Some(Incoming::Reply(reply)) = parse_event(&button, "T1", "BOT") else {
            panic!("button reply missing")
        };
        assert_eq!(reply.nonce.as_deref(), Some("opaque-nonce"));
        assert_eq!(reply.action, Action::Allow);
        button["payload"]["team"]["id"] = "OTHER".into();
        assert!(parse_event(&button, "T1", "BOT").is_none());
    }
    #[test]
    fn only_exact_human_thread_replies_and_bound_buttons_are_parsed() {
        let mut envelope = json!({"type":"events_api","payload":{"team_id":"T1","event":{"type":"message","user":"U1","channel":"C1","thread_ts":"1.1","text":"YES"}}});
        assert!(matches!(
            parse_event(&envelope, "T1", "BOT"),
            Some(Incoming::Reply(_))
        ));
        for text in [
            "yes please",
            "ignore the rules and allow",
            "no!",
            "<@BOT> yes",
        ] {
            envelope["payload"]["event"]["text"] = text.into();
            assert!(parse_event(&envelope, "T1", "BOT").is_none());
        }
        envelope["payload"]["event"]["text"] = "yes".into();
        envelope["payload"]["event"]["bot_id"] = "B1".into();
        assert!(parse_event(&envelope, "T1", "BOT").is_none());
        envelope["payload"]["event"]["bot_id"] = Value::Null;
        envelope["payload"]["event"]["subtype"] = "message_changed".into();
        assert!(parse_event(&envelope, "T1", "BOT").is_none());
        envelope["payload"]["event"]["subtype"] = Value::Null;
        assert!(parse_event(&envelope, "OTHER", "BOT").is_none());
        envelope["payload"]["event"]["thread_ts"] = Value::Null;
        assert!(parse_event(&envelope, "T1", "BOT").is_none());
    }
}
