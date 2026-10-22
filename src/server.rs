use crate::{
    broker::Broker,
    model::Connection,
    policy,
    protocol::{
        self,
        ui_server::{Ui, UiServer},
    },
};
use anyhow::Result;
use std::{os::unix::fs::MetadataExt, pin::Pin, sync::Arc};
use tokio::net::UnixListener;
use tokio_stream::{
    Stream,
    wrappers::{ReceiverStream, UnixListenerStream},
};
use tonic::{Request, Response, Status};

pub struct OpenSnitch {
    broker: Arc<Broker>,
}
#[tonic::async_trait]
impl Ui for OpenSnitch {
    async fn ping(
        &self,
        request: Request<protocol::PingRequest>,
    ) -> Result<Response<protocol::PingReply>, Status> {
        self.broker.ping();
        Ok(Response::new(protocol::PingReply {
            id: request.into_inner().id,
        }))
    }
    async fn ask_rule(
        &self,
        request: Request<protocol::Connection>,
    ) -> Result<Response<protocol::Rule>, Status> {
        let connection = Connection::try_from(request.into_inner())
            .map_err(|_| Status::invalid_argument("invalid connection metadata"))?;
        let verdict = match self.broker.submit(connection.clone()) {
            Ok(receiver) => receiver
                .await
                .unwrap_or_else(|_| policy::fallback("Broker unavailable")),
            Err(_) => policy::fallback("Request queue full"),
        };
        // Every rule is generated from captured metadata; model prose never enters an operator.
        Ok(Response::new(policy::rule(
            &uuid::Uuid::new_v4().to_string(),
            &connection,
            &verdict,
        )))
    }
    async fn subscribe(
        &self,
        request: Request<protocol::ClientConfig>,
    ) -> Result<Response<protocol::ClientConfig>, Status> {
        let config = request.into_inner();
        self.broker.subscribe(config.name, config.rules.len());
        // Empty config is deliberate. Echoing the daemon's config can cause it
        // to treat a UI connection as a request to change its settings.
        Ok(Response::new(protocol::ClientConfig {
            name: "snitchgate".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            ..Default::default()
        }))
    }
    type NotificationsStream =
        Pin<Box<dyn Stream<Item = Result<protocol::Notification, Status>> + Send>>;
    async fn notifications(
        &self,
        request: Request<tonic::Streaming<protocol::NotificationReply>>,
    ) -> Result<Response<Self::NotificationsStream>, Status> {
        let mut inbound = request.into_inner();
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        tokio::spawn(async move {
            // Keep the bidirectional channel open without issuing management
            // actions. Drop it when either peer disconnects.
            tokio::select! {
                _ = sender.closed() => {},
                _ = async { while let Ok(Some(_)) = inbound.message().await {} } => {},
            }
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(receiver))))
    }
    async fn post_alert(
        &self,
        request: Request<protocol::Alert>,
    ) -> Result<Response<protocol::MsgResponse>, Status> {
        self.broker.alert();
        // Alert payloads can contain environment/argument data; do not store them.
        Ok(Response::new(protocol::MsgResponse {
            id: request.into_inner().id,
        }))
    }
}

pub async fn serve(listener: UnixListener, broker: Arc<Broker>) -> Result<()> {
    tonic::transport::Server::builder()
        .concurrency_limit_per_connection(256)
        .add_service(
            UiServer::new(OpenSnitch { broker }).max_decoding_message_size(16 * 1024 * 1024),
        )
        .serve_with_incoming(UnixListenerStream::new(listener))
        .await?;
    Ok(())
}

/// grpc-go 1.32 uses a filesystem Unix target as its HTTP/2 authority, which
/// modern HTTP stacks correctly reject. A slash-free abstract socket name is
/// compatible with the installed daemon without weakening HTTP validation.
pub async fn serve_abstract(name: &str, broker: Arc<Broker>) -> Result<()> {
    use futures_util::StreamExt;
    use std::os::linux::net::SocketAddrExt;
    anyhow::ensure!(
        !name.is_empty()
            && name.len() <= 100
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_')),
        "invalid abstract socket name"
    );
    let address = std::os::unix::net::SocketAddr::from_abstract_name(name)?;
    let listener = std::os::unix::net::UnixListener::bind_addr(&address)?;
    listener.set_nonblocking(true)?;
    let listener = UnixListener::from_std(listener)?;
    let uid = std::fs::metadata("/proc/self")?.uid();
    // Abstract sockets have no filesystem permissions. Require kernel peer
    // credentials: only the owner and root daemon may use this local endpoint.
    let incoming = UnixListenerStream::new(listener).filter_map(move |stream| async move {
        match stream {
            Ok(stream)
                if stream
                    .peer_cred()
                    .is_ok_and(|cred| cred.uid() == 0 || cred.uid() == uid) =>
            {
                Some(Ok::<_, std::io::Error>(stream))
            }
            Err(error) => Some(Err(error)),
            _ => None,
        }
    });
    tonic::transport::Server::builder()
        .concurrency_limit_per_connection(256)
        .add_service(
            UiServer::new(OpenSnitch { broker }).max_decoding_message_size(16 * 1024 * 1024),
        )
        .serve_with_incoming(incoming)
        .await?;
    Ok(())
}

pub async fn connect(
    path: &std::path::Path,
) -> Result<protocol::ui_client::UiClient<tonic::transport::Channel>> {
    let path = path.to_owned();
    let channel = tonic::transport::Endpoint::try_from("http://[::]:50051")?
        .connect_with_connector(tower::service_fn(move |_| {
            let path = path.clone();
            async move {
                tokio::net::UnixStream::connect(path)
                    .await
                    .map(hyper_util::rt::TokioIo::new)
            }
        }))
        .await?;
    Ok(protocol::ui_client::UiClient::new(channel))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn real_grpc_wire_flow_includes_subscription_and_temporary_reply() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("private/opensnitch.sock");
        let listener = crate::ipc::bind(&path).unwrap();
        let broker = Broker::new(
            crate::config::Config::default(),
            crate::store::Store::memory(100).unwrap(),
            false,
        )
        .unwrap();
        let server = tokio::spawn(serve(listener, broker.clone()));
        let mut client = connect(&path).await.unwrap();
        let reply = client
            .subscribe(protocol::ClientConfig {
                name: "mock-host".into(),
                config: "private".into(),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner();
        assert!(reply.config.is_empty());
        assert_eq!(
            client
                .ping(protocol::PingRequest {
                    id: 42,
                    stats: None
                })
                .await
                .unwrap()
                .into_inner()
                .id,
            42
        );
        let asking = tokio::spawn(async move {
            client
                .ask_rule(protocol::Connection {
                    protocol: "tcp".into(),
                    dst_ip: "127.0.0.1".into(),
                    dst_port: 8000,
                    dst_host: "gist.githubusercontent.com".into(),
                    process_path: "/usr/bin/curl".into(),
                    process_args: vec!["http://gist.githubusercontent.com:8000/noel/123/raw/abc/script.sh?token=SECRET_QUERY".into()],
                    user_id: 1000,
                    ..Default::default()
                })
                .await
                .unwrap()
                .into_inner()
        });
        let id = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if let Some(entry) = broker.snapshot().unwrap().pending.first() {
                    assert_eq!(
                        entry.connection.url_hints,
                        ["http://gist.githubusercontent.com:8000/noel/123/raw/abc/script.sh"]
                    );
                    break entry.id.clone();
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        broker
            .decide(
                &id,
                crate::model::Action::Allow,
                crate::model::Duration::Once,
            )
            .unwrap();
        let rule = asking.await.unwrap();
        assert_eq!(rule.action, "allow");
        assert_eq!(rule.duration, "once");
        let operators = rule.operator.unwrap().list;
        assert_eq!(operators.len(), 5);
        assert!(operators.iter().all(|op| !op.data.contains("script.sh")
            && !op.data.contains("SECRET_QUERY")
            && op.operand != "process.command"));
        assert_eq!(
            broker.snapshot().unwrap().health.daemon.as_deref(),
            Some("mock-host")
        );
        server.abort();
    }
}
