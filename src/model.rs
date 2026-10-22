use crate::protocol;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    net::IpAddr,
    time::{SystemTime, UNIX_EPOCH},
};

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Control and formatting characters are never passed through to a terminal.
pub fn display_text(value: &str) -> String {
    value
        .chars()
        .filter(|c| {
            !c.is_control() && !matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
        .take(4096)
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Connection {
    pub process: String,
    pub pid: u32,
    pub uid: u32,
    pub protocol: String,
    pub ip: IpAddr,
    pub host: String,
    pub port: u16,
    /// Human inspection only: matching argv URLs with user info/query/fragment removed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub url_hints: Vec<String>,
}

fn argument_url_hints(raw: &protocol::Connection, ip: IpAddr, port: u16) -> Vec<String> {
    if !raw.protocol.eq_ignore_ascii_case("tcp") {
        return vec![];
    }
    let mut hints = vec![];
    let mut scanned = 0;
    for argument in raw.process_args.iter().take(128) {
        scanned += argument.len();
        if scanned > 32 * 1024 {
            break;
        }
        if argument.len() > 4096
            || argument.chars().any(char::is_whitespace)
            || argument.chars().any(char::is_control)
        {
            continue;
        }
        let Ok(mut url) = reqwest::Url::parse(argument) else {
            continue;
        };
        if !matches!(url.scheme(), "http" | "https") || url.port_or_known_default() != Some(port) {
            continue;
        }
        let Some(host) = url.host_str() else {
            continue;
        };
        let matches_host = !raw.dst_host.is_empty()
            && host
                .trim_end_matches('.')
                .eq_ignore_ascii_case(raw.dst_host.trim_end_matches('.'));
        let matches_ip = host.trim_matches(['[', ']']).parse::<IpAddr>().ok() == Some(ip);
        if !matches_host && !matches_ip {
            continue;
        }
        let _ = url.set_username("");
        let _ = url.set_password(None);
        url.set_query(None);
        url.set_fragment(None);
        let hint = url.to_string();
        if hint.len() <= 768 && !hints.contains(&hint) {
            hints.push(hint);
            if hints.len() == 3 {
                break;
            }
        }
    }
    hints
}

impl Connection {
    pub fn resource_details(&self) -> String {
        if self.url_hints.is_empty() {
            "URL/file: unavailable. OpenSnitch has no HTTP URL field; HTTPS paths are encrypted. A matching command-line URL may provide a hint.".into()
        } else {
            format!(
                "URL/path hints from process arguments (unverified; user info, query and fragment omitted):\n{}\nApproval covers the connection, not an individual file.",
                self.url_hints
                    .iter()
                    .map(|url| display_text(url))
                    .collect::<Vec<_>>()
                    .join("\n")
            )
        }
    }
}

impl TryFrom<protocol::Connection> for Connection {
    type Error = anyhow::Error;
    fn try_from(raw: protocol::Connection) -> Result<Self> {
        ensure!(
            raw.process_path.len() <= 4096 && raw.dst_host.len() <= 253,
            "oversized connection metadata"
        );
        ensure!(
            raw.process_path.chars().all(|c| !c.is_control()),
            "invalid process path"
        );
        ensure!(
            raw.dst_host.is_ascii()
                && raw
                    .dst_host
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')),
            "invalid hostname"
        );
        let protocol = raw.protocol.to_ascii_lowercase();
        ensure!(
            matches!(protocol.as_str(), "tcp" | "udp"),
            "unsupported protocol"
        );
        let ip = raw.dst_ip.parse()?;
        let port = u16::try_from(raw.dst_port)?;
        let url_hints = argument_url_hints(&raw, ip, port);
        Ok(Self {
            process: raw.process_path,
            pid: raw.process_id,
            uid: raw.user_id,
            protocol,
            ip,
            host: raw.dst_host,
            port,
            url_hints,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Allow,
    Deny,
}
impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum Duration {
    Once,
    FiveMinutes,
}
impl Duration {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Once => "once",
            Self::FiveMinutes => "5m",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub action: Action,
    pub duration: Duration,
    pub source: String,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Expected,
    Development,
    Telemetry,
    Suspicious,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Assessment {
    pub category: Category,
    pub confidence: f64,
    pub model: String,
    pub explanation: String,
    pub llm_model: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub id: String,
    pub connection: Connection,
    pub received: u64,
    pub deadline: u64,
    pub assessment: Option<Assessment>,
    pub classifier_status: String,
    pub verdict: Option<Verdict>,
    pub finished: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Health {
    pub daemon: Option<String>,
    pub last_ping: Option<u64>,
    pub rule_count: usize,
    pub alerts: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub pending: Vec<Entry>,
    pub history: Vec<Entry>,
    pub health: Health,
    pub mode: String,
    pub classifier_enabled: bool,
    pub automation_scopes: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    fn gist_connection(args: &[&str]) -> protocol::Connection {
        protocol::Connection {
            dst_ip: "192.0.2.1".into(),
            dst_host: "gist.githubusercontent.com".into(),
            dst_port: 443,
            protocol: "tcp".into(),
            process_args: args.iter().map(|arg| (*arg).into()).collect(),
            ..Default::default()
        }
    }
    #[test]
    fn keeps_matching_file_path_without_credentials_query_fragment_or_other_arguments() {
        let connection = Connection::try_from(gist_connection(&[
            "curl", "--header", "Authorization: Bearer SECRET_HEADER",
            "https://user:SECRET_PASSWORD@gist.githubusercontent.com/noel/123/raw/abc/setup.sh?token=SECRET_QUERY#SECRET_FRAGMENT",
            "https://elsewhere.example/SECRET_OTHER_HOST",
            "https://gist.githubusercontent.com:8443/SECRET_OTHER_PORT",
            "file:///tmp/SECRET_LOCAL_FILE",
        ])).unwrap();
        assert_eq!(
            connection.url_hints,
            ["https://gist.githubusercontent.com/noel/123/raw/abc/setup.sh"]
        );
        let json = serde_json::to_string(&connection).unwrap();
        assert!(!json.contains("SECRET"));
        assert!(connection.resource_details().contains("unverified"));
        assert!(
            connection
                .resource_details()
                .contains("not an individual file")
        );
    }
    #[test]
    fn hints_are_bounded_deduplicated_and_absence_is_explicit() {
        let raw = gist_connection(&[
            "https://gist.githubusercontent.com/one?secret=1",
            "https://gist.githubusercontent.com/one?secret=2",
            "https://gist.githubusercontent.com/two",
            "https://gist.githubusercontent.com/three",
            "https://gist.githubusercontent.com/four",
        ]);
        let connection = Connection::try_from(raw).unwrap();
        assert_eq!(connection.url_hints.len(), 3);
        assert!(!connection.url_hints.iter().any(|url| url.contains("four")));
        let mut raw = gist_connection(&["https://gist.githubusercontent.com/file.sh"]);
        raw.dst_host = String::new();
        let connection = Connection::try_from(raw).unwrap();
        assert!(connection.url_hints.is_empty());
        assert!(connection.resource_details().contains("unavailable"));
        let mut raw = gist_connection(&[]);
        raw.process_args = vec![format!(
            "https://gist.githubusercontent.com/{}",
            "x".repeat(1000)
        )];
        assert!(Connection::try_from(raw).unwrap().url_hints.is_empty());
        let mut raw = gist_connection(&["https://gist.githubusercontent.com/file.sh"]);
        raw.protocol = "udp".into();
        assert!(Connection::try_from(raw).unwrap().url_hints.is_empty());
    }
    #[test]
    fn old_history_without_url_hints_remains_readable() {
        let connection = Connection::try_from(gist_connection(&[])).unwrap();
        let json = serde_json::to_string(&connection).unwrap();
        assert!(!json.contains("url_hints"));
        assert!(
            serde_json::from_str::<Connection>(&json)
                .unwrap()
                .url_hints
                .is_empty()
        );
    }
    #[test]
    fn drops_secrets_at_protocol_boundary() {
        let raw = protocol::Connection {
            dst_ip: "127.0.0.1".into(),
            protocol: "tcp".into(),
            process_args: vec!["secret-token".into()],
            process_env: [("SECRET".into(), "password".into())].into(),
            ..Default::default()
        };
        let json = serde_json::to_string(&Connection::try_from(raw).unwrap()).unwrap();
        assert!(!json.contains("secret") && !json.contains("password"));
    }
    #[test]
    fn rejects_malformed_destination() {
        assert!(
            Connection::try_from(protocol::Connection {
                dst_ip: "bad".into(),
                protocol: "tcp".into(),
                ..Default::default()
            })
            .is_err()
        );
    }
    #[test]
    fn sanitizes_terminal_control_characters() {
        assert_eq!(display_text("hi\x1b[31m\n\u{202e}end"), "hi[31mend");
    }
}
