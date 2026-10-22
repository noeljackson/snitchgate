use crate::{
    broker::Broker,
    ipc::{self, Command},
    model::{Action, Duration, Entry, Snapshot, display_text, now},
};
use anyhow::Result;
use crossterm::event::{Event, EventStream, KeyCode, KeyEventKind, KeyModifiers};
use futures_util::StreamExt;
use ratatui::{
    Frame,
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState, Tabs, Wrap},
};
use std::{path::PathBuf, sync::Arc, time::Duration as StdDuration};

const BG: Color = Color::Rgb(14, 19, 26);
const PANEL: Color = Color::Rgb(22, 29, 38);
const FG: Color = Color::Rgb(214, 224, 235);
const MUTED: Color = Color::Rgb(133, 151, 169);
const ACCENT: Color = Color::Rgb(102, 226, 187);
const WARNING: Color = Color::Rgb(255, 199, 111);

pub enum Source {
    Service(PathBuf),
    Demo(Arc<Broker>),
}
impl Source {
    async fn snapshot(&self) -> Result<Snapshot> {
        match self {
            Self::Service(path) => Ok(ipc::request(path, Command::Snapshot)
                .await?
                .snapshot
                .ok_or_else(|| anyhow::anyhow!("missing snapshot"))?),
            Self::Demo(broker) => broker.snapshot(),
        }
    }
    async fn decide(&self, id: String, action: Action, duration: Duration) -> Result<()> {
        match self {
            Self::Service(path) => {
                ipc::request(
                    path,
                    Command::Decide {
                        id,
                        action,
                        duration,
                    },
                )
                .await?;
                Ok(())
            }
            Self::Demo(broker) => broker.decide(&id, action, duration),
        }
    }
}

#[derive(Default)]
pub struct App {
    tab: usize,
    selected: Option<String>,
    table: TableState,
    filter: String,
    searching: bool,
    duration: Option<Duration>,
    status: String,
    scroll: u16,
}

impl App {
    fn entries<'a>(&self, snapshot: &'a Snapshot) -> Vec<&'a Entry> {
        let source = if self.tab == 1 {
            &snapshot.history
        } else {
            &snapshot.pending
        };
        let query = self.filter.to_lowercase();
        source
            .iter()
            .filter(|e| {
                format!(
                    "{} {} {} {}",
                    e.connection.process, e.connection.host, e.connection.ip, e.connection.port
                )
                .to_lowercase()
                .contains(&query)
            })
            .collect()
    }
    fn sync_selection(&mut self, snapshot: &Snapshot) {
        let entries = self.entries(snapshot);
        let index = self
            .selected
            .as_ref()
            .and_then(|id| entries.iter().position(|e| &e.id == id));
        let index = index.or(if entries.is_empty() { None } else { Some(0) });
        self.selected = index.map(|i| entries[i].id.clone());
        self.table.select(index);
    }
    fn navigate(&mut self, snapshot: &Snapshot, delta: isize) {
        let entries = self.entries(snapshot);
        if entries.is_empty() {
            return;
        }
        let index = self
            .table
            .selected()
            .unwrap_or(0)
            .saturating_add_signed(delta)
            .min(entries.len() - 1);
        self.selected = Some(entries[index].id.clone());
        self.table.select(Some(index));
        self.scroll = 0;
    }
}

fn panel(title: &str) -> Block<'_> {
    Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Rgb(46, 62, 77)))
        .style(Style::default().bg(PANEL).fg(FG))
}

pub fn draw(frame: &mut Frame<'_>, app: &mut App, snapshot: &Snapshot) {
    frame.render_widget(
        Block::default().style(Style::default().bg(BG).fg(FG)),
        frame.area(),
    );
    if frame.area().width < 60 || frame.area().height < 15 {
        frame.render_widget(Paragraph::new("Snitchgate needs a terminal at least 60 x 15.\nResize the terminal, or press q to quit.").style(Style::default().fg(FG)), frame.area());
        return;
    }
    let rows = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(2),
        Constraint::Min(5),
        Constraint::Length(3),
    ])
    .split(frame.area());
    let title = Line::from(vec![
        Span::styled(
            " SNITCHGATE ",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ),
        Span::styled(" / OpenSnitch control room", Style::default().fg(MUTED)),
    ]);
    let mode = format!(
        " {}  |  {} pending  |  {} recent decisions",
        snapshot.mode,
        snapshot.pending.len(),
        snapshot.history.len()
    );
    frame.render_widget(Paragraph::new(vec![title, Line::from(mode)]), rows[0]);
    frame.render_widget(
        Tabs::new(["1 Inbox", "2 History", "3 Health"])
            .select(app.tab)
            .highlight_style(Style::default().fg(ACCENT).add_modifier(Modifier::BOLD))
            .divider("  "),
        rows[1],
    );
    if app.tab == 2 {
        let ping = snapshot
            .health
            .last_ping
            .map(|p| format!("{} seconds ago", now().saturating_sub(p)))
            .unwrap_or_else(|| "not yet connected".into());
        let daemon = snapshot
            .health
            .daemon
            .as_deref()
            .unwrap_or("waiting for daemon subscription");
        let text = format!(
            "\n  Daemon                 {}\n  Last heartbeat         {}\n  Rules at subscription  {}\n  Alerts received        {}\n\n  Jev                    {}\n  Automation scopes      {}\n  Mode                   {}\n\n  Timeout decisions deny once. Permanent policy is proposed into Git.\n  Closing this TUI leaves an attached service running.\n  Arguments and environment variables are never stored or sent to models.",
            display_text(daemon),
            ping,
            snapshot.health.rule_count,
            snapshot.health.alerts,
            if snapshot.classifier_enabled {
                "enabled"
            } else {
                "disabled"
            },
            snapshot.automation_scopes,
            snapshot.mode
        );
        frame.render_widget(
            Paragraph::new(text)
                .block(panel(" Service health "))
                .wrap(Wrap { trim: false }),
            rows[2],
        );
    } else {
        let columns = if rows[2].width >= 100 {
            Layout::horizontal([Constraint::Percentage(56), Constraint::Percentage(44)])
                .split(rows[2])
        } else {
            Layout::vertical([Constraint::Percentage(50), Constraint::Percentage(50)])
                .split(rows[2])
        };
        let entries = app.entries(snapshot);
        let table_rows: Vec<_> = entries
            .iter()
            .map(|entry| {
                let c = &entry.connection;
                let process = c
                    .process
                    .rsplit('/')
                    .next()
                    .filter(|s| !s.is_empty())
                    .unwrap_or("unattributed");
                let destination = if c.host.is_empty() {
                    c.ip.to_string()
                } else {
                    c.host.clone()
                };
                let result = entry
                    .verdict
                    .as_ref()
                    .map(|v| v.action.as_str().to_string())
                    .unwrap_or_else(|| format!("{}s", entry.deadline.saturating_sub(now())));
                let category = entry
                    .assessment
                    .as_ref()
                    .map(|a| format!("{:?}", a.category).to_lowercase())
                    .unwrap_or_else(|| entry.classifier_status.clone());
                Row::new([
                    Cell::from(display_text(process)),
                    Cell::from(display_text(&format!("{destination}:{}", c.port))),
                    Cell::from(result),
                    Cell::from(category),
                ])
            })
            .collect();
        let title = format!(
            " {} · {} requests {} ",
            if app.tab == 1 { "History" } else { "Inbox" },
            entries.len(),
            if app.filter.is_empty() {
                String::new()
            } else {
                format!("/{}", display_text(&app.filter))
            }
        );
        let table = Table::new(
            table_rows,
            [
                Constraint::Percentage(23),
                Constraint::Percentage(37),
                Constraint::Length(7),
                Constraint::Min(8),
            ],
        )
        .header(
            Row::new(["PROCESS", "DESTINATION", "STATE", "CLASSIFICATION"])
                .style(Style::default().fg(MUTED))
                .bottom_margin(1),
        )
        .block(panel(&title))
        .row_highlight_style(Style::default().bg(Color::Rgb(35, 64, 65)).fg(ACCENT))
        .highlight_symbol("› ");
        frame.render_stateful_widget(table, columns[0], &mut app.table);
        let selected = app
            .selected
            .as_ref()
            .and_then(|id| entries.iter().find(|e| &e.id == id))
            .copied();
        let text = match selected {
            Some(entry) => {
                let c = &entry.connection;
                let assessment = entry.assessment.as_ref().map(|a| format!("{:?} · {:.1}% confidence\nJev: {}\nLLM: {}\n\n{}", a.category, a.confidence * 100.0, a.model, a.llm_model.as_deref().unwrap_or("not used"), a.explanation)).unwrap_or_else(|| if entry.verdict.is_some() { "No model classification was used.".into() } else { "Awaiting manual review.\n\nClassification does not grant permission.\nAllow and deny decisions are temporary.".into() });
                let verdict = entry.verdict.as_ref().map(|v| format!("\n\nDecision: {} / {}\nSource: {}\n{}", v.action.as_str(), v.duration.as_str(), v.source, v.reason)).unwrap_or_default();
                format!("Process\n{}\n\nUID {}  ·  PID {}\n{}://{}:{}\nHost: {}\n\n{}\nStatus: {}{}\n\nRequest {}", display_text(&c.process), c.uid, c.pid, c.protocol, c.ip, c.port, display_text(&c.host), assessment, entry.classifier_status, verdict, entry.id)
            }
            None => "No requests here.\n\nWaiting for OpenSnitch, or change the filter.\n\nUse `snitchgate mock` against the isolated socket to send a test request.".into(),
        };
        frame.render_widget(
            Paragraph::new(text)
                .block(panel(" Inspect "))
                .wrap(Wrap { trim: false })
                .scroll((app.scroll, 0)),
            columns[1],
        );
    }
    let footer = if app.searching {
        format!(
            " Search: {}█   Enter apply / Esc clear",
            display_text(&app.filter)
        )
    } else {
        format!(
            " j/k move · a allow · d deny · t duration:{} · / filter · Tab view · q quit\n {}",
            app.duration.unwrap_or(Duration::Once).as_str(),
            display_text(&app.status)
        )
    };
    frame.render_widget(
        Paragraph::new(footer).style(Style::default().fg(WARNING)),
        rows[3],
    );
}

pub async fn run(source: Source) -> Result<()> {
    let mut snapshot = source.snapshot().await?;
    let mut terminal = ratatui::init();
    let result = async {
        let mut app = App { status: "Decisions apply to the selected request ID. Timeout denies once.".into(), ..Default::default() };
        let mut events = EventStream::new();
        let mut interval = tokio::time::interval(StdDuration::from_millis(500));
        loop {
            app.sync_selection(&snapshot);
            terminal.draw(|frame| draw(frame, &mut app, &snapshot))?;
            tokio::select! {
                _ = interval.tick() => match source.snapshot().await {
                    Ok(current) => snapshot = current,
                    Err(_) => { app.status = "Service disconnected. Decisions are disabled until reconnection.".into(); snapshot.pending.clear(); }
                },
                event = events.next() => {
                    let Some(event) = event else { break; };
                    let Event::Key(key) = event? else { continue; };
                    if key.kind != KeyEventKind::Press { continue; }
                    if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) { break; }
                    if app.searching {
                        match key.code {
                            KeyCode::Enter => app.searching = false,
                            KeyCode::Esc => { app.searching = false; app.filter.clear(); },
                            KeyCode::Backspace => { app.filter.pop(); },
                            KeyCode::Char(c) if !c.is_control() && app.filter.len() < 128 => app.filter.push(c),
                            _ => {},
                        }
                        continue;
                    }
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => break,
                        KeyCode::Char('j') | KeyCode::Down => app.navigate(&snapshot, 1),
                        KeyCode::Char('k') | KeyCode::Up => app.navigate(&snapshot, -1),
                        KeyCode::PageDown => app.scroll = app.scroll.saturating_add(5),
                        KeyCode::PageUp => app.scroll = app.scroll.saturating_sub(5),
                        KeyCode::Tab => { app.tab = (app.tab + 1) % 3; app.selected = None; app.scroll = 0; },
                        KeyCode::Char(c @ '1'..='3') => { app.tab = c as usize - '1' as usize; app.selected = None; app.scroll = 0; },
                        KeyCode::Char('/') => app.searching = true,
                        KeyCode::Char('t') => app.duration = Some(if app.duration.unwrap_or(Duration::Once) == Duration::Once { Duration::FiveMinutes } else { Duration::Once }),
                        KeyCode::Char(c @ ('a' | 'd')) if app.tab == 0 => {
                            if let Some(id) = app.selected.clone() {
                                let action = if c == 'a' { Action::Allow } else { Action::Deny };
                                app.status = match source.decide(id, action, app.duration.unwrap_or(Duration::Once)).await {
                                    Ok(()) => format!("{} / {} recorded", action.as_str(), app.duration.unwrap_or(Duration::Once).as_str()),
                                    Err(_) => "Decision rejected. The request may have expired or the service disconnected.".into(),
                                };
                                if let Ok(current) = source.snapshot().await { snapshot = current; }
                            }
                        }
                        _ => {},
                    }
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    }.await;
    ratatui::restore();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn renders_requests_and_small_terminal_without_panicking() {
        let broker = Broker::new(
            crate::config::Config::default(),
            crate::store::Store::memory(100).unwrap(),
            true,
        )
        .unwrap();
        crate::broker::seed_demo(&broker).unwrap();
        let snapshot = broker.snapshot().unwrap();
        let mut app = App::default();
        app.sync_selection(&snapshot);
        for (width, height) in [(120, 36), (65, 24), (20, 5)] {
            let mut terminal =
                ratatui::Terminal::new(ratatui::backend::TestBackend::new(width, height)).unwrap();
            terminal
                .draw(|frame| draw(frame, &mut app, &snapshot))
                .unwrap();
            let screen: String = terminal
                .backend()
                .buffer()
                .content
                .iter()
                .map(|c| c.symbol())
                .collect();
            assert!(screen.to_lowercase().contains("snitchgate"));
        }
        broker.shutdown();
    }
}
