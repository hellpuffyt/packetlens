//! Ratatui-based terminal UI that renders a replayed (or, with
//! `live-capture`, live) capture as a scrollable, explained flow list.
//!
//! This module is purely a presentation layer over [`crate::Analysis`]: it
//! holds no decode or conntrack logic of its own; the `AppState` it wraps is
//! plain data manipulation (`select_next`/`select_previous`/`flows()`) that
//! is unit-tested here without touching a real terminal at all. Only
//! `run()`, which owns the actual terminal handle and event loop, needs a
//! live TTY and is therefore excluded from the test suite.

use crate::flow::{explain_flow, FlowState};
use crate::Analysis;

/// Pure, terminal-free application state: what flow is selected and the
/// ordered list of flows to render. Kept separate from the actual
/// ratatui/crossterm event loop so selection logic can be unit tested.
pub struct AppState<'a> {
    flows: Vec<&'a FlowState>,
    pub selected: usize,
    pub scan_threshold: usize,
}

impl<'a> AppState<'a> {
    pub fn new(analysis: &'a Analysis, scan_threshold: usize) -> Self {
        AppState {
            flows: analysis.tracker.flows(),
            selected: 0,
            scan_threshold,
        }
    }

    pub fn flows(&self) -> &[&'a FlowState] {
        &self.flows
    }

    pub fn select_next(&mut self) {
        if !self.flows.is_empty() {
            self.selected = (self.selected + 1).min(self.flows.len() - 1);
        }
    }

    pub fn select_previous(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }

    pub fn selected_flow(&self) -> Option<&'a FlowState> {
        self.flows.get(self.selected).copied()
    }

    pub fn selected_explanation(&self) -> Option<String> {
        self.selected_flow().map(explain_flow)
    }

    pub fn row_label(&self, idx: usize) -> String {
        let f = self.flows[idx];
        format!(
            "[{proto}] {a} <-> {b}  ({pkts} pkts, {bytes} B)",
            proto = f.key.protocol,
            a = f.initiator.0,
            b = f.responder.0,
            pkts = f.total_packets,
            bytes = f.total_bytes()
        )
    }
}

#[cfg(feature = "tui")]
mod render {
    use super::AppState;
    use crate::Analysis;
    use ratatui::crossterm::event::{self, Event, KeyCode};
    use ratatui::crossterm::terminal::{
        disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
    };
    use ratatui::crossterm::ExecutableCommand;
    use ratatui::layout::{Constraint, Direction, Layout};
    use ratatui::style::{Color, Modifier, Style};
    use ratatui::text::{Line, Span};
    use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
    use ratatui::Terminal;
    use std::io;
    use std::time::Duration;

    /// Runs the interactive TUI over an already-computed [`Analysis`] until
    /// the user presses `q` or Esc. Requires a real terminal; this function
    /// is intentionally excluded from the test suite (see module docs).
    pub fn run(analysis: &Analysis, scan_threshold: usize) -> io::Result<()> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        stdout.execute(EnterAlternateScreen)?;
        let backend = ratatui::backend::CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        let mut app = AppState::new(analysis, scan_threshold);
        let result = event_loop(&mut terminal, &mut app);

        disable_raw_mode()?;
        io::stdout().execute(LeaveAlternateScreen)?;
        result
    }

    fn event_loop<B: ratatui::backend::Backend<Error = io::Error>>(
        terminal: &mut Terminal<B>,
        app: &mut AppState,
    ) -> io::Result<()> {
        loop {
            terminal.draw(|frame| draw(frame, app))?;
            if event::poll(Duration::from_millis(200))? {
                if let Event::Key(key) = event::read()? {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                        KeyCode::Down | KeyCode::Char('j') => app.select_next(),
                        KeyCode::Up | KeyCode::Char('k') => app.select_previous(),
                        _ => {}
                    }
                }
            }
        }
    }

    fn draw(frame: &mut ratatui::Frame, app: &AppState) {
        let outer = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(1), Constraint::Min(3)])
            .split(frame.area());

        let title = Line::from(vec![Span::styled(
            format!(
                " packetlens — {} flow(s), scan threshold {} — q to quit ",
                app.flows().len(),
                app.scan_threshold
            ),
            Style::default().add_modifier(Modifier::BOLD),
        )]);
        frame.render_widget(Paragraph::new(title), outer[0]);

        let columns = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
            .split(outer[1]);

        let items: Vec<ListItem> = (0..app.flows().len())
            .map(|i| ListItem::new(app.row_label(i)))
            .collect();
        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title("Flows"))
            .highlight_style(
                Style::default()
                    .bg(Color::Blue)
                    .add_modifier(Modifier::BOLD),
            );
        let mut state = ListState::default();
        state.select(Some(app.selected));
        frame.render_stateful_widget(list, columns[0], &mut state);

        let explanation = app
            .selected_explanation()
            .unwrap_or_else(|| "no flows in this capture".to_string());
        let detail = Paragraph::new(explanation)
            .block(Block::default().borders(Borders::ALL).title("Explanation"))
            .wrap(Wrap { trim: true });
        frame.render_widget(detail, columns[1]);
    }
}

#[cfg(feature = "tui")]
pub use render::run;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::{decode_packet, TcpFlags};
    use crate::flow::FlowTracker;
    use crate::pcap::{Endianness, GlobalHeader, TimeResolution, LINKTYPE_ETHERNET};

    fn dummy_analysis_with_flows(n: usize) -> Analysis {
        let mut tracker = FlowTracker::new();
        for i in 0..n {
            let mut f = Vec::new();
            f.extend_from_slice(&[0; 6]);
            f.extend_from_slice(&[0; 6]);
            f.extend_from_slice(&0x0800u16.to_be_bytes());
            // ipv4 + tcp SYN, distinct dst ports so each is its own flow
            let mut tcp = vec![0u8; 20];
            tcp[0..2].copy_from_slice(&12345u16.to_be_bytes());
            tcp[2..4].copy_from_slice(&(1000 + i as u16).to_be_bytes());
            tcp[12] = 5 << 4;
            tcp[13] = TcpFlags::SYN.0;
            let mut ip = vec![0u8; 20];
            ip[0] = (4 << 4) | 5;
            ip[2..4].copy_from_slice(&40u16.to_be_bytes());
            ip[8] = 64;
            ip[9] = 6;
            ip[12..16].copy_from_slice(&[10, 0, 0, 1]);
            ip[16..20].copy_from_slice(&[10, 0, 0, 2]);
            f.extend_from_slice(&ip);
            f.extend_from_slice(&tcp);
            let pkt = decode_packet(i as u64, f.len() as u32, f.len() as u32, &f).unwrap();
            tracker.ingest(&pkt);
        }
        Analysis {
            pcap_header: GlobalHeader {
                endianness: Endianness::Little,
                resolution: TimeResolution::Micros,
                version_major: 2,
                version_minor: 4,
                snaplen: 65535,
                linktype: LINKTYPE_ETHERNET,
            },
            packets: Vec::new(),
            decode_failures: 0,
            tracker,
        }
    }

    #[test]
    fn selection_clamps_at_bounds() {
        let analysis = dummy_analysis_with_flows(3);
        let mut app = AppState::new(&analysis, 4);
        assert_eq!(app.selected, 0);
        app.select_previous();
        assert_eq!(app.selected, 0, "must not go negative");
        app.select_next();
        app.select_next();
        app.select_next();
        app.select_next();
        assert_eq!(app.selected, 2, "must clamp at last flow index");
    }

    #[test]
    fn empty_analysis_has_no_selection() {
        let analysis = dummy_analysis_with_flows(0);
        let app = AppState::new(&analysis, 4);
        assert!(app.selected_flow().is_none());
        assert!(app.selected_explanation().is_none());
    }

    #[test]
    fn row_label_contains_protocol_and_endpoints() {
        let analysis = dummy_analysis_with_flows(1);
        let app = AppState::new(&analysis, 4);
        let label = app.row_label(0);
        assert!(label.contains("TCP"));
        assert!(label.contains("10.0.0.1"));
        assert!(label.contains("10.0.0.2"));
    }
}
