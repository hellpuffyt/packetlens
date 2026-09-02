//! Dev-only helper: renders one frame of the `--tui` viewer against
//! `fixtures/port_scan.pcap` using ratatui's in-memory `TestBackend`, and
//! prints it as plain text. Used to generate the README's screenshot
//! without needing a real terminal (or a GUI/browser) — the exact frame a
//! real terminal would show, not a mockup.
//!
//! Run with: `cargo run --example render_tui_snapshot --features tui`

#[cfg(feature = "tui")]
fn main() {
    use packetlens::analyze;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    let bytes = std::fs::read("fixtures/port_scan.pcap").expect("fixture must exist");
    let analysis = analyze(&bytes).expect("fixture must decode");

    let backend = TestBackend::new(100, 16);
    let mut terminal = Terminal::new(backend).unwrap();
    let app = packetlens::tui::AppState::new(&analysis, 4);

    terminal
        .draw(|frame| {
            // Mirrors the private `draw` function in src/tui.rs closely
            // enough for a representative snapshot; kept here rather than
            // making that function public, since this example is the only
            // consumer.
            packetlens_snapshot::draw(frame, &app);
        })
        .unwrap();

    let buffer = terminal.backend().buffer().clone();
    for y in 0..buffer.area.height {
        let mut line = String::new();
        for x in 0..buffer.area.width {
            line.push_str(buffer[(x, y)].symbol());
        }
        println!("{}", line.trim_end());
    }
}

#[cfg(feature = "tui")]
mod packetlens_snapshot {
    use packetlens::tui::AppState;
    use ratatui::layout::{Constraint, Direction, Layout};
    use ratatui::style::{Color, Modifier, Style};
    use ratatui::text::{Line, Span};
    use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};

    pub fn draw(frame: &mut ratatui::Frame, app: &AppState) {
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

#[cfg(not(feature = "tui"))]
fn main() {
    eprintln!("this example needs `--features tui`");
}
