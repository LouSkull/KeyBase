#![cfg_attr(windows, windows_subsystem = "windows")]

mod app;
mod config_gen;
mod i18n;
mod install;
mod platform;
mod selftest;
mod ui;
mod wizard;

#[cfg(windows)]
mod ui_gui;

use anyhow::Result;

#[cfg(not(windows))]
use std::{io, time::Duration};

#[cfg(not(windows))]
use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers,
    },
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};

#[cfg(not(windows))]
use ratatui::{backend::CrosstermBackend, Terminal};

#[cfg(not(windows))]
use app::{App, Phase};

fn main() -> Result<()> {
    // Switch Windows console to UTF-8 so Unicode symbols render correctly.
    #[cfg(windows)]
    {
        extern "system" {
            fn SetConsoleOutputCP(cp: u32) -> i32;
        }
        unsafe {
            SetConsoleOutputCP(65001);
        }
    }

    // On Windows — launch the native GUI window.
    // On Linux / macOS — run the TUI in the terminal.
    #[cfg(windows)]
    {
        return ui_gui::run();
    }

    #[cfg(not(windows))]
    {
        run_tui()
    }
}

#[cfg(not(windows))]
fn run_tui() -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new();
    let res = run_loop(&mut terminal, &mut app);

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture,
    )?;
    terminal.show_cursor()?;

    if let Err(e) = &res {
        eprintln!("Fatal error: {e:#}");
    }
    if app.phase == Phase::Done {
        app.print_summary();
    }

    res
}

#[cfg(not(windows))]
fn run_loop<B: ratatui::backend::Backend>(terminal: &mut Terminal<B>, app: &mut App) -> Result<()> {
    loop {
        terminal.draw(|f| ui::render(f, app))?;

        // Poll for 100 ms so background threads can update progress
        if event::poll(Duration::from_millis(100))? {
            match event::read()? {
                // Only handle Press — ignore Repeat and Release to prevent scroll drift
                Event::Key(key) if key.kind == KeyEventKind::Press => {
                    if key.modifiers.contains(KeyModifiers::CONTROL)
                        && key.code == KeyCode::Char('c')
                    {
                        break;
                    }
                    app.handle_key(key);
                }
                _ => {}
            }
        }

        app.drain_progress();

        if app.should_quit {
            break;
        }
    }
    Ok(())
}
