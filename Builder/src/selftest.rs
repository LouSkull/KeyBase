use anyhow::Result;
use std::{
    path::Path,
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use crate::install::{cancel_requested, CancelFlag};

pub enum TestMsg {
    Log(String),
    Done(TestResult),
}

#[derive(Clone, PartialEq, Eq)]
pub enum TestResult {
    Pass,
    Fail(String),
    Skipped,
    Cancelled,
}

/// Start the server, wait for it to respond, then kill it.
pub fn spawn_selftest(
    output_dir: std::path::PathBuf,
    port: u16,
    cancel: CancelFlag,
) -> (thread::JoinHandle<()>, mpsc::Receiver<TestMsg>) {
    let (tx, rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let result = run_test(&output_dir, port, &tx, &cancel);
        let _ = tx.send(TestMsg::Done(result));
    });
    (handle, rx)
}

fn run_test(dir: &Path, port: u16, tx: &mpsc::Sender<TestMsg>, cancel: &CancelFlag) -> TestResult {
    let python = venv_python(dir);
    if !std::path::Path::new(&python).exists() {
        log(tx, "Python venv not found - skipping self-test.");
        return TestResult::Skipped;
    }

    log(tx, "Starting server subprocess…");
    let mut child = match Command::new(&python)
        .arg("-m")
        .arg("keybase")
        .current_dir(dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return TestResult::Fail(format!("Failed to start server: {e}")),
    };

    let url = format!("http://127.0.0.1:{port}/");
    log(tx, format!("Waiting for {url} (up to 30 s)…"));

    let deadline = Instant::now() + Duration::from_secs(30);
    let mut attempts = 0u32;
    let result = loop {
        if cancel_requested(cancel) {
            log(tx, "Self-test cancelled by user.");
            break TestResult::Cancelled;
        }
        if Instant::now() > deadline {
            break TestResult::Fail(format!("Server did not respond within 30 s"));
        }
        thread::sleep(Duration::from_millis(500));
        attempts += 1;

        match http_get(&url) {
            Ok(_) => {
                log(
                    tx,
                    format!("Server responded after {:.1}s ✓", attempts as f32 * 0.5),
                );
                break TestResult::Pass;
            }
            Err(_) => {
                if attempts % 4 == 0 {
                    log(tx, format!("  {:.0}s elapsed…", attempts as f32 * 0.5));
                }
            }
        }
    };

    kill_child(&mut child);
    result
}

fn http_get(url: &str) -> Result<()> {
    let resp = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()?
        .get(url)
        .send()?;
    // Any HTTP response (even 404 / 302) means the server is up.
    let _ = resp.status();
    Ok(())
}

fn kill_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn venv_python(dir: &Path) -> String {
    if cfg!(windows) {
        dir.join(".venv")
            .join("Scripts")
            .join("python.exe")
            .to_string_lossy()
            .to_string()
    } else {
        dir.join(".venv")
            .join("bin")
            .join("python")
            .to_string_lossy()
            .to_string()
    }
}

fn log(tx: &mpsc::Sender<TestMsg>, msg: impl Into<String>) {
    let _ = tx.send(TestMsg::Log(msg.into()));
}
