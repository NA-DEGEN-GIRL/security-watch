//! security-watch: security monitor for this PC and your SSH servers.
//! Double-click: live dashboard window. `--once`: one text report and exit.
//! Read-only on every host.
#![windows_subsystem = "windows"]

mod app;
mod baseline;
mod config;
mod eval;
mod gui;
mod live;
mod notify;
mod probe;
mod report;
mod rules;
mod runner;
mod scan;
mod ui;
mod usb;
mod win;

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_epoch() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let has = |flag: &str| args.iter().any(|a| a == flag);
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("."));
    let root = config::resolve_root(&exe_dir);
    win::tie_children_to_process();

    // Developer aid: `--replay <windows|linux> <capture file>` prints what a saved
    // capture of a live script would raise (for tuning the rules against false alarms).
    if let Some(i) = args.iter().position(|a| a == "--replay") {
        win::ensure_console();
        let text = args.get(i + 2).and_then(|p| std::fs::read(p).ok()).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default();
        for line in live::replay(args.get(i + 1).map(String::as_str) == Some("windows"), &text) {
            println!("{line}");
        }
        return;
    }
    if has("--once") {
        let interactive = win::ensure_console();
        report::run_once(&root, interactive);
        return;
    }
    ui::run(root, has("--demo"));
}
