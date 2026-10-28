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
mod probe;
mod report;
mod runner;
mod scan;
mod ui;
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

    if has("--once") {
        let interactive = win::ensure_console();
        report::run_once(&root, interactive);
        return;
    }
    ui::run(root, has("--demo"));
}
