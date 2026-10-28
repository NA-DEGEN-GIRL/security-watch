//! Dashboard mode: local web UI in an Edge app window, live feeds, periodic full scans.

use crate::app::App;
use crate::config::{self, Target};
use crate::{live, scan, server, win};
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

fn random_token() -> String {
    let mut s = String::new();
    for i in 0..2u64 {
        // RandomState is seeded from the OS RNG for every new instance.
        let mut h = RandomState::new().build_hasher();
        h.write_u64(i);
        h.write_u128(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0));
        s.push_str(&format!("{:016x}", h.finish()));
    }
    s
}

fn lock_path(root: &Path) -> PathBuf {
    root.join("state").join("ui.lock")
}

/// Small lifecycle log (window/heartbeat decisions) for diagnosing the GUI app.
fn log(root: &Path, msg: &str) {
    use std::fs::OpenOptions;
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(root.join("state").join("ui.log")) {
        let _ = writeln!(f, "{} {msg}", win::now_display());
    }
}

/// An already running dashboard (port, token), if it still answers.
fn running_instance(root: &Path) -> Option<(u16, String)> {
    let text = std::fs::read_to_string(lock_path(root)).ok()?;
    let (port, token) = text.trim().split_once(' ')?;
    let port: u16 = port.parse().ok()?;
    let mut s = TcpStream::connect_timeout(&([127, 0, 0, 1], port).into(), Duration::from_millis(500)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    write!(s, "GET /api/ping HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-Token: {token}\r\nConnection: close\r\n\r\n").ok()?;
    let mut resp = String::new();
    let _ = s.read_to_string(&mut resp);
    resp.starts_with("HTTP/1.1 200").then(|| (port, token.to_string()))
}

fn edge_path() -> Option<PathBuf> {
    let mut c = vec![
        PathBuf::from(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
        PathBuf::from(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"),
    ];
    if let Ok(l) = std::env::var("LOCALAPPDATA") {
        c.push(Path::new(&l).join(r"Microsoft\Edge\Application\msedge.exe"));
    }
    c.into_iter().find(|p| p.is_file())
}

/// Opens the dashboard as an Edge app window (own profile, so closing the window
/// ends the Edge process we spawned). Falls back to the default browser.
fn open_window(root: &Path, port: u16, token: &str) -> Option<Child> {
    let url = format!("http://127.0.0.1:{port}/?t={token}");
    if let Some(edge) = edge_path() {
        let profile = root.join("ui-profile");
        let spawned = Command::new(edge)
            .arg(format!("--app={url}"))
            .arg("--window-size=1440,920")
            .arg(format!("--user-data-dir={}", profile.display()))
            .args(["--no-first-run", "--no-default-browser-check", "--disable-sync"])
            .creation_flags(win::CREATE_BREAKAWAY_FROM_JOB)
            .spawn();
        if let Ok(c) = spawned {
            return Some(c);
        }
    }
    let _ = Command::new("cmd").args(["/c", "start", "", &url]).creation_flags(CREATE_NO_WINDOW).spawn();
    None
}

fn scanner(app: Arc<App>) {
    loop {
        if app.is_stopping() {
            return;
        }
        let now = crate::now_epoch();
        let due: Vec<Target> = {
            let mut g = app.lock();
            let force = std::mem::take(&mut g.force_scan);
            let period = g.scan_minutes * 60;
            g.hosts
                .iter_mut()
                .filter(|h| !h.scanning && (force || h.last_scan == 0 || now >= h.last_scan + period))
                .map(|h| {
                    h.scanning = true;
                    h.target.clone()
                })
                .collect()
        };
        for t in due {
            let app = Arc::clone(&app);
            thread::spawn(move || {
                let now = crate::now_epoch();
                let r = scan::check(&t, &app.root, now, Some(now - scan::DAY));
                app.lock().apply_scan(&t.name, r, now);
            });
        }
        thread::sleep(Duration::from_secs(1));
    }
}

pub fn run(root: PathBuf, no_window: bool) {
    let (targets, _) = config::load(&root);
    if let Some((port, token)) = running_instance(&root) {
        if !no_window {
            let _ = open_window(&root, port, &token);
        }
        return;
    }
    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(l) => l,
        Err(e) => {
            win::message_box("security-watch", &format!("로컬 서버를 열지 못했습니다: {e}"));
            return;
        }
    };
    let port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
    let token = random_token();
    let _ = std::fs::create_dir_all(root.join("state"));
    let _ = std::fs::write(lock_path(&root), format!("{port} {token}"));

    let app = Arc::new(App::new(root.clone(), targets.clone(), token.clone(), crate::now_epoch()));
    {
        let app = Arc::clone(&app);
        thread::spawn(move || server::serve(app, listener, port));
    }
    for t in targets {
        live::start(&app, t);
    }
    {
        let app = Arc::clone(&app);
        thread::spawn(move || scanner(app));
    }

    if no_window {
        println!("http://127.0.0.1:{port}/?t={token}");
    }
    let started = Instant::now();
    log(&root, &format!("started port={port}"));
    if !no_window {
        if let Some(mut edge) = open_window(&root, port, &token) {
            // The Edge process is NOT the window's lifetime: Edge may relaunch itself
            // (e.g. to apply an update) and keep the window. Only log it.
            let root = root.clone();
            thread::spawn(move || {
                log(&root, &format!("edge spawned pid={}", edge.id()));
                let status = edge.wait();
                log(&root, &format!("edge process exited after {}s: {status:?}", started.elapsed().as_secs()));
            });
        }
    }
    // Lifetime follows the page: a "pagehide" beacon (window closed or reloading)
    // followed by silence means closed; a reload polls again within a second.
    let mut page_seen = false;
    loop {
        thread::sleep(Duration::from_secs(2));
        if no_window {
            continue;
        }
        let (last, closing) = {
            let g = app.lock();
            (g.last_poll, g.closing_at)
        };
        if !page_seen && last.is_some() {
            page_seen = true;
            log(&root, &format!("page connected after {}s", started.elapsed().as_secs()));
        }
        let reason = match (last, closing) {
            (_, Some(c)) if c.elapsed() > Duration::from_secs(10) => Some("window closed"),
            // Minimized windows may throttle timers to about once a minute.
            (Some(t), _) if t.elapsed() > Duration::from_secs(180) => Some("page stopped polling"),
            (None, _) if started.elapsed() > Duration::from_secs(600) => Some("page never connected"),
            _ => None,
        };
        if let Some(r) = reason {
            log(&root, &format!("{r} -> exit"));
            app.shutdown();
        }
    }
}
