//! Shared dashboard state: per-host scan results, live counters/connections, event feed.

use crate::baseline;
use crate::config::{Kind, Target};
use crate::eval::{Finding, Level};
use crate::scan::ScanResult;
use std::collections::{BTreeMap, VecDeque};
use std::path::PathBuf;
use std::process::Child;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Instant;

const MAX_EVENTS: usize = 3000;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LiveState {
    Connecting,
    Connected,
    Disconnected,
}

pub struct Conn {
    pub local: String,
    pub peer: String,
    pub proc_name: String,
    pub public: bool,
}

pub struct Event {
    pub id: u64,
    /// Bumped on every update so the UI can fetch only what changed.
    pub seq: u64,
    pub ts: u64,
    pub last_ts: u64,
    pub count: u64,
    pub host: String,
    pub level: Level,
    pub text: String,
    pub public: bool,
    key: String,
}

pub struct HostState {
    pub target: Target,
    pub hostname: Option<String>,
    pub live: LiveState,
    pub live_error: String,
    pub scanning: bool,
    pub last_scan: u64,
    pub scan_ok: bool,
    pub findings: Vec<Finding>,
    pub changes: Vec<Finding>,
    pub items: Option<baseline::Items>,
    pub counters: BTreeMap<&'static str, u64>,
    pub conns: Vec<Conn>,
    pub conns_ts: u64,
}

pub struct Inner {
    pub hosts: Vec<HostState>,
    pub events: VecDeque<Event>,
    next_id: u64,
    seq: u64,
    pub scan_minutes: u64,
    pub force_scan: bool,
    pub last_poll: Option<Instant>,
    /// Set by the page's "pagehide" beacon; cleared by the next poll (reload).
    pub closing_at: Option<Instant>,
    /// Reference point for log-based findings (0 = none).
    pub watch_since: u64,
}

pub struct App {
    pub inner: Mutex<Inner>,
    pub root: PathBuf,
    pub token: String,
    pub children: Mutex<Vec<Child>>,
    pub stopping: AtomicBool,
    pub started: u64,
}

impl App {
    pub fn new(root: PathBuf, targets: Vec<Target>, token: String, started: u64) -> App {
        let hosts = targets
            .into_iter()
            .map(|target| HostState {
                target,
                hostname: None,
                live: LiveState::Connecting,
                live_error: String::new(),
                scanning: false,
                last_scan: 0,
                scan_ok: false,
                findings: Vec::new(),
                changes: Vec::new(),
                items: None,
                counters: BTreeMap::new(),
                conns: Vec::new(),
                conns_ts: 0,
            })
            .collect();
        App {
            inner: Mutex::new(Inner {
                hosts,
                events: VecDeque::new(),
                next_id: 1,
                seq: 0,
                scan_minutes: 5,
                force_scan: false,
                last_poll: None,
                closing_at: None,
                watch_since: crate::scan::load_watch_since(&root),
            }),
            root,
            token,
            children: Mutex::new(Vec::new()),
            stopping: AtomicBool::new(false),
            started,
        }
    }

    pub fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn is_stopping(&self) -> bool {
        self.stopping.load(Ordering::Relaxed)
    }

    pub fn track_child(&self, child: Child) -> u32 {
        let id = child.id();
        self.children.lock().unwrap_or_else(|e| e.into_inner()).push(child);
        id
    }

    /// Reaps a finished child; returns false if it was not tracked.
    pub fn forget_child(&self, pid: u32) {
        let mut v = self.children.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(pos) = v.iter().position(|c| c.id() == pid) {
            let mut c = v.remove(pos);
            let _ = c.kill();
            let _ = c.wait();
        }
    }

    pub fn shutdown(&self) -> ! {
        self.stopping.store(true, Ordering::Relaxed);
        for c in self.children.lock().unwrap_or_else(|e| e.into_inner()).iter_mut() {
            let _ = c.kill();
        }
        let _ = std::fs::remove_file(self.root.join("state").join("ui.lock"));
        std::process::exit(0);
    }
}

impl Inner {
    pub fn host_mut(&mut self, name: &str) -> Option<&mut HostState> {
        self.hosts.iter_mut().find(|h| h.target.name == name)
    }

    pub fn bump(&mut self, host: &str, counter: &'static str) {
        if let Some(h) = self.host_mut(host) {
            *h.counters.entry(counter).or_insert(0) += 1;
        }
    }

    /// Adds an event, or folds it into a recent one with the same key
    /// (repeated logins/attempts from the same source become one "×N" row).
    pub fn push_event(&mut self, host: &str, level: Level, key: String, text: String, public: bool, ts: u64, fold_secs: u64) {
        self.seq += 1;
        let seq = self.seq;
        if fold_secs > 0 {
            if let Some(e) = self
                .events
                .iter_mut()
                .rev()
                .take(500)
                .find(|e| e.host == host && e.key == key && ts.saturating_sub(e.last_ts) <= fold_secs)
            {
                e.count += 1;
                e.last_ts = e.last_ts.max(ts);
                e.level = e.level.max(level);
                e.seq = seq;
                return;
            }
        }
        let id = self.next_id;
        self.next_id += 1;
        self.events.push_back(Event { id, seq, ts, last_ts: ts, count: 1, host: host.to_string(), level, text, public, key });
        while self.events.len() > MAX_EVENTS {
            self.events.pop_front();
        }
    }

    pub fn apply_scan(&mut self, name: &str, r: ScanResult, now: u64) {
        if let Some(h) = self.host_mut(name) {
            h.scanning = false;
            h.last_scan = now;
            h.scan_ok = r.complete;
            if r.hostname.is_some() {
                h.hostname = r.hostname;
            }
            h.findings = r.findings;
            h.changes = r.changes;
            if r.items.is_some() {
                h.items = r.items;
            }
        }
    }
}

// ---------- JSON (hand-written; no serde) ----------

pub fn js(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

fn level_key(l: Level) -> &'static str {
    match l {
        Level::Ok => "ok",
        Level::Info => "info",
        Level::Warn => "warn",
        Level::Alert => "alert",
    }
}

fn findings_json(fs: &[Finding]) -> String {
    let mut v: Vec<&Finding> = fs.iter().collect();
    v.sort_by(|a, b| b.level.cmp(&a.level));
    let items: Vec<String> = v
        .iter()
        .map(|f| {
            let d: Vec<String> = f.details.iter().map(|x| js(x)).collect();
            format!("{{\"level\":\"{}\",\"text\":{},\"details\":[{}]}}", level_key(f.level), js(&f.text), d.join(","))
        })
        .collect();
    format!("[{}]", items.join(","))
}

pub fn state_json(inner: &Inner, since_seq: u64, now: u64, started: u64) -> String {
    let recent = now.saturating_sub(3600);
    let hosts: Vec<String> = inner
        .hosts
        .iter()
        .map(|h| {
            let live_alert = inner
                .events
                .iter()
                .filter(|e| e.host == h.target.name && e.last_ts >= recent)
                .map(|e| e.level)
                .max()
                .unwrap_or(Level::Ok);
            let scan_level = h.findings.iter().chain(&h.changes).map(|f| f.level).max().unwrap_or(Level::Ok);
            let mut level = live_alert.max(scan_level);
            if level == Level::Info {
                level = Level::Ok;
            }
            let counters: Vec<String> = h.counters.iter().map(|(k, v)| format!("\"{k}\":{v}")).collect();
            let conns: Vec<String> = h
                .conns
                .iter()
                .map(|c| format!("{{\"local\":{},\"peer\":{},\"proc\":{},\"public\":{}}}", js(&c.local), js(&c.peer), js(&c.proc_name), c.public))
                .collect();
            let (kind, lan) = match h.target.kind {
                Kind::Local => ("local", true),
                Kind::Remote { lan_only } => ("remote", lan_only),
            };
            let live = match h.live {
                LiveState::Connecting => "connecting",
                LiveState::Connected => "connected",
                LiveState::Disconnected => "disconnected",
            };
            format!(
                concat!(
                    "{{\"name\":{},\"title\":{},\"hostname\":{},\"kind\":\"{}\",\"lan\":{},\"live\":\"{}\",\"live_error\":{},",
                    "\"scanning\":{},\"last_scan\":{},\"scan_ok\":{},\"level\":\"{}\",\"findings\":{},\"changes\":{},",
                    "\"counters\":{{{}}},\"conns\":[{}],\"conns_ts\":{}}}"
                ),
                js(&h.target.name),
                js(&h.target.title()),
                js(h.hostname.as_deref().unwrap_or("")),
                kind,
                lan,
                live,
                js(&h.live_error),
                h.scanning,
                h.last_scan,
                h.scan_ok,
                level_key(level),
                findings_json(&h.findings),
                findings_json(&h.changes),
                counters.join(","),
                conns.join(","),
                h.conns_ts
            )
        })
        .collect();

    let mut evs: Vec<&Event> = inner.events.iter().filter(|e| e.seq > since_seq).collect();
    if since_seq == 0 && evs.len() > 400 {
        evs = evs.split_off(evs.len() - 400);
    }
    let events: Vec<String> = evs
        .iter()
        .map(|e| {
            format!(
                "{{\"id\":{},\"seq\":{},\"ts\":{},\"last_ts\":{},\"count\":{},\"host\":{},\"level\":\"{}\",\"text\":{},\"public\":{}}}",
                e.id, e.seq, e.ts, e.last_ts, e.count, js(&e.host), level_key(e.level), js(&e.text), e.public
            )
        })
        .collect();
    let next_scan = inner.hosts.iter().filter(|h| h.last_scan > 0).map(|h| h.last_scan).min().map(|t| t + inner.scan_minutes * 60).unwrap_or(0);
    format!(
        "{{\"now\":{now},\"started\":{started},\"seq\":{},\"scan_minutes\":{},\"watch_since\":{},\"next_scan\":{next_scan},\"hosts\":[{}],\"events\":[{}]}}",
        inner.seq,
        inner.scan_minutes,
        inner.watch_since,
        hosts.join(","),
        events.join(",")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_escapes_control_and_quotes() {
        assert_eq!(js("a\"b\\c\n\u{1}"), "\"a\\\"b\\\\c\\n\\u0001\"");
    }

    #[test]
    fn repeated_events_are_folded() {
        let t = Target { name: "h".into(), kind: Kind::Local };
        let app = App::new(PathBuf::from("."), vec![t], "x".into(), 0);
        let mut g = app.lock();
        g.push_event("h", Level::Info, "k".into(), "login".into(), false, 100, 600);
        g.push_event("h", Level::Warn, "k".into(), "login".into(), false, 200, 600);
        g.push_event("h", Level::Info, "k".into(), "login".into(), false, 2000, 600);
        assert_eq!(g.events.len(), 2);
        assert_eq!(g.events[0].count, 2);
        assert_eq!(g.events[0].level, Level::Warn);
    }
}
