//! Real-time feeds: one long-lived `ssh` stream per Linux host and one PowerShell
//! loop for this PC. Lines are classified into feed events, counters and the
//! current inbound-connection table. Streams reconnect automatically.

use crate::app::{App, Conn, LiveState};
use crate::config::{Kind, Target};
use crate::eval::Level;
use crate::probe::is_private_ip;
use crate::runner;
use std::collections::HashSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::windows::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const FOLD: u64 = 600; // fold repeats from the same source within 10 minutes
const LIVE_LINUX: &str = include_str!("live_linux.sh");
const LIVE_WINDOWS: &str = include_str!("live_windows.ps1");
pub const INTERVAL_SECS: u32 = 5;

pub fn start(app: &Arc<App>, target: Target) {
    let app = Arc::clone(app);
    thread::spawn(move || run(app, target));
}

fn set_live(app: &App, host: &str, state: LiveState, err: &str) {
    if let Some(h) = app.lock().host_mut(host) {
        h.live = state;
        h.live_error = err.to_string();
    }
}

fn run(app: Arc<App>, target: Target) {
    let name = target.name.clone();
    let lan = !matches!(target.kind, Kind::Remote { lan_only: false });
    loop {
        if app.is_stopping() {
            return;
        }
        set_live(&app, &name, LiveState::Connecting, "");
        let (mut cmd, stdin_data) = match target.kind {
            Kind::Local => {
                let script = LIVE_WINDOWS.replace("__INTERVAL__", &INTERVAL_SECS.to_string());
                let mut c = Command::new("powershell.exe");
                c.args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", &runner::encode_ps(&script)]);
                (c, None)
            }
            Kind::Remote { .. } => {
                let mut c = Command::new("ssh");
                c.args([
                    "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
                    "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3",
                    &name, "bash", "-s", "--", &INTERVAL_SECS.to_string(),
                ]);
                (c, Some(LIVE_LINUX.replace('\r', "").into_bytes()))
            }
        };
        cmd.stdin(if stdin_data.is_some() { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .creation_flags(CREATE_NO_WINDOW);

        match cmd.spawn() {
            Err(e) => set_live(&app, &name, LiveState::Disconnected, &format!("실행 실패: {e}")),
            Ok(mut child) => {
                if let (Some(data), Some(mut si)) = (stdin_data, child.stdin.take()) {
                    let _ = si.write_all(&data); // dropped here: closes stdin after the script
                }
                let stdout = child.stdout.take().expect("piped");
                let err_tail = Arc::new(Mutex::new(String::new()));
                if let Some(mut se) = child.stderr.take() {
                    let tail = Arc::clone(&err_tail);
                    thread::spawn(move || {
                        let mut s = String::new();
                        let _ = se.read_to_string(&mut s);
                        if let Some(l) = s.lines().rev().find(|l| !l.trim().is_empty()) {
                            *tail.lock().unwrap_or_else(|e| e.into_inner()) = l.trim().to_string();
                        }
                    });
                }
                let pid = app.track_child(child);
                let mut pending: Option<Vec<Conn>> = None;
                let mut connected = false;
                for line in BufReader::new(stdout).lines() {
                    let Ok(line) = line else { break };
                    if !connected {
                        connected = true;
                        set_live(&app, &name, LiveState::Connected, "");
                    }
                    handle_line(&app, &name, lan, line.trim_end(), &mut pending);
                }
                app.forget_child(pid);
                thread::sleep(Duration::from_millis(300));
                let e = err_tail.lock().unwrap_or_else(|e| e.into_inner()).clone();
                set_live(&app, &name, LiveState::Disconnected, if e.is_empty() { "연결이 끊어졌습니다" } else { &e });
            }
        }
        for _ in 0..15 {
            if app.is_stopping() {
                return;
            }
            thread::sleep(Duration::from_secs(1));
        }
    }
}

fn handle_line(app: &App, host: &str, lan: bool, line: &str, pending: &mut Option<Vec<Conn>>) {
    if let Some(rest) = line.strip_prefix("EV ") {
        let mut it = rest.splitn(2, ' ');
        let ts = it.next().and_then(|t| t.parse::<f64>().ok()).map(|t| t as u64).unwrap_or_else(crate::now_epoch);
        let body = it.next().unwrap_or("");
        if body.starts_with("RDP") || body.starts_with("LOGONFAIL") {
            windows_event(app, host, ts, body);
        } else {
            // journalctl short-unix: "<hostname> <ident>[pid]: <message>"
            let mut p = body.splitn(3, ' ');
            let (_, ident, msg) = (p.next(), p.next().unwrap_or(""), p.next().unwrap_or(""));
            linux_event(app, host, lan, ts, ident, msg);
        }
    } else if line.starts_with("CONNS ") {
        *pending = Some(Vec::new());
    } else if let Some(rest) = line.strip_prefix("CONN ") {
        let f: Vec<&str> = rest.split_whitespace().collect();
        if let (Some(list), [_, local, peer, ..]) = (pending.as_mut(), f.as_slice()) {
            let ip = ip_of(peer);
            list.push(Conn {
                local: local.to_string(),
                peer: peer.to_string(),
                proc_name: f.get(3).copied().unwrap_or("?").to_string(),
                public: !is_private_ip(&ip),
            });
        }
    } else if line == "CONNS_END" {
        if let Some(list) = pending.take() {
            commit_conns(app, host, lan, list);
        }
    }
}

fn commit_conns(app: &App, host: &str, lan: bool, list: Vec<Conn>) {
    let now = crate::now_epoch();
    let mut g = app.lock();
    let Some(h) = g.host_mut(host) else { return };
    let before: HashSet<String> = h.conns.iter().filter(|c| c.public).map(|c| ip_of(&c.peer)).collect();
    let fresh: Vec<(String, String, String)> = list
        .iter()
        .filter(|c| c.public && !before.contains(&ip_of(&c.peer)))
        .map(|c| (ip_of(&c.peer), c.local.clone(), c.proc_name.clone()))
        .collect();
    h.conns = list;
    h.conns_ts = now;
    let level = if lan { Level::Alert } else { Level::Warn };
    for (ip, local, proc_name) in fresh {
        g.bump(host, "conn_pub");
        g.push_event(host, level, format!("conn:{ip}"), format!("외부 IP가 접속해 있음: {ip} → {local} ({proc_name})"), true, now, FOLD);
    }
}

/// "1.2.3.4:22", "[::ffff:1.2.3.4]:22", "fe80::1%3:22" -> bare address.
pub fn ip_of(addr: &str) -> String {
    let a = addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(addr);
    let a = a.trim_matches(['[', ']']);
    a.strip_prefix("::ffff:").unwrap_or(a).to_string()
}

fn first_ip(msg: &str) -> Option<String> {
    msg.split(|c: char| c.is_whitespace() || c == ',')
        .map(|t| t.trim_end_matches(':'))
        .find(|t| t.parse::<std::net::IpAddr>().is_ok())
        .map(str::to_string)
}

fn word_after<'a>(msg: &'a str, marker: &str) -> Option<&'a str> {
    let i = msg.find(marker)? + marker.len();
    msg[i..].split_whitespace().next()
}

fn kv<'a>(msg: &'a str, key: &str) -> Option<&'a str> {
    msg.split_whitespace().find_map(|t| t.strip_prefix(key))
}

fn linux_event(app: &App, host: &str, lan: bool, ts: u64, ident: &str, msg: &str) {
    let mut g = app.lock();
    if ident.starts_with("sshd") {
        if let Some(i) = msg.find("Accepted ") {
            let t: Vec<&str> = msg[i..].split_whitespace().collect();
            // Accepted <method> for <user> from <ip> port <n> ...
            let (method, user, ip) = (t.get(1).copied().unwrap_or("?"), t.get(3).copied().unwrap_or("?"), t.get(5).copied().unwrap_or("?"));
            let public = !is_private_ip(ip);
            if public {
                g.bump(host, "login_pub");
                let level = if lan { Level::Alert } else { Level::Warn };
                g.push_event(host, level, format!("login:{user}:{ip}"), format!("SSH 로그인 성공 (공인 IP) {user} ← {ip} [{method}]"), true, ts, FOLD);
            } else {
                g.bump(host, "login");
                let level = if method == "password" || method.starts_with("keyboard") { Level::Warn } else { Level::Info };
                g.push_event(host, level, format!("login:{user}:{ip}"), format!("SSH 로그인 {user} ← {ip} [{method}]"), false, ts, FOLD);
            }
            return;
        }
        let failure = ["Failed ", "Invalid user", "authenticating user", "invalid user", "Unable to negotiate", "banner exchange", "maximum authentication"]
            .iter()
            .any(|m| msg.contains(m))
            || (msg.contains("Received disconnect") && msg.contains("[preauth]"));
        if failure {
            let Some(ip) = first_ip(msg) else { return };
            let user = word_after(msg, "invalid user ")
                .or_else(|| word_after(msg, "Invalid user "))
                .or_else(|| word_after(msg, "authenticating user "))
                .or_else(|| word_after(msg, "Failed password for "))
                .unwrap_or("");
            let public = !is_private_ip(&ip);
            let who = if user.is_empty() { String::new() } else { format!(" (계정: {user})") };
            if public {
                g.bump(host, "ssh_fail_pub");
                let level = if lan { Level::Alert } else { Level::Info };
                g.push_event(host, level, format!("fail:{ip}"), format!("공인 IP의 SSH 접속 시도 ← {ip}{who}"), true, ts, FOLD);
            } else {
                g.bump(host, "ssh_fail");
                g.push_event(host, Level::Warn, format!("fail:{ip}"), format!("SSH 인증 실패 ← {ip}{who}"), false, ts, FOLD);
            }
        }
    } else if ident.starts_with("sudo") && msg.contains("authentication failure") {
        let user = kv(msg, "ruser=").filter(|u| !u.is_empty()).or_else(|| kv(msg, "logname=")).unwrap_or("?");
        g.bump(host, "sudo_fail");
        g.push_event(host, Level::Warn, format!("sudo:{user}"), format!("sudo 비밀번호 실패 ({user})"), false, ts, FOLD);
    } else if msg.contains("UFW BLOCK") {
        let src = kv(msg, "SRC=").unwrap_or("");
        if src.is_empty() || is_private_ip(src) || src.starts_with("ff0") {
            return;
        }
        let port = kv(msg, "DPT=").unwrap_or("?");
        let proto = kv(msg, "PROTO=").unwrap_or("?");
        g.bump(host, "fw_pub");
        g.push_event(host, Level::Info, format!("fw:{src}"), format!("방화벽 차단 ← {src} ({proto}/{port})"), true, ts, FOLD);
    }
}

fn windows_event(app: &App, host: &str, ts: u64, body: &str) {
    let f: Vec<&str> = body.split_whitespace().collect();
    let mut g = app.lock();
    match f.as_slice() {
        ["RDPCONN", ip, ..] => {
            if is_private_ip(ip) {
                g.bump(host, "rdp");
                g.push_event(host, Level::Info, format!("rdp:{ip}"), format!("RDP 접속 ← {ip}"), false, ts, FOLD);
            } else {
                g.bump(host, "rdp_pub");
                g.push_event(host, Level::Alert, format!("rdp:{ip}"), format!("공인 IP의 RDP 접속 ← {ip} (RDP가 인터넷에 노출됨)"), true, ts, FOLD);
            }
        }
        ["RDPFAIL", ip, ..] => {
            let public = !is_private_ip(ip);
            g.bump(host, if public { "rdp_fail_pub" } else { "rdp_fail" });
            let level = if public { Level::Alert } else { Level::Warn };
            g.push_event(host, level, format!("rdpfail:{ip}"), format!("RDP 로그인 실패 ← {ip}"), public, ts, FOLD);
        }
        ["RDPLOGON", user, ip, ..] => {
            let public = !is_private_ip(ip);
            g.bump(host, if public { "login_pub" } else { "login" });
            let (level, text) = if public {
                (Level::Warn, format!("RDP 로그인 성공 (공인 IP) {user} ← {ip}"))
            } else {
                (Level::Info, format!("RDP 로그인 {user} ← {ip}"))
            };
            g.push_event(host, level, format!("rdplogon:{user}:{ip}"), text, public, ts, FOLD);
        }
        ["LOGONFAIL", ip, ..] => {
            let public = !is_private_ip(ip);
            g.bump(host, "logon_fail");
            let level = if public { Level::Alert } else { Level::Warn };
            g.push_event(host, level, format!("logonfail:{ip}"), format!("Windows 로그인 실패 ← {ip}"), public, ts, FOLD);
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Kind;
    use std::path::PathBuf;

    fn app() -> App {
        App::new(PathBuf::from("."), vec![Target { name: "h".into(), kind: Kind::Remote { lan_only: true } }])
    }

    #[test]
    fn extracts_bare_ip() {
        assert_eq!(ip_of("192.168.1.2:22"), "192.168.1.2");
        assert_eq!(ip_of("[::ffff:203.0.113.5]:443"), "203.0.113.5");
        assert_eq!(ip_of("[2001:db8::1]:22"), "2001:db8::1");
    }

    #[test]
    fn classifies_ssh_lines() {
        let a = app();
        let mut p = None;
        handle_line(&a, "h", true, "EV 100.5 box sshd-session[1]: Accepted publickey for dev from 192.168.1.5 port 5 ssh2", &mut p);
        handle_line(&a, "h", true, "EV 101 box sshd-session[2]: Invalid user admin from 203.0.113.9 port 4", &mut p);
        handle_line(&a, "h", true, "EV 102 box kernel: [UFW BLOCK] IN=eth0 SRC=203.0.113.7 DST=1.1.1.1 PROTO=UDP DPT=500", &mut p);
        let g = a.lock();
        let h = &g.hosts[0];
        assert_eq!(h.counters.get("login"), Some(&1));
        assert_eq!(h.counters.get("ssh_fail_pub"), Some(&1));
        assert_eq!(h.counters.get("fw_pub"), Some(&1));
        assert!(g.events.iter().any(|e| e.level == Level::Alert && e.text.contains("admin")));
    }

    #[test]
    fn new_public_connection_raises_one_event() {
        let a = app();
        for _ in 0..3 {
            let mut p = None;
            handle_line(&a, "h", true, "CONNS 1", &mut p);
            handle_line(&a, "h", true, "CONN tcp 192.168.1.2:22 203.0.113.5:4000 sshd", &mut p);
            handle_line(&a, "h", true, "CONNS_END", &mut p);
        }
        let g = a.lock();
        assert_eq!(g.hosts[0].conns.len(), 1);
        assert_eq!(g.events.len(), 1);
    }
}
