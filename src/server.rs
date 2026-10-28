//! Tiny HTTP/1.1 server on 127.0.0.1 for the dashboard (std only).
//! Every request must carry the per-run random token (page: `?t=`, API: `X-Token`)
//! and a loopback Host header, so other local programs or web pages (CSRF,
//! DNS rebinding) cannot read the state or accept a baseline.

use crate::app::{state_json, App};
use crate::baseline;
use crate::eval::Level;
use crate::scan;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const PAGE: &str = include_str!("ui.html");

pub fn serve(app: Arc<App>, listener: TcpListener, port: u16) {
    for stream in listener.incoming().flatten() {
        let app = Arc::clone(&app);
        thread::spawn(move || {
            let _ = handle(&app, stream, port);
        });
    }
}

struct Request {
    method: String,
    path: String,
    query: String,
    headers: Vec<(String, String)>,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }
    fn param(&self, name: &str) -> Option<String> {
        self.query.split('&').find_map(|kv| {
            let (k, v) = kv.split_once('=')?;
            (k == name).then(|| percent_decode(v))
        })
    }
}

fn read_request(s: &mut TcpStream) -> Option<Request> {
    s.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let mut buf = Vec::with_capacity(2048);
    let mut chunk = [0u8; 2048];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = s.read(&mut chunk).ok()?;
        if n == 0 || buf.len() > 16 * 1024 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let text = String::from_utf8_lossy(&buf);
    let mut lines = text.split("\r\n");
    let mut first = lines.next()?.split_whitespace();
    let (method, target) = (first.next()?.to_string(), first.next()?);
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let headers = lines
        .take_while(|l| !l.is_empty())
        .filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string())))
        .collect();
    Some(Request { method, path: path.to_string(), query: query.to_string(), headers })
}

fn respond(s: &mut TcpStream, status: &str, ctype: &str, body: &[u8]) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nCache-Control: no-store\r\n\
         X-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nConnection: close\r\n\r\n",
        body.len()
    );
    s.write_all(head.as_bytes())?;
    s.write_all(body)?;
    s.flush()
}

fn handle(app: &App, mut s: TcpStream, port: u16) -> std::io::Result<()> {
    let Some(req) = read_request(&mut s) else { return Ok(()) };
    let host_ok = matches!(req.header("host"), Some(h) if h == format!("127.0.0.1:{port}") || h == format!("localhost:{port}"));
    if !host_ok {
        return respond(&mut s, "403 Forbidden", "text/plain; charset=utf-8", b"forbidden");
    }
    let text = "text/plain; charset=utf-8";
    if req.path == "/" {
        return if req.param("t").as_deref() == Some(app.token.as_str()) {
            let page = PAGE.replace("__TOKEN__", &app.token);
            respond(&mut s, "200 OK", "text/html; charset=utf-8", page.as_bytes())
        } else {
            respond(&mut s, "403 Forbidden", text, "security-watch 창에서 열어 주세요.".as_bytes())
        };
    }
    if !req.path.starts_with("/api/") {
        return respond(&mut s, "404 Not Found", text, b"not found");
    }
    // sendBeacon cannot set headers, so the close beacon carries the token in the query.
    let token_ok = req.header("x-token") == Some(app.token.as_str())
        || (req.path == "/api/bye" && req.param("t").as_deref() == Some(app.token.as_str()));
    if !token_ok {
        return respond(&mut s, "403 Forbidden", text, b"forbidden");
    }
    let now = crate::now_epoch();
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/api/ping") => respond(&mut s, "200 OK", text, b"ok"),
        ("GET", "/api/state") => {
            let since = req.param("since").and_then(|v| v.parse().ok()).unwrap_or(0);
            let body = {
                let mut g = app.lock();
                g.last_poll = Some(Instant::now());
                g.closing_at = None;
                state_json(&g, since, now, app.started)
            };
            respond(&mut s, "200 OK", "application/json; charset=utf-8", body.as_bytes())
        }
        ("POST", "/api/bye") => {
            app.lock().closing_at = Some(Instant::now());
            respond(&mut s, "200 OK", text, b"ok")
        }
        ("POST", "/api/scan") => {
            app.lock().force_scan = true;
            respond(&mut s, "200 OK", text, b"ok")
        }
        ("POST", "/api/watch-since") => {
            scan::save_watch_since(&app.root, now);
            let mut g = app.lock();
            g.watch_since = now;
            g.force_scan = true;
            g.push_event("", Level::Info, String::new(), "기준 시점을 지금으로 바꿨습니다. 이전 로그 기록은 점검 결과에서 제외됩니다".into(), false, now, 0);
            respond(&mut s, "200 OK", text, b"ok")
        }
        ("POST", "/api/settings") => {
            if let Some(m) = req.param("scan_minutes").and_then(|v| v.parse::<u64>().ok()).filter(|m| (1..=1440).contains(m)) {
                app.lock().scan_minutes = m;
            }
            respond(&mut s, "200 OK", text, b"ok")
        }
        ("POST", "/api/accept") => {
            let name = req.param("host").unwrap_or_default();
            let mut g = app.lock();
            let saved = match g.host_mut(&name) {
                Some(h) => match &h.items {
                    Some(items) if baseline::save(&scan::baseline_path(&app.root, &h.target), items).is_ok() => {
                        h.changes.clear();
                        Some(h.target.title())
                    }
                    _ => None,
                },
                None => None,
            };
            match saved {
                Some(title) => {
                    g.push_event(&name, Level::Info, String::new(), format!("{title}: 현재 상태를 새 기준선으로 승인했습니다"), false, now, 0);
                    respond(&mut s, "200 OK", text, b"ok")
                }
                None => respond(&mut s, "409 Conflict", text, "저장할 검사 결과가 없습니다".as_bytes()),
            }
        }
        _ => respond(&mut s, "404 Not Found", text, b"not found"),
    }
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => {
                let hex = |c: u8| (c as char).to_digit(16);
                match (hex(b[i + 1]), hex(b[i + 2])) {
                    (Some(h), Some(l)) => {
                        out.push((h * 16 + l) as u8);
                        i += 2;
                    }
                    _ => out.push(b'%'),
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    /// A syntax error in the page script silently kills the whole dashboard,
    /// so check it with `node --check` when Node is installed.
    #[test]
    fn page_script_parses() {
        let page = super::PAGE;
        let start = page.find("<script>").expect("script start") + "<script>".len();
        let end = page.rfind("</script>").expect("script end");
        let path = std::env::temp_dir().join(format!("security-watch-ui-{}.js", std::process::id()));
        std::fs::write(&path, &page[start..end]).unwrap();
        let out = std::process::Command::new("node").arg("--check").arg(&path).output();
        let _ = std::fs::remove_file(&path);
        match out {
            Ok(o) => assert!(o.status.success(), "ui.html script: {}", String::from_utf8_lossy(&o.stderr)),
            Err(_) => eprintln!("node not found; skipped page script check"),
        }
    }

    #[test]
    fn decodes_percent_and_plus() {
        assert_eq!(super::percent_decode("my-server"), "my-server");
        assert_eq!(super::percent_decode("a%20b+c%2"), "a b c%2");
    }
}
