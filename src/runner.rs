//! Child-process execution with a hard timeout, plus the probe launchers.

use std::io::{Read, Write};
use std::os::windows::process::CommandExt;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

pub struct Output {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

pub fn run(mut cmd: Command, stdin_data: Option<Vec<u8>>, timeout: Duration) -> Result<Output, String> {
    cmd.stdin(if stdin_data.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(CREATE_NO_WINDOW);
    let mut child = cmd.spawn().map_err(|e| format!("실행 실패: {e}"))?;

    if let (Some(data), Some(mut stdin)) = (stdin_data, child.stdin.take()) {
        thread::spawn(move || {
            let _ = stdin.write_all(&data);
        });
    }
    let mut out = child.stdout.take().expect("piped stdout");
    let mut err = child.stderr.take().expect("piped stderr");
    let out_t = thread::spawn(move || {
        let mut b = Vec::new();
        let _ = out.read_to_end(&mut b);
        b
    });
    let err_t = thread::spawn(move || {
        let mut b = Vec::new();
        let _ = err.read_to_end(&mut b);
        b
    });

    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) if start.elapsed() > timeout => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{}초 안에 끝나지 않아 중단함", timeout.as_secs()));
            }
            Ok(None) => thread::sleep(Duration::from_millis(100)),
            Err(e) => return Err(format!("대기 실패: {e}")),
        }
    };
    Ok(Output {
        success: status.success(),
        stdout: String::from_utf8_lossy(&out_t.join().unwrap_or_default()).into_owned(),
        stderr: String::from_utf8_lossy(&err_t.join().unwrap_or_default()).into_owned(),
    })
}

const LINUX_PROBE: &str = include_str!("probe_linux.sh");
const WINDOWS_PROBE: &str = include_str!("probe_windows.ps1");

/// Runs the read-only probe on a remote host through the user's own `ssh` config.
pub fn probe_remote(host: &str, since: u64) -> Result<Output, String> {
    let mut cmd = Command::new("ssh");
    cmd.args([
        "-T",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=10",
        "-o", "ServerAliveInterval=10",
        host,
        "bash", "-s", "--", &since.to_string(),
    ]);
    let script = LINUX_PROBE.replace('\r', "").into_bytes();
    run(cmd, Some(script), Duration::from_secs(120))
}

/// Runs the PowerShell probe on this PC (passed as -EncodedCommand: no temp files).
pub fn probe_local(since: u64) -> Result<Output, String> {
    let script = WINDOWS_PROBE.replace("__SINCE__", &since.to_string());
    let utf16: Vec<u8> = script.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    let mut cmd = Command::new("powershell.exe");
    cmd.args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", &base64(&utf16)]);
    run(cmd, None, Duration::from_secs(180))
}

fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        s.push(T[(n >> 18) as usize & 63] as char);
        s.push(T[(n >> 12) as usize & 63] as char);
        s.push(if c.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        s.push(if c.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    s
}

#[cfg(test)]
mod tests {
    #[test]
    fn base64_matches_known_vectors() {
        assert_eq!(super::base64(b""), "");
        assert_eq!(super::base64(b"f"), "Zg==");
        assert_eq!(super::base64(b"fo"), "Zm8=");
        assert_eq!(super::base64(b"foobar"), "Zm9vYmFy");
    }
}
