//! Locating the private data folder and reading the host list.

use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub enum Kind {
    Local,
    /// `lan_only`: the host should never see traffic from public IPs.
    Remote { lan_only: bool },
}

#[derive(Clone, Debug)]
pub struct Target {
    pub name: String,
    pub kind: Kind,
}

impl Target {
    pub fn title(&self) -> String {
        match self.kind {
            Kind::Local => "이 PC".to_string(),
            Kind::Remote { .. } => self.name.clone(),
        }
    }
    pub fn state_name(&self) -> String {
        let n = match self.kind {
            Kind::Local => "local",
            Kind::Remote { .. } => &self.name,
        };
        n.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect()
    }
}

pub const CONFIG_FILE: &str = "security-watch.conf";

const DEFAULT_CONFIG: &str = "\
# security-watch 설정 (이 폴더는 개인 정보가 들어가므로 git에 올리지 마세요)
#
# local                        이 PC(Windows) 검사
# host <ssh 별칭> [lan|public]  원격 Linux 서버 검사
#   <ssh 별칭>: ~/.ssh/config 의 Host 이름. 키 인증으로 비밀번호 없이 접속돼야 합니다.
#   lan    : 공유기 안쪽 서버(기본값). 공인 IP에서 들어온 흔적이 있으면 '위험'으로 표시합니다.
#   public : 인터넷에 직접 열린 서버(VPS 등). 공인 IP의 무차별 대입 시도는 '정보'로만 집계합니다.
local
# host my-server lan
";

/// Where config, baselines and reports live (never inside the published repo):
/// 1. the exe's own folder, if it already holds `security-watch.conf` (portable copy)
/// 2. the nearest `.private/` folder in the exe's folder or its parents (dev checkout)
/// 3. otherwise the exe's folder
pub fn resolve_root(exe_dir: &Path) -> PathBuf {
    if exe_dir.join(CONFIG_FILE).is_file() {
        return exe_dir.to_path_buf();
    }
    for dir in exe_dir.ancestors() {
        let p = dir.join(".private");
        if p.is_dir() {
            return p;
        }
    }
    exe_dir.to_path_buf()
}

/// Returns the targets and whether a default config had to be created.
pub fn load(root: &Path) -> (Vec<Target>, bool) {
    let path = root.join(CONFIG_FILE);
    let (text, created) = match fs::read_to_string(&path) {
        Ok(t) => (t, false),
        Err(_) => {
            let _ = fs::create_dir_all(root);
            let _ = fs::write(&path, DEFAULT_CONFIG);
            (DEFAULT_CONFIG.to_string(), true)
        }
    };
    (parse(&text), created)
}

fn parse(text: &str) -> Vec<Target> {
    let mut out = Vec::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let mut w = line.split_whitespace();
        match w.next() {
            Some("local") => out.push(Target { name: "local".into(), kind: Kind::Local }),
            Some("host") => {
                if let Some(name) = w.next() {
                    let lan_only = w.next() != Some("public");
                    out.push(Target { name: name.to_string(), kind: Kind::Remote { lan_only } });
                }
            }
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_local_and_hosts() {
        let t = parse("# c\nlocal\nhost a\nhost b public\nbogus\n");
        assert_eq!(t.len(), 3);
        assert!(matches!(t[1].kind, Kind::Remote { lan_only: true }));
        assert!(matches!(t[2].kind, Kind::Remote { lan_only: false }));
    }
}
