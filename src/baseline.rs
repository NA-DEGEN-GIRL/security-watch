//! Baseline: the set of "things that should not change silently" (ports, accounts,
//! keys, autoruns...). Each run is diffed against the last accepted baseline.

use crate::probe::Snapshot;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

/// (category, key) -> value. Value is empty for plain set-like categories.
pub type Items = BTreeMap<(String, String), String>;

/// Every category `items` can produce. A baseline file records which of them it was
/// saved with, so checks added by a newer version start from the current state
/// instead of reporting everything they see as new.
pub const CATEGORIES: &[&str] = &[
    "LISTEN", "MTIME", "USER", "FIREWALL", "RDP", "SSHD", "SHELLUSER", "UID0", "ADMIN", "AUTHKEY", "UNIT", "CRON", "CRONFILE",
    "AUTORUN", "TASK", "SERVICE", "PERSIST", "HOSTS", "PROXY", "SUID", "FILEHASH", "UNITHASH",
];
/// How many of them a file without a `# categories:` line was saved with.
const ORIGINAL: usize = 16;

pub fn items(snap: &Snapshot) -> Items {
    let mut m = Items::new();
    for r in &snap.records {
        let f = r.fields();
        let (key, value) = match r.key.as_str() {
            "LISTEN" if f.len() >= 3 => {
                let proc_name = f.get(3).copied().unwrap_or("?");
                let port = f[2].parse::<u32>();
                // Discovery protocols (NetBIOS, SSDP, WS-Discovery, mDNS, LLMNR): shared by
                // many apps whose owner process flips between runs; not an exposure signal.
                if f[0] == "udp" && matches!(port, Ok(137 | 138 | 1900 | 3702 | 5353 | 5355)) {
                    continue;
                }
                match port {
                    // Clients and some servers use random high ports; track them per process only.
                    Ok(p) if p >= 32768 => (format!("{} {} (임시 포트)", f[0], proc_name), String::new()),
                    _ => (format!("{} {}:{} ({})", f[0], f[1], f[2], proc_name), String::new()),
                }
            }
            "MTIME" | "FILEHASH" if f.len() >= 2 => (f[0].to_string(), f[1].to_string()),
            "UNITHASH" if f.len() >= 3 => (format!("{} {}", f[0], f[1]), f[2].to_string()),
            "PERSIST" => match r.rest.split_once(" = ") {
                Some((name, value)) => (name.to_string(), value.to_string()),
                None => continue,
            },
            "PROXY" => ("proxy".to_string(), r.rest.clone()),
            "USER" if f.len() >= 2 => (f[0].to_string(), f[1].to_string()),
            "FIREWALL" if !f.is_empty() => (f[0].to_string(), f[1..].join(" ")),
            "RDP" | "SSHD" => (r.key.to_lowercase(), r.rest.clone()),
            "SHELLUSER" | "UID0" | "ADMIN" | "AUTHKEY" | "UNIT" | "CRON" | "CRONFILE" | "AUTORUN" | "TASK"
            | "SERVICE" | "SUID" | "HOSTS" => (r.rest.clone(), String::new()),
            _ => continue,
        };
        m.insert((r.key.clone(), key), value);
    }
    m
}

pub struct Change {
    pub category: String,
    pub key: String,
    pub old: Option<String>,
    pub new: Option<String>,
}

pub fn diff(base: &Items, cur: &Items) -> Vec<Change> {
    let mut out = Vec::new();
    for ((cat, key), v) in cur {
        match base.get(&(cat.clone(), key.clone())) {
            None => out.push(Change { category: cat.clone(), key: key.clone(), old: None, new: Some(v.clone()) }),
            Some(old) if old != v => out.push(Change {
                category: cat.clone(),
                key: key.clone(),
                old: Some(old.clone()),
                new: Some(v.clone()),
            }),
            _ => {}
        }
    }
    for ((cat, key), v) in base {
        if !cur.contains_key(&(cat.clone(), key.clone())) {
            out.push(Change { category: cat.clone(), key: key.clone(), old: Some(v.clone()), new: None });
        }
    }
    out
}

/// The saved baseline, plus the categories it was saved without (checks added since).
pub fn load(path: &Path) -> Option<(Items, Vec<&'static str>)> {
    Some(parse(&fs::read_to_string(path).ok()?))
}

fn parse(text: &str) -> (Items, Vec<&'static str>) {
    let mut m = Items::new();
    let mut known: Vec<&str> = CATEGORIES[..ORIGINAL].to_vec();
    for line in text.lines() {
        if let Some(list) = line.strip_prefix("# categories:") {
            known = list.split_whitespace().collect();
        } else if !line.starts_with('#') {
            let mut p = line.splitn(3, '\t');
            if let (Some(c), Some(k), Some(v)) = (p.next(), p.next(), p.next()) {
                m.insert((c.to_string(), k.to_string()), v.to_string());
            }
        }
    }
    let missing = CATEGORIES.iter().copied().filter(|c| !known.contains(c)).collect();
    (m, missing)
}

fn render(items: &Items) -> String {
    let mut s = String::from("# security-watch baseline: category<TAB>key<TAB>value\n");
    s.push_str(&format!("# categories: {}\n", CATEGORIES.join(" ")));
    for ((c, k), v) in items {
        s.push_str(&format!("{c}\t{k}\t{v}\n"));
    }
    s
}

pub fn save(path: &Path, items: &Items) -> std::io::Result<()> {
    fs::write(path, render(items))
}

pub fn load_last_run(path: &Path) -> Option<u64> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

pub fn save_last_run(path: &Path, epoch: u64) {
    let _ = fs::write(path, epoch.to_string());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_added_changed_removed() {
        let a = items(&Snapshot::parse("LISTEN tcp 0.0.0.0 22 sshd\nMTIME /etc/passwd 1\nUID0 root\nEND"));
        let b = items(&Snapshot::parse("LISTEN tcp 0.0.0.0 22 sshd\nLISTEN tcp 0.0.0.0 4444 nc\nMTIME /etc/passwd 2\nEND"));
        let d = diff(&a, &b);
        assert!(d.iter().any(|c| c.category == "LISTEN" && c.old.is_none()));
        assert!(d.iter().any(|c| c.category == "MTIME" && c.old.is_some() && c.new.is_some()));
        assert!(d.iter().any(|c| c.category == "UID0" && c.new.is_none()));
    }

    #[test]
    fn a_file_from_an_older_version_reports_which_checks_it_lacks() {
        let cur = items(&Snapshot::parse(
            "UID0 root\nPERSIST winlogon\\Shell = explorer.exe\nPROXY enable=0 server=- pac=-\nHOSTS 203.0.113.9 a.example\nSUID /usr/bin/sudo\nFILEHASH /etc/profile ab12\nUNITHASH system a.service cd34\nEND",
        ));
        assert_eq!(cur.len(), 7);
        assert_eq!(cur[&("PERSIST".to_string(), "winlogon\\Shell".to_string())], "explorer.exe");
        let (old, missing) = parse("# security-watch baseline: category<TAB>key<TAB>value\nUID0\troot\t\n");
        assert_eq!(old.len(), 1);
        assert_eq!(missing, &CATEGORIES[ORIGINAL..]);
        let (new, missing) = parse(&render(&cur));
        assert!(missing.is_empty());
        assert!(diff(&new, &cur).is_empty());
    }

    #[test]
    fn shared_discovery_ports_are_ignored() {
        let a = items(&Snapshot::parse("LISTEN udp 0.0.0.0 5353 chrome\nEND"));
        assert!(a.is_empty());
    }

    #[test]
    fn ephemeral_ports_are_grouped_per_process() {
        let a = items(&Snapshot::parse("LISTEN udp * 40001 cloudflared\nEND"));
        let b = items(&Snapshot::parse("LISTEN udp * 51234 cloudflared\nEND"));
        assert!(diff(&a, &b).is_empty());
    }
}
