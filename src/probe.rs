//! Parsed probe output: one `KEY rest...` record per line.

pub struct Record {
    pub key: String,
    pub rest: String,
}

impl Record {
    pub fn fields(&self) -> Vec<&str> {
        self.rest.split_whitespace().collect()
    }
    /// Field `i` parsed as a number (0 when missing or malformed).
    pub fn num(&self, i: usize) -> u64 {
        self.fields().get(i).and_then(|s| s.parse().ok()).unwrap_or(0)
    }
}

pub struct Snapshot {
    pub records: Vec<Record>,
    /// The probe printed its final `END` marker.
    pub complete: bool,
}

impl Snapshot {
    pub fn parse(text: &str) -> Snapshot {
        let mut records = Vec::new();
        let mut complete = false;
        for line in text.lines() {
            let line = line.trim_end_matches('\r');
            let (key, rest) = line.split_once(' ').unwrap_or((line, ""));
            if key.is_empty() || !key.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit()) {
                continue;
            }
            if key == "END" {
                complete = true;
                continue;
            }
            records.push(Record { key: key.to_string(), rest: rest.trim().to_string() });
        }
        Snapshot { records, complete }
    }

    pub fn all<'a>(&'a self, key: &'a str) -> impl Iterator<Item = &'a Record> + 'a {
        self.records.iter().filter(move |r| r.key == key)
    }

    pub fn first(&self, key: &str) -> Option<&Record> {
        self.records.iter().find(|r| r.key == key)
    }

    pub fn meta(&self, name: &str) -> Option<&str> {
        self.all("META").find_map(|r| {
            let (k, v) = r.rest.split_once(' ').unwrap_or((&r.rest, ""));
            (k == name).then_some(v)
        })
    }
}

/// Private, loopback, link-local, CGNAT/Tailscale and unique-local addresses.
pub fn is_private_ip(ip: &str) -> bool {
    if let Ok(v4) = ip.parse::<std::net::Ipv4Addr>() {
        let o = v4.octets();
        return v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified()
            || (o[0] == 100 && (64..=127).contains(&o[1]));
    }
    if let Ok(v6) = ip.trim_matches(['[', ']']).split('%').next().unwrap_or("").parse::<std::net::Ipv6Addr>() {
        let s = v6.segments()[0];
        return v6.is_loopback() || v6.is_unspecified() || (s & 0xffc0) == 0xfe80 || (s & 0xfe00) == 0xfc00;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_records_and_end_marker() {
        let s = Snapshot::parse("META hostname box\nSSHFAIL 3 1 1\nnoise line\nEND\r\n");
        assert!(s.complete);
        assert_eq!(s.meta("hostname"), Some("box"));
        assert_eq!(s.first("SSHFAIL").unwrap().num(1), 1);
        assert_eq!(s.records.len(), 2);
    }

    #[test]
    fn classifies_ips() {
        assert!(is_private_ip("192.168.1.10"));
        assert!(is_private_ip("100.101.1.1"));
        assert!(is_private_ip("fe80::1%12"));
        assert!(!is_private_ip("203.0.113.5"));
        assert!(!is_private_ip("2001:db8::1"));
    }
}
