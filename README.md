# security-watch

Double-click security check for a Windows PC and the Linux servers it manages over SSH.
It looks for intrusion traces and risky exposure, prints a colored summary, and saves a
text report. It never changes anything on the checked hosts. No external crates; only the
Rust standard library plus `ssh` and PowerShell, which ship with Windows.

## What it checks

**This PC (Windows)**
- RDP: enabled/NLA, inbound connections and failed logins from **public IPs** (a sign the
  router forwards RDP to the internet), log rollover caused by floods, successful RDP logons
- Failed Windows logons (event 4625; needs "Run as administrator")
- Defender real-time protection, Windows Firewall profiles, OpenSSH server
- Changes vs. baseline: listening ports, local accounts, Administrators group,
  Run keys / Startup folder, non-Microsoft scheduled tasks, auto-start services

**Linux servers (via `ssh <alias>`)**
- SSH failures and successful logins, split by public/private source IP
  (`lan` hosts raise an alert on any public-IP traffic)
- Password-based SSH logins, sudo password failures, public packets blocked by ufw
- Extra UID 0 accounts, `/etc/ld.so.preload`, processes running from `/tmp` or `/dev/shm`,
  new ELF/script files in temp folders, pending reboot
- Changes vs. baseline: listening ports, login-capable users, `authorized_keys`
  fingerprints, sensitive files (`passwd`, `shadow`, `sudoers`, `sshd_config`, PAM),
  systemd units, cron jobs

Each run covers the time since the previous run (first run: last 24 h, at most 7 days).
On the first run the current state is saved as the **baseline**; later runs list anything
added, removed or modified, and ask whether to accept the changes as the new baseline.

## Setup

1. `cargo build --release`
2. Create a private folder that git ignores and copy the exe there:
   ```
   mkdir .private
   copy target\release\security-watch.exe .private\
   ```
3. Run it once. It creates `.private\security-watch.conf`. Add your servers:
   ```
   local
   host my-server lan      # ~/.ssh/config Host alias, key-based login (BatchMode)
   host my-vps public      # internet-facing host: public brute force is only "info"
   ```
4. Double-click `.private\security-watch.exe` whenever you want a check.

Remote hosts need key-based SSH without a password prompt. Reading SSH/firewall logs on
the server needs journal access (`adm` or `systemd-journal` group) or passwordless `sudo`;
without it the report says so instead of guessing.

## Where data goes

Everything personal (host aliases, baselines, reports) lives next to the exe in the
`.private/` folder, which `.gitignore` excludes:

```
.private/
  security-watch.conf
  state/<host>.baseline   accepted baseline
  state/<host>.lastrun    end of the last checked window
  reports/report-*.txt    one report per run
```

If the exe's own folder contains `security-watch.conf`, that folder is used instead, so a
copied exe works anywhere.
