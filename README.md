# security-watch

Security monitor for a Windows PC and the Linux servers it manages over SSH.
Double-click it and a dashboard window shows intrusion traces and risky exposure, live.
It never changes anything on the checked hosts. No external crates; only the Rust
standard library plus `ssh`, PowerShell and Edge, which ship with Windows.

## Dashboard

- **Live feed (seconds):** one long-lived `ssh` stream per server follows SSH, sudo and
  firewall events from the journal as they happen; this PC is polled every 5 s for RDP
  and logon events. Inbound connections to listening ports are refreshed every 5 s and
  a public IP showing up there raises an event. Repeats from one source fold into "×N".
- **Full scans (minutes):** the heavier checks below run every 5 minutes (1–60, set in
  the window) or on demand, over the last 24 h.
- **Reference point:** "기준 시점을 지금으로" hides log entries older than now, e.g. after
  you fixed an exposure, so already-handled attacks stop showing up.
- **Baseline:** differences from the accepted baseline are listed per host with an
  "accept" button.

The window is an Edge app window on a private profile; closing it stops the program.
The UI is served on `127.0.0.1` only and every request must carry a random per-run token
and a loopback `Host` header, so other programs or web pages cannot read or change it.
All child processes run in a kill-on-close job object and die with the program.

`security-watch.exe --once` keeps the original one-shot text report (for scheduled tasks).

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
4. Double-click `.private\security-watch.exe` to open the dashboard.

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
  state/<host>.lastrun    end of the last checked window (--once)
  state/watch_since       reference point set from the dashboard
  state/ui.lock, ui.log   running dashboard (port + token), lifecycle log
  ui-profile/             Edge profile used for the dashboard window
  reports/report-*.txt    one report per --once run
```

If the exe's own folder contains `security-watch.conf`, that folder is used instead, so a
copied exe works anywhere.
