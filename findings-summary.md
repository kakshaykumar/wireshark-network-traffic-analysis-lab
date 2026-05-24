# Findings Summary

Consolidated findings ranked by security impact.

---

## Critical

### FTP transmits credentials in plaintext
**Scenarios:** FTP Brute Force, FTP Credential Capture, FTP vs SSH Comparison
`PASS labuser` visible in the Wireshark packet list Info column — no decryption, no tooling, no analysis required. Any observer on the network segment captures complete credentials passively.
**Fix:** Disable vsftpd; configure SFTP via `Subsystem sftp /usr/lib/openssh/sftp-server`

---

### HTTP Basic Auth uses encoding not encryption
**Scenarios:** HTTP Basic Auth Attack, HTTP Traffic Analysis
`Authorization: Basic YWRtaW46YWRtaW4=` decoded with one command: `admin:admin`. Credentials recoverable from any captured HTTP traffic without specialised tools.
**Fix:** Deploy HTTPS; replace Basic Auth with session-based or token-based authentication

---

### Password equals username on both accounts
**Accounts:** `labuser/labuser`, `admin/admin`
FTP credential cracked in 9 attempts; HTTP in 1 attempt — both from a 12-entry wordlist.
**Fix:** Enforce password complexity; password must not equal username

---

## Major

### Exact software versions exposed via banner grabbing
**Scenario:** Service Version Detection
`vsftpd 3.0.5`, `OpenSSH 10.2p1 Ubuntu-2ubuntu3.2`, `Apache httpd 2.4.66 (Ubuntu)` — complete attack surface from one 10-second scan.
**Fix:** `ServerTokens Prod` (Apache), `ftpd_banner=` (vsftpd), `DebianBanner no` (SSH)

---

### Nmap fingerprinted by TCP window size
**Scenario:** TCP SYN Scan
`Win=1024` in every SYN probe — not a real OS window size. IDS can identify Nmap without signature databases.
**Fix (detection):** IDS rule: alert on TCP SYN with `window_size_value == 1024` from external source

---

### Hydra fingerprinted in both SSH and HTTP
**Scenarios:** SSH Brute Force, HTTP Basic Auth Attack
`SSH-2.0-libssh_0.11.3` (SSH) and `User-Agent: Mozilla/4.0 (Hydra)` (HTTP) in every request.
**Fix (detection):** IDS: alert on `libssh` in SSH client banner; WAF: block `User-Agent: *Hydra*`

---

### NSE probed /.git/HEAD automatically
**Scenario:** Aggressive Scan
Nmap checks for exposed Git repositories without additional configuration. Common misconfiguration that leaks source code and credentials.
**Fix:** Apache: `<Directory "*.git"> Deny from all </Directory>`; never deploy with `.git` in webroot

---

### Direct DNS to external resolver detected
**Scenario:** DNS Analysis
DNS query to `8.8.8.8` instead of the internal resolver — bypasses internal DNS monitoring and filtering.
**Fix:** Firewall rule blocking outbound UDP/TCP port 53 to any destination except authorised resolvers

---

## Informational

### OS fingerprinting via ICMP TTL
TTL 64 = Linux, TTL 128 = Windows — identifiable from ping responses without a dedicated OS scan.

### SSH brute force detectable without credential visibility
5 rapid connections from same source within seconds — behavioural pattern is unmistakable even though SSH encryption is effective.

### NXDOMAIN pattern identified for DGA detection
Single NXDOMAIN is normal. High-volume NXDOMAIN from one host = DGA malware indicator.

---

## Attack Path Reconstruction

Using only information captured in this lab:

1. **Reconnaissance:** 3 live hosts, 3 open services, exact software versions, web paths — from two Nmap scans
2. **Credential access:** FTP cracked in 9 attempts, HTTP in 1 attempt — both from a 12-entry wordlist
3. **Post-access intelligence from FTP session:** home directory `/home/labuser`, OS type, filesystem structure, supported protocols

Complete path from initial scan to active access: one Nmap scan (30s) + one Hydra run (5s). The entire attack surface was exposed by the absence of three controls: encryption (FTP/HTTP), password policy, and brute force protection.

---

## Priority Control Recommendations

| Priority | Control | Findings addressed |
|----------|---------|-------------------|
| Critical | Disable FTP; configure SFTP | Finding 1, 3 |
| Critical | Deploy HTTPS | Finding 2, 3 |
| Critical | Password complexity policy | Finding 3 |
| High | Suppress version banners | Finding 4 |
| High | SSH key auth; disable password auth | Finding 6 |
| High | Fail2ban for SSH and HTTP | Finding 6 |
| High | Block outbound DNS to unauthorised resolvers | Finding 8 |
| Medium | IDS rules for Nmap and Hydra fingerprints | Findings 5, 7 |
| Medium | Remove .git from webroot | Finding 7 |
| Medium | SIEM rule: NXDOMAIN flood detection | Finding 10 |
