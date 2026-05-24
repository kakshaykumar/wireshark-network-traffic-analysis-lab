# FTP Credential Capture

## Objective
Demonstrate what a network observer sees during a single FTP session — showing that credentials, system information, and the complete post-login session are all transmitted in cleartext.

---

## Lab Setup
| Property | Value |
|----------|-------|
| Attacker | Kali Linux — 192.168.110.132 |
| Target | Ubuntu 22.04 — 192.168.110.130 (vsftpd 3.0.5, port 21) |
| Capture interface | Ubuntu ens37 (defender perspective) |
| Capture file | `ch2c-ftp-clean-login.pcapng` |

---

## Command Used

```bash
ftp 192.168.110.130
# Username: labuser
# Password: labuser
```

---

## Wireshark Filter

```
ftp
```

---

## Traffic Analysis

### Complete session in 39 packets

The entire FTP session — from connection to logout — is captured in plaintext:

```
220 (vsFTPd 3.0.5)                           ← server banner
USER labuser                                  ← username
331 Please specify the password.
PASS labuser                                  ← password in cleartext
230 Login successful.
SYST → 215 UNIX Type: L8                     ← OS type exposed
FEAT → 211-Features: EPRT, PASV              ← supported features
EPSV → 229 Entering Extended Passive Mode    ← data channel negotiated
LIST → 150/226                               ← directory listing transferred
PWD → 257 "/home/labuser" is the current directory  ← full path exposed
QUIT → 221 Goodbye.
```

The password `labuser` appears in the packet list at row 10 — readable in the Info column without clicking anything.

### What a passive observer learns from one session

| Intelligence | Value |
|-------------|-------|
| Username | labuser |
| Password | labuser |
| FTP software | vsftpd 3.0.5 |
| OS type | UNIX Type: L8 (Linux) |
| Home directory | /home/labuser |
| Supported protocols | EPRT, PASV |

Complete lateral movement intelligence from passive observation of one user session.

### Critical credential weakness

`password = username`. This is one of the most common patterns in real-world credential breaches. It indicates: default credentials never changed, or password policy enforcement is absent. It would be cracked in the first attempt of any basic wordlist.

---

## Attacker Perspective
Zero effort required beyond observing the traffic. No active attack, no brute force, no tooling — passive network observation is sufficient to obtain the complete credential and system context.

## Defender Perspective
`PASS labuser` is visible directly in the Wireshark packet list Info column — no middle pane expansion, no Follow TCP Stream, no decryption. A network tap monitoring port 21 captures this automatically. The credential, home path, and OS type are all exposed in one observed session.

---

## Screenshot

**FTP clean login: PASS labuser highlighted in packet list. Middle pane confirms Request arg: labuser. Hex pane shows raw bytes spelling out the password.**

![FTP clean login credential exposure](screenshots/ftp-clean-login.png)

---

## Key Findings

- `PASS labuser` readable in the packet list Info column — no analysis required
- Complete post-login session context exposed: OS type, directory path, feature list
- Password = username — crackable in the first attempt of any wordlist
- Passive observation only — no attack tool required to capture this

---

## MITRE ATT&CK

| ID | Technique |
|----|-----------|
| T1040 | Network Sniffing |

---

## Defensive Recommendations

- Disable FTP — passive observation of any FTP session captures the complete credential
- Enforce credential uniqueness — password must not equal username; enforce at account creation
- Audit existing accounts — check for accounts where the password matches the username
- Migrate to SFTP — same functionality, full encryption, no additional service required
