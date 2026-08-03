---
title: "OS Detection Techniques: TTL, Nmap, and Banner Grabbing"
description: A practical guide to identifying operating systems through software versions, port analysis, TTL values, and Nmap fingerprinting.
date: 2026-08-03 00:00:00 +0000
categories: [Security, Reconnaissance]
tags: [os-detection, fingerprinting, nmap, ttl, enumeration, penetration-testing]
image:
  path: /assets/img/posts/os-detection-techniques/cover.png
toc: true
---

When you're staring at a raw IP address with no context, figuring out what OS is running on the other end is the first thing to nail down. The wrong assumption wastes time and sends you down dead-end paths.

This cheatsheet covers the main methods for OS identification: software version mapping, port-based heuristics, TTL and window size analysis, Nmap's TCP/IP stack fingerprinting, passive observation, and container detection.

> None of these methods are foolproof on their own. Firewalls, custom configurations, and load balancers can mask or misrepresent the OS. Cross-reference multiple techniques before making a call.

## Software Version Fingerprinting

Different OS versions ship with specific versions of common software. If you can grab a version string from an open port, you can narrow down the OS with reasonable confidence.

### Ubuntu

Ubuntu LTS releases are the most common targets. OpenSSH and Apache versions map cleanly to specific releases:

| Ubuntu Version | OpenSSH | Apache | nginx |
| -------------- | ------- | ------ | ----- |
| 20.04 - focal [LTS] | 8.2p1 | 2.4.41 | 1.18.0 |
| 22.04 - jammy [LTS] | 8.9p1 | 2.4.52 | 1.18.0 |
| 23.04 - lunar | 9.0p1 | 2.4.55 | 1.22.0 |
| 24.04 - noble [LTS] | 9.6p1 | 2.4.58 | 1.24.0 |
| 25.04 - plucky | 9.9p1 | 2.4.63 | 1.26.3 |
| 25.10 - questing | 10.0p1 | 2.4.64 | 1.28.0 |
| 26.04 - resolute [LTS] | 10.2p1 | 2.4.66 | 1.28.3 |

Security updates increment the patch version, so `8.9p1` on Ubuntu 22.04 might show as `8.9p1-3ubuntu0.10` in practice. The base version is what matters.

### Debian

Debian releases less frequently, but the version mapping is just as reliable:

| Debian Version | Release Year | OpenSSH | nginx |
| -------------- | ------------ | ------- | ----- |
| 10 - Buster | 2019 | 7.9p1 | 1.14.2 |
| 11 - Bullseye | 2021 | 8.4p1 | 1.18.0 |
| 12 - Bookworm | 2023 | 9.2p1 | 1.22.1 |
| 13 - Trixie | 2025 | 10.0p1 | 1.26.3 |

Apache versions on Debian tend to update while the OS is supported, making them less reliable for precise identification.

### Red Hat / CentOS

| Version | OpenSSH | Apache (varies by minor) |
| ------- | ------- | ------------------------ |
| 7 | 7.4p1 | 2.4.6 |
| 8 | 8.0p1 | 2.4.37 |
| 9 | 8.7p1 | 2.4.51 to 2.4.62 |
| 10 | 9.9p1 | 2.4.63 |

CentOS Stream 9 ships OpenSSH 9.9p1 while RHEL 9 stays on 8.7p1, so a 9.x banner on `el9` means Stream.

### Windows IIS

IIS version tracking was reliable until Windows 10 / Server 2016 standardized on IIS 10.0. Still useful for legacy targets:

| Windows Version | IIS |
| --------------- | --- |
| Windows 10 / Server 2016+ | 10.0 |
| Windows 8.1 / Server 2012 R2 | 8.5 |
| Windows 8 / Server 2012 | 8.0 |
| Windows 7 / Server 2008 R2 | 7.5 |
| Windows Vista / Server 2008 | 7.0 |
| Windows Server 2003 | 6.0 |

### Grabbing Versions

```bash
nmap -sV -p 22,80,443 <target>              # Get SSH, HTTP, HTTPS versions
nmap -sV --version-intensity 9 <target>     # Deeper probe (slower)

# Manual banner grab
nc -nv <target> 22                # SSH banner
openssl s_client -connect <target>:443 -servername <target> 2>/dev/null | openssl x509 -noout -subject -dates
curl -I http://<target>           # HTTP server header
```

Versions in the SSH banner or HTTP `Server` header are usually enough to place the OS within 1-2 releases.

### Filesystem Case Sensitivity

If the target only exposes a web server, the underlying filesystem still leaks something about the OS family. Windows filesystems are case-insensitive, and so is macOS by default, since APFS ships in both variants and installers pick the insensitive one. Linux and BSD filesystems are case-sensitive:

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://<target>/index.html
curl -s -o /dev/null -w '%{http_code}\n' http://<target>/INDEX.HTML
```

Two `200`s mean a case-insensitive filesystem, so Windows or macOS. A `200` followed by a `404` means case-sensitive, so Linux or BSD. This works through a proxy and sends nothing unusual, but URL rewriting, CDNs, and frameworks that normalize paths can all mask the result, so confirm with a second technique.

## Port-Based Heuristics

### Windows Domain Controller

A Windows DC opens a distinctive set of ports. Seeing this combination is a strong indicator:

- TCP/UDP 53: DNS (often "Simple DNS Plus")
- TCP/UDP 88: Kerberos
- UDP 123: NTP
- TCP 135: RPC
- TCP/UDP 389: LDAP
- TCP 445: SMB
- TCP/UDP 464: Kerberos password change
- TCP 636: LDAPS
- TCP 3268/3269: LDAP GC

### Windows Client / Server

Common Windows ports that don't typically appear together on Linux:

- TCP 135: RPC
- TCP 139: NetBIOS
- TCP 445: SMB
- TCP 1433: MSSQL
- TCP 3389: RDP
- TCP 5985/5986: WinRM

Linux can run Samba on port 445, but the SMB version string makes it obvious. NetExec is the reliable first move, because it speaks modern SMB dialects:

```bash
netexec smb <target>
# [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:corp.local) (signing:True) (SMBv1:False)
```

The build number is exact. The edition is not, because build 17763 covers both Windows 10 1809 and Server 2019, which is why NetExec prints a slash rather than picking one.

```bash
nmap -p445 --script smb-protocols <target>     # Which dialects are actually offered
nmap -p445 --script smb-os-discovery <target>  # Only useful where SMBv1 is enabled
```

Treat `smb-os-discovery` as a legacy-host tool, not a default.

### NTLM Info

Several services disclose their build version inside an NTLMSSP handshake before any authentication succeeds. `rdp-ntlm-info` sends an incomplete CredSSP request with null credentials, and the service answers with NetBIOS and DNS names plus an exact build number:

```bash
nmap -p3389 --script rdp-ntlm-info <target>
# | rdp-ntlm-info:
# |   Target_Name: W2016
# |   NetBIOS_Computer_Name: W16GA-SRV01
# |   DNS_Domain_Name: W2016.lab
# |_  Product_Version: 10.0.14393
```

No credentials and no SMBv1, and it works in the common case where 445 is filtered but 3389 is open. Sibling scripts cover HTTP, SMTP, IMAP, POP3, and MSSQL:

```bash
nmap --script='*-ntlm-info' <target>
```

### SNMP

If UDP 161 is open with a default community string, SNMP's `sysDescr` OID hands over the OS as a literal string. That is more definitive than anything you can infer from a stack fingerprint:

```bash
snmpwalk -v2c -c public <target> 1.3.6.1.2.1.1.1.0
# SNMPv2-MIB::sysDescr.0 = STRING: Linux web01 5.15.0-88-generic #98-Ubuntu SMP x86_64

nmap -sU -p 161 --script snmp-info <target>
onesixtyone <target>              # Brute-force community strings
```

Default community strings such as `public` and `private` are still common on printers, switches, and forgotten appliances.

### Linux

Linux has no equivalent to the Windows RPC and SMB cluster. Cross-platform services give nothing away, since MySQL, PostgreSQL, and SMTP all run on Windows too, so on those you need the banner rather than the port.

A few ports still lean Unix:

- TCP/UDP 111: rpcbind
- TCP 2049: NFS
- TCP 631: CUPS (also macOS)
- TCP 6000-6063: X11
- TCP 22: SSH, though Windows can run OpenSSH since Server 2019

The strongest signal is absence: 22 open with no 135, 139, or 445.

## TTL and Window Size Analysis

Every IP packet has a Time-to-Live field. Different OSes initialize it to different values, and each router hop decrements it by one.

### Quick Rule of Thumb

| Seen TTL | Likely OS |
| -------- | --------- |
| 64 | Linux, macOS, *BSD |
| 128 | Windows |
| 254 / 255 | Cisco and other network gear |

> Solaris is the trap here: it answers ICMP with 255 but uses 64 for TCP on 2.8 and later, so over TCP it is indistinguishable from Linux on TTL alone.

### Checking TTL

```bash
ping -c 3 <target>
# 64 bytes from 10.10.10.10: icmp_seq=1 ttl=63 time=0.5 ms

# Windows Firewall drops inbound ICMP echo by default, so a silent ping does
# not mean the host is down. Read the TTL off a TCP reply instead:
sudo hping3 -S -p 443 -c 1 <target>
```

A TTL of 63 means the initial value was likely 64 and it went through one hop. A TTL of 127 likely started at 128.

### Full Reference

| Device / OS | Initial TTL |
| ----------- | ----------- |
| Linux (2.4+, modern) | 64 |
| macOS (10.5.6+) | 64 |
| FreeBSD (5+) | 64 |
| Windows (2000+) | 128 |
| Windows (95/98) | 32 |
| Solaris (2.8+) | 255 (ICMP) / 64 (TCP) |
| AIX | 60 (TCP) / 255 (ICMP) |
| Cisco IOS | 255 |
| Android | 64 |
| HP-UX (11) | 64 (TCP) / 255 (ICMP) |
| Juniper | 64 |

> TTL is unreliable across the open internet, because you have no idea how many hops the packet took. It works best on LAN segments or lab environments where the hop count is known.

### TCP Window Size

TTL alone is coarse. Pairing it with the advertised TCP window size from the SYN/ACK narrows things considerably:

| OS | Initial TTL | TCP Window |
| -- | ----------- | ---------- |
| Linux (kernel 2.4 / 2.6) | 64 | 5840 |
| Linux (kernel 3.x+) | 64 | 29200 |
| Windows XP | 128 | 65535 |
| Windows 7 / Server 2008 | 128 | 8192 |
| Windows 10 / 11 | 128 | 64240 |
| FreeBSD | 64 | 65535 |
| Cisco IOS 12.4 | 255 | 4128 |

Window scaling, TCP offload, and middleboxes all rewrite these values in practice, so treat the window size as corroboration rather than proof.

### Caveats

- TTL can be modified in kernel parameters on any OS. On Linux, `sysctl -w net.ipv4.ip_default_ttl=128` makes the host look like Windows to every technique in this section, and Windows exposes the same knob via the registry. Treat TTL as corroboration, never proof.
- Intermediate hops decrement the value, so what you see isn't the initial TTL.
- Some containers and VMs change how TTL is handled (discussed below).

## Nmap OS Detection (-O)

Nmap's `-O` flag sends a series of probes to open and closed ports, then analyzes the responses against a fingerprint database. It tests TCP ISN sequence generation, IP ID patterns, TCP timestamps, window sizes, and a dozen other attributes.

`-O` builds raw packets, so it requires root. Without it, Nmap exits with *"You requested a scan type which requires root privileges."*

```bash
sudo nmap -O <target>
sudo nmap -O --osscan-guess <target>    # Aggressive guess when confidence is low
sudo nmap -O --osscan-limit <target>    # Skip hosts without an open and a closed port
sudo nmap -O --max-os-tries 1 <target>  # Fail fast instead of retrying
sudo nmap -6 -O <target>                # IPv6 uses a separate fingerprint database
```

### When It Works

- On targets with both an open and closed port visible, accuracy is high.
- Common OSes like Windows, Ubuntu, and CentOS are well-represented in the database.
- Nmap shows a confidence percentage, and anything above 90% is usually reliable.

### When It Fails

- Firewalls blocking the probes return nothing for Nmap to fingerprint.
- Windows with strict firewall profiles may not respond to probes sent to closed ports.
- Custom or lightweight Linux kernels can confuse the fingerprint engine.
- Nmap shows "OS details: Linux 2.6.32 - 3.10" when the kernel matches but the exact version is unclear.

### What Nmap Is Actually Testing

Nmap sends up to 16 probes: TCP SYN, ACK, NULL, and FIN packets, UDP probes, ICMP echo requests, and ECN-capable SYN packets. Each response is checked for:

- **Sequence prediction**: how the initial sequence number increments (random vs predictable)
- **IP ID generation**: incremental, random, or zeroed
- **TCP timestamp frequency**: 2 Hz, 100 Hz, and 200 Hz get their own result values, while the very common 1000 Hz falls through to a generic binary-logarithm branch
- **Window size and scaling**: OS-specific defaults
- **TCP options ordering**: MSS, window scale, SACK, and timestamp order varies per stack
- **Don't Fragment bit**: whether the OS sets DF in responses

## Passive Fingerprinting

Every technique above sends packets at the target. When active scanning is off-limits or would trip an IDS, `p0f` reads the same TCP/IP stack characteristics out of traffic you can already see:

```bash
sudo p0f -i eth0                  # Live capture
sudo p0f -r capture.pcap          # Offline, against an existing capture
```

It classifies traffic by window size, options ordering, and TTL, then reports the OS along with the distance in hops. It reads SYN+ACK from servers as well as SYN from clients, and also reasons about link type, MTU, and uptime.

Two caveats. The tradeoff is positioning, since you need to be on-path: a tap, a span port, or a machine the target already talks to. And p0f has been unmaintained since 3.09b in April 2016, so misidentification of current operating systems is expected rather than surprising.

For a modern counterpart, FoxIO's JA4T applies the same idea in the opposite direction. Where p0f fuzzy-matches against a list of operating systems, JA4T emits a stable fingerprint intended to be logged and pivoted on, which also surfaces proxies, load balancers, and port forwarding rather than hiding them.

## Container / VM Detection

When different ports on the same target show different OS fingerprints, virtualization is likely. You can use TTL-based traceroutes per port to confirm:

```bash
# Install lft (layered traceroute)
sudo apt install lft

# Trace to different ports
sudo lft <target>:22
sudo lft <target>:80
sudo lft <target>:2222
```

If one port's trace terminates a hop deeper than another's, the services sit behind different routing boundaries, typically a host and a container it forwards a port into.

A representative pattern: a Debian host running SSH on port 22, forwarding port 2222 to an Ubuntu container. The banners disagree, and the container sits one hop further away:

```bash
sudo lft <target>:22      # 2 hops, the host itself
sudo lft <target>:2222    # 3 hops, one boundary deeper

# Banners confirm the split
# Port 22 banner:   OpenSSH 9.2p1 Debian  (Debian 12)
# Port 2222 banner: OpenSSH 8.9p1 Ubuntu  (Ubuntu 22.04)
```

Cross-referencing the two banners against the version tables above turns "something is virtualized here" into two concrete OS versions.

The inference only runs one way, though. `lft` measures hops on your TCP connection, not application topology, so anything that terminates that connection at the host hides whatever sits behind it: a reverse proxy such as nginx, a load balancer, or Docker's default userland `docker-proxy` forwarder. A container behind any of those looks exactly like the host. Equal hop counts do not mean same host.

On **Linux hosts**, packets passed to containers or VMs typically decrement the TTL, so these differences show up. On **Windows**, Hyper-V VMs often don't decrement TTL the same way, making the same target appear to have a consistent hop count across ports.

## Automated Tools

| Tool | What It Does | Command |
| ---- | ------------ | ------- |
| **Nmap -O** | TCP/IP stack fingerprint | `sudo nmap -O <target>` |
| **Nmap -sV** | Version detection from service banners | `nmap -sV <target>` |
| **NetExec** | SMB-based Windows OS detection, modern dialects | `netexec smb <target>` |
| **smb-protocols** | Which SMB dialects a host offers | `nmap -p445 --script smb-protocols <target>` |
| **smb-os-discovery** | Windows build via SMB, needs SMBv1 | `nmap -p445 --script smb-os-discovery <target>` |
| **rdp-ntlm-info** | Exact build via NTLMSSP, null credentials | `nmap -p3389 --script rdp-ntlm-info <target>` |
| **snmpwalk** | Literal OS string via SNMP `sysDescr` | `snmpwalk -v2c -c public <target> 1.3.6.1.2.1.1.1.0` |
| **lft** | TCP traceroute per port (container detection) | `sudo lft <target>:<port>` |
| **p0f** | Fingerprints hosts whose traffic you can already see. Takes an interface, not a target | `sudo p0f -i eth0` |

## References

| Resource | Description | URL |
| -------- | ----------- | --- |
| **0xdf OS Enumeration** | OS detection cheatsheet covering versions, TTL, containers | https://0xdf.gitlab.io/cheatsheets/os/ |
| **Nmap OS Detection** | Official docs on TCP/IP fingerprinting methods | https://nmap.org/book/osdetect-methods.html |
| **Nmap -O Man Page** | OS detection usage and options | https://nmap.org/book/man-os-detection.html |
| **Nmap smb-os-discovery** | NSE script docs for SMB-based OS discovery | https://nmap.org/nsedoc/scripts/smb-os-discovery.html |
| **Nmap smb-protocols** | NSE script listing the SMB dialects a host offers | https://nmap.org/nsedoc/scripts/smb-protocols.html |
| **Nmap rdp-ntlm-info** | NSE script that leaks build version over RDP | https://nmap.org/nsedoc/scripts/rdp-ntlm-info.html |
| **NetExec** | Network service exploitation with SMB OS detection | https://www.netexec.wiki/ |
| **Subin's TTL Values** | Historical TTL reference table, published 2014 | https://subinsb.com/default-device-ttl-values/ |
| **p0f v3** | Passive OS fingerprinting tool and documentation | https://lcamtuf.coredump.cx/p0f3/ |
| **JA4T** | Modern TCP fingerprinting from FoxIO | https://blog.foxio.io/ja4t-tcp-fingerprinting |

> **Disclaimer:** This material is for authorized security testing and research only. Always obtain written permission before probing systems you do not own.
