# CyberGuard Inc — Threat Intelligence Report

**Report ID:** TI-2026-0042 | **Classification:** TLP:AMBER | **Date:** April 2026
**Prepared by:** CyberGuard Threat Research Unit | **Distribution:** SOC L2+, CISO

---

## Executive Summary

This report covers active threat campaigns observed in Q1 2026 targeting mid-market enterprise organizations in the financial services, healthcare, and critical infrastructure sectors. Three primary threat clusters are detailed: a financially motivated ransomware-as-a-service (RaaS) operation, a state-sponsored espionage group, and a newly identified supply chain attack campaign.

Organizations using VPN appliances from Fortinet, Palo Alto, and Ivanti should patch immediately per the CVEs listed in Section 4.

---

## Section 1: Threat Actor Profile — APT-COBALT-7

**Alias:** Cobalt Typhoon, UNC-3887, TEMP.Ariel
**Origin:** Assessed with high confidence as nation-state aligned (East Asia)
**Primary Motivation:** Espionage — intellectual property and government contract data theft
**Active Since:** 2021

**TTPs (MITRE ATT&CK):**
- T1190 — Exploit Public-Facing Application (initial access via VPN appliance 0-days)
- T1078 — Valid Accounts (credential harvesting via spear-phishing and LDAP enumeration)
- T1105 — Ingress Tool Transfer (staging tools via compromised S3 buckets)
- T1071.001 — Application Layer Protocol: Web Protocols (C2 over HTTPS to legitimate-looking domains)
- T1560.001 — Archive via Utility (7-Zip and custom packer for exfiltration staging)

**Recent Activity:** APT-COBALT-7 was observed in February 2026 targeting defense contractors with active DoD contracts. Initial access was achieved through a zero-day in Ivanti Connect Secure (CVE-2026-11492, CVSS 9.8). After gaining a foothold, the group moved laterally using stolen Kerberos tickets and deployed a novel implant called SILENTRAIL.

**SILENTRAIL Indicators:**
- Process: `svchost.exe` spawning `conhost.exe` with unusual parent chain
- Registry key: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList\SVC_HELPR`
- C2 domains: `analytics-cdn.msedgeservices[.]net`, `telemetry-api.windowsupdate-cdn[.]com`
- File hash (SHA-256): `a3f8c2d147b9e061f4520a8c3b7d2e9f1a6b4c8d0e2f7a9b3c5d1e4f6a8b0c2`

---

## Section 2: Threat Actor Profile — BLACKVOID RaaS

**Alias:** BlackVoid, BV-Gang, Darknet Collective #14
**Origin:** Eastern Europe (criminal, financially motivated)
**Target Sectors:** Healthcare, manufacturing, logistics
**Average Ransom Demand:** $2.1M (Q1 2026 median)

**Attack Chain:**
1. Phishing email with macro-enabled Office document or HTML smuggling
2. Cobalt Strike beacon deployed via PowerShell download cradle
3. Lateral movement using BloodHound/SharpHound for AD enumeration
4. Exfiltration of data (avg. 180 GB) to attacker-controlled SFTP before encryption
5. Deployment of BLACKVOID encryptor using PsExec or GPO abuse

**Encryptor Technical Details:**
- Targets: `*.docx, *.xlsx, *.pdf, *.sql, *.bak, *.vmdk, *.vhd`
- Excluded: `C:\Windows\`, `C:\Program Files\`
- Ransom note: `BLACKVOID_README_[timestamp].txt` dropped in each directory
- Encrypted file extension: `.bv2026`
- Persistence: Scheduled task `MicrosoftEdgeUpdateTaskMachineCore` (disguised)

**IOC File Hashes (SHA-256):**
- Dropper: `7b2e9f4c1a8d3f6b0e5c2a9d4f7b1e3c8a2d5f9b0c4e7a1d6f3b9c2e8a5d0f4b`
- Beacon: `3c8a1d7f4b2e9c0f5a3d8b6e1c9f4a2b7d0e5c3a8f1b4d9e2c7a0f3b6d1e8c5a`
- Encryptor: `9f1b4e7c2a8d3f0b5e9c2a7f4d1b8e3c6a0f5d2b9e4c7a1f8d3b6e0c5a2f9b4d`

---

## Section 3: Supply Chain Campaign — NPM Typosquatting Wave

In March 2026, CyberGuard observed a coordinated npm typosquatting campaign targeting JavaScript developers. At least 47 malicious packages were published mimicking popular libraries:

| Malicious Package | Impersonates | Downloads (before takedown) |
|---|---|---|
| `lodash-utils-pro` | `lodash` | 14,200 |
| `axios-request-helper` | `axios` | 8,900 |
| `react-dom-extended` | `react-dom` | 22,100 |
| `express-middleware-core` | `express` | 6,400 |

**Payload behavior:** When installed, the packages execute a postinstall script that:
1. Collects environment variables (including `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, `NPM_TOKEN`)
2. Exfiltrates to `https://telemetry.npmstats-cdn[.]com/collect`
3. Installs a persistent backdoor in `~/.npm/_cacache/`

**Detection:** Audit your `package-lock.json` for unexpected indirect dependencies. Use `npm audit` and cross-reference with the malicious package hashes in Appendix B.

---

## Section 4: Critical CVEs Requiring Immediate Patching

| CVE | CVSS | Product | Description |
|---|---|---|---|
| CVE-2026-11492 | 9.8 | Ivanti Connect Secure ≤ 22.7R2 | Unauthenticated RCE via path traversal in web API |
| CVE-2026-09871 | 9.1 | Fortinet FortiOS ≤ 7.4.3 | Heap overflow in SSL-VPN daemon |
| CVE-2026-08234 | 8.6 | Palo Alto PAN-OS ≤ 11.1.2 | Authentication bypass in GlobalProtect portal |
| CVE-2025-48219 | 7.8 | Microsoft Exchange Server 2019 | SSRF leading to NTLM relay |

All CVEs above have confirmed public proof-of-concept exploit code. Patch or mitigate within 24 hours.

---

## Section 5: Recommendations

1. **Patch immediately** all VPN and perimeter appliances listed in Section 4.
2. **Enable MFA** on all remote access services; VPN credentials alone are insufficient.
3. **Audit npm/pip dependencies** in CI pipelines for typosquatted packages; pin dependency hashes.
4. **Deploy EDR** with behavioral detection for Cobalt Strike beacon patterns (process injection, named pipe usage).
5. **Segment backups** — maintain at least one offline, air-gapped backup copy. BLACKVOID specifically targets network-accessible backup systems.
6. **Monitor C2 domains** listed in Section 1; block at DNS and proxy layer.
7. **Threat hunt** for SILENTRAIL IOCs in Windows Event Logs (Event IDs 4624, 4625, 4688 with suspicious parent-child process chains).

---

## Appendix A: YARA Rule — SILENTRAIL

```yara
rule SILENTRAIL_Implant {
    meta:
        author = "CyberGuard TRU"
        description = "Detects SILENTRAIL implant used by APT-COBALT-7"
        date = "2026-03"
    strings:
        $s1 = "SVC_HELPR" ascii wide
        $s2 = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF }
        $s3 = "analytics-cdn.msedgeservices" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}
```

*This report is classified TLP:AMBER. Do not distribute beyond the authorized recipient list without CISO approval.*
