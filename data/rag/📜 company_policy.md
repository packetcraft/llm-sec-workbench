# Acme Corp — Employee Policy Manual

**Version:** 3.1 | **Effective Date:** January 1, 2026 | **Owner:** Legal & Compliance

---

## Section 1: Data Classification

Acme Corp classifies all company data into four tiers:

- **Tier 1 — Public:** Marketing materials, press releases, and published product specs. No access controls required.
- **Tier 2 — Internal:** Internal memos, project roadmaps, and operational procedures. Accessible to all employees on the corporate network.
- **Tier 3 — Confidential:** Customer PII, financial forecasts, contracts, and HR records. Requires role-based access and encryption at rest.
- **Tier 4 — Restricted:** Trade secrets, M&A plans, source code repositories, and board communications. Accessible only by named individuals with written VP approval.

Employees who handle Tier 3 or Tier 4 data must complete the annual Data Stewardship Certification by March 31 each year. Failure to certify results in revocation of access privileges until the training is completed.

---

## Section 2: Acceptable Use of Technology

Company-issued devices and network resources are provided for business use. Incidental personal use is permitted provided it does not:

- Interfere with job performance
- Consume excessive bandwidth (streaming media during business hours is prohibited)
- Violate any other provision of this policy

**Prohibited activities:**

- Installing unlicensed software or browser extensions not on the approved list
- Connecting to public Wi-Fi without an active VPN session
- Sharing credentials or MFA tokens with colleagues, contractors, or third parties
- Accessing the dark web or known malicious domains from company infrastructure

All endpoint devices are managed via Acme's MDM solution. Employees consent to remote wipe in the event of loss, theft, or separation from the company.

---

## Section 3: Email and Communication Security

All email sent from @acme-retail.com addresses is subject to retention and may be reviewed for compliance purposes.

Employees must not:
- Send Tier 3 or Tier 4 data via unencrypted email
- Use personal email (Gmail, Outlook.com, Yahoo, etc.) for business correspondence
- Click links in unsolicited email without verifying the sender via a second channel

**Phishing response:** If you receive a suspected phishing email, forward it as an attachment to phishing@acme-retail.com and delete the original. Do not reply to the sender.

Acme uses Proofpoint for inbound email filtering. Quarantined messages are released by IT Security upon request.

---

## Section 4: Remote Work and VPN Policy

Employees working remotely must connect via GlobalProtect VPN before accessing any internal system. Split-tunnel VPN is not permitted; all traffic must route through Acme's corporate gateway.

Home office requirements:
- Router firmware must be current (check every 90 days)
- A dedicated work area is strongly recommended; screen privacy filters are required when working in public spaces
- Acme-issued hardware must be stored securely when not in use (locked office or cable-locked to desk)

Contractors and vendors receive time-limited VPN credentials valid for the duration of their engagement. IT Security must be notified within 24 hours of contract completion to deactivate credentials.

---

## Section 5: Software and Patch Management

The IT team pushes operating system and application patches on the second Tuesday of each month ("Patch Tuesday"). Critical zero-day patches are deployed within 48 hours of vendor release. Employees may not defer patches beyond the 14-day grace period.

**Approved software list:** The current approved software catalog is maintained at the IT portal (it.acme-retail.internal/catalog). Requests for new software require manager approval and a 5-business-day security review.

Unapproved AI tools — including browser-based LLM chatbots — may not be used to process Tier 3 or Tier 4 data. Approved AI tools are listed in the AI Governance Register maintained by the CISO's office.

---

## Section 6: Incident Reporting

All suspected security incidents must be reported to security@acme-retail.com within 1 hour of discovery. Incidents include:

- Suspected malware infection or unusual device behavior
- Loss or theft of a company device
- Unauthorized access to an account or system
- Accidental disclosure of Tier 3/4 data to unauthorized parties

The Security Operations team will open a ticket and contact the reporting employee within 2 hours during business hours. A post-incident review is conducted for all Severity 1 and Severity 2 events.

Employees who report incidents in good faith are protected from retaliation. Deliberate non-reporting of known incidents is grounds for disciplinary action up to and including termination.

---

## Section 7: Travel and Expense Policy

**Domestic travel:** Airfare must be booked at least 14 days in advance. Coach class is standard; business class is permitted for flights over 6 hours with VP approval.

**International travel:** Employees traveling to Tier 1 risk countries (as defined by the Corporate Travel Risk Register) must notify the Security team before departure. Loaner laptops with clean images are provided for travel to China, Russia, and other high-risk destinations. Personal devices must not be connected to hotel networks in those regions.

**Expense reporting:** All expenses must be submitted within 30 days of the transaction via Concur. Receipts are required for any single purchase over $25.

---

## Section 8: Violations and Enforcement

Violations of this policy are subject to disciplinary action commensurate with severity:

| Severity | Example | Consequence |
|---|---|---|
| Minor | Missed patch deadline | Written warning |
| Moderate | Sending Tier 3 data via personal email | Formal reprimand + retraining |
| Major | Sharing credentials with a third party | Suspension pending investigation |
| Critical | Deliberate data exfiltration | Immediate termination + legal referral |

Questions about this policy should be directed to compliance@acme-retail.com.
