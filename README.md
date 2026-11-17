# ARTEX vs. Mock Customer — TTP Coverage Gap Analysis

> **Hands-on study — simulated scenario.** The "mock customer" telemetry is sample
> OCSF data in an Anomali ThreatStream sandbox. ARTEX is analysed as source code in
> this repository and as described in a (simulated) FBI FLASH advisory. No live
> target was touched. This is a *defensive* exercise: mapping where a defender can
> and cannot see an ARTEX-driven intrusion.

---

## Bottom line up front (BLUF)

A mock customer whose security telemetry comes from **only two products — a
Palo Alto PAN-OS firewall and a Bluecoat web proxy** — has strong visibility at the
**two ends** of the ARTEX kill chain (inbound reconnaissance/scanning and outbound
C2/exfiltration) but is **effectively blind through the entire middle and across the
whole identity/cloud plane**: execution, persistence, privilege escalation,
credential access, lateral movement, and all cloud/SaaS/API activity.

That blind zone is exactly where ARTEX concentrates its highest-impact work. The
(simulated) FBI FLASH FLASH-20261113-001 attributes ARTEX intrusions that reach
**privileged access in under three hours**, a **supply-chain compromise of 2,250+
downstream tenants**, and **exfiltration of PII for ~67,000 individuals** — all
driven by cloud-credential abuse, trusted-relationship pivots, and application-layer
authorisation abuse (IDOR / sequential record access). **None of those three headline
outcomes would be visible in this customer's current telemetry.**

Of ~35 ATT&CK techniques the advisory attributes to ARTEX, this telemetry footprint
leaves roughly **two-thirds in a blind spot**. Closing the gap does not require
blocking ARTEX technique-by-technique; it requires adding the **four missing
telemetry planes**: endpoint/EDR, identity/Active-Directory, cloud/SaaS audit
(CloudTrail / Entra / Graph / M365), and application-layer logs.

---

## 1. Scenario and method

| Input | Source | Role in the analysis |
|---|---|---|
| Mock customer telemetry | Anomali ThreatStream, OCSF lookup table (`class_name` / `category_name` with event volumes) | Proxy for the customer's **defensive TTP coverage** — what they can detect |
| ARTEX offensive capability | This repository (Dockerfile toolchain, `agent/` worker execution model) + simulated FBI FLASH-20261113-001 ATT&CK mapping | The **offensive TTPs** a defender must cover |
| Gap | Cross-product of the two | ATT&CK techniques ARTEX runs that the customer **cannot see** |

**Coverage assumption (given by the exercise):** OCSF `class_name` / `category_name`
volume stands in for defensive strength. High event counts in a category ⇒ the
customer has mature collection and therefore detection potential there; a category
that returns **zero** events ⇒ no collection ⇒ a blind spot, regardless of any
controls that might exist but emit no telemetry.

---

## 2. Mock customer — defensive telemetry coverage (OCSF)

Pulled from the ThreatStream OCSF lookup table (aggregated `count` by
`category_name`, `class_name`):

| OCSF category | OCSF class | Event count | Source product |
|---|---|--:|---|
| Network Activity | **HTTP Activity** | **152,285** | Bluecoat Proxy |
| System Activity | Module Activity | 27,744 | PAN-OS |
| Findings | **Detection Finding** | 18,873 | PAN-OS |
| Identity & Access Management | Entity Management | 8,388 | PAN-OS |
| Findings | Security Finding | 6,206 | PAN-OS |
| Network Activity | Network Activity | 6,205 | PAN-OS |
| System Activity | Device Config State Change | 3,164 | PAN-OS |
| Identity & Access Management | Authentication | 3,064 | PAN-OS |

**Queried but returned zero events:** `Application Activity`, `Discovery`.
(The copilot's AQL filtered for six categories — Application Activity, IAM, Network
Activity, System Activity, Findings, Discovery — and only four returned data.)

### What this footprint actually means

- **Two products only: PAN-OS (perimeter firewall) and Bluecoat (web proxy).**
  Every OCSF class above is firewall- or proxy-sourced. There is **no endpoint,
  identity-provider, cloud, email, or application** telemetry feeding this lake.
- **Network Activity is the strength.** 152K HTTP-Activity events from the proxy plus
  6K firewall Network-Activity events give genuine **north–south visibility**:
  inbound scanning and, critically, **outbound connections** (including to LLM API
  endpoints and exfil destinations).
- **Findings (25K combined) are PAN-OS IPS/IDS detections** — signature-based
  coverage of known exploit and malware traffic crossing the perimeter.
- **The "IAM" and "System Activity" rows are a trap.** They look like identity and
  host coverage, but the product is **PAN-OS** — this is the *firewall's own* admin
  authentication, GlobalProtect VPN auth, and the firewall's config/module state. It
  is **not** Windows Security logs, domain-controller logs, an IdP (Entra/Okta), or
  host EDR. Treating these as "identity coverage" would badly overstate the defence.
- **`Application Activity` and `Discovery` are empty** — no app-layer request/record
  telemetry and no host/cloud discovery telemetry at all.

**Customer coverage summary:** strong **network perimeter** (ingress + egress),
signature IDS/IPS at the edge — and nothing below the network layer.

---

## 3. ARTEX — offensive TTP coverage

### 3.1 What the framework can execute (from this repo)

ARTEX is an LLM multi-agent platform (Go monolith + PostgreSQL). Its **worker**
agents execute *real* tools through a recording MITM proxy (`agent/worker.go`:
"Bash: kali tooling through the recording proxy", plus `WebFetch`, browser, and MCP
tools). The execution surface is therefore effectively a full offensive toolkit:

- **Recon / enum:** `nmap`, `nuclei`, `httpx`, `subfinder`, `katana`, `ffuf`, `bbot`
  (with `wafw00f`, `paramminer`, `lightfuzz`, `sslcert`, `gowitness`, `retirejs`),
  WHOIS, DNS utils (Dockerfile toolchain).
- **Web exploitation:** `sqlmap` (SQLi), `dalfox` (XSS), `nuclei` templates, plus
  arbitrary Bash/HTTP for SSRF, XXE, SSTI, IDOR, auth-bypass, command injection.
- **Browser-driven:** Playwright + Chromium for authenticated/JS-heavy targets; a
  browser extension replays authenticated sessions into the traffic store.
- **Autonomy:** a planner decomposes goals into intents; workers chain multi-step
  attacks and share traces; budgets/scope gates bound the run.

The design goal — autonomous goal→intent→execute→write-back loops at machine speed —
is what the advisory describes as "intrusions progressing from initial targeting to
privileged access in under three hours."

### 3.2 ATT&CK techniques attributed to ARTEX

From simulated FBI FLASH-20261113-001 ("Threat Overview of ARTEX Autonomous
Penetration Testing Framework," 13 Nov 2026), observed activity mapped to ATT&CK:

| Phase | ATT&CK techniques |
|---|---|
| **Reconnaissance** | T1595 Active Scanning · T1580 Cloud Infrastructure Discovery · T1087.004 Account Discovery: Cloud · T1069.003 Permission Groups: Cloud · T1526 Cloud Service Discovery |
| **Initial Access** | T1190 Exploit Public-Facing Application · T1078 Valid Accounts · T1133 External Remote Services · T1195 Supply Chain Compromise · T1199 Trusted Relationship · T1606.002 Forge Web Credentials: SAML · T1552.001 Unsecured Credentials: Credentials in Files |
| **Persistence** | T1505.003 Web Shell · T1078.004 Valid Accounts: Cloud · T1098.001 Account Manipulation: Additional Cloud Credentials · T1574.001 Hijack Execution Flow: DLL · T1036.005 Masquerading · T1105 Ingress Tool Transfer · T1059 Command & Scripting Interpreter |
| **Privilege Escalation** | T1134.001 Access Token Manipulation · T1098.003 Account Manipulation: Additional Cloud Roles · T1552.005 Unsecured Credentials: Cloud Instance Metadata API · T1606 / T1606.002 Forge Web Credentials · T1558.003 Steal/Forge Kerberos Tickets: Kerberoasting |
| **Internal Recon / Discovery** | T1518.001 Software Discovery: Security Software · T1555 Credentials from Password Stores · T1087.002 Account Discovery: Domain · T1552.006 Group Policy Preferences · T1059.001 PowerShell |
| **Lateral Movement** | T1550.003 Pass-the-Ticket · T1550.002 Pass-the-Hash · T1021.006 WinRM · T1557.001 AiTM: LLMNR/NBT-NS Poisoning & SMB Relay |
| **Collection / Exfil Prep** | T1114.002 Email Collection: Remote · T1555.006 Cloud Secrets Management Stores · T1530 Data from Cloud Storage · T1005 Data from Local System · T1074.001/.002 Data Staged |
| **Command & Control** | T1090 / T1090.003 Proxy (Multi-hop) · T1572 Protocol Tunneling · T1071.001 Application Layer Protocol: Web Protocols |

---

## 4. Gap analysis — ARTEX TTPs × customer detectability

Verdict key:
- 🟩 **COVERED** — technique is network-observable and the customer has the telemetry.
- 🟨 **PARTIAL** — some edge signal exists, but the detection is incomplete or
  depends on placement (e.g. inline inbound, internal segmentation).
- 🟥 **BLIND** — detection requires a telemetry plane the customer does not collect.

| Technique | Telemetry needed to detect | Present? | Verdict |
|---|---|---|---|
| T1595 Active Scanning | Network / proxy / IDS | Bluecoat HTTP + PAN-OS Net + Findings | 🟩 COVERED |
| T1071.001 Web-protocol C2 (LLM API calls) | Egress proxy/firewall | Bluecoat HTTP + PAN-OS | 🟩 COVERED |
| T1090/.003 Proxy / multi-hop C2 | Egress | Bluecoat + PAN-OS | 🟩 COVERED |
| Exfil over HTTPS (to webhook.site etc.) | Egress volume/destination | Bluecoat HTTP | 🟩 COVERED |
| T1572 Protocol Tunneling (Chisel/SoftEther) | Egress anomaly | Proxy/firewall | 🟨 PARTIAL |
| T1190 Exploit Public-Facing App | Inline inbound IDS + app logs | PAN-OS Findings / Bluecoat (network layer only) | 🟨 PARTIAL |
| T1133 External Remote Services | VPN/firewall auth | PAN-OS GlobalProtect auth | 🟨 PARTIAL |
| T1078 Valid Accounts | IdP / app / cloud auth | PAN-OS VPN auth only | 🟨 PARTIAL |
| T1105 Ingress Tool Transfer | Network download + host | Download visible at proxy; host side not | 🟨 PARTIAL |
| T1074.002 Remote Data Staging | Network / host | Network portion only | 🟨 PARTIAL |
| T1021.006 WinRM (lateral) | East-west network + host | Only if PAN-OS segments internally | 🟨 PARTIAL |
| T1505.003 Web Shell | Web-server file/app logs | — | 🟥 BLIND |
| T1059 / T1059.001 Command/PowerShell | Endpoint/EDR | — | 🟥 BLIND |
| T1518.001 Security Software Discovery | Endpoint/EDR | — | 🟥 BLIND |
| T1134.001 Access Token Manipulation | Endpoint/cloud | — | 🟥 BLIND |
| T1574.001 DLL Hijack | Endpoint/EDR | — | 🟥 BLIND |
| T1036.005 Masquerading | Endpoint/EDR | — | 🟥 BLIND |
| T1005 Data from Local System | Endpoint/EDR | — | 🟥 BLIND |
| T1555 / T1552.006 Credential/GPP theft | Endpoint/DC | — | 🟥 BLIND |
| T1087.002 Domain Account Discovery | DC / Windows logs | — | 🟥 BLIND |
| T1558.003 Kerberoasting | DC logs | — | 🟥 BLIND |
| T1550.002 Pass-the-Hash | DC / EDR | — | 🟥 BLIND |
| T1550.003 Pass-the-Ticket | DC / EDR | — | 🟥 BLIND |
| T1557.001 LLMNR/NBT-NS + SMB Relay | Host / L2 network | — | 🟥 BLIND |
| T1580 Cloud Infra Discovery | Cloud API audit | — | 🟥 BLIND |
| T1526 Cloud Service Discovery | Cloud API audit | — | 🟥 BLIND |
| T1087.004 / T1069.003 Cloud account/group discovery | Cloud / IdP audit | — | 🟥 BLIND |
| T1078.004 Valid Accounts: Cloud | CloudTrail / Entra sign-in | — | 🟥 BLIND |
| T1098.001/.003 Cloud credential/role manipulation | Cloud / Entra audit | — | 🟥 BLIND |
| T1552.005 Cloud Metadata API | Cloud / host | — | 🟥 BLIND |
| T1606 / T1606.002 Forge Web Creds / SAML | IdP logs | — | 🟥 BLIND |
| T1195 Supply Chain Compromise | Cloud / vendor / CI-CD | — | 🟥 BLIND |
| T1199 Trusted Relationship | Cloud federation / Graph | — | 🟥 BLIND |
| T1530 Data from Cloud Storage | Cloud storage audit | — | 🟥 BLIND |
| T1555.006 Cloud Secrets Stores | Cloud audit | — | 🟥 BLIND |
| T1114.002 Remote Email Collection | M365 / mail audit | — | 🟥 BLIND |
| T1552.001 Credentials in Files | Host / repo / secret scan | — | 🟥 BLIND |

**Tally:** 🟩 4 covered · 🟨 7 partial · 🟥 ~26 blind.

### The shape of the gap

```
ARTEX kill chain:   Recon → InitAccess → Persist → PrivEsc → CredAccess → Lateral → Collect → C2/Exfil
Customer sees:      🟩🟨        🟨          🟥         🟥          🟥         🟥/🟨      🟥         🟩
                    └── edge ──┘      └──────────── blind middle ────────────┘      └─ edge ─┘
```

Two structural blind planes amplify this:

1. **No endpoint plane (EDR).** Everything ARTEX does *on a host* — web shells, RAT
   installs (WISP/vshell/AdaptixC2), PowerShell enumeration, token theft, local
   staging — is invisible. The advisory notes some lateral movement was "blocked by
   endpoint protection" at victims; **this customer has no endpoint telemetry at
   all**, so it would neither block nor see it.
2. **No cloud/identity plane.** The advisory's two worst outcomes — the ConnectWise
   supply-chain pivot (Graph API, service-principal abuse, SAML forgery) and the
   67K-record PII theft (application IDOR + sequential record access) — live entirely
   in **cloud audit** and **application** telemetry. Both OCSF categories that would
   carry them (`Application Activity`, cloud audit classes) are **empty here**.

The one genuinely strong defence — egress visibility — is also the advisory's most
actionable detection: **outbound calls to `api.anthropic.com`, `api.deepseek.com`,
`open.bigmodel.cn`, `api.x.ai`** and high-frequency sequential enumeration are
observable at Bluecoat/PAN-OS today. That is the gap the customer can exploit
*immediately*, while the deeper planes are built out.

---

## 5. Recommendations — close the gap by telemetry plane

Ordered by impact against ARTEX's actual kill chain, not by effort.

1. **Add an endpoint/EDR plane (highest impact).** Onboard EDR telemetry (OCSF
   Process Activity, File System Activity, Module Activity *from hosts*). This single
   plane converts ~12 BLIND techniques to detectable: web shells, PowerShell, token
   manipulation, local staging, RAT installs, security-software discovery.
2. **Add cloud/SaaS audit.** Ingest CloudTrail, Entra ID sign-in + audit, Microsoft
   Graph, and M365 audit (OCSF IAM + API/Cloud classes from *real IdP/cloud*, not the
   firewall). Covers the entire cloud kill chain and the supply-chain scenario. Alert
   on service-principal credential additions, consent grants, and app-only activity.
3. **Add application-layer logs.** Populate OCSF `Application Activity`: per-session
   record-access counts, sequential-lookup patterns, auth decisions. Directly targets
   the IDOR / mass-PII-read scenario. Enforce server-side authorisation and rate/
   recipient limits on partner and employee portals.
4. **Add domain-controller / Windows Security logs.** Covers Kerberoasting, PtH/PtT,
   domain account discovery, LLMNR/SMB relay, GPP credential theft.
5. **Exploit the strength you have now (do today).** On Bluecoat/PAN-OS egress:
   alert on outbound connections to LLM API endpoints and unfamiliar LLM proxies/
   resellers; alert on high-frequency sequential enumeration against login/search
   endpoints; alert on structured-data outbound transfers to unapproved destinations.
   These are high-signal ARTEX tells and need **no new data source**.
6. **Correct the telemetry map.** Stop counting PAN-OS-sourced "IAM" and "System
   Activity" as identity/host coverage in posture reporting — they are firewall
   self-telemetry and create a false sense of coverage.

---

## 6. Caveats

- `class_name`/`category_name` volume is a *proxy* for detection capability, as the
  exercise specifies. High volume means collection exists, not that a tuned detection
  fires. Low/zero volume is the more reliable signal — it means the plane is absent.
- The ARTEX TTP set is taken from a **simulated** advisory for this study; real-world
  ARTEX behaviour depends on operator goals, scope, and the model driving it.
- "PARTIAL" verdicts depend on deployment placement (inline inbound inspection,
  internal segmentation, TLS inspection at the proxy). Verify these before relying on
  edge visibility for inbound exploitation or lateral movement.

---

## 7. Sources

- **OCSF customer telemetry:** Anomali ThreatStream OCSF lookup table (sandbox),
  aggregated by `category_name` / `class_name`.
- **ARTEX framework:** this repository — `Dockerfile` (toolchain), `agent/worker.go`,
  `agent/tools.go`, `agent/toolcatalog.go`, `README.md`.
- **ARTEX TTPs (simulated):** FBI FLASH-20261113-001, "Threat Overview of ARTEX
  Autonomous Penetration Testing Framework," TLP:CLEAR, 13 Nov 2026
  (`https://www.ic3.gov/CSA/2026/261113.pdf`).
- **Framework:** MITRE ATT&CK Enterprise; OCSF schema (category/class taxonomy).
