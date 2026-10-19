# Notifications

## Critical: case C — umpub-14297

[Critical] Case C: umpub-14297
ALERT: Unprotected Asset Detected

Asset AST-40867 (UMPUB-14297) is externally visible without EDR protection.

Ledger observed: UMPUB-14297 at 192.0.2.16 (instance i-d01ee46c) owned by Sales department, sal.user4245.

ASM observed: 192.0.2.16 reachable as umpub-14297.example.com with port 22 open and vulnerability score 7.4.

EDR observed: No agent detected on this asset.

The asset is in inventory yet lacks endpoint protection despite external visibility.

Recommended: Deploy EDR agent immediately and restrict public SSH access if not essential.

Why combined: LLM judged umpub-14297 and umpub-14297 to be the same device: Hostname matches (case-insensitive), IP matches exactly (192.0.2.16), asset_id and department present

## Critical: case C — umpub-2a2cc

[Critical] Case C: umpub-2a2cc
ALERT: Unprotected Asset Detected

Ledger observed: Asset AST-28677, hostname UMPUB-2A2CC, IP 192.0.2.2, FQDN umpub-2a2cc.corp.example.local, owned by Engineering (eng.user9309).

ASM observed: Public IP 192.0.2.2, open port 8443, discovered 2024-01-19T20:38:00Z, vulnerability score 8.7.

EDR: No agent detected.

Asset AST-28677 is classified as case C—internally tracked and externally visible but completely unmonitored.

Recommended Actions:
1. Deploy EDR agent to UMPUB-2A2CC immediately
2. Remediate vulnerability (score 8.7) on port 8443

Why combined: LLM judged (a record without a hostname) and umpub-2a2cc to be the same device: IP (192.0.2.2) matches between ASM and ledger; ASM missing domain is not contradictory

## Critical: case C — umpub-33abf

[Critical] Case C: umpub-33abf
**Asset Unprotected Despite External Visibility**

Asset AST-38206 (UMPUB-33ABF, 10.11.0.30) identified as case C: in internal ledger and externally visible, but without EDR agent protection.

**Observations:**
- **Ledger:** Asset AST-38206, hostname UMPUB-33ABF, IP 10.11.0.30, FQDN umpub-33abf.corp.example.local, owned by HR department
- **ASM:** Domains umpub-33abf.example.com (discovered 2024-01-24) and legacy-umpub-33abf.example.com (discovered 2019-08-28) expose ports 22, 443, 8080; vulnerability score 4.9
- **EDR:** No agent installed

**Risk:** Unmonitored external-facing asset lacks threat detection capability.

**Recommended Actions:**
1. Deploy EDR agent to AST-38206 immediately
2. Restrict external access to ports 22, 443, 8080

Why combined: LLM judged umpub-33abf and umpub-33abf to be the same device: Hostname matches exactly (case-insensitive), asset_id present, missing IP in ASM is acceptable; LLM judged umpub-33abf and legacy-umpub-33abf to be the same device: Same domain base (umpub-33abf) with legacy prefix. Identical open ports (22,443,8080) and vulnerability score (4.9). 5-year gap indicates version progression. Strong evidence despite time separation.

## Critical: case C — umpub-3d48b

[Critical] Case C: umpub-3d48b
ASM discovered domain umpub-3d48b.example.com on 2024-01-22T19:17:00Z with open port 21 and vulnerability score 4.3. Ledger records asset AST-60449 (hostname UMPUB-3D48B, IP 10.4.9.149, FQDN umpub-3d48b.corp.example.local) owned by IT department (it.user2037). The asset is externally visible and registered in inventory but lacks EDR agent coverage, leaving it unmonitored. FTP exposure on port 21 presents additional security risk.

**Recommended actions:**
1. Deploy EDR agent to 10.4.9.149 immediately
2. Investigate and restrict open port 21 access

Why combined: LLM judged umpub-3d48b and umpub-3d48b to be the same device: Hostname/domain (umpub-3d48b) match exactly between ASM and ledger; ASM lacking public IP is expected for internal assets

## Critical: case C — umpub-57496

[Critical] Case C: umpub-57496
ALERT: Unprotected Asset Detected

Ledger records asset AST-26359 (UMPUB-57496.vm, 192.0.2.6, instance i-603a6980) owned by Operations. ASM independently discovered 192.0.2.6 externally visible on 2024-01-08T00:41:00Z with open ports 21, 22 and vulnerability score 0.4. No EDR agent is deployed on this asset.

Recommended actions:
1. Deploy EDR agent to UMPUB-57496.vm immediately
2. Review and restrict access to ports 21, 22

Why combined: LLM judged (a record without a hostname) and umpub-57496 to be the same device: IP (192.0.2.6) matches between ASM and ledger; ASM missing domain is not contradictory, open_ports align with database/FTP usage

## Critical: case C — umpub-5c52a

[Critical] Case C: umpub-5c52a
Ledger documents asset AST-78756 (UMPUB-5C52A, 10.17.0.63, umpub-5c52a.corp.example.local) owned by Engineering. ASM discovered external domain "umpub-5c52a.example.com" on 2024-01-14T04:23:00Z with open ports 21, 3389, 8443 and vulnerability score 8.5. EDR shows no agent protection.

Risk: Asset is internally documented and externally visible but unprotected.

Recommended actions:
1. Deploy EDR agent immediately to AST-78756
2. Restrict access to ports 21, 3389, 8443; address vulnerability score 8.5

Why combined: LLM judged umpub-5c52a and umpub-5c52a to be the same device: Hostname/domain (umpub-5c52a) match exactly between ASM and ledger; ASM lacks public_ip field which is expected for internal assets

## Critical: case C — umpub-a60de-x

[Critical] Case C: umpub-a60de-x
ALERT: Unprotected Asset Missing EDR Coverage

Ledger records asset AST-81170 (UMPUB-A60DE-x / umpub-a60de.corp.example.local, owned by Finance/fin.user9298). ASM independently discovered the same asset externally visible at 203.0.114.223 (domain: umpub-a60de.example.com.vm) on 2024-01-20T00:48:00Z with open ports 22, 80, 3389 and vulnerability score 0.6. However, no EDR agent is present on this asset.

Recommended Actions:
1. Deploy EDR agent to AST-81170 immediately.
2. Review access controls on open ports 22, 80, 3389 and assess vulnerability score 0.6.

Why combined: LLM judged umpub-a60de and umpub-a60de-x to be the same device: Same hostname base (umpub-a60de). Domain names match at base (internal corp.example.local vs external example.com.vm indicates DNS variants). Owner department (Finance) provides context. Minor name suffix (-x) consistent with naming modifications.

## Critical: case C — umpub-aa422

[Critical] Case C: umpub-aa422
ALERT: Unprotected Asset

Ledger contains asset UMPUB-AA422 (AST-81754) at 192.0.2.7, owned by Sales department. ASM externally detected this IP with domain umpub-aa422.example.com, open ports 3306, 8080, and critical vulnerability score 9.1. ASM also identified legacy-umpub-aa422.example.com at 192.0.2.25 (discovered 2019-04-15T13:11:00Z) with matching open ports 3306, 8080 and vuln_score 9.1.

The asset is in the ledger and externally visible but lacks EDR agent protection.

Recommended actions: (1) Deploy EDR agent to 192.0.2.7 immediately. (2) Remediate critical vulnerabilities on ports 3306 and 8080.

Why combined: LLM judged umpub-aa422 and umpub-aa422 to be the same device: Hostname matches (case-insensitive), IP matches exactly (192.0.2.7), asset_id present; LLM judged umpub-aa422 and legacy-umpub-aa422 to be the same device: Matching hostname (umpub-aa422), identical open ports (3306,8080) and vulnerability score (9.1). Different IPs (192.0.2.7 vs 192.0.2.25) in same subnet, consistent with DHCP reassignment. 'legacy-' prefix indicates historical record of same asset.

## Critical: case D — shdpub-0dab3

[Critical] Case D: shdpub-0dab3
SHADOW IT ASSET ALERT

ASM discovered externally visible asset at public IP 203.0.114.41 (domain shdpub-0dab3.example.com-x) on 2024-01-04, with open ports 21 and 8443. EDR subsequently identified internal asset shdpub-0dab3 (10.11.0.71) on 2024-01-15, communicating with internal peer 10.5.6.86 (peer-68557.corp.example.local). This asset is not in the inventory ledger, indicating unauthorized deployment. The combination of external visibility with open ports and internal network communication presents elevated risk.

Recommended actions: (1) Immediately identify asset owner and business justification. (2) Isolate or remove asset from network if not authorized.

Why combined: LLM judged shdpub-0dab3 and shdpub-0dab3 to be the same device: Matching hostname (shdpub-0dab3; '-x' suffix in ASM domain appears to be a formatting artifact). Both from January 2024. Public IP (203.0.114.41) in ASM and private IP (10.11.0.71) in EDR consistent with NAT pattern described in background.

## Critical: case D — shdpub-2edd4

[Critical] Case D: shdpub-2edd4
SHADOW IT ALERT - Case D: Externally Visible, Not in Ledger

ASM identified host "shdpub-2edd4.example.com.vm" (192.0.2.11) discovered 2024-01-11T01:27:00Z with open port 8443 and vulnerability score 0.1. EDR confirms asset "shdpub-2edd4" (192.0.2.11) communicating with internal peer "peer-25957.corp.example.local" (10.3.1.215). This host is externally visible but absent from the asset ledger, indicating shadow IT with internal network access.

Recommended Actions:
1. Immediately inventory and authenticate this asset
2. Assess connectivity to internal resources and apply network segmentation if unauthorized

Why combined: LLM judged shdpub-2edd4 and shdpub-2edd4 to be the same device: IP (192.0.2.11) and hostname (shdpub-2edd4) match exactly between ASM and EDR records

## Critical: case D — shdpub-61795

[Critical] Case D: shdpub-61795
Unauthorized asset detected. EDR observed "shdpub-61795" at 10.14.6.156 (2024-01-06T22:33:00Z) and "shdpub-61795-legacy" at 10.14.6.157 (2019-05-26T12:00:00Z), both connecting to 10.1.3.204. ASM identified external exposure: domain shdpub-61795.example.com on public IP 203.0.114.32 with ports 22 and 80 open (discovered 2024-01-20T00:00:00Z). Asset is absent from IT ledger.

Recommended actions: 1) Immediately determine asset ownership and business justification. 2) Restrict or close external exposure on ports 22 and 80.

Why combined: LLM judged shdpub-61795 and shdpub-61795 to be the same device: Hostname matches (shdpub-61795), IPs differ (203.0.114.32 vs 10.14.6.156) consistent with NAT/external IP scenario described in background; LLM judged shdpub-61795 and shdpub-61795-legacy to be the same device: Matching hostname core (shdpub-61795), sequential private IPs in same subnet (10.14.6.156 vs 10.14.6.157), identical destination peer (10.1.3.204). 'legacy-' suffix and temporal gap (2019 vs 2024) indicate historical record of same asset.

## Critical: case D — shdpub-8ac57-legacy

[Critical] Case D: shdpub-8ac57-legacy
ASM identified two unmanaged external assets: legacy-shdpub-8ac57.example.com (192.0.2.24, port 21, vulnerability score 8.5, discovered 2019-02-03) and shdpub-8ac57.example.com (192.0.2.4, port 21, vulnerability score 8.5, discovered 2024-01-09). EDR confirmed these systems as shdpub-8ac57-legacy and shdpub-8ac57, both connecting internally to 10.8.2.61 (peer-90248.corp.example.local). Assets are absent from the ledger.

Recommended actions: Immediately investigate deployment ownership and purpose, then remediate exposed FTP services or decommission systems.

Why combined: LLM judged shdpub-8ac57 and shdpub-8ac57 to be the same device: Hostname matches (shdpub-8ac57), IP matches exactly (192.0.2.4), open ports listed provide additional support; LLM judged legacy-shdpub-8ac57 and shdpub-8ac57-legacy to be the same device: IP (192.0.2.24) and normalized hostname (shdpub-8ac57) match; legacy/shdpub prefix variations are common naming conventions; LLM judged shdpub-8ac57 and legacy-shdpub-8ac57/shdpub-8ac57-legacy to be the same device: Same hostname base (shdpub-8ac57). Identical open ports (21) and vulnerability score (8.5). Same destination peer (peer-90248). Legacy prefix and 5-year gap (2019 vs 2024) indicate old vs new version of same asset.

## Critical: case D — shdpub-f0c02

[Critical] Case D: shdpub-f0c02
Shadow IT Alert - High Risk

ASM discovered asset at 192.0.2.19 (shdpub-f0c02.example.com) on 2024-01-07T21:20:00Z with open ports 22, 8443 and vulnerability score 6.1. EDR observed this same IP on host shdpub-f0c02.vm communicating to peer-91579.corp.example.local. The asset is absent from the IT ledger. This externally exposed system without ledger records poses high risk.

Recommended Actions: (1) Verify asset ownership and authorization immediately; (2) Isolate and perform security assessment.

Why combined: LLM judged shdpub-f0c02 and shdpub-f0c02 to be the same device: Hostname matches (case-insensitive, ignoring .vm suffix), IP matches exactly (192.0.2.19)

## Critical: case D — shdpub-f90f3

[Critical] Case D: shdpub-f90f3
**SHADOW IT ALERT - HIGH RISK**

Asset-reconciliation identified an unapproved system classified as externally visible but absent from the ledger:

- **ASM**: Discovered external domain shdpub-f90f3.example.com (192.0.2.3) on 2024-01-02 with vulnerability score 8.4
- **EDR**: Detected active system shdpub-f90f3.vm (192.0.2.3) on 2024-01-28, communicating internally with peer-00009.corp.example.local
- **Ledger**: No matching approved asset

This represents shadow IT with external exposure and active internal network communication, indicating unauthorized infrastructure.

**Recommended actions:**
1. Immediately investigate asset ownership and business justification
2. Isolate or remediate depending on approval status

Why combined: LLM judged shdpub-f90f3 and shdpub-f90f3 to be the same device: IP (192.0.2.3) and hostname (shdpub-f90f3) match; .vm suffix variation is typical for hypervisor guests

## Critical: case G — 192.0.2.10

[Critical] Case G: 192.0.2.10 — Externally visible only, unknown internally: typical shadow IT
- asm: public_ip=192.0.2.10, discovered_at=2024-01-22T21:34:00Z, open_ports=3306,8443, vuln_score=8.0
Recommended: Identify who runs this Internet-facing service. If nobody owns it, take it down; otherwise register it and install EDR.

Why combined: single record

## Critical: case G — 192.0.2.21

[Critical] Case G: 192.0.2.21
**SHADOW IT ALERT – Unmanaged External Asset**

ASM discovered IP address 192.0.2.21 on 2024-01-18T09:36:00Z with vulnerability score 4.0. This asset is visible externally but has no corresponding record in EDR or asset ledger, indicating unknown shadow IT infrastructure outside organizational control.

The untracked external presence creates potential security and compliance risks.

**Recommended Actions:**
1. Identify the asset owner and determine legitimate business purpose
2. Assess whether to onboard into inventory or decommission

Why combined: single record

## Critical: case G — 203.0.113.67

[Critical] Case G: 203.0.113.67
ALERT: Shadow IT Asset Detected

ASM discovered external asset at 203.0.113.67 on 2024-01-25T16:53:00Z with open ports 22, 443, 3389 and vulnerability score 7.1. No associated domain. No matching records in internal systems (ledger/EDR), confirming shadow IT classification.

Recommended actions:
1. Immediately investigate asset ownership and business purpose
2. Determine authorization status and remediate vulnerabilities

Why combined: single record

## Critical: case G — ext-0b13f

[Critical] Case G: ext-0b13f
ASM discovered domain ext-0b13f.example.com on 2024-01-06 at 09:52:00Z with open ports 443 and 8443 and vulnerability score 2.1. This asset is externally visible but has no corresponding records in internal ledger or EDR systems, indicating potential shadow IT.

Recommended actions:
1. Investigate ownership and purpose of ext-0b13f.example.com
2. Scan internally for related systems and verify authorization status

Why combined: single record

## Critical: case G — ext-0baa2

[Critical] Case G: ext-0baa2
**SHADOW IT ALERT: Unmanaged External Assets**

ASM discovered two assets with high vulnerability scores:
- **ext-0baa2.example.com** (192.0.2.14): Discovered 2024-01-15T15:31:00Z, port 443, vulnerability score 8.7
- **legacy-ext-0baa2.example.com** (192.0.2.27): Discovered 2019-01-29T14:14:00Z, port 443, vulnerability score 8.7

No corresponding records in ledger or EDR. This shadow IT asset pair spans since 2019 with critical vulnerabilities unmanaged.

**Recommended Actions:**
1. Immediately identify ownership and business justification
2. Initiate emergency vulnerability remediation

Why combined: LLM judged ext-0baa2 and legacy-ext-0baa2 to be the same device: Same domain base (ext-0baa2) with legacy prefix. Identical open ports (443) and vulnerability score (8.7). Sequential public IPs (192.0.2.14 vs 192.0.2.27). 5-year gap suggests version progression.

## Critical: case G — ext-24d97

[Critical] Case G: ext-24d97
**Security Alert: Shadow IT Asset Detected**

ASM observed an externally visible asset previously unknown internally:
- Domain: ext-24d97.example.com
- Public IP: 192.0.2.15
- Open port: 443
- Vulnerability score: 8.7

This asset is classified as shadow IT—external-facing infrastructure without internal documentation. The high vulnerability score presents significant security risk.

**Recommended Actions:**
1. Investigate ownership and business purpose of ext-24d97.example.com
2. Initiate security assessment and vulnerability remediation

Why combined: single record

## Critical: case G — ext-3bf90

[Critical] Case G: ext-3bf90
**SHADOW IT ALERT**

ASM discovered domain ext-3bf90.example.com at 192.0.2.5 on 2024-01-29T13:32:00Z with vulnerability score 2.7 and no open ports recorded. The asset is externally visible but unknown internally, indicating potential shadow IT infrastructure.

**Recommended Actions:**
1. Immediately query internal asset databases and IT ticketing systems to identify the owner and business purpose of ext-3bf90.example.com
2. Escalate if ownership cannot be established within 24 hours for potential unauthorized infrastructure investigation

Why combined: single record

## Critical: case G — ext-6825f

[Critical] Case G: ext-6825f
**SECURITY ALERT: Unmanaged External Asset Detected**

ASM discovered an external asset at 192.0.2.20 with domain ext-6825f.example.com on 2024-01-03T03:22:00Z. The asset has open port 21 and a vulnerability score of 7.8. This represents an externally visible service unknown to internal systems—suspected shadow IT.

**Recommended Actions:**
1. Investigate ownership and business justification for this asset
2. Assess FTP exposure on port 21 and remediate vulnerabilities or decommission if unauthorized

Why combined: single record

## Critical: case G — ext-70e03

[Critical] Case G: ext-70e03
ASM discovered domain "ext-70e03.example.com-x" with open ports 443 and 3306 and vulnerability score 5.2. This asset is externally visible but absent from internal systems—confirming unmanaged shadow IT.

Port 3306 (MySQL) exposed on the internet presents critical data exposure risk. Unknown ownership and lack of controls create significant security gap.

**Recommended Actions:**
1. Immediately identify asset owner and validate business necessity
2. Restrict external port 3306 access; audit for sensitive data exposure

Why combined: single record

## Critical: case G — ext-b7948

[Critical] Case G: ext-b7948
SECURITY ALERT: Unidentified External Asset

ASM discovered asset 192.0.2.18 (ext-b7948.example.com) on 2024-01-02T15:14:00Z with open ports 80,8443 and vulnerability score 4.9. The asset is externally visible but absent from internal ledger and EDR records—classic shadow IT.

Recommended actions:
1. Investigate ownership and business justification for ext-b7948.example.com
2. Assess and remediate the vulnerability score 4.9 exposure on ports 80 and 8443

Why combined: single record

## Critical: case G — ext-b9948

[Critical] Case G: ext-b9948
**Shadow IT Asset Alert - Case G**

ASM identified an external asset absent from internal systems. Domain ext-b9948.example.com (public IP 192.0.2.23) is internet-exposed with port 8443 open and vulnerability score 2.0. No internal visibility or ownership identified.

**Recommended Actions:**
1. Identify asset owner and business justification immediately
2. Determine if port 8443 exposure is intentional; restrict if unauthorized

Why combined: single record

## Critical: case G — ext-da2dd

[Critical] Case G: ext-da2dd
**ALERT: Unmanaged External Asset Detected**

ASM discovered an asset externally visible but absent from internal systems:
- Domain: ext-da2dd.example.com
- Public IP: 203.0.113.99
- Discovered: 2024-01-28T15:39:00Z
- Vulnerability score: 9.0 (critical)

This represents potential shadow IT with a critical vulnerability posture requiring urgent action.

**Recommended Actions:**
1. Identify the asset owner and validate business purpose
2. Initiate vulnerability remediation for the critical-severity issues

Why combined: single record

## Critical: case G — legacy-ext-da2dd

[Critical] Case G: legacy-ext-da2dd
ASM identified domain legacy-ext-da2dd.example.com at public IP 203.0.113.100, first discovered 2019-05-29T11:02:00Z with vulnerability score 9.0. Asset is externally visible but absent from internal ledger and EDR records, indicating unmanaged shadow IT. No open ports currently reported.

Recommended actions:
1. Verify business ownership and authorization
2. Establish internal asset management records or decommission if unauthorized

Why combined: single record

## Critical: case G — legacy-pub-12d1f

[Critical] Case G: legacy-pub-12d1f
ALERT: Shadow IT Asset Identified

ASM discovered "legacy-pub-12d1f.example.com" (192.0.2.29) on 2019-02-17T17:32:00Z with vulnerability score of 3.5. No open ports documented. This asset is externally visible but unknown internally, indicating potential shadow IT.

Recommended actions:
1. Identify and verify authorization of asset owner
2. Assess and remediate documented vulnerabilities

Why combined: single record

## Critical: case G — legacy-shdpub-f0c02

[Critical] Case G: legacy-shdpub-f0c02
Alert: Shadow IT Detection - Case G

ASM identified external asset at 192.0.2.28 (legacy-shdpub-f0c02.example.com) discovered 2019-04-19T07:57:00Z with open ports 22, 8443, and vulnerability score 6.1. Ledger and EDR contain no matching records, confirming unmanaged external infrastructure typical of shadow IT.

Recommended Actions:
1. Verify legitimate business purpose and asset ownership
2. Establish remediation path: integrate under management or decommission

Why combined: single record

## Critical: case G — pub-12d1f

[Critical] Case G: pub-12d1f
**Alert: Shadow IT Asset Detected**

ASM detected an externally visible asset at 192.0.2.22 (domain: pub-12d1f.example.com) with a vulnerability score of 3.5. This asset appears in external scans but has no corresponding records in EDR or asset ledger systems.

This indicates potential shadow IT—infrastructure operating outside standard IT governance and monitoring. The external visibility without internal awareness creates security gaps, limiting visibility into patch status, configuration, and operational controls.

**Recommended actions:**
1. Investigate ownership and purpose of pub-12d1f.example.com and determine business justification
2. If legitimate, add to asset inventory and integrate into EDR/monitoring systems; otherwise, consider decommissioning

Why combined: single record

## Critical: case G — shdpub-f55e1

[Critical] Case G: shdpub-f55e1
ALERT - Shadow IT Asset Detected

ASM has identified an externally visible domain not registered internally:
- Domain: shdpub-f55e1.example.com
- Open port: 8443
- Vulnerability score: 6.4

This asset is externally discoverable yet absent from internal inventory systems, indicating potential shadow IT infrastructure. The vulnerability score requires assessment.

Recommended actions:
1. Identify ownership and business justification for shdpub-f55e1.example.com
2. Evaluate security exposure on port 8443 and either secure if legitimate or decommission if unauthorized

Why combined: single record

## Important: 45 assets to review

45 assets to review:
- case A pub-12a1f: In ledger, EDR and external scan: managed but exposed (check vulnerabilities)
- case A pub-1728e: In ledger, EDR and external scan: managed but exposed (check vulnerabilities)
- case A pub-25e2e: In ledger, EDR and external scan: managed but exposed (check vulnerabilities)
- case A pub-6bd0a: In ledger, EDR and external scan: managed but exposed (check vulnerabilities)
- case A pub-9a24b: In ledger, EDR and external scan: managed but exposed (check vulnerabilities)
- case A pub-b6f8e: In ledger, EDR and external scan: managed but exposed (check vulnerabilities)
- case A pub-bd82f: In ledger, EDR and external scan: managed but exposed (check vulnerabilities)
- case A pub-c84c9: In ledger, EDR and external scan: managed but exposed (check vulnerabilities)
- case A pub-c85: In ledger, EDR and external scan: managed but exposed (check vulnerabilities)
- case E 10.13.4.82: Ledger only, not detected: retired or inactive asset
- case E 10.19.4.163: Ledger only, not detected: retired or inactive asset
- case E dorm-1f40f: Ledger only, not detected: retired or inactive asset
- case E dorm-56bed: Ledger only, not detected: retired or inactive asset
- case E dorm-6085c: Ledger only, not detected: retired or inactive asset
- case E dorm-63a16: Ledger only, not detected: retired or inactive asset
- case E dorm-85302: Ledger only, not detected: retired or inactive asset
- case E dorm-853d2: Ledger only, not detected: retired or inactive asset
- case E dorm-be7ea: Ledger only, not detected: retired or inactive asset
- case E dorm-e3d79: Ledger only, not detected: retired or inactive asset
- case E dorm_df446: Ledger only, not detected: retired or inactive asset
- case E ledger_19: Ledger only, not detected: retired or inactive asset
- case E ledger_23: Ledger only, not detected: retired or inactive asset
- case E pub-bdf2f: Ledger only, not detected: retired or inactive asset
- case E umpub-1f468: Ledger only, not detected: retired or inactive asset
- case F 10.15.0.113: EDR only, not in the ledger: unmanaged internal asset
- case F 10.16.2.114: EDR only, not in the ledger: unmanaged internal asset
- case F 10.16.2.115: EDR only, not in the ledger: unmanaged internal asset
- case F pub-25e2c: EDR only, not in the ledger: unmanaged internal asset
- case F pub-6b40a: EDR only, not in the ledger: unmanaged internal asset
- case F pub-9a248: EDR only, not in the ledger: unmanaged internal asset
- case F shd-3b0f1: EDR only, not in the ledger: unmanaged internal asset
- case F shd-3f6f2: EDR only, not in the ledger: unmanaged internal asset
- case F shd-4aef7: EDR only, not in the ledger: unmanaged internal asset
- case F shd-4fef7: EDR only, not in the ledger: unmanaged internal asset
- case F shd-85143: EDR only, not in the ledger: unmanaged internal asset
- case F shd-aba89-x: EDR only, not in the ledger: unmanaged internal asset
- case F shd-b359b: EDR only, not in the ledger: unmanaged internal asset
- case F shd-d9eab: EDR only, not in the ledger: unmanaged internal asset
- case F shd_70031: EDR only, not in the ledger: unmanaged internal asset
- case F shd_70031-legacy: EDR only, not in the ledger: unmanaged internal asset
- case F shdpub-3fb71: EDR only, not in the ledger: unmanaged internal asset
- case F wks-33f7d: EDR only, not in the ledger: unmanaged internal asset
- case F wks-5eb4a: EDR only, not in the ledger: unmanaged internal asset
- case F wks-5eb4a-legacy: EDR only, not in the ledger: unmanaged internal asset
- case F wks-7c7f2: EDR only, not in the ledger: unmanaged internal asset
