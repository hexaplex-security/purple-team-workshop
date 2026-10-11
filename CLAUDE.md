# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a **documentation repository** for a hands-on Purple Team Workshop run by hexaplex-security. Workshop content is Markdown, PDFs, images, and MITRE ATT&CK Navigator JSON layers. The only code is `worker/`, the Cloudflare Worker that gates the paid site at workshop.hexaplex.ch and logs attendee access (see `worker/README.md`; tests: `cd worker && npm test`).

The workshop simulates **Black Basta ransomware attacks** and validates defensive coverage using a hosted Sentinel Attack Range (SAR) environment in Azure. This repo ships only the workshop content — the lab infrastructure is external.

## Workshop Flow

The workshop runs in this sequence, each backed by a guide file:

1. **`intro_and_setup.md`** — Lab access via Guacamole VNC, Microsoft Sentinel, and Azure Portal
2. **`cti-lab.md`** — Threat intelligence analysis: MITRE ATT&CK Navigator, Sigma rules, kill chain mapping, adversary profiling
3. **`emulation.md`** — 24 step-by-step red team commands (PowerShell, Kali, mimikatz, Bloodhound, rclone, certutil) mapped to ATT&CK techniques
4. **`blue-verification.md`** — Detection verification in Microsoft Sentinel against the emulation steps
5. **`detection_engineering.md`** — Detection improvement: Pyramid of Pain, LOLBAS evasion, Sigma rule tuning, correlation searches

## ATT&CK Navigator Layers

`resources/cti/` organizes ATT&CK Navigator JSON layers by perspective:

All layers target **ATT&CK v19** (April 2026). v19 split Defense Evasion into **Stealth (TA0005)** and **Defense Impairment (TA0112)**; there is no longer a "defense-evasion" tactic slug. T1562 (Impair Defenses) and its sub-techniques were revoked; the key replacement is **T1685** (Disable or Modify Tools, under Defense Impairment). Re-run `resources/cti/update_to_v19.py` when MITRE publishes a new major version.

- **`red/`** — Threat actor TTPs (Black Basta, QakBot, Cobalt Strike, Mimikatz, PsExec, BITSAdmin, Rclone, CISA advisory, cumulated layer)
- **`blue/`** — Defensive coverage (SIEM detections, Sysmon, preventions, triggered TTPs)
- **`purple/`** — Analysis output: configured-vs-triggered gap analysis (`black_basta_detection_coverage.json`, `configured_vs_triggered.json`)

## Key Reference Files

| File | Purpose |
|------|---------|
| `resources/emulation-reference.md` | Maps all 24 emulation steps to ATT&CK technique IDs |
| `resources/detection-reference.md` | Maps 25 configured Sigma detection rules to ATT&CK technique IDs |
| `resources/adversaryprofile-template.md` | Template for documenting other threat actors |
| `splunk_correlation_search_examples.md` | Splunk SPL queries for correlation and alerting |

## Repository

- **GitHub:** `hexaplex-security/purple-team-workshop` (public)
- **License:** Creative Commons CC0 1.0 Universal (public domain)
- Commit and push after any content changes per global CLAUDE.md conventions.
