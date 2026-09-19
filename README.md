# Cyber Kill Chain Simulation Lab

A hands-on home-lab project simulating each stage of Lockheed Martin's **Cyber Kill Chain**, end-to-end: attacker execution on one side, network/SIEM detection on the other. Built on a segmented network (Kali → Palo Alto NGFW → Windows/Linux targets → Wazuh SIEM), running as an EVE-NG topology under VMware Workstation, to show not just *how an attack works*, but *what it actually looks like in the logs* when detection is configured correctly — and where it isn't.

The full write-up (`methodology.md`) covers all seven stages in one document: objective, lab setup, attacker steps with command explanations, the detection pipeline, and analysis — screenshots included throughout.

## Lab Architecture

| Component | Role |
|---|---|
| Kali Linux | Attacker platform, Untrusted zone |
| Palo Alto (PA-VM) | Perimeter firewall / inter-zone policy enforcement |
| Windows host | Target, Trusted zone (Sysmon + Wazuh agent) |
| Ubuntu Linux host | Secondary target, Trusted zone |
| Wazuh | SIEM — log ingestion, decoding, correlation, alerting |

Full topology, addressing, and firewall rulebase are documented in [`methodology.md`](methodology.md#2-lab-environment).

**Note:** Windows Defender and the Windows Firewall are disabled on the target VM for this series — a deliberate simplification to isolate and showcase the kill-chain stages and the network/SIEM detection pipeline, not an attempt to demonstrate evasion of endpoint protection.

## Progress

| # | Stage | Status |
|---|---|---|
| 1 | Reconnaissance | ✅ Complete |
| 2 | Weaponization | ✅ Complete |
| 3 | Delivery | ✅ Complete |
| 4 | Exploitation | ✅ Complete |
| 5 | Installation | ✅ Complete |
| 6 | Command & Control | ✅ Complete |
| 7 | Actions on Objectives (Exfiltration) | ✅ Complete |

Full detail for every stage: [`methodology.md`](methodology.md)

## Why This Project

Most kill-chain write-ups online either show the attack or show the detection — rarely both, tied together with real log evidence. The goal here is to close that gap: every stage pairs an actual attacker action with the actual SIEM alert (or documented detection gap) it produced, mapped to MITRE ATT&CK, with enough detail (commands, flags, decoder/rule config) that the detection logic can be reproduced or adapted.

Stage 7 in particular contrasts two exfiltration techniques — one that evaded host/network detection entirely (Meterpreter in-session `download`) and one that was caught cleanly via Sysmon process-creation logging (PowerShell `Invoke-WebRequest` POST to an external listener) — as a concrete illustration of why command-line telemetry and session-anomaly detection are complementary controls, not substitutes.

## Possible Next Steps

- Re-run the chain with Windows Defender and host firewall enabled, to see how the Stage 3–7 detection picture changes.
- License (or replace) AV / Vulnerability Protection profiles on the perimeter firewall to close the Delivery-stage detection gap.
- Test "low and slow" recon variants against the Stage 1 correlation rule.

## Disclaimer

All activity was performed in an isolated, self-hosted lab environment (EVE-NG under VMware Workstation on a personal laptop) against systems owned and controlled by the author. Nothing here targets third-party infrastructure. This project is for educational and portfolio purposes.
