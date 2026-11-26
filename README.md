# Microsoft Sentinel SOC Lab

A Sentinel lab written up as SOC Level 1 work. I sent Windows Security events from one Azure VM into Microsoft Sentinel, wrote three analytics rules, ran a controlled attack chain against them, and investigated each incident from the raw events. I ran every test myself. Nothing here is a real attack.

No code was written beyond KQL queries. Every finding comes from reading the events in Sentinel.

## Objectives

- Send Windows Security events from a VM into Sentinel
- Write three KQL analytics rules and map them to MITRE ATT&CK
- Run a controlled attack chain to test the rules
- Investigate each incident from the raw events and give a verdict
- Tune the rules to cut duplicate incidents, and measure the result
- Document the findings with evidence

## Investigation workflow

| Step | What I do |
|---|---|
| 1. Open | Open the incident and note the rule, severity, time and entities |
| 2. Pull events | Query SecurityEvent for that account and host around that time |
| 3. Read details | Check logon type, failure codes, command line, parent process and SIDs |
| 4. Compare | Compare what happened with what I would expect from that account |
| 5. Verdict | Decide a verdict, write the next step, and note what the rule missed |

## Repository structure

```
sentinel-soc-lab/
├── README.md
├── kql-notes.md
├── detections/
│   ├── README.md
│   ├── 01-multiple-failed-logons.kql
│   ├── 02-suspicious-powershell.kql
│   └── 03-new-local-admin.kql
├── investigations/
│   ├── 01-failed-logons-then-success.md
│   ├── 02-suspicious-powershell.md
│   ├── 03-new-local-admin-account.md
│   └── 04-security-log-cleared.md
├── mitre-mapping/
│   └── README.md
└── screenshots/
    └── 01 to 09 (setup, evidence, tuning and timeline images)
```

- detections: the three rule queries, and a page on what each rule looks for and where it is weak
- investigations: one write-up per case
- mitre-mapping: each technique with the event and incident that showed it
- kql-notes.md: the rule notes and the evidence queries
- screenshots: the images used on these pages

## Detections

All three rules run every 5 minutes with a 15-minute lookback.

| # | Detection | Event | Severity | MITRE | Query |
|---|---|---|---|---|---|
| 1 | Multiple Failed Logons | 4625 | Medium | T1110 | [01-multiple-failed-logons.kql](detections/01-multiple-failed-logons.kql) |
| 2 | Suspicious PowerShell Execution | 4688 | High | T1059.001 | [02-suspicious-powershell.kql](detections/02-suspicious-powershell.kql) |
| 3 | New Local Account and Admin Group Modification | 4720, 4732 | High | T1136.001, T1098 | [03-new-local-admin.kql](detections/03-new-local-admin.kql) |

No rule covers event 1102, the Security log being cleared (T1070.001). I found it by query. The technique mapping is in [mitre-mapping](mitre-mapping/README.md).

## Investigations

| Case | Trigger | Verdict |
|---|---|---|
| [01 Failed logons then success](investigations/01-failed-logons-then-success.md) | Incident 10: six failed logons in 14 seconds, then a success | Suspicious, escalate |
| [02 PowerShell IEX command](investigations/02-suspicious-powershell.md) | Incident 11: IEX with a harmless string | Harmless alone, suspicious in context |
| [03 New local admin account](investigations/03-new-local-admin-account.md) | Incident 12: svc_update created and added to Administrators | True positive, persistence |
| [04 Security log cleared](investigations/04-security-log-cleared.md) | No incident. Found by query for event 1102 | High concern |

## Test run

On 25 Nov 2026 I ran one chain on the VM, in this order:

1. Six wrong passwords at the RDP login, then the correct one.
2. A PowerShell command with IEX.
3. A new local account, added to Administrators.
4. The Security log cleared with `wevtutil cl Security`, run twice.

![Attack chain timeline](screenshots/09-attack-chain-timeline.png)

## Tuning

On 24 Nov each rule created 3 incidents from a single test, about 5 minutes apart. With a 5-minute schedule and a 15-minute lookback, each event falls inside three runs.

![Before tuning](screenshots/07-incidents-before-tuning.png)

I turned off suppression on Rule 1, set up entity mapping on all three rules, and turned on alert grouping. I also changed two queries. Rule 1 now counts across the whole lookback instead of fixed 5-minute blocks, and Rule 3 now ignores groups other than Administrators.

| Rule | Incidents before | Incidents after | Alerts in that incident | Last event to incident |
|---|---|---|---|---|
| Multiple Failed Logons | 3 | 1 | 3 | about 8 minutes |
| Suspicious PowerShell Execution | 3 | 1 | 3 | about 7 minutes |
| New Local Account and Admin Group Modification | 3 | 1 | 4 | about 5 minutes |

The alert counts show that the rules still fire several times. Grouping merges the alerts into one incident.

![After tuning](screenshots/08-incidents-after-tuning.png)

## Lab setup

| Component | Configuration |
|---|---|
| Cloud | Azure free account, Central India |
| VM | Windows Server 2022, Standard B2s_v2 |
| Log platform | Log Analytics workspace |
| SIEM | Microsoft Sentinel |
| Log collection | Azure Monitor Agent with a data collection rule for all Windows Security events |
| Auditing | Process creation with command line logging |
| Access | RDP from one IP address only |
| Query language | KQL |

The data path:

```
VM > Azure Monitor Agent > data collection rule > Log Analytics workspace > Microsoft Sentinel > analytics rules > alerts > incidents
```

## Tools used

| Purpose | Tool |
|---|---|
| Rules, alerts and incidents | Microsoft Sentinel |
| Queries and log storage | Log Analytics, KQL |
| Log collection | Azure Monitor Agent, data collection rule |
| Test machine | Azure VM, RDP |
| Technique mapping | MITRE ATT&CK |

## Limits

- One VM, one account, and tests I ran myself. There is no normal traffic to measure false positives against.
- Event 4688 shows that a process started. It does not show what the process did. I have no network logs.
- Rule 1 only detects the failures. I found the successful logon with a separate query.
- No rule covers event 1102.
- The overlapping runs still create repeat alerts. Setting the lookback closer to the schedule would reduce them. I did not test that.

## Skills demonstrated

Microsoft Sentinel analytics rules, KQL, Windows Security event analysis (4624, 4625, 4688, 4720, 4732, 1102), alert tuning, incident triage, MITRE ATT&CK mapping, incident write-ups.

## Safety note

All tests ran on a VM I created in my own Azure account. No other system was touched. The VM's public IP address and the RDP source address are covered in the screenshots.

## Setup screenshots

![Data collection rule](screenshots/01-dcr-windows-security-events.png)

![Process creation with command line](screenshots/02-securityevent-4688-command-line.png)

![RDP limited to one address](screenshots/03-network-rule-rdp-restricted-to-single-ip.png)

## Author

Manikanta Rapolu. See also: [SOC Analyst Notes](https://github.com/Manikantarapolu/soc-analyst-notes) and [Phishing Email Investigation](https://github.com/Manikantarapolu/phishing-email-investigation)
