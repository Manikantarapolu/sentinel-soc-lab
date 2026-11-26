# KQL notes

All queries run in Microsoft Sentinel > Logs on the SecurityEvent, SecurityAlert and SecurityIncident tables. Times are UTC. The three rule queries are also saved as files in `detections/`.

## Rule 1: Multiple Failed Logons

Medium severity. Credential Access, T1110. Runs every 5 minutes with a 15-minute lookback. Alerts when the query returns more than 0 rows.

```
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count(), FirstAttempt = min(TimeGenerated), LastAttempt = max(TimeGenerated) by TargetUserName, Computer, IpAddress
| where FailedAttempts >= 5
```

My first version grouped failures into fixed 5-minute blocks. In one test, six failures crossed a block boundary and split into 2 and 4, so neither group reached 5. Counting over the whole lookback fixes that.

Failed logons show the account as `-\labadmin`, with a dash for the domain.

## Rule 2: Suspicious PowerShell Execution

High severity. Execution, T1059.001. Same schedule and lookback.

```
SecurityEvent
| where EventID == 4688
| where NewProcessName endswith "powershell.exe"
| where CommandLine has_any ("IEX", "Invoke-Expression", "-enc", "-EncodedCommand", "FromBase64String", "DownloadString", "Invoke-WebRequest", "Invoke-RestMethod")
| project TimeGenerated, Computer, Account, CommandLine, ParentProcessName
```

Note: `has_any` matches whole terms, so `-enc` is read as the term enc. Short forms like `-e` and `-ec` are not matched. A 4688 event shows that a process started. It does not show that a download worked.

## Rule 3: New Local Account and Admin Group Modification

High severity. Persistence, T1136.001 and T1098. Same schedule and lookback.

```
SecurityEvent
| where EventID == 4720 or (EventID == 4732 and TargetAccount has "Administrators")
| project TimeGenerated, Computer, EventID, Activity, SubjectAccount, TargetAccount, TargetSid, MemberName, MemberSid
```

4720 is a user account created. 4732 is a member added to a security-enabled local group. The first version alerted on every 4732, including the automatic add to Users that follows each new account. The filter keeps only the Administrators group.

MemberName is empty for local accounts, so I match the SID in TargetSid on the 4720 event with MemberSid on the 4732 event.

## Incident settings on all three rules

- Alert grouping on, match all entities, grouping period 5 hours.
- Suppression off.
- Entity mapping: Account and Host on every rule, plus IP on Rule 1.

## Evidence queries

Failed logons and successes for one account (screenshot 04):

```
SecurityEvent
| where EventID in (4625, 4624)
| where Account has "labadmin"
| project TimeGenerated, EventID, Activity, Account, LogonType
| sort by TimeGenerated asc
```

Account created and added to Administrators, with SIDs (screenshot 06):

```
SecurityEvent
| where EventID in (4720, 4732)
| project TimeGenerated, EventID, SubjectAccount, TargetAccount, TargetSid, MemberSid
| sort by TimeGenerated asc
```

Incidents with the number of alerts in each (screenshots 07 and 08):

```
SecurityIncident
| where TimeGenerated > datetime(2026-11-25 07:29:00)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| extend AlertCount = array_length(AlertIds)
| project IncidentNumber, Title, Severity, Status, AlertCount, CreatedTime
| sort by CreatedTime asc
```

Attack chain timeline (screenshot 09). The window starts at 07:32 to skip activity from the VM booting:

```
SecurityEvent
| where TimeGenerated > datetime(2026-11-25 07:32:00)
| where EventID in (4625, 4624, 4688, 4720, 4732, 1102)
| where EventID != 4688 or CommandLine has_any ("IEX", "cl Security")
| where EventID != 4624 or Account has "labadmin"
| project TimeGenerated, EventID, Activity, Account, LogonType, CommandLine, TargetAccount
| sort by TimeGenerated asc
```

This window is fixed on purpose. It is an investigation query around the incident times, not part of a rule.

## Log type notes

- A new RDP session logs two 4624 events, type 3 then type 10.
- Type 7 is an unlock or a reconnect to an existing session.
- Event 1102 has no account in Sentinel. I tie it to the 4688 event for `wevtutil cl Security` that comes just before it.
