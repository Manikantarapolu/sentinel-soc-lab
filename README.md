# Detections

Each rule is saved here as a `.kql` file with a comment header. This page says what each rule looks for, which test fired it, what I changed, and where it is weak.

All three rules run every 5 minutes with a 15-minute lookback and alert when the query returns any rows. All three use alert grouping (match all entities) and entity mapping for the account and host.

## 01 Multiple failed logons

File: [01-multiple-failed-logons.kql](01-multiple-failed-logons.kql). Event 4625. MITRE T1110.

It looks for 5 or more failed logons for one account, host and source address inside the lookback.

Fired by: six wrong passwords at the RDP login on 25 Nov. That created incident 10.

What I changed: my first version counted failures in fixed 5-minute blocks. In one test, six failures crossed a block boundary and split into 2 and 4, so neither group reached 5. The rule now counts across the whole lookback. I also turned off suppression, which paused the rule for 15 minutes after each alert and would have hidden a second attack in that window.

Weak spots: it does not detect the successful logon that followed, so I found that with a separate query. The threshold of 5 is a choice and not a measurement. This lab has one VM, so I saw no noise from system accounts and cannot say how the rule behaves on a busy network.

## 02 Suspicious PowerShell execution

File: [02-suspicious-powershell.kql](02-suspicious-powershell.kql). Event 4688. MITRE T1059.001.

It looks for powershell.exe process creation where the command line has IEX, Invoke-Expression, -enc, -EncodedCommand, FromBase64String, DownloadString, Invoke-WebRequest or Invoke-RestMethod.

Fired by: `IEX ('Write-Output TEST')` on 25 Nov. That created incident 11.

Weak spots: it matches terms in the text, so a harmless command with IEX in it fires the rule. `-enc` is read as the term enc, and short forms like `-e` and `-ec` are not matched. It only matches powershell.exe, so pwsh.exe is missed. Severity is set to high, and for a bare IEX medium would fit better.

## 03 New local account and admin group change

File: [03-new-local-admin.kql](03-new-local-admin.kql). Events 4720 and 4732. MITRE T1136.001 and T1098.

It fires on a new local account (4720), or on a member added to the local Administrators group (4732).

Fired by: creating svc_update and adding it to Administrators on 25 Nov. That created incident 12.

What I changed: my first version fired on every 4732. Windows adds each new account to the Users group automatically, so every account creation produced a second alert. The rule now keeps only the Administrators group.

Weak spots: MemberName is empty for local accounts, so the query returns the SIDs and I match them by hand.

## Not covered

Nothing detects event 1102, the Security log being cleared. I found it by query. See [investigation 04](../investigations/04-security-log-cleared.md).
