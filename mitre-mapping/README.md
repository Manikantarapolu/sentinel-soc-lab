# MITRE ATT&CK mapping

Each technique below is tied to the event that showed it and the incident that came from it. A mapping says what a behaviour resembles. It does not prove an attack. Everything here came from my own tests.

## T1110 Brute Force (Credential Access)

Rule: multiple failed logons. Event 4625. Incident 10.

Six failed logons for labadmin in 14 seconds, followed by a success. All six have SubStatus 0xc000006a, which means the account name was valid and the password was wrong. See [investigation 01](../investigations/01-failed-logons-then-success.md).

## T1059.001 PowerShell (Execution)

Rule: suspicious PowerShell execution. Event 4688. Incident 11.

powershell.exe ran with `IEX ('Write-Output TEST')`. The command is harmless, and the mapping fits the technique and not the intent. See [investigation 02](../investigations/02-suspicious-powershell.md).

## T1136.001 Create Account: Local Account (Persistence)

Rule: new local account and admin group change. Event 4720. Incident 12.

labadmin created svc_update at 07:39:24 UTC.

## T1098 Account Manipulation (Persistence)

Rule: new local account and admin group change. Event 4732. Incident 12.

svc_update was added to Builtin\Administrators 53 seconds later. The SIDs on the two events match. See [investigation 03](../investigations/03-new-local-admin-account.md).

## T1070.001 Clear Windows Event Logs (Defense Evasion)

No rule. Events 4688 and 1102.

`wevtutil cl Security` ran twice, at 07:47:32 and 07:47:57 UTC, and each run was followed by a 1102 event about 20 milliseconds later. I found it by query. See [investigation 04](../investigations/04-security-log-cleared.md).
