# PwnCrypt Ransomware Threat Hunt

> **Environment:** Controlled Microsoft Defender for Endpoint lab  
> **Affected device:** `ta-zero-day`  
> **Account:** `alex`  
> **Investigation date:** July 12, 2026  
> **Status:** Execution and ransomware impact confirmed; endpoint isolated

---

## Executive Summary

This threat hunt investigated a simulated PwnCrypt ransomware outbreak using Microsoft Defender for Endpoint Advanced Hunting.

The investigation confirmed that `C:\ProgramData\pwncrypt.ps1` was created and executed on `ta-zero-day` through `cmd.exe` and PowerShell. Immediately after execution, multiple CSV files were created or renamed with the `_pwncrypt` marker, and a decryption-instructions file was written to the user's desktop.

Environment-wide searches for the discovered indicators returned activity only from `ta-zero-day`. The endpoint was isolated through Microsoft Defender for Endpoint to contain the threat.

### Final Assessment

| Assessment area | Result | Evidence | Confidence |
|---|---|---|---|
| Payload present | Confirmed | `C:\ProgramData\pwncrypt.ps1` was created | High |
| Execution | Confirmed | PowerShell executed the script using `ExecutionPolicy Bypass` | High |
| Impact | Confirmed | Multiple `_pwncrypt` files and a ransom note were created | High |
| Scope | One affected endpoint identified | All matching indicators mapped to `ta-zero-day` | High |
| Delivery | Scenario-supported | Lab command used `Invoke-WebRequest`; download command was not independently recovered from MDE telemetry | Medium |

---

## 1. Preparation

### Threat Context

The scenario described PwnCrypt as a PowerShell-based ransomware payload that encrypts files and modifies their filenames with a PwnCrypt-related marker.

The scenario indicated that an encrypted filename could contain `.pwncrypt`. During this investigation, the observed files used the `_pwncrypt` naming pattern.

### Hunt Hypothesis

> PwnCrypt may have executed on an endpoint and produced observable PowerShell, file-creation, file-rename, and ransom-note activity.

### Known Behaviors and Expected Telemetry

| Known behavior | Expected MDE evidence | Primary table |
|---|---|---|
| PowerShell-based payload | `powershell.exe` process and command line | `DeviceProcessEvents` |
| Script written to disk | `.ps1` `FileCreated` event and folder path | `DeviceFileEvents` |
| File encryption | Rapid file creation or rename activity with a PwnCrypt marker | `DeviceFileEvents` |
| Ransom note | Decryption-instructions file created | `DeviceFileEvents` |
| Payload delivery | Download command, URL, or related network activity | `DeviceProcessEvents` / `DeviceNetworkEvents` |

### Investigation Path

1. Identify suspicious file artifacts.
2. Record the device and timestamp.
3. Identify the process that created the artifact.
4. Examine its command line and parent process.
5. Determine whether the payload executed.
6. Review file activity immediately after execution.
7. Scope the discovered indicators across the environment.
8. Contain the affected endpoint.
9. Map evidence-supported behavior to MITRE ATT&CK.

---

## 2. Data Collection

The hunt used Microsoft Defender for Endpoint Advanced Hunting.

Primary telemetry sources:

- `DeviceFileEvents`
- `DeviceProcessEvents`

Before applying indicator filters, file telemetry was verified for `ta-zero-day` to confirm that the device name was correct and that MDE was receiving recent events.

---

## 3. Data Analysis and Investigation

### 3.1 PowerShell Script Discovery

The first query searched broadly for PowerShell scripts on the endpoint:

```kql
DeviceFileEvents
| where DeviceName == "ta-zero-day"
| where FileName endswith ".ps1"
```

The query was then expanded to display the fields needed to evaluate each script event:

```kql
DeviceFileEvents
| where DeviceName == "ta-zero-day"
| where FileName endswith ".ps1"
| project Timestamp,
          FileName,
          ActionType,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine,
          InitiatingProcessParentFileName,
          InitiatingProcessAccountName,
          FolderPath
```

### Finding

The results confirmed that the following payload was created:

```text
C:\ProgramData\pwncrypt.ps1
```

The event occurred on `ta-zero-day` at approximately **8:43:02 PM EDT** under the account `alex`.

The initiating process was `powershell.exe`, and its parent process was `explorer.exe`.

![PwnCrypt payload creation evidence](assets/payload-creation.png)

---

### 3.2 Process Execution Pivot

The payload-creation timestamp was used to pivot into `DeviceProcessEvents`.

```kql
let suspiciousTime = datetime(2026-07-13T00:43:02.7034862Z);

DeviceProcessEvents
| where DeviceName == "ta-zero-day"
| where Timestamp between ((suspiciousTime - 3m) .. (suspiciousTime + 3m))
| where AccountName contains "Alex"
| project Timestamp,
          FileName,
          ProcessCommandLine,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine,
          AccountName
| order by Timestamp desc
```

### Finding

The process telemetry confirmed the following execution command:

```text
powershell.exe -ExecutionPolicy Bypass -File C:\ProgramData\pwncrypt.ps1
```

The observed process chain was:

```text
powershell.exe
└── cmd.exe /c
    └── powershell.exe -ExecutionPolicy Bypass -File C:\ProgramData\pwncrypt.ps1
```

The activity ran under the account `alex`.

`ExecutionPolicy Bypass` provided execution-policy context, but it was not treated as proof that a security product was disabled or impaired.

![PwnCrypt process execution evidence](assets/process-execution.png)

---

### 3.3 File-Impact Confirmation

File activity immediately before and after execution was reviewed.

```kql
let executionTime = datetime(2026-07-13T00:43:02.7034862Z);

DeviceFileEvents
| where DeviceName == "ta-zero-day"
| where Timestamp between ((executionTime - 1m) .. (executionTime + 5m))
| project FileName,
          Timestamp,
          ActionType,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine,
          FolderPath,
          InitiatingProcessAccountName,
          InitiatingProcessParentFileName
| order by Timestamp asc
```

### Confirmed Impact

One second after execution, the same PowerShell command created or renamed files including:

- `5086_CompanyFinancials_pwncrypt.csv`
- `5107_ProjectList_pwncrypt.csv`
- `2377_EmployeeRecords_pwncrypt.csv`
- `__________decryption-instructions.txt`

The encrypted filenames and ransom note were associated with:

```text
powershell.exe -ExecutionPolicy Bypass -File C:\ProgramData\pwncrypt.ps1
```

The close timing, matching command line, same account, and ransom-note creation confirmed ransomware impact.

![Company financial file impact evidence](assets/file-impact-company-financials.png)

![Additional encrypted files and ransom note](assets/file-impact-projects-records-ransom-note.png)

---

### 3.4 Scope Assessment

The device restriction was removed from follow-up searches to check the available environment for the discovered indicators.

#### File indicators

```kql
DeviceFileEvents
| where FileName contains "pwncrypt"
   or FileName contains "decryption-instructions"
| project Timestamp,
          DeviceName,
          FileName,
          FolderPath,
          ActionType,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine,
          InitiatingProcessAccountName
| order by Timestamp asc
```

#### Execution indicator

```kql
DeviceProcessEvents
| where ProcessCommandLine contains "pwncrypt.ps1"
| project Timestamp,
          DeviceName,
          AccountName,
          FileName,
          ProcessCommandLine,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp asc
```

### Scope Conclusion

All matching activity was associated with `ta-zero-day`. No additional affected endpoints were identified from the discovered PwnCrypt indicators.

This confirms the scope observed in the available telemetry. It does **not** claim that every possible lateral-movement method was exhaustively ruled out.

---

## 4. Timeline Summary

| Time (EDT) | Event | Significance |
|---|---|---|
| 8:43:02 PM | `pwncrypt.ps1` created in `C:\ProgramData` | Payload placed on the endpoint |
| 8:43:02 PM | PowerShell executed the script through `cmd.exe` | Execution confirmed |
| 8:43:03 PM | `_pwncrypt` files created or renamed | File-encryption impact confirmed |
| 8:43:03 PM | Decryption-instructions file created | Ransomware behavior confirmed |
| Post-investigation | `ta-zero-day` isolated in MDE | Threat contained |

> **Time note:** MDE displayed the activity at approximately 8:43 PM EDT. The KQL pivot used the equivalent UTC timestamp `2026-07-13T00:43:02.7034862Z`.

---

## 5. MITRE ATT&CK TTP Mapping

Only techniques supported by the collected evidence were included.

| Tactic | Technique | Observed procedure | Evidence status | Confidence |
|---|---|---|---|---|
| Execution | [T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/) | PowerShell executed `C:\ProgramData\pwncrypt.ps1` with `-ExecutionPolicy Bypass`. | Telemetry-confirmed | High |
| Execution | [T1059.003 — Windows Command Shell](https://attack.mitre.org/techniques/T1059/003/) | `cmd.exe /c` launched PowerShell to execute the ransomware payload. | Telemetry-confirmed | High |
| Impact | [T1486 — Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/) | Multiple files were created or renamed with the `_pwncrypt` marker, and decryption instructions were generated. | Telemetry-confirmed | High |
| Command and Control | [T1105 — Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/) | The lab scenario used `Invoke-WebRequest` to retrieve `pwncrypt.ps1` from an external GitHub location. | Scenario-derived; not independently recovered from MDE telemetry | Medium |

### Mapping Notes

#### T1059.001 — PowerShell

The strongest execution evidence was the direct use of PowerShell to run the payload:

```text
powershell.exe -ExecutionPolicy Bypass -File C:\ProgramData\pwncrypt.ps1
```

#### T1059.003 — Windows Command Shell

The parent-child process chain showed `cmd.exe /c` invoking PowerShell. This supports Windows Command Shell execution in addition to PowerShell.

#### T1486 — Data Encrypted for Impact

The immediate creation or renaming of files with the `_pwncrypt` marker, followed by the creation of a decryption-instructions file, directly supports ransomware-related encryption impact.

#### T1105 — Ingress Tool Transfer

The simulation command used `Invoke-WebRequest` to transfer the payload from an external web source into `C:\ProgramData`.

This technique is included as scenario-supported context because the initial download command was not independently recovered from the available MDE process telemetry.

### Techniques Not Mapped

The following techniques were intentionally excluded because the collected evidence did not establish them:

- User Execution: Malicious File
- Deobfuscate/Decode Files or Information
- Inhibit System Recovery
- Impair Defenses
- Persistence techniques
- Credential Access techniques
- Lateral Movement techniques

---

## 6. Response and Containment

After confirming execution, ransomware impact, and the observed environment-wide scope, `ta-zero-day` was isolated through Microsoft Defender for Endpoint.

Isolation restricted network communication while preserving connectivity to Microsoft Defender for continued response actions.

![MDE device-isolation action](assets/mde-device-isolation.png)

### Response Summary

> The affected endpoint, `ta-zero-day`, was isolated after confirming PwnCrypt execution and file-encryption activity. Environment-wide IOC searches did not identify additional affected endpoints.

---

## 7. Final Assessment

PwnCrypt execution and ransomware impact were confirmed on `ta-zero-day`.

The payload was executed through `cmd.exe` and PowerShell under the account `alex`. Immediately afterward, multiple CSV files were created or renamed with the `_pwncrypt` marker, and a decryption-instructions file was created.

Environment-wide searches for the discovered indicators did not identify additional affected endpoints. The affected device was isolated through Microsoft Defender for Endpoint.

---

## 8. Improvement Opportunities

| Improvement | Purpose |
|---|---|
| Enable enhanced PowerShell logging and centralized retention | Improve visibility into script blocks, command lines, and download behavior |
| Alert on PowerShell execution from writable paths such as `C:\ProgramData` and user Temp directories | Detect suspicious script placement and execution earlier |
| Detect rapid file creation or rename activity paired with ransom-note indicators | Identify encryption behavior even when the malware filename changes |
| Use application control and least privilege where operationally feasible | Reduce unauthorized script execution and limit endpoint impact |
| Maintain tested, protected, and offline backups | Support recovery without relying on attacker-provided decryption |
| Create reusable KQL hunting templates | Accelerate future payload, execution, impact, and scope pivots |
| Provide user-awareness training | Reduce the chance of users executing untrusted commands or files |

### Hunting-Process Improvements

- Begin with the strongest available IOC, then broaden only when necessary.
- Preserve `Timestamp`, `DeviceName`, command-line, parent-process, user, and path fields during pivots.
- Use narrow time windows to reconstruct process and file activity.
- Separate telemetry-confirmed findings from scenario-derived context.
- Scope indicators across all endpoints before declaring an incident contained.
- Avoid mapping ATT&CK techniques that are not directly supported by evidence.

---

## 9. Key Takeaways

- Threat hunting is driven by investigative questions, not by memorizing one large KQL query.
- File events can provide the timestamp needed to pivot into process telemetry.
- PowerShell activity requires context; the command line, parent process, account, path, and timing determine significance.
- A suspicious script on disk does not prove execution.
- Execution does not prove impact until associated file activity is identified.
- Environment-wide IOC scoping should be completed before documenting the incident as limited to one endpoint.
- MITRE ATT&CK mappings should reflect observed behavior and clearly distinguish confirmed evidence from contextual assumptions.

---

## References

- [MITRE ATT&CK — PowerShell (T1059.001)](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK — Windows Command Shell (T1059.003)](https://attack.mitre.org/techniques/T1059/003/)
- [MITRE ATT&CK — Data Encrypted for Impact (T1486)](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK — Ingress Tool Transfer (T1105)](https://attack.mitre.org/techniques/T1105/)
- Microsoft Defender for Endpoint Advanced Hunting telemetry
- Controlled PwnCrypt ransomware simulation and investigation notes

---

## Disclaimer

This project was completed in a controlled lab environment for defensive cybersecurity training. The ransomware behavior was intentionally simulated on an authorized virtual machine.
