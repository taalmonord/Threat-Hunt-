# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

# PwnCrypt Ransomware Threat Hunt

In this project, we conduct a structured threat hunt for a simulated PwnCrypt ransomware incident using Microsoft Defender for Endpoint Advanced Hunting.

_**Inception State:**_ A newly announced ransomware threat may have reached an environment with immature security controls, requiring investigators to determine whether the payload was present, executed, and caused impact.

_**Completion State:**_ PwnCrypt execution and ransomware impact are confirmed on one endpoint, the discovered indicators are scoped across the environment, the affected endpoint is isolated, and the observed behaviors are mapped to MITRE ATT&CK.

---

# Technology Utilized

- Microsoft Defender for Endpoint (MDE)
- Advanced Hunting with Kusto Query Language (KQL)
- Windows endpoint process and file telemetry
- PowerShell and Windows Command Shell analysis
- MITRE ATT&CK Framework

---

# Project Details

| Field | Value |
|---|---|
| Environment | Controlled Microsoft Defender for Endpoint lab |
| Affected device | `ta-zero-day` |
| Account | `alex` |
| Investigation date | July 12, 2026 |
| Status | Execution and ransomware impact confirmed; endpoint isolated |

---

# Table of Contents

- [Executive Summary](#executive-summary)
- [Step 1: Preparation](#step-1-preparation)
- [Step 2: Data Collection](#step-2-data-collection)
- [Step 3: Data Analysis and Investigation](#step-3-data-analysis-and-investigation)
  - [PowerShell Script Discovery](#powershell-script-discovery)
  - [Process Execution Pivot](#process-execution-pivot)
  - [File-Impact Confirmation](#file-impact-confirmation)
  - [Scope Assessment](#scope-assessment)
- [Step 4: Timeline Summary](#step-4-timeline-summary)
- [Step 5: MITRE ATT&CK TTP Mapping](#step-5-mitre-attck-ttp-mapping)
- [Step 6: Response and Containment](#step-6-response-and-containment)
- [Step 7: Final Assessment](#step-7-final-assessment)
- [Step 8: Improvement Opportunities](#step-8-improvement-opportunities)
- [Step 9: Key Takeaways](#step-9-key-takeaways)
- [References](#references)
- [Disclaimer](#disclaimer)

---

### Executive Summary

This threat hunt investigated a simulated PwnCrypt ransomware outbreak using Microsoft Defender for Endpoint (MDE) Advanced Hunting.

The investigation confirmed that `C:\ProgramData\pwncrypt.ps1` was created and executed on `ta-zero-day` via `cmd.exe` and PowerShell. Immediately after execution, multiple CSV files were created or renamed with a `_pwncrypt` marker, and a decryption-instructions file was written to the user's desktop.

Environment-wide searches for the discovered indicators returned activity only from `ta-zero-day`. The endpoint was isolated through Microsoft Defender for Endpoint to contain the threat.

#### Final Assessment

| Assessment Area | Result | Evidence | Confidence |
|---|---|---|---|
| Payload present | Confirmed | `C:\ProgramData\pwncrypt.ps1` was created | High |
| Execution | Confirmed | PowerShell executed the script using `-ExecutionPolicy Bypass` | High |
| Impact | Confirmed | Multiple `_pwncrypt` files and a ransom note were created | High |
| Scope | One affected endpoint identified in available telemetry | All matching indicators mapped to `ta-zero-day` | High |
| Delivery | Scenario-supported | Lab briefing specified `Invoke-WebRequest`; download activity was not independently recovered from MDE telemetry | Medium |

---

### Step 1) Preparation

#### Threat Context

The lab briefing described PwnCrypt as a PowerShell-based ransomware payload using AES-256 encryption, targeting directories such as `C:\Users\Public\Desktop` and appending a `.pwncrypt` marker to encrypted filenames (for example, `hello.txt` to `hello.pwncrypt.txt`). The encryption algorithm and target-directory description are scenario-provided context; the hunt independently confirmed execution and ransomware-related file impact through MDE telemetry.

**Note on naming convention:** The observed files during this hunt used a `_pwncrypt` suffix inserted before the original extension (e.g., `CompanyFinancials_pwncrypt.csv`) rather than the `.pwncrypt.<ext>` pattern described in the original briefing. This discrepancy is documented rather than silently reconciled, since evidence should reflect what was actually observed in telemetry.

#### Hunt Hypothesis

> PwnCrypt may have executed on an endpoint and produced observable PowerShell, file-creation, file-rename, and ransom-note activity. Given immature security controls and no user training at the organization, the ransomware may have reached the corporate network.

#### Known Behaviors and Expected Telemetry

| Known Behavior | Expected MDE Evidence | Primary Table |
|---|---|---|
| PowerShell-based payload | `powershell.exe` process and command line | `DeviceProcessEvents` |
| Script written to disk | `.ps1` `FileCreated` event and folder path | `DeviceFileEvents` |
| File encryption | Rapid file creation/rename activity with a PwnCrypt marker | `DeviceFileEvents` |
| Ransom note | Decryption-instructions file created | `DeviceFileEvents` |
| Payload delivery | Download command, URL, or related network activity | `DeviceProcessEvents` / `DeviceNetworkEvents` |

#### Investigation Path

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

### Step 2) Data Collection

The hunt used Microsoft Defender for Endpoint Advanced Hunting.

**Primary telemetry sources:**
- `DeviceFileEvents`
- `DeviceProcessEvents`

Before applying indicator filters, file telemetry was verified for `ta-zero-day` to confirm the device name was correct and that MDE was receiving recent events. An initial broad `.ps1` query returned PowerShell policy-test artifacts and several other scripts. These results were treated as background activity and manually triaged rather than assumed malicious. The PwnCrypt payload was identified when `pwncrypt.ps1` appeared in the results.

<img width="1340" height="625" alt="01_ps1_broad_search_results" src="https://github.com/user-attachments/assets/c9a8e874-1139-4a2e-b05f-fc4ac5e0b63e" />

---

### Step 3) Data Analysis and Investigation

#### PowerShell Script Discovery

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

**Finding:**

| Field | Value |
|---|---|
| Timestamp | Jul 12, 2026 8:43:02 PM |
| FileName | `pwncrypt.ps1` |
| ActionType | `FileCreated` |
| InitiatingProcessFileName | `powershell.exe` |
| InitiatingProcessCommandLine | `powershell.exe` |
| InitiatingProcessParentFileName | `explorer.exe` |
| InitiatingProcessAccountName | `alex` |
| FolderPath | `C:\ProgramData\pwncrypt.ps1` |

The payload `C:\ProgramData\pwncrypt.ps1` was created on `ta-zero-day` at approximately **8:43:02 PM EDT** under the account `alex`. The initiating process was `powershell.exe`, launched from `explorer.exe`.

<img width="1316" height="367" alt="02_payload_creation_evidence" src="https://github.com/user-attachments/assets/e57807ec-627b-40cc-bbe4-9e42f78b2519" />

---

#### Process Execution Pivot

The payload-creation timestamp was used to pivot into `DeviceProcessEvents`:

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

**Finding:**

| Field | Value |
|---|---|
| Timestamp | Jul 12, 2026 8:43:02 PM |
| FileName | `powershell.exe` |
| ProcessCommandLine | `powershell.exe -ExecutionPolicy Bypass -File C:\programdata\pwncrypt.ps1` |
| InitiatingProcessFileName | `cmd.exe` |
| InitiatingProcessCommandLine | `"cmd.exe" /c powershell.exe -ExecutionPolicy Bypass -File C:\programdata\pwncrypt.ps1` |
| AccountName | `alex` |

The execution event showed `cmd.exe` launching PowerShell:

```text
cmd.exe /c
└── powershell.exe -ExecutionPolicy Bypass -File C:\ProgramData\pwncrypt.ps1
```

The script was executed under the account `alex`. The `-ExecutionPolicy Bypass` option instructed that PowerShell invocation not to enforce the configured execution policy. Because PowerShell execution policy is not a security boundary, this was documented as execution context rather than proof that a security product was disabled or impaired.

Separately, the `pwncrypt.ps1` file-creation event recorded `powershell.exe` with `explorer.exe` as its parent. Since the captured evidence does not include process IDs needed to fully correlate every event into one end-to-end chain, the creation and execution observations are documented separately.

<img width="1316" height="242" alt="03_process_execution_evidence" src="https://github.com/user-attachments/assets/9af011de-16e3-44e9-8a9d-5c7fe0315547" />

---

#### File-Impact Confirmation

File activity immediately before and after execution was reviewed:

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

**Confirmed Impact** (all events at 8:43:03 PM, one second after execution, all initiated by `powershell.exe -ExecutionPolicy Bypass -File C:\programdata\pwncrypt.ps1` under account `alex`, parent process `cmd.exe`):

| FileName | ActionType | FolderPath |
|---|---|---|
| `temp.csv` | FileCreated | `C:\Users\Alex\Desktop\temp.csv` |
| `5086_CompanyFinancials_pwncrypt.csv` | FileRenamed | `C:\Windows\Temp\5086_CompanyFinancials_pwncrypt.csv` |
| `5107_ProjectList_pwncrypt.csv` | FileCreated | `C:\Users\Alex\Desktop\5107_ProjectList_pwncrypt.csv` |
| `2377_EmployeeRecords_pwncrypt.csv` | FileRenamed | `C:\Windows\Temp\2377_EmployeeRecords_pwncrypt.csv` |
| `__________decryption-instructions.txt` | FileCreated | `C:\Users\Alex\Desktop\__________decryption-instructions.txt` |

The close timing, matching command line, same account, PwnCrypt filename markers, and ransom-note creation together confirm ransomware impact. The file telemetry shows payload-associated file creation and rename activity, while the ransom note provides additional corroboration.

**Supporting screenshots** (in chronological order as returned by the query, `executionTime - 1m` to `executionTime + 5m`):

<img width="1160" height="481" alt="04_impact_query_first_result" src="https://github.com/user-attachments/assets/75dc2667-ac3e-43a8-9fe2-a0d0eab5195e" />

<img width="1316" height="417" alt="05_impact_temp_csv" src="https://github.com/user-attachments/assets/ade309ef-98b4-41ea-b0b3-c732801f3c4f" />

<img width="1316" height="411" alt="06_impact_companyfinancials" src="https://github.com/user-attachments/assets/d7645804-78e2-4e49-a6c4-e0fa93a4795e" />

<img width="1316" height="398" alt="07_impact_projectlist" src="https://github.com/user-attachments/assets/6360d11c-4c57-4c69-8704-25ad293d46e3" />

<img width="1316" height="415" alt="08_impact_employeerecords" src="https://github.com/user-attachments/assets/2104599f-b54e-4006-97e7-a089d1d2ec6b" />

<img width="1316" height="373" alt="09_impact_ransom_note" src="https://github.com/user-attachments/assets/5d0bba60-6e91-4ce7-b16c-469b10970d1f" />

---

#### Scope Assessment

The device restriction was removed from follow-up searches to check the wider environment for the discovered indicators.

**File indicators:**

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

**Execution indicator:**

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

**Scope Conclusion:** All matching activity was associated with `ta-zero-day`. No additional affected endpoints were identified from the discovered PwnCrypt indicators. This confirms the scope observed in available telemetry - it does **not** claim that every possible lateral-movement method was exhaustively ruled out.

---

### Step 4) Timeline Summary

| Time (EDT) | Event | Significance |
|---|---|---|
| 8:43:02 PM | `pwncrypt.ps1` created in `C:\ProgramData` | Payload placed on the endpoint |
| 8:43:02 PM | PowerShell executed the script through `cmd.exe` | Execution confirmed |
| 8:43:03 PM | `_pwncrypt` files created or renamed | File-encryption impact confirmed |
| 8:43:03 PM | Decryption-instructions file created | Ransomware behavior confirmed |
| Post-investigation | `ta-zero-day` isolated in MDE | Threat contained |

> **Time note:** MDE displayed the activity at approximately 8:43 PM EDT. The KQL pivots used the equivalent UTC timestamp `2026-07-13T00:43:02.7034862Z`.

---

### Step 5) MITRE ATT&CK TTP Mapping

Only techniques supported by collected evidence are included.

| Tactic | Technique | Observed Procedure | Evidence Status | Confidence |
|---|---|---|---|---|
| Execution | [T1059.001 - PowerShell](https://attack.mitre.org/techniques/T1059/001/) | PowerShell executed `C:\ProgramData\pwncrypt.ps1` with `-ExecutionPolicy Bypass`. | Telemetry-confirmed | High |
| Execution | [T1059.003 - Windows Command Shell](https://attack.mitre.org/techniques/T1059/003/) | `cmd.exe /c` launched PowerShell to execute the ransomware payload. | Telemetry-confirmed | High |
| Impact | [T1486 - Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/) | Multiple files were created or renamed with the `_pwncrypt` marker, and decryption instructions were generated. | Telemetry-confirmed | High |
| Command and Control | [T1105 - Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/) | The lab scenario specified `Invoke-WebRequest` to retrieve `pwncrypt.ps1` from an external GitHub location. | Scenario-derived; not independently recovered from MDE telemetry | Medium |

#### Mapping Notes

**T1059.001 - PowerShell:** The strongest execution evidence was the direct use of PowerShell to run the payload: `powershell.exe -ExecutionPolicy Bypass -File C:\ProgramData\pwncrypt.ps1`.

**T1059.003 - Windows Command Shell:** The parent-child process chain showed `cmd.exe /c` invoking PowerShell, supporting Windows Command Shell execution in addition to PowerShell.

**T1486 - Data Encrypted for Impact:** The immediate creation/renaming of files with the `_pwncrypt` marker, followed by the ransom-note file, directly supports ransomware-related encryption impact.

**T1105 - Ingress Tool Transfer:** The simulation setup used `Invoke-WebRequest` to transfer the payload from an external web source into `C:\ProgramData`. This is included as scenario-supported context because the download command was not independently recovered from available MDE process telemetry.

#### Techniques Not Mapped

Excluded because collected evidence did not establish them:
- User Execution: Malicious File
- Deobfuscate/Decode Files or Information
- Inhibit System Recovery
- Impair Defenses
- Persistence techniques
- Credential Access techniques
- Lateral Movement techniques

---

### Step 6) Response and Containment

After confirming execution, ransomware impact, and environment-wide scope, `ta-zero-day` was isolated through Microsoft Defender for Endpoint. Isolation restricted network communication while preserving connectivity to Microsoft Defender for continued response actions.

<img width="1316" height="592" alt="10_mde_device_isolation" src="https://github.com/user-attachments/assets/45473caa-5ca3-4c9c-af00-850be85b8e07" />

**Isolation action comment logged in MDE:**
> "I confirmed that pwncrypt.ps1 was executed on this endpoint"

#### Response Summary

> The affected endpoint, `ta-zero-day`, was isolated after confirming PwnCrypt execution and file-encryption activity. Environment-wide IOC searches did not identify additional affected endpoints.

---

### Step 7) Final Assessment

PwnCrypt execution and ransomware impact were confirmed on `ta-zero-day`. The payload was executed through `cmd.exe` and PowerShell under the account `alex`. Immediately afterward, multiple CSV files were created or renamed with the `_pwncrypt` marker, and a decryption-instructions file was created.

Environment-wide searches for the discovered indicators did not identify additional affected endpoints. The affected device was isolated through Microsoft Defender for Endpoint.

---

### Step 8) Improvement Opportunities

| Improvement | Purpose |
|---|---|
| Enable enhanced PowerShell logging and centralized retention | Improve visibility into script blocks, command lines, and download behavior |
| Alert on PowerShell execution from writable paths such as `C:\ProgramData` and user Temp directories | Detect suspicious script placement and execution earlier |
| Detect rapid file creation/rename activity paired with ransom-note indicators | Identify encryption behavior even when the malware filename changes |
| Use application control and least privilege where operationally feasible | Reduce unauthorized script execution and limit endpoint impact |
| Maintain tested, protected, and offline backups | Support recovery without relying on attacker-provided decryption |
| Create reusable KQL hunting templates | Accelerate future payload, execution, impact, and scope pivots |
| Provide user-awareness training | Reduce the chance of users executing untrusted commands or files |

#### Hunting-Process Improvements

- Begin with the strongest available IOC, then broaden only when necessary.
- Preserve `Timestamp`, `DeviceName`, command-line, parent-process, user, and path fields during pivots.
- Use narrow time windows to reconstruct process and file activity.
- Separate telemetry-confirmed findings from scenario-derived context.
- Scope indicators across all endpoints before declaring an incident contained.
- Avoid mapping ATT&CK techniques that are not directly supported by evidence.

---

### Step 9) Key Takeaways

- Threat hunting is driven by investigative questions, not by memorizing one large KQL query.
- File events can provide the timestamp needed to pivot into process telemetry.
- A suspicious script on disk does not prove execution.
- Execution does not prove impact until associated file activity is identified.
- Environment-wide IOC scoping should be completed before documenting an incident as limited to one endpoint.
- MITRE ATT&CK mappings should reflect observed behavior and clearly distinguish confirmed evidence from contextual assumptions.

---

### References

- [MITRE ATT&CK - PowerShell (T1059.001)](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK - Windows Command Shell (T1059.003)](https://attack.mitre.org/techniques/T1059/003/)
- [MITRE ATT&CK - Data Encrypted for Impact (T1486)](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK - Ingress Tool Transfer (T1105)](https://attack.mitre.org/techniques/T1105/)
- Microsoft Defender for Endpoint Advanced Hunting telemetry
- Controlled PwnCrypt ransomware simulation and investigation notes

---

### Disclaimer

This project was completed in a controlled lab environment for defensive cybersecurity training. The ransomware behavior was intentionally simulated on an authorized virtual machine.
