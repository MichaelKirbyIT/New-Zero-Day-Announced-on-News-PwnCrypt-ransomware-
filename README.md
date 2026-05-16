# 🛡️ Project: Zero-Day-Exploitation-and-Ransomware-Deployment
> **Threat Hunt & Incident Analysis Report** | *Platform: Microsoft Defender for Endpoint (MDE)*

---
```
[ ZERO-DAY BREACH ] 
            │
            │  (Initial Foothold & Tool Transfer)
            ▼
  ┌───────────────────┐
  │ 📂 pwncrypt.ps1   │  <-- Staged in C:\ProgramData
  └─────────┬─────────┘
            │
            ▼
 ┌─────────────────────┐     ┌───────────────────────┐
 │   michael-mde-vm    │ ──> │ MDE EDR Telemetry     │
 │  (FileRenamed/Temp) │     │ (AES-256 Encryption)  │
 └──────────┬──────────┘     └───────────────────────┘
            │
            ▼
  ┌───────────────────┐
  │ 🔒 Host Isolated  │  <-- Containment Action (Success)
  └───────────────────┘
```
## Platforms and Languages Leveraged
- Operating System / Infrastructure: Windows 11 Virtual Machine (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint (MDE)
- Query Language: Kusto Query Language (KQL)
- Threat Vector: Post-Exploitation Ransomware Execution & Data Staging

##  Scenario

Following news of a newly weaponized zero-day exploit chain circulating in the wild, an external adversary successfully bypassed the organization's perimeter security controls to gain an initial foothold. Once inside the corporate network, the threat actor targeted `michael-mde-vm` to deploy a destructive ransomware payload.
The attacker dropped a specialized PowerShell encryption script (`pwncrypt.ps1`) into a publicly writeable directory. To maximize impact, the script moved high-value company documents through a hidden staging phase within temporary directories before encrypting the data with an un-bypasable AES-256 algorithm, appending the `.pwncrypt` extension, and dropping ransom notes across the system.
The primary focus of this hunt is to map the specific timeline of the ransomware's deployment, verify data staging behaviors, and validate the scope of the encrypted assets using advanced EDR telemetry correlation.

### High-Level Brute-Force IoC Discovery Plan

- **Track Ransomware Extensions:** Query `DeviceFileEvents` to catch rapid file modification and creation events using the `.pwncrypt` extension.
- **Identify Security Policy Evasion:** Audit `DeviceProcessEvents` to target instances of `powershell.exe` executing scripts out of public folders using explicit execution policy bypass parameters.
- **Reconstruct Staging Patterns:** Trace file manipulation histories to correlate temporary staging paths (like `C:\Windows\Temp\`) with final file outputs on user-facing directories.
- **Isolate Finalization Triggers:** Capture the exact drop timestamp of the ransom instructions file (`__________decryption-instructions.txt`) to mark the formal conclusion of the ransomware execution tree.

---

## Steps Taken

### 1. Verification of Active Ransomware File Actions

An analysis of the `DeviceFileEvents` table confirmed the widespread creation of `.pwncrypt` files, indicating that the ransomware successfully targeted and modified critical business spreadsheets.

**Query used to locate events:**

```kql
let VMName = "michael-mde-vm";
DeviceFileEvents
| where DeviceName == VMName
| where FileName endswith ".pwncrypt.csv" or FileName contains "pwncrypt"
| project Timestamp, ActionType, FileName, FolderPath, InitiatingProcessCommandLine
| order by Timestamp desc
```
**Results:**

<img width="840" height="277" alt="image" src="https://github.com/user-attachments/assets/20f00b4b-53d1-40cf-add6-a9335743d8b0" />


---

### 2. Time-Window Process Analysis ($\pm2$-Minute Pivot)

By pivoting to the `DeviceProcessEvents` table using a narrow window around the attack finalization timestamp ($15:07:28$), logs caught a parent `cmd.exe` process spawning `powershell.exe` with an explicit `-ExecutionPolicy Bypass` flag to dodge default execution constraints.

**Query used to locate events:**

```kql
let specificTime = datetime(2026-05-03T20:07:28.4442274Z);
let VMName = "michael-mde-vm";
DeviceProcessEvents
| where DeviceName == VMName
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| project Timestamp, ActionType, FileName, FolderPath, ProcessCommandLine, InitiatingProcessCommandLine
| order by Timestamp desc
```
**Results:**

<img width="842" height="143" alt="image" src="https://github.com/user-attachments/assets/3059bab7-3f01-4cc0-994f-766bf490d849" />

---

### Summary of Findings

Telemetry confirms a highly coordinated ransomware compromise on `michael-mde-vm` driven by the `pwncrypt.ps1` script block. The adversary successfully exploited an unpatched zero-day to drop the initial payload into `C:\ProgramData\`. Running under a subverted security context, the script systematically routed high-value data arrays through `C:\Windows\Temp\` to bypass real-time file monitors before dropping the finalized encrypted files on the local Desktop. The arrival of the `__________decryption-instructions.txt` artifact confirms that the automated ransomware loop executed to completion.

---

### Threat Hunt Documentation: Michael-MDE-VM Compromise

* **Incident Summary**: A PowerShell-based ransomware attack successfully encrypted sensitive CSV files on a corporate workstation. The attack bypassed existing security controls by leveraging execution policy bypass techniques.
* **Timeline of Events (2026-05-03)**: 
    * **15:07:15**: Malicious execution loop starts; `cmd.exe` initializes the `pwncrypt.ps1` script out of `C:\ProgramData\`.
    * **15:07:22**: Mass data staging and file redirection observed inside `C:\Windows\Temp\`.
    * **15:07:28**: Final data encryption wave finishes; the ransomware drops `__________decryption-instructions.txt` on the Desktop.
* **Key Indicators of Compromise (IOCs)**:
    * **Identified Extensions**: `.pwncrypt`, `.pwncrypt.csv`
    * **Malicious Artifacts**: `pwncrypt.ps1`, `__________decryption-instructions.txt`

---

### MITRE ATT&CK TTP Mapping

* **Tactic: Impact**
    * **Technique:** Data Encrypted for Impact (T1486) — The encryption of EmployeeRecords, ProjectList, and CompanyFinancials.
* **Tactic: Execution**
    * **Technique:** Command and Scripting Interpreter: PowerShell (T1059.001) — Automated payload execution.
* **Tactic: Defense Evasion**
    * **Technique:** Impair Defenses: Disable or Modify Tools (T1562.001) — Circumventing script execution limits via the `Bypass` flag.
    * **Technique:** Masquerading (T1036) — Using common system temp directories to obscure staging behavior.
* **Tactic: Lateral Movement / Lateral Tool Transfer**
    * **Technique:** Lateral Tool Transfer (T1570) — Staging payloads inside writeable public folders.

---

### Response Actions

* **Immediate Network Isolation**: Quarantined `michael-mde-vm` within Microsoft Defender for Endpoint immediately to kill any lateral spreading mechanisms or active command-and-control communication channels.
* **Process Eradication**: Force-terminated all active rogue PowerShell loops and cleanly expunged `c:\programdata\pwncrypt.ps1` alongside temporary files stored in `C:\Windows\Temp\`.
* **Data Integrity Recovery**: Initiated an immediate business continuity workflow to completely restore the encrypted business assets from an uncompromised, air-gapped backup reservoir.
* **Strategic Escalation**: Handed all logged process strings and KQL timelines over to the threat intelligence cell to develop localized signatures against this emerging zero-day variant.

---

### Continuous Security Improvement (Post-Incident Hardening)

#### Prevention (Hardening Posture)
* **PowerShell Strategy Realignment**: Implemented an enterprise-wide Group Policy Object (GPO) enforcing an `AllSigned` or `Restricted` PowerShell execution policy, stripping out standard users' ability to apply execution bypass arguments.
* **Public Directory Locking**: Hardened file-system ACLs across public paths like `C:\ProgramData\` and `C:\Windows\Temp\` to strictly block standard user profiles from executing script binaries or dropping unapproved files.
* **Application Control Enforcement**: Deployed stringent AppLocker application control policies to block unauthorized binaries and scripts from operating within localized user-writeable space.


---

#### Hunting Process Refinement

* **Automated Evasion Logic Alerts**: Implemented a continuous Sentinel Analytic Rule tailored to look for instances of `cmd.exe` executing silent, unapproved command flags or launching obfuscated script configurations.

```kql
// Custom Alert Rule: Target suspicious cmd-to-powershell bypass behavior
DeviceProcessEvents
| where DeviceName == "michael-mde-vm"
| where ProcessCommandLine has_any (" /s", " -s", " /quiet", " -quiet", " /silent", " -silent", " /verysilent", " -qn", " /qn") or ProcessCommandLine has "Bypass"
| where not(FolderPath startswith "c:\\windows\\system32")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessCommandLine
| order by Timestamp desc
```

* **Ransomware Extension Custom Analytics:** Standardized a highly reliable, case-insensitive KQL rule directly within the central monitoring queue to catch quick-burst file manipulations using suspicious file names or extension variants.

* **Behavioral Correlation Rules:** Programmed behavioral detection correlation modules designed to trigger high-severity incident responses the moment rapid `FileRenamed` actions in temporary paths match up symmetrically with new text file generations on user Desktops.
