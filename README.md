# RDP-Exposure-Abuse-Password-Spray-Resulting-in-Endpoint-Takeover

## 🧾 Executive Summary

A remote threat actor successfully compromised the **Windows 11 Pro** endpoint **`Windows-11-pro`** via a **password spray / brute-force attack** against an **exposed RDP service**. The adversary authenticated using valid credentials for the **local administrative account `adam2040`** on **2026-01-11 at 18:40:57 UTC**, originating from the external IP address **50.116.54.114**.

Following initial access, the attacker executed a **fully scripted post-exploitation chain**, which included:

- Host and environment reconnaissance  
- Malicious PowerShell execution  
- Data collection and staging  
- Persistence deployment  
- **Confirmed data exfiltration** to an external **command-and-control (C2)** server at **50.116.54.114:35393**

The attack demonstrated **advanced defense evasion techniques**, including:

- Process injection into a trusted Microsoft binary (`msedge.exe`)
- Modification of **Microsoft Defender** configuration via exclusion rules
- Masqueraded persistence mechanisms using **Microsoft-themed naming conventions and directories**

Notably, **Microsoft Defender for Endpoint (MDE)** generated **no alerts at any stage of the attack**, indicating a **complete detection failure across the entire kill chain**.

No evidence of **lateral movement** or **credential dumping** was observed. All malicious activity remained **fully contained to the compromised host**.


## 🔓 Initial Access

**MITRE ATT&CK Technique:**  
- **T1110.001 – Brute Force: Password Guessing**

**Attack Vector:**  
- Remote Desktop Protocol (RDP)

**Entry Point:**  
- TCP Port **3389**

**Attack Source IP:**  
- `50.116.54.114`

**Compromised Account:**  
- Local Administrator account: **`adam2040`**

**Successful Authentication Time:**  
- **2026-01-11 18:40:57 UTC**

The adversary gained initial access by successfully authenticating to an externally exposed RDP service using valid credentials. Activity indicates a password spray or brute-force attempt that ultimately resulted in a successful logon to the target Windows 11 Pro endpoint.

---

### 📊 Evidence: Microsoft Defender for Endpoint – DeviceLogonEvents

The following KQL query was used to identify RDP logon activity associated with the compromised host and timeframe:

```kql
DeviceLogonEvents
| where DeviceName contains "Windows-11-pro"
| where Timestamp between (datetime(2026-01-11) .. datetime(2026-01-15))
| project Timestamp, AccountName, DeviceName, Protocol, RemoteIP, ActionType, FailureReason,InitiatingProcessCommandLine, RemoteIPType,RemoteDeviceName, RemotePort
```
<img width="934" height="373" alt="inital access " src="https://github.com/user-attachments/assets/d624ec05-e1e2-49e5-89c5-47acc77e4895" />

## ⚔️ Attack Details

The adversary conducted an **RDP brute-force attack** against the host **`flare`** originating from the external IP address **169.71.116.189**. Authentication telemetry indicates repeated failed logon attempts consistent with password guessing activity.

### 🔍 Observed Telemetry

- **Attack Source IP:** `169.71.116.189`
- **Attack Technique:** Brute Force via RDP (MITRE ATT&CK **T1110.001**)
- **Total Failed Login Attempts:** **18**
- **Successful Logins:** **0**
- **Targeted Accounts:**
  - `adam2040`
  - `admin`
- **Number of Distinct Accounts Targeted:** **2**

### 🧠 Analysis

The pattern of repeated failed RDP authentication attempts across multiple accounts strongly indicates a **password spray / brute-force attempt**. No successful authentication was observed from this source IP, suggesting the attack was **unsuccessful** at this stage.

This activity likely represents **pre-compromise reconnaissance or credential access attempts** and may have preceded or coincided with a successful compromise from a different source IP observed elsewhere in the investigation.

Despite the clear brute-force indicators, **no Microsoft Defender for Endpoint alerts were generated**, highlighting a missed detection opportunity during the credential access phase.

<img width="484" height="188" alt="Failure" src="https://github.com/user-attachments/assets/89b59fe9-162f-45c6-acb1-0c5ece43d082" />

## 🧪 Authentication Telemetry & OSINT Correlation

To quantify authentication activity by source IP, the following KQL query was executed against **Microsoft Defender for Endpoint** telemetry:

```kql
DeviceLogonEvents
| where DeviceName contains "Windows-11-pro"
| where Timestamp between (datetime(2026-01-11) .. datetime(2026-01-15))
| summarize 
    Failures   = countif(ActionType == "LogonFailed"),
    Successes  = countif(ActionType == "LogonSuccess"),
    Users      = dcount(AccountName)
by RemoteIP
```
## 📊 Results — Source IP: `169.71.116.189`

- **Failed Logon Attempts:** 18  
- **Successful Logons:** 0  
- **Distinct Accounts Targeted:** 2  
- **Targeted Host:** `Windows-11-pro`  
- **Authentication Method:** RDP  

---

## 🌐 Network Attribution

- **IP Address:** `169.71.116.189`  
- **Autonomous System (ASN):** DIGITALOCEAN-ASN  
- **Hosting Type:** Cloud Infrastructure (High Abuse Potential)  

---

## 🕵️ OSINT Findings

Open-source intelligence enrichment for the source IP revealed:

- 🚩 Flagged as **malicious** on **VirusTotal**
- 🚫 Reported for **abusive activity** on **AbuseIPDB**

---


<img width="883" height="331" alt="virustotal" src="https://github.com/user-attachments/assets/0f6a86bf-7e8e-430a-8180-e3a02ab02dac" />


## 🧩 Post-Login Activity

Immediately following successful authentication, the adversary initiated a series of **post-exploitation actions** indicative of automated attacker tradecraft.

### 🔎 Execution & Discovery

- Execution of **PowerShell** and **Command Prompt (CMD)** for system and environment discovery
- Use of native Windows utilities (LOLBins) to enumerate host configuration, users, and processes

### 🧪 Suspicious Script Execution

The following **PowerShell scripts** were executed shortly after logon:

- `update_check.ps1`
- `wmi_maintenance.ps1`
- `mscloudsync.ps1`

<img width="940" height="422" alt="Powershell" src="https://github.com/user-attachments/assets/4e2d9287-d840-441e-861d-6b7879a7a142" />

## 🌐 Command-and-Control (C2) Network Activity

Post-compromise analysis identified **outbound network connections** from the compromised host **`Windows-11-pro`** to the external IP address **`50.116.54.114`**, consistent with **command-and-control (C2) communication**.

### 🔗 Observed Network Behavior

- **Destination IP:** `50.116.54.114`
- **Initiating Process:** `svchost.exe`
- **Connection Direction:** Outbound
- **Behavior Pattern:** Periodic external connections following script execution

The use of **`svchost.exe`**—a trusted Windows system binary—to initiate network traffic strongly indicates **process masquerading or injection**, enabling the attacker to blend malicious communications into normal system activity.

---

### 📊 Evidence: Microsoft Defender for Endpoint – DeviceNetworkEvents

The following KQL query was used to pivot from host activity to network telemetry associated with the suspected C2 infrastructure:

```kql
// Pivot to network events from flare to candidate IP
DeviceNetworkEvents
| where DeviceName contains "Windows-11-pro"
| where Timestamp between (datetime(2026-01-11) .. datetime(2026-01-15))
| where RemoteIP == "50.116.54.114"
| where InitiatingProcessCommandLine contains "svchost.exe"
| project  Timestamp,  RemoteIP,RemotePort, InitiatingProcessFileName
```


<img width="1521" height="1121" alt="network" src="https://github.com/user-attachments/assets/6f628fa2-45f8-40d0-bdf2-dc01ee06a6f1" />

# Malicious Execution Chain

Manual Reconnaissance Commands (01:21 – 10:26)

- `systeminfo`
- `whoami`
- `net user`
- `net localgroup administrators`
- `ipconfig /all`
- `netstat -ano`
- `tasklist /svc`
- `wmic computersystem get domain`

---

## Script Execution (01:05 - 01:07)

- `update_check.ps1: Unknown function (requires collection)`

- `wmi_maintenance.ps1: - Process injection script targeting `msedge.exe`
  
- `mscloudsync.ps1 -: Data collection and persistence script`

<img width="1129" height="814" alt="zip" src="https://github.com/user-attachments/assets/a7fb9ef9-7c3a-414c-b2d0-64f2b8192637" />

Persistence Mechanism Creation (01:06 - 01:07)

## Persistence Mechanisms

### Fake Windows Service
- **Service Name:** `MSUpdateService`

### Registry Persistence
- **Run Key:** `MSCloudSync`

### Scheduled Task
- **Task Name:** `MicrosoftUpdateSync`

<img width="1100" height="1108" alt="update" src="https://github.com/user-attachments/assets/3c58ead7-e6b3-4182-bd4e-129a5fb16484" />

## Process Injection Evidence

- **Suspected Script:** `wmi_maintenance.ps1`
- **Injection Target:** `msedge.exe`

### Description
- The script contains logic consistent with **process injection** techniques.
- Execution of `wmi_maintenance.ps1` initiated malicious activity by injecting into a legitimate process (`msedge.exe`).
- The technique appears **designed to evade EDR logging and antivirus detection**.

### Detection & Response
- **Microsoft Defender for Endpoint (MDE):** No alerts generated during execution.
- This indicates **successful evasion** of endpoint security controls.

## Malicious / Attacker-Created Artifacts

### Fake Microsoft Update Directory
**Path:**  
`C:\ProgramData\Microsoft\Windows\Update*`

- Masquerades as a legitimate Windows Update location
- **Contains:**
  - `mscloudsync.ps1` — persistence and data collection script

---

### Public User Directory Abuse
**Path:**  
`C:\Users\Public*`

- User-writable directory abused for malware staging
- **Contains:**
  - `msupdate.exe`
  - `update_check.ps1`

---

### Temporary Directory (Data Staging / Exfiltration)
**Path:**  
`C:\Users\adam2040\AppData\Local\Temp*`

- Used as a staging location for stolen data
- **Contains:**
  - `backup_sync.zip` — suspected exfiltration archive

---

### WMI Log Directory Abuse
**Path:**  
`C:\Windows\System32\LogFiles\WMI*`

- Unusual location for PowerShell scripts
- **Contains:**
  - `wmi_maintenance.ps1` — **high-confidence process injection script**

## Legitimate Windows Folders (Abused)

### System32 Abuse
**Path:**  
`C:\Windows\System32*`

- Legitimate Windows system directory
- Abused by the attacker to execute `cmd.exe` as part of malicious activity

---

### PowerShell Engine Abuse
**Path:**  
`C:\Windows\System32\WindowsPowerShell\v1.0*`

- Standard PowerShell installation path
- Used to execute malicious PowerShell scripts while blending in with legitimate activity

---

## Key Observations
- The attacker deliberately used  
  `C:\ProgramData\Microsoft\Windows\Update`  
  to **blend in with legitimate Microsoft Update processes**.
- A mix of **user-writable directories** (e.g., `C:\Users\Public\`) and **system directories** was used to reduce suspicion.
- Temporary directories were leveraged for **data staging prior to exfiltration**, indicating an organized attack workflow.

<img width="1649" height="1353" alt="exfiltrationi" src="https://github.com/user-attachments/assets/576ac25a-b489-4f77-acb6-b3d4afc35237" />

==

Environment Scope: All malicious execution isolated to host adam2040 only. No other devices contacted malicious IPs or executed suspicious scripts.

```KQL
// Pivot to network events from flare to candidate IP
DeviceNetworkEvents
| where DeviceName contains "Windows-11-pro"
| where Timestamp between (datetime(2026-01-11) .. datetime(2026-01-15))
| where RemoteIP == "50.116.54.114"
| where InitiatingProcessCommandLine contains "svchost.exe"
| project Timestamp, RemoteIP, RemotePort, InitiatingProcessFileName
```
<img width="1521" height="1121" alt="network" src="https://github.com/user-attachments/assets/4c7aeeac-2c03-404d-b197-6ab372df7256" />

## Persistence Mechanisms Deployed

### 1. Fake Windows Service — `MSUpdateService`
- **Registry Path:**  
  `HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\MSUpdateService`
- **Binary Path:**  
  `C:\ProgramData\Microsoft\Windows\Update\mscloudsync.ps1`
- **Purpose:** Execute malicious payload on system boot
- **Masquerading:** Designed to appear as a legitimate Microsoft Update service

---

### 2. Registry Run Key — `MSCloudSync`
- **Registry Path:**  
  `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- **Value Name:** `MSCloudSync`
- **Value Data:** PowerShell execution of `mscloudsync.ps1`
- **Purpose:** Execute payload on user login
- **Masquerading:** Mimics a Microsoft cloud synchronization service

---

### 3. Scheduled Task — `MicrosoftUpdateSync`
- **Registry Path:**  
  `TaskCache\Tree\MicrosoftUpdateSync`
- **Creation Time:** `2026-01-11 01:06:26`
- **Purpose:** Additional persistence and execution trigger
- **Masquerading:** Mimics Windows Update scheduling behavior


```kql
// Registry hunt for persistence mechanisms
DeviceRegistryEvents
| where DeviceName contains "Windows-11-pro"
| where Timestamp between (datetime(2026-01-11) .. datetime(2026-01-15))
| where RegistryKey has_any ("MSUUpdateService","MSUpdateService")
    or RegistryValueData contains "mscloudsync"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, ActionType
| order by Timestamp desc
```

<img width="1534" height="1128" alt="regis" src="https://github.com/user-attachments/assets/40a0afdc-6390-46ff-b3e2-4cad318b10eb" />


## Scope Validation

- All identified persistence mechanisms were **isolated to a single host**: `Windows-11-pro`.
- No other systems in the environment showed indicators of:
  - Fake Windows services
  - Registry Run key abuse
  - Malicious scheduled tasks
- No evidence of lateral movement or persistence deployment on additional hosts was observed.

---

## Privilege Escalation

### Assessment
**Not applicable.**  
The compromised account already possessed sufficient privileges to achieve attacker objectives.

### Privileged Access Confirmation
The account `adam2040` was confirmed to have **administrative or elevated privileges**, as evidenced by the ability to:

- Create and manage Windows services
- Modify `HKEY_LOCAL_MACHINE` registry keys
- Create scheduled tasks
- Add Microsoft Defender exclusions

### Conclusion
- No additional privilege escalation techniques were observed.
- Elevated access was available from initial compromise and remained sufficient throughout the attack lifecycle.

## Defense Evasion

### 1. Windows Defender Exclusions
- **Timestamp:** `2025-09-16 19:39:48`
- **Purpose:** Bypass signature-based detection of malicious executables
- **Folder Exclusion:**  
  `C:\Windows\Temp`
- **Registry Path:**  
  `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths`

<img width="1430" height="1116" alt="defender" src="https://github.com/user-attachments/assets/f914b1a5-b97b-4ded-b72c-7428afa029f1" />


### 2. Masquerading (T1036)

All malicious components were deliberately named to **mimic legitimate Microsoft services** to evade detection.

#### Masqueraded Artifacts
- `MSUpdateService` → Windows Update Service
- `MSCloudSync` → Microsoft Cloud Sync
- `MicrosoftUpdateSync` → Microsoft Update Scheduler
- `mscloudsync.ps1` → Microsoft cloud sync script

#### Blending Technique
- File paths were chosen to resemble legitimate Windows locations:
  - `C:\ProgramData\Microsoft\Windows\Update\`

```Kql
DeviceFileEvents
| where DeviceName contains "Windows-11-pro"
| where Timestamp between (datetime(2026-01-11) .. datetime(2026-01-15))
| where FileName has_any ("update_check.ps1","wmi_maintenance.ps1","mscloudsync.ps1","msupdate.exe")
| project Timestamp, DeviceName, FolderPath, FileName, ActionType
| order by Timestamp desc
```

### 3. Process Injection (Suspected)

- **Script:** `wmi_mscloudsync.ps1`
- **Target Process:** `msedge.exe` (Microsoft Edge)
- **Purpose:** Execute malicious code within a trusted process to evade EDR detection

#### Findings
- Second-stage payload execution generated **no Microsoft Defender for Endpoint (MDE) alerts**.
- Command-line activity and script behavior strongly indicate **process injection techniques**.
- Memory-level confirmation was not performed; therefore, injection remains **suspected but high-confidence**.

#### Detection Gap
- **EDR Visibility:** Microsoft Defender for Endpoint generated **zero alerts across the entire attack chain**.
- This indicates **successful evasion of endpoint detection mechanisms**.

---

## Credential Access

### Assessment
- **No credential dumping or credential access activity detected**.
- No evidence of LSASS access, credential harvesting tools, or password extraction techniques was observed.

## Checks Performed

Comprehensive hunting queries were executed to identify potential credential access activity, including:

- **LSASS memory access**
  - `lsass.exe`, `procdump`, `rundll32`, `comsvcs.dll`
- **Registry hive dumping**
  - `reg save` of `SAM`, `SECURITY`, `SYSTEM` hives
- **Credential theft tools**
  - `mimikatz`, `sekurlsa`, `nanodump`, `Get-Credential`
- **Volume Shadow Copy abuse**
  - `vssadmin`

### Results
- No command-line or process activity related to credential dumping was observed within the investigation timeframe.

---

## Analysis

The absence of credential theft activity suggests:

- The attacker did **not require additional credentials** to meet their objectives.
- Command-and-control (C2) beacon activity may have occurred **in-memory**, bypassing command-line logging.
- The compromise may have been **limited to local data access and exfiltration objectives**.

### Recommendation
- **Escalate to Tier 2** for memory forensics and deeper analysis to confirm the absence of stealthy credential theft techniques.

---

## Discovery

### Discovery Commands Executed
The attacker executed a scripted sequence of reconnaissance commands via `cmd.exe` and `powershell.exe`.

### Discovery Analysis

**Behavior Pattern**
- All commands executed in **rapid succession (within ~2 minutes)**, indicating:
  - Automated or tool-assisted execution
  - Pre-scripted reconnaissance phase
  - Lack of interactive or exploratory behavior

**Focus Areas**
- Host reconnaissance (OS version, running processes, services)
- Privilege and group membership enumeration
- Network discovery and domain environment assessment

**Not Observed**
- No Active Directory enumeration tools were used (e.g., `nltest`, `dsquery`).

### Key Finding
- Execution of `wmic computersystem get domain` suggests the attacker assessed **lateral movement potential**.
- No subsequent lateral movement or domain-based activity was observed.

### Discovery Commands Executed

## Lateral Movement

### Assessment
- **No lateral movement detected.**

---

## Checks Performed

### 1. Account Reuse on Other Hosts
- **Query:** Searched for usage of the `adam2040` account across all devices
- **Result:** No successful logons observed on any host other than `Windows-11-pro`

---

### 2. Remote Execution Tools
- **Query:** Searched for evidence of:
  - PsExec
  - WMI-based remote execution
  - WinRM
  - `Invoke-Command`
  - `New-PSSession`
- **Result:** No evidence of remote execution tools used

---

### 3. Cross-Host Process Execution
- **Query:** Reviewed process creation events associated with the `adam2040` account
- **Result:** All observed process activity was limited to `Windows-11-pro`

---

### 4. Lateral Network Connections
- **Query:** Investigated internal network connections using common lateral movement ports:
  - `135` (RPC)
  - `139` (NetBIOS)
  - `445` (SMB)
  - `3389` (RDP)
- **Result:** No internal lateral connections were observed
```Kql
// General Discovery Commands from Attacker Account
DeviceProcessEvents
| where DeviceName contains "Windows-11-pro"
| where Timestamp between (datetime(2026-01-11) .. datetime(2026-01-15))
| where ProcessCommandLine has_any ("systeminfo", "whoami", "tasklist", "ipconfig",
    "netstat", "net user", "net localgroup", "nltest", "dsquery")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```

<img width="1541" height="1278" alt="discovery" src="https://github.com/user-attachments/assets/bf878582-5bce-4b9e-a8a1-438f5b31908a" />

### Domain Discovery Evidence

Single Command: wmic computersystem get domain executed at 01:07:22

```Kql
DeviceProcessEvents
| where DeviceName contains "Windows-11-pro"
| where Timestamp between (datetime(2026-01-11) .. datetime(2026-01-15))
| where InitiatingProcessAccountName == "adam2040"
| where ProcessCommandLine contains "wmic computersystem get domain"
| project Timestamp, FileName, ProcessCommandLine
```
### Domain Discovery Assessment

This command is commonly used to:

- Fingerprint the domain environment
- Assess lateral movement opportunities
- Determine whether the host is domain-joined

**Conclusion:**  
The attacker performed domain discovery to assess the environment but did **not** proceed with lateral movement.

This suggests one of the following:

1. The attack objective was limited to **local data exfiltration**
2. Lateral movement phases had **not yet begun** at the time of detection
3. The compromised host was the **intended target**

**Scope:**  
All malicious activity remains isolated to host `adam2040`. No other systems were compromised.

---

## Collection

Files Staged for Exfiltration

```KQL
 // Find staged sensitive files and correlate with C2
DeviceFileEvents
| where Timestamp between (datetime(2026-01-11) .. datetime(2026-01-15))
| where FolderPath has_any ("Documents", "AppData\\Local\\Temp")
    and FileName has_any ("backup_sync.zip", "network_credentials.txt", "financial_report_Q4.pdf")
| project Timestamp, DeviceName, InitiatingProcessFileName, FolderPath, FileName, ActionType
| join kind=inner (
    DeviceNetworkEvents
    //| where RemoteIP == "185.92.220.87" and RemotePort == 8081
    | project OutboundTime=Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort, Protocol
) on DeviceName
```
<img width="649" height="353" alt="exfiltrationi" src="https://github.com/user-attachments/assets/5a4273a6-b9cf-442f-a6b3-0b87275e5107" />


### Collected Artifacts

| Timestamp | Filename                  | Location                                      | Initiating Process |
|----------|---------------------------|-----------------------------------------------|--------------------|
| 01:08:26 | network_credentials.txt   | C:\Users\adam2040\Documents\                  | powershell.exe     |
| 01:08:26 | financial_report_Q4.pdf   | C:\Users\adam204\Documents\                   | powershell.exe     |
| 01:08:27 | backup_sync.zip           | C:\Users\adam2040\AppData\Local\Temp\         | powershell.exe     |

### Collection Process

#### File Discovery (01:08 – 01:20)
The attacker enumerated multiple directories commonly used to store sensitive user data:

- `C:\Users\adam2040\Documents\`
- `C:\Users\adam2040\Downloads\`
- `C:\Users\adam2040\Desktop\`
- `C:\Users\adam2040\AppData\Local\Temp\`

#### Archive Creation (01:08:06)
- A compressed archive, `backup_sync.zip`, was created via `powershell.exe`.
- The archive likely contains collected sensitive files.
- The file was stored in the user’s temporary directory, indicating **data staging prior to exfiltration**.

<img width="389" height="261" alt="backup" src="https://github.com/user-attachments/assets/3d251bb9-ad71-4526-a08b-20ed42a72dba" />

## Timeline Analysis

- Collection activity occurred **immediately after host discovery commands**.
- The attack followed a **tightly scripted execution flow**:
  - Reconnaissance → File collection → Archiving
- There was an estimated **3-minute window** between file staging and suspected exfiltration.

---

## Collection Techniques

- **Script-based collection:**  
  Likely automated via PowerShell scripts (e.g., `mscloudsync.ps1`).
- **No visible tooling:**  
  No evidence of common archiving or collection tools such as `7z.exe`, `robocopy`, or similar utilities.
- **In-memory operations:**  
  Suspected process injection into `msedge.exe` was used to execute malicious logic while avoiding antivirus and EDR logging.

## Command and Control / Exfiltration

### Command and Control Infrastructure
- **C2 IP Address:** `185.92.220.87`
- **C2 Port:** `8081`
- **Protocol:** HTTP POST
- **Initiating Process:** `powershell.exe`

---

### Exfiltration Activity
- **Timestamp:** `2025-09-16 19:41:30`
- **Method:** HTTP POST
- **Destination:** `50.116.54.114:35393`
- **Exfiltrated File:** `backup_sync.zip`
- **Staging Location:**  
  `C:\Users\adam2040\AppData\Local\Temp\`
- **Process:** `powershell.exe`

---

### Timeline Correlation

- **19:41:26** — Sensitive files created  
  (`network_credentials.txt`, `financial_report_Q4.pdf`)
- **19:41:30** — Archive created  
  (`backup_sync.zip`)
- **19:41:30** — Outbound HTTP POST to `185.92.220.87:8081`  
  (data exfiltration)
- **19:42:02** — Network connection terminated

---

### Analysis
- The extremely tight timing (**~4 seconds**) between archive creation and outbound HTTP POST confirms **automated, script-driven exfiltration**.
- Activity strongly indicates a **pre-configured exfiltration workflow**, rather than manual attacker interaction.
- 
 ## Indicators of Compromise (IOCs)
- `C:\Users\adam2040\AppData\Local\Temp\backup_sync.zip`
- `C:\Users\adam2040\Documents\financial_report_Q4.pdf`

```kql
KQL : 
// Find staged sensitive files and correlate with C2
DeviceFileEvents
| where Timestamp between (datetime(2026-01-11) .. datetime(2026-01-15))
| where FolderPath has_any ("Documents", @"AppData\Local\Temp")
| where FileName has_any ( "backup_sync.zip", "network_credentials.txt", "financial_report_Q4.pdf")
| project Timestamp,DeviceName,InitiatingProcessFileName,FolderPath,FileName,ActionType
| join kind=inner (
 DeviceNetworkEvents
| where Timestamp between (datetime(2026-01-11) .. datetime(2026-01-15))
| where RemoteIP == "50.116.54.114"
| where RemotePort == 35393
| project  OutboundTime = Timestamp,DeviceName,InitiatingProcessFileName, RemoteIP, RemotePort,Protocol) on DeviceName
| order by Timestamp desc
```

## Network Indicators

- No interactive command-and-control (C2) beaconing observed.
- A **single HTTP POST** transaction was used for data exfiltration.
- No additional C2 channels or IP addresses were detected within the investigation window.
- Outbound network activity was limited to **malicious infrastructure**:
  - `50.116.54.114`
    
<img width="923" height="466" alt="c2" src="https://github.com/user-attachments/assets/0b8d8ba7-761e-42a5-b007-d8de7b06e96b" />

## Impact

### Impact Summary
**Full-chain compromise resulting in confirmed data exfiltration and endpoint trust violation.**

---

## Confirmed Business Impact

### 1. Data Exfiltration
**Critical Documents Exfiltrated:**
- `network_credentials.txt` — Potential credential exposure
- `financial_report_Q4.pdf` — Confidential financial data
- `backup_sync.zip` — Aggregated sensitive data archive

- **Data Loss Type:** Confidentiality breach
- **Exfiltration Confirmed:** HTTP POST to `50.116.54.114:35393`

---

### 2. EDR Detection Gaps
- **Zero alerts** generated by Microsoft Defender for Endpoint (MDE) throughout the entire attack chain
- Evasion techniques successfully bypassed signature-based detection
- Process injection into `msedge.exe` avoided EDR telemetry
- Defender exclusions disabled scanning of malicious file paths

---

### 3. Endpoint Compromise
- **Host Status:** `adam2040` (`Windows-11-pro`) fully compromised
- **Compromised Account:** `adam2040` (administrative privileges)

**Persistence Mechanisms:**
- Fake Windows service
- Registry Run key
- Scheduled task

**Trust Violation:**
- Endpoint integrity **cannot be assured**

**Required Action:**
- Immediate isolation
- Forensic triage
- Full system rebuild

---

### 4. Breach Severity
- **Classification:** **High**

**Justification:**
- Attacker achieved full access to the compromised host
- All endpoint detection mechanisms were bypassed
- Sensitive data was successfully exfiltrated to external C2 infrastructure
- Persistent access was maintained via multiple mechanisms
- No detection or prevention at any stage of the attack

---

## Scope of Compromise
- **Affected Systems:** 1 host (`adam2040`)
- **Lateral Spread:** None observed
- **Credential Theft:** Not detected (requires validation via memory forensics)
- **Data Exfiltration:** Confirmed (3 sensitive files)

---

## Recommendations

### Immediate Containment
- Isolate host `Windows-11-pro` from the network
- Force password reset for account `adam2040` and related accounts
- Capture forensic memory and disk images

### Environment Hardening
- Hunt for related IOCs across all endpoints
- Review and tune EDR detection rules
- Engage Tier 2 / Tier 3 IR for advanced threat hunting and root cause analysis

---

## Conclusion
This was **not** a failed intrusion attempt.

The attacker:
- Successfully gained access
- Established persistence
- Evaded endpoint detection
- Collected and staged sensitive data
- Exfiltrated data to external command-and-control infrastructure

The complete absence of EDR alerts throughout the attack chain indicates **effective and deliberate evasion techniques** and highlights **critical gaps in defensive capabilities**.

---

## Attack Timeline

| Timestamp | Stage | Event | Source IP |
|--------|------|------|----------|
| 2025-09-14 | Reconnaissance | Initial probing activity begins | 50.116.54.114 |
| 2025-09-16 18:40:57 | Initial Access | Successful RDP login | 50.116.54.114 |
| 2025-09-16 19:26:10 | Execution | `wmi_maintenance.ps1` created | - |
| 2025-09-16 19:38:01 | Execution | `msupdate.exe`, `update_check.ps1`, `mscloudsync.ps1` created | - |
| 2025-09-16 19:39:02 | Defense Evasion | Process injection into `msedge.exe` | - |
| 2025-09-16 19:39:45 | Persistence | Scheduled task created (`MicrosoftUpdateSync`) | - |
| 2025-09-16 19:39:48 | Defense Evasion | Defender exclusions added | - |
| 2025-09-16 19:40:28 | Discovery | System and network enumeration | - |
| 2025-09-16 19:41:26 | Collection | Sensitive files staged | - |
| 2025-09-16 19:41:30 | Collection | `backup_sync.zip` created | - |
| 2025-09-16 19:41:30 | C2 | Connection established | 50.116.54.114 |
| 2025-09-16 19:41:30 | Exfiltration | HTTP POST to external server | - |
| 2025-09-16 19:42:02 | Exfiltration | Data transfer completed | 50.116.54.114 |
| 2025-09-17 00:40:57 | - | End of observed activity window | - |

---

## Indicators of Compromise (IOCs)

### Network Indicators

| Type | Value | Description | First Seen | Last Seen |
|----|------|------------|-----------|-----------|
| IPv4 | 159.26.106.84 | Initial access / RDP activity | 2025-09-14 | 2025-09-20 |
| IPv4 | 185.92.220.87 | C2 / Exfiltration server | 2025-09-16 19:41:30 | 2025-09-16 19:42:02 |
| Port | 3389 | RDP service | 2025-09-14 | 2025-09-16 |
| Port | 8081 | HTTP C2 / Exfiltration | 2025-09-16 19:41:30 | 2025-09-16 19:42:02 |
| URL | http://185.92.220.87:8081 | Exfiltration endpoint | 2025-09-16 19:41:30 | - |

---

### File Indicators

| File | Path | SHA256 | Description |
|----|------|--------|-------------|
| `wmi_maintenance.ps1` | `C:\Windows\System32\LogFiles\WMI\` | `cd5ef463312a11969441ce659c5576b7e16043428a877ceb706692455f86ff0e` | Process injection |
| `update_check.ps1` | `C:\Users\Public\` | `462113381eb7f63034b9cc6af084acb4c5d992de5241b9fe9e3aa5a3bba6ab04` | Unknown malicious |
| `mscloudsync.ps1` | `C:\ProgramData\Microsoft\Windows\Update\` | `8e9e4c6397dede1449118baf3314b2ee63edf45fbb303bc347ae4a9c2777dbbd` | Persistence / collection |
| `msupdate.exe` | `C:\Users\Public\` | `9785001b0dcf755eddb8af294a373c0b87b2498660f724e76c4d53f9c217c7a3` | Malicious binary |
| `backup_sync.zip` | Temp directory | `ec9cd68162f4cf8adaaac76b64ca537a610bbd8755de47f28ddcb155b71c391a` | Exfil archive |

---

## Detection & Recommendations

### Immediate (0–24h)
- Isolate affected host
- Reset compromised credentials
- Block malicious IPs
- Collect forensic images

### Short Term (1–7 days)
- Rebuild endpoint
- Tune EDR detections
- Enable tamper protection
- Monitor outbound traffic

### Long Term (1–3 months)
- Enforce MFA
- Harden RDP
- Implement PAM
- Improve PowerShell/WMI logging
- Establish continuous threat hunting

## Detections (KQL)

---

### 1. Initial Access Detection — RDP Brute Force Pattern

```kql
// Find candidate attacker IPs (failed attempts + at least one success)
DeviceLogonEvents
| where DeviceName contains "flare"
| where Timestamp between (datetime(2025-09-14) .. datetime(2025-09-18))
| summarize Failures = countif(ActionType == "LogonFailed"),Successes = countif(ActionType == "LogonSuccess"), Users = dcount(AccountName)
  by RemoteIP
| where Failures > 3 and Successes > 0 and Users > 1
| order by Failures desc
```

2. Execution Detection — Malicious Script Identification
```Kql
// Find suspect scripts / filenames in the execution window
DeviceProcessEvents
| where Timestamp between (datetime(2025-09-16 18:40:57) .. datetime(2025-09-17 00:40:57))
| where FileName in ("msupdate.exe", "powershell.exe", "cmd.exe")
   or ProcessCommandLine contains "update_check.ps1"
   or ProcessCommandLine contains "wmi_maintenance.ps1"
   or ProcessCommandLine contains "mscloudsync.ps1"
| project  Timestamp,  DeviceName, AccountName = InitiatingProcessAccountName, FileName, ProcessCommandLine, FolderPath
| order by Timestamp asc
```
3. Persistence Detection — Fake Service and Run Key
```Kql
// Known persistence registry and service entries
DeviceRegistryEvents
| where DeviceName == "flare"
| where InitiatingProcessAccountName == "slflare"
| where Timestamp between (datetime(2025-09-16 18:40:57) .. datetime(2025-09-17 00:40:57))
| where RegistryKey has_any (
    @"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services",
    @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
)
| projectTimestamp,  RegistryKey,RegistryValueName, RegistryValueData, ActionType
| order by Timestamp asc
```

4. Defense Evasion Detection — Defender Exclusion

```Kql
// Defender exclusion hunting
DeviceRegistryEvents
| where DeviceName contains "flare"
| where RegistryKey contains "Windows Defender"
| where RegistryKey contains "Exclusions"
| project Timestamp, RegistryKey,  RegistryValueName, InitiatingProcessAccountName
```
5. Collection & Exfiltration Correlation
   
```Kql
    // File staging event
DeviceFileEvents
| where Timestamp between (datetime(2025-09-16T19:35:00Z) .. datetime(2025-09-16T19:45:00Z))
| where FolderPath has "AppData\\Local\\Temp"
| where FileName == "backup_sync.zip"
| project
    Timestamp,
    DeviceName,
    FolderPath,
    FileName,
    InitiatingProcessFileName
// Join with outbound traffic to known attacker IP
| join kind=inner (
    DeviceNetworkEvents
    | where RemoteIP == "185.92.220.87"
    | where RemotePort == 8081
    | where Timestamp between (datetime(2025-09-16T19:35:00Z) .. datetime(2025-09-16T19:50:00Z))
    | project
        OutboundTime = Timestamp,
        DeviceName,
        InitiatingProcessFileName,
        RemoteIP,
        RemotePort
) on DeviceName
```

# Detection Gaps Identified

## Microsoft Defender for Endpoint (MDE)
- Zero alerts generated throughout the attack chain
- Process injection into `msedge.exe` bypassed EDR telemetry
- PowerShell script execution not flagged
- Data exfiltration to external IP not detected

## Network Detection
- No firewall alerts for outbound connections to suspicious IPs
- No proxy logs showing HTTP POST to non-standard port `8081`

## Endpoint Protection
- Defender exclusions allowed malware staging without detection
- Service creation with masqueraded name not flagged
- Registry Run key modification not alerted

---

# MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Procedure | Evidence |
|------|-------------|---------------|----------|----------|
| Initial Access | T1078 | Valid Accounts | RDP brute-force against `adam2040` account | `DeviceLogonEvents`: 10 failures, 5 successes from `159.26.106.84` |
| Initial Access | T1110.001 | Brute Force: Password Guessing | Automated RDP password guessing | Multiple failed attempts followed by success |
| Execution | T1059.001 / T1059.003 | PowerShell & Windows Command Shell | Execution of PowerShell scripts and discovery commands | `wmi_maintenance.ps1`, `mscloudsync.ps1`; `systeminfo`, `whoami`, `net user`, `ipconfig`, `netstat`, `tasklist` |
| Persistence | T1543.003 / T1547.001 / T1053.005 | Services, Registry Run Keys, Scheduled Task | Fake service and scheduled task for persistence | `HKLM\SYSTEM\...\MSUpdateService`, `HKLM\SOFTWARE\...\Run\MSCloudSync`, `TaskCache\Tree\MicrosoftUpdateSync` at `19:39:45` |
| Privilege Escalation | – | Built-in Admin Access | `adam2040` had administrative rights | Account already elevated |
| Defense Evasion | T1562.001 | Impair Defenses | Windows Defender exclusions added | `C:\Windows\Temp` excluded |
| Defense Evasion | T1055 | Process Injection | Script injected into `msedge.exe` | No MDE alert; based on script analysis |
| Defense Evasion | T1036.004 / T1036.005 | Masquerading | Tasks/services named to appear legitimate | `MSUpdateService`, `MicrosoftUpdateSync`, files in `C:\ProgramData\Microsoft\Windows\Update\` |
| Credential Access | – | Not Observed | No credential dumping detected | No LSASS or SAM hive access |
| Discovery | T1082 / T1033 / T1087.001 / T1069.001 / T1016 / T1049 / T1057 / T1018 | System & Network Discovery | Standard recon commands via `cmd.exe` | `systeminfo`, `whoami`, `net user`, `net localgroup`, `ipconfig`, `netstat`, `tasklist`, `wmic` |
| Lateral Movement | – | Not Observed | No lateral movement detected | Activity restricted to local system |
| Collection | T1005 / T1560.001 | Local Data Collection & Archiving | Collected local files and archived | `network_credentials.txt`, `financial_report_Q4.pdf`, `backup_sync.zip` |
| Command and Control | T1071.001 / T1095 | HTTP-based C2 on Non-standard Port | HTTP POST traffic over port `8081` | `powershell.exe → 50.116.54.114:35393` |
| Exfiltration | T1041 / T1048 | Exfiltration Over C2 / Alt Protocol | Data sent over HTTP | `backup_sync.zip` exfiltrated at `19:41:30` |
| Impact | – | Data Theft | Exfiltration of sensitive data | Credentials and financial reports stolen |

