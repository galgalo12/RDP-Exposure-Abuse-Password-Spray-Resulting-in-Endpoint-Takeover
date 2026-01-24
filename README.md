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


