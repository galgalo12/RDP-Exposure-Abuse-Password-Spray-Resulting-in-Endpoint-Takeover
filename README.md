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


