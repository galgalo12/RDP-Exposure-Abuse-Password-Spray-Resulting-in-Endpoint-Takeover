# RDP-Exposure-Abuse-Password-Spray-Resulting-in-Endpoint-Takeover

## 🧾 Executive Summary

A remote threat actor successfully compromised the **Windows 11 Pro** endpoint **`flare`** via a **password spray / brute-force attack** against an **exposed RDP service**. The adversary authenticated using valid credentials for the **local administrative account `adam2040`** on **2026-01-11 at 18:40:57 UTC**, originating from the external IP address **50.116.54.114**.

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


