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
