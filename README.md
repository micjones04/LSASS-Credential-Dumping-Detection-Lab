# LSASS Credential Dumping Detection Lab

## Overview

This project simulates a credential dumping attack targeting the LSASS process and demonstrates how the activity can be detected using Sysmon telemetry and Splunk SIEM.

Credential dumping is a common technique used by attackers to extract user credentials from system memory, allowing them to perform lateral movement and privilege escalation within a network.

In this lab, LSASS memory was dumped using Sysinternals ProcDump and the activity was detected using Sysmon Event ID 10 logs ingested into Splunk.

---

## Lab Objectives

- Simulate credential dumping on a Windows endpoint
- Collect endpoint telemetry using Sysmon
- Ingest logs into Splunk SIEM
- Create a detection query for suspicious LSASS access
- Map the activity to the MITRE ATT&CK framework

---

## Lab Environment

| System | Role |
|------|------|
| Kali Linux | Attacker Machine |
| Windows 10 | Target Endpoint |
| Windows Server 2022 | Domain Controller |
| Splunk Enterprise | SIEM |
| Sysmon | Endpoint Logging |

---

# Attack Simulation

To simulate credential dumping, the Sysinternals **ProcDump** utility was used to create a memory dump of the LSASS process.

The following command was executed on the Windows endpoint:

procdump64.exe -ma lsass.exe lsass.dmp
<img width="624" height="195" alt="procdump_lsass_execution" src="https://github.com/user-attachments/assets/60ce29de-3262-4e6a-998e-a9a0d6b5d27b" />

This command forces a full memory dump of the **Local Security Authority Subsystem Service (LSASS)** process.

LSASS stores sensitive authentication material such as:

- NTLM password hashes
- Kerberos tickets
- Cached credentials

Attackers frequently dump LSASS memory to extract credentials and perform **lateral movement** across the network.

After execution, the following dump file was created:

lsass.dmp

---

# Detection Telemetry

The credential dumping activity triggered **Sysmon Event ID 10 (Process Access)**.

This event occurs when a process attempts to access another process's memory.

Key fields observed in the event log:

| Field | Value |
|------|------|
| SourceImage | procdump64.exe |
| TargetImage | lsass.exe |
| GrantedAccess | 0x1fffff |

The **GrantedAccess value 0x1fffff** indicates full access to the LSASS process memory, which is commonly associated with credential dumping attempts.

---

# Splunk Detection Query

The activity was detected in Splunk using the following search query:

index=endpoint source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=10
TargetImage="*lsass.exe"
| table _time host SourceImage TargetImage GrantedAccess

This query identifies processes attempting to access LSASS memory and highlights suspicious activity that may indicate credential dumping.

---

# MITRE ATT&CK Mapping

| Technique | Description |
|------|------|
| T1003.001 | OS Credential Dumping: LSASS |

This technique is commonly used by attackers to obtain credentials from system memory and move laterally through a network.

---

# SOC Investigation Workflow

If this alert were triggered in a real Security Operations Center (SOC), an analyst would typically follow an investigation process similar to the steps below.

### 1. Triage
The analyst identifies that **Sysmon Event ID 10** indicates a process attempting to access LSASS memory.

Since LSASS stores authentication material, unauthorized access is considered highly suspicious.

### 2. Investigation
The analyst reviews the event details and confirms that **procdump64.exe** accessed the LSASS process.

This behavior is commonly associated with credential dumping techniques.

### 3. Scope Analysis
The analyst searches across the SIEM for similar activity on other systems to determine whether the behavior is isolated or part of a larger compromise.

Example investigation query:


### 4. Containment
If malicious activity is confirmed, the affected endpoint would be isolated from the network to prevent lateral movement.

### 5. Eradication
Security teams would remove attacker tools, reset compromised credentials, and analyze the LSASS dump file to understand what data may have been exposed.

### 6. Lessons Learned
Detection rules may be improved to better detect suspicious LSASS access in the future.

### Splunk Log Ingestion Verification
<img width="624" height="384" alt="splunk_log_ingestion_verification" src="https://github.com/user-attachments/assets/85163b4b-46fa-43c4-8d9b-4667a56e04e7" />

### Sysmon Event Statistics
<img width="624" height="300" alt="splunk_sysmon_event_statistics" src="https://github.com/user-attachments/assets/5e1224ee-60d8-4cdc-bdea-249cca51b4d5" />

### Sysmon Event ID 10 – LSASS Access
<img width="624" height="301" alt="sysmon_event10_lsass_detection" src="https://github.com/user-attachments/assets/24c6f212-ee95-4c26-8a5f-3d6efb558ada" />

### Splunk Detection Results
<img width="624" height="309" alt="splunk_lsass_event_results" src="https://github.com/user-attachments/assets/c9018bfa-edfc-4ce1-a4b1-a092c1c80bce" />
