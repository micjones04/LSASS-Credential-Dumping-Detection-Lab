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



