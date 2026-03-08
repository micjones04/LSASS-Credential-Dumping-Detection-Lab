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
