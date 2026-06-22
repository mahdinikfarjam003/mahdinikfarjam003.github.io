---
layout: default
title: MMC20 Application Lateral Movement
---

# MMC20 Application for Lateral Movement
### PoC and Detection

Hello everyone,

You have probably encountered situations where, while designing and creating a Detection Rule or Use Case to identify the MMC20 Application Object-based Lateral Movement technique, you needed to conduct research on this topic.

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

---

## Introduction

The Microsoft Component Object Model (COM) is a platform-independent, distributed, object-oriented architecture that enables software components to communicate and interact with one another. COM serves as the underlying technology for several Microsoft technologies, including OLE, ActiveX, and many other Windows-based applications and services.

Because COM objects can also be accessed remotely through the Distributed Component Object Model (DCOM), this functionality can be abused by attackers to perform lateral movement between systems within an enterprise environment.

To demonstrate this technique, the following lab environment was used throughout this research.

**Reference:**
https://docs.microsoft.com/en-us/windows/win32/com/the-component-object-model

The diagram below illustrates the relationship between the attacker and victim hosts used throughout this research.
![DCOM Lab Environment](images/MMC20.png)
