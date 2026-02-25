# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/Adrian-bolt/threat-hunting-scenario/blob/main/threat-hunting-scenario.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for ANY file that had the string "tor" in it and discovered what looks like the user "employee"  downloaded a tor installer, did something that resulted in many tor-related files being copied to the desktop and the creation of a file called "tor-shopping-list.txt" on the desktop at 2026-02-18T01:14:20.6525237Z. These events began at:  2026-02-24T20:00:07.0651464Z

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "adrian-mde-test"
| where InitiatingProcessAccountName == "adrian"
| where FileName contains "tor"
| where Timestamp >= datetime(2026-02-24T20:00:07.0651464Z)
| order by Timestamp desc 
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, account = InitiatingProcessAccountName

```
<<img width="929" height="830" alt="image" src="https://github.com/user-attachments/assets/90318a26-b485-41a5-b62a-08f6f396c211" />
>

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.1.exe". Based on the logs returned, at `2024-11-08T22:16:47.4484567Z`, an employee on the "threat-hunt-lab" device ran the file `tor-browser-windows-x86_64-portable-14.0.1.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents  
| where DeviceName == "threat-hunt-lab"  
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.1.exe"  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b07ac4b4-9cb3-4834-8fac-9f5f29709d78">

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "employee" actually opened the TOR browser. There was evidence that they did open it at `2024-11-08T22:17:21.6357935Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "threat-hunt-lab"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b13707ae-8c2d-4081-a381-2b521d3a0d8f">

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2024-11-08T22:18:01.1246358Z`, an employee on the "threat-hunt-lab" device successfully established a connection to the remote IP address `176.198.159.33` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "threat-hunt-lab"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/87a02b5b-7d12-4f53-9255-f5e750d0e3cb">

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2026-02-24T20:00:07.0651464Z`
- **Event:** The user "adrian" downloaded the file tor-browser-windows-x86_64-portable-15.0.7.exe to the Downloads folder.
- **Action:** File creation/rename activity detected in Downloads directory.
- **File Path:** `C:\Users\adrian\Downloads\tor-browser-windows-x86_64-portable-15.0.7.exe`

### 2. Process Execution - TOR Installer Launch

- **Timestamp:** `2026-02-24T20:00:27Z`
- **Event:** User "adrian" executed the TOR portable installer, initiating extraction of the Tor Browser files.
- **Action:** Process creation detected for the installer executable.
- **File Path:** `C:\Users\adrian\Downloads\tor-browser-windows-x86_64-portable-15.0.7.exe`

### 3. File Extraction – TOR Browser Deployment to Desktop

- **Timestamp:** `2026-02-24T20:03:40Z – 2026-02-24T20:04:30Z`
- **Event:** The Tor Browser package was extracted to the Desktop directory. Multiple TOR-related files were created, including tor.exe, firefox.exe, configuration files, and tor-shopping-list.txt.
- **Action:** Multiple file creation events detected within the Tor Browser directory.
- **File Path:** `C:\Users\adrian\Desktop\Tor Browser\`

### 4. Process Execution – TOR Browser Launch

- **Timestamp:** `2026-02-24T20:04:13.7007024Z`
- **Event:** User "adrian" launched the TOR browser. Associated processes tor.exe and firefox.exe were spawned from the Tor Browser directory, indicating successful startup.
- **Action:** `Process creation of TOR browser-related executables detected.`
- **File Path:** `C:\Users\adrian\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe
C:\Users\adrian\Desktop\Tor Browser\Browser\firefox.exe`

### 5. Network Connection – TOR Network Activity

- **Timestamps:** - `2026-02-24T20:04:32.9244535Z`.
- **Event:** `A successful outbound network connection was established by tor.exe to external IP 212.227.65.236 over port 9001, confirming TOR relay communication.`
- **Action:** `Connection success detected.`
- **File Path:** `C:\Users\adrian\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`
- 
### 6. Additional Network Connections – Continued TOR Activity

- **Timestamp:** `2026-02-24T20:05:04Z`
- **Event:** Additional outbound connections were established by tor.exe, including TOR-related traffic over port 9001 and encrypted HTTPS communication over port 443, indicating sustained TOR session activity.
- **Action:** Multiple successful outbound connections detected.
- **File Path:** `C:\Users\adrian\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
