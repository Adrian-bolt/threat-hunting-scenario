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
<img width="929" height="830" alt="image" src="https://github.com/user-attachments/assets/90318a26-b485-41a5-b62a-08f6f396c211" />


---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table or any ProcessCommandLine that contained the string "tor-browser-windows-x86_64-portable-15.0.7.exe"
Based on the logs returned at exactly 3:00 PM on February 24, 2026, the user adrian logged into the virtual machine adrian-mde-test and launched the Tor Browser installer directly from his Downloads folder, executing the file tor-browser-windows-x86_64-portable-15.0.7.exe, which carried the unique SHA256 fingerprint 958626901dbe17fc003ed671b61b3656375e6f0bc06c9dff60bd2f80d4ace21b.


**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "adrian-mde-test"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.7.exe"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine

```
<img width="956" height="626" alt="image" src="https://github.com/user-attachments/assets/96a67558-a034-44a2-9cca-ced106e7ba4a" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that user "employee" actually opened the tor browser. There was evidence that they did not open it at 2026-02-24T20:04:13.7007024Z.
There were several other instances of firefox.exe (Tor) as well as tor.exe spawned afterwards


**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "adrian-mde-test"
| where FileName has_any ("tor.exe","firefox.exe","tor-browser.exe")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc

```
<img width="924" height="833" alt="image" src="https://github.com/user-attachments/assets/fd357444-8333-42ba-b219-c1fd6dc5cd5d" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworkEvents table for any indication the tor browser was used to establish a connection using any of the known tor ports. At 2026-02-24T20:04:32.9244535Z, the user adrian on the virtual machine adrian-mde-test successfully established an outbound network connection using tor.exe, which was launched from the Tor Browser folder on the desktop. The connection reached the external IP address 212.227.65.236 over port 9001, communicating with the URL https://www.rfr5ve2umvj.com. There were other connections to sites over port 443.  

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "adrian-mde-test"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9001", "9030", "9040", "9050", "9051")
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessAccountName, InitiatingProcessFolderPath
| order by Timestamp desc

```
<img width="937" height="666" alt="image" src="https://github.com/user-attachments/assets/1ad668c4-f0cb-4c37-a8af-d33f418eb294" />


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

On February 24, 2026, the user adrian downloaded and executed the Tor Browser portable installer on the system adrian-mde-test from the Downloads folder. The installer extracted the Tor Browser package to the Desktop, creating key components including tor.exe, firefox.exe, configuration files, and a file named tor-shopping-list.txt. Shortly after extraction, the user launched the Tor Browser, and process logs confirm that both tor.exe and the bundled firefox.exe were executed from the Tor Browser directory. Within seconds of launch, tor.exe established outbound network connections over port 9001 to external IP addresses consistent with Tor network activity, along with additional encrypted traffic observed over port 443, confirming active Tor usage.


---

## Response Taken

TOR usage was confirmed on endpoint ___adrian-MDE-test___________by the user adrian. The device was isolated and the user's direct manager was notified.


---
