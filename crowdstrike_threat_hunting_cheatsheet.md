# CrowdStrike Next-Gen SIEM Threat Hunting Cheatsheet
*Field-Ready Guide for Security Analysts*

## Table of Contents
1. [Platform Overview](#platform-overview)
2. [LogScale Query Language Essentials](#logscale-query-language-essentials)
3. [Falcon Data Model & Event Types](#falcon-data-model--event-types)
4. [Core Threat Hunting Queries](#core-threat-hunting-queries)
5. [MITRE ATT&CK Mapped Hunting](#mitre-attck-mapped-hunting)
6. [Advanced Investigation Techniques](#advanced-investigation-techniques)
7. [Real-Time Response Integration](#real-time-response-integration)
8. [Threat Intelligence Correlation](#threat-intelligence-correlation)
9. [Output Interpretation & Red Flags](#output-interpretation--red-flags)
10. [Performance Optimization & Best Practices](#performance-optimization--best-practices)

---

## Platform Overview

### CrowdStrike Falcon Components
- **Falcon LogScale** - Next-gen SIEM with streaming analytics
- **Falcon Insight XDR** - Extended detection and response
- **Falcon Intelligence** - Threat intelligence platform
- **Falcon Real Time Response** - Remote investigation and remediation
- **Falcon OverWatch** - Managed threat hunting service

### Access Methods
```bash
# Web Console
https://falcon.crowdstrike.com

# API Access
curl -X POST "https://api.crowdstrike.com/oauth2/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=YOUR_ID&client_secret=YOUR_SECRET&grant_type=client_credentials"

# PowerShell Module
Install-Module -Name PSFalcon
Import-Module PSFalcon
```

---

## LogScale Query Language Essentials

### Basic Query Structure
```
#event_simpleName=ProcessRollup2
| aid=YOUR_AID
| timestamp >= "2024-01-01T00:00:00Z"
| ImageFileName=/.*powershell.*/i
| head(100)
```

### Core Operators & Functions

#### Time Filtering
```
// Last 24 hours
| timestamp >= now() - 24hours

// Specific time range
| timestamp >= "2024-01-01T00:00:00Z" 
| timestamp <= "2024-01-02T00:00:00Z"

// Relative time buckets
| bucket(@timestamp, span=1h)
```

#### Field Operations
```
// Field existence check
| ?ImageFileName

// Field value filtering
| ImageFileName=/.*cmd\.exe$/i
| ProcessId != ""
| ProcessId > 1000

// Regex matching (case insensitive)
| CommandLine=/download.*exe/i

// Field extraction
| regex("(?P<domain>[^\\\\]+)\\\\(?P<user>.+)", field=UserName)
```

#### String Manipulation
```
// Case operations
| lower(ImageFileName)
| upper(CommandLine)

// String functions
| length(CommandLine) > 100
| startsWith(ImageFileName, "C:\\Windows")
| endsWith(ImageFileName, ".exe")
| contains(CommandLine, "powershell")

// Field splitting
| split(field=ImageFileName, by="\\", as=[path_parts])
| array:get(path_parts, index=-1, as=filename)
```

#### Aggregation & Statistics
```
// Count events
| groupBy([aid, ImageFileName], function=count())

// Unique counts
| groupBy([aid], function=[count(), count(ImageFileName, distinct=true)])

// Statistical functions
| groupBy([aid], function=[avg(ProcessDuration), max(ProcessDuration)])

// Percentiles
| groupBy([aid], function=percentile(ResponseTime, percentiles=[50, 90, 95]))
```

#### Data Enrichment
```
// Join with lookup tables
| join({
    #repo=threat_intel 
    | IOCType=ip
  }, field=[RemoteAddressIP4], include=[IOCValue, ThreatType])

// Self-join for correlation
| join({
    #event_simpleName=NetworkConnectIP4
    | aid=$aid
  }, field=aid, include=[RemoteAddressIP4])
```

---

## Falcon Data Model & Event Types

### Key Event Types

#### Process Events
```
#event_simpleName=ProcessRollup2     // Process execution
#event_simpleName=SyntheticProcessRollup2  // Synthetic process events
#event_simpleName=ProcessBlocked     // Blocked processes

// Core fields
aid, timestamp, ImageFileName, CommandLine, UserName, ParentProcessId
RawProcessId, ProcessStartTime, ProcessEndTime, SHA256HashData
```

#### Network Events
```
#event_simpleName=NetworkConnectIP4  // IPv4 connections
#event_simpleName=NetworkConnectIP6  // IPv6 connections
#event_simpleName=DnsRequest         // DNS queries

// Core fields
aid, timestamp, LocalAddressIP4, LocalPort, RemoteAddressIP4, RemotePort
ConnectionDirection, DomainName, RequestType
```

#### File Events
```
#event_simpleName=NewExecutableWritten    // New executable files
#event_simpleName=PeVersionInfoWritten    // PE file version info
#event_simpleName=QuarantineFile          // Quarantined files

// Core fields
aid, timestamp, TargetFileName, SHA256HashData, MD5HashData
FilePath, FileSize, FileDescription, FileVersion
```

#### Authentication Events
```
#event_simpleName=UserLogon          // User logons
#event_simpleName=UserLogoff         // User logoffs
#event_simpleName=AuthenticationPackageLoaded  // Auth package loads

// Core fields
aid, timestamp, UserName, LogonDomain, LogonType, LogonId
LogonTime, SessionId, AuthenticationPackageName
```

#### Registry Events
```
#event_simpleName=RegKeySecurityDecrease   // Registry security changes
#event_simpleName=RegGenericValue          // Registry value changes

// Core fields
aid, timestamp, RegObjectName, RegValueName, RegValueType, RegValueData
```

---

## Core Threat Hunting Queries

### Suspicious Process Execution

#### Encoded PowerShell Commands
```
#event_simpleName=ProcessRollup2
| CommandLine=/.*-e[nc]*\s+[A-Za-z0-9+\/=]{20,}.*/i
| CommandLine!=/.*Get-ExecutionPolicy.*/i
| table([timestamp, aid, UserName, ImageFileName, CommandLine])
| head(100)
```

#### Living off the Land Binaries (LOLBins)
```
#event_simpleName=ProcessRollup2
| ImageFileName=/.*\\(certutil|bitsadmin|regsvr32|rundll32|mshta|wscript|cscript)\.exe$/i
| CommandLine=/(?i)(download|http|ftp|base64|decode)/
| !CommandLine=/(?i)(windows\\system32|program files)/
| table([timestamp, aid, UserName, ImageFileName, CommandLine, ParentProcessId])
```

#### Suspicious Parent-Child Relationships
```
// Office applications spawning unusual processes
#event_simpleName=ProcessRollup2
| ParentBaseFileName=/(?i)(winword|excel|powerpnt|outlook|msaccess)\.exe/
| ImageFileName=/(?i).*(cmd|powershell|wscript|cscript|regsvr32)\.exe$/
| !CommandLine=/(?i)(office|microsoft|update)/
| table([timestamp, aid, ParentBaseFileName, ImageFileName, CommandLine])
```

### Network Anomaly Detection

#### Suspicious Outbound Connections
```
#event_simpleName=NetworkConnectIP4
| ConnectionDirection="Outbound"
| RemotePort in [21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 993, 995, 3389]
| !RemoteAddressIP4=/^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)/
| groupBy([RemoteAddressIP4, RemotePort], function=count(aid, distinct=true))
| count >= 5  // Multiple hosts connecting to same external IP
| sort(count, order=desc)
```

#### DNS Tunneling Detection
```
#event_simpleName=DnsRequest
| length(DomainName) > 50
| DomainName=/.*\.[a-z]{2,3}$/i
| !DomainName=/.*(microsoft|windows|office|adobe|google)\.com/i
| groupBy([DomainName], function=count())
| count > 10
| sort(count, order=desc)
```

#### Beaconing Detection
```
// Identify regular communication patterns
#event_simpleName=NetworkConnectIP4
| ConnectionDirection="Outbound"
| bucket(@timestamp, span=1m)
| groupBy([aid, RemoteAddressIP4, _bucket], function=count())
| groupBy([aid, RemoteAddressIP4], function=[count(_bucket, distinct=true), avg(count)])
| distinct_buckets > 10 and avg_count < 5  // Regular, low-volume connections
```

### File System Monitoring

#### Suspicious File Writes
```
#event_simpleName=NewExecutableWritten
| TargetFileName=/(?i).*\\(temp|appdata|programdata|users\\public).*/
| !TargetFileName=/(?i).*(microsoft|windows|program files).*/
| join({
    #event_simpleName=ProcessRollup2
    | SHA256HashData=*
  }, field=SHA256HashData, include=[ImageFileName, CommandLine])
| table([timestamp, aid, TargetFileName, SHA256HashData, ImageFileName])
```

#### Executable Masquerading
```
#event_simpleName=ProcessRollup2
| ImageFileName=/.*\.exe$/i
| regex("(?P<filename>[^\\\\]+)$", field=ImageFileName)
| filename!=/(?i).*(svchost|explorer|winlogon|csrss|smss|wininit|services)\.exe$/
| join({
    #event_simpleName=NewExecutableWritten
    | TargetFileName=*
  }, field=SHA256HashData, include=[TargetFileName])
| regex("(?P<target_filename>[^\\\\]+)$", field=TargetFileName)
| filename != target_filename  // Original name differs from written name
```

---

## MITRE ATT&CK Mapped Hunting

### Initial Access (TA0001)

#### T1566.001 - Spearphishing Attachment
```
// Detect Office documents spawning suspicious processes
#event_simpleName=ProcessRollup2
| ParentBaseFileName=/(?i)(winword|excel|powerpnt)\.exe/
| ImageFileName=/(?i).*(powershell|cmd|wscript|rundll32)\.exe$/
| timestamp >= now() - 1hour
| table([timestamp, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])
```

#### T1190 - Exploit Public-Facing Application
```
// Web shell detection through process ancestry
#event_simpleName=ProcessRollup2
| ParentBaseFileName=/(?i)(w3wp|httpd|nginx|apache|tomcat)\.exe/
| ImageFileName=/(?i).*(cmd|powershell|net)\.exe$/
| table([timestamp, aid, ParentBaseFileName, ImageFileName, CommandLine])
```

### Execution (TA0002)

#### T1059.001 - PowerShell
```
// Suspicious PowerShell execution patterns
#event_simpleName=ProcessRollup2
| ImageFileName=/.*powershell\.exe$/i
| (CommandLine=/(?i)(invoke-expression|iex|downloadstring|new-object.*net\.webclient)/ 
  or CommandLine=/(?i)(-e[nc]*|-windowstyle\s+hidden|-noprofile)/
  or CommandLine=/(?i)(bypass|unrestricted)/)
| !CommandLine=/(?i)(microsoft|office|windows)/
| table([timestamp, aid, UserName, ImageFileName, CommandLine])
```

#### T1059.003 - Windows Command Shell
```
// Command shell with network activity correlation
#event_simpleName=ProcessRollup2
| ImageFileName=/.*cmd\.exe$/i
| CommandLine=/(?i)(curl|wget|certutil|bitsadmin).*http/
| join({
    #event_simpleName=NetworkConnectIP4
    | ConnectionDirection="Outbound"
    | timestamp >= now() - 5minutes
  }, field=aid, include=[RemoteAddressIP4, RemotePort])
| table([timestamp, aid, CommandLine, RemoteAddressIP4, RemotePort])
```

### Persistence (TA0003)

#### T1547.001 - Registry Run Keys
```
// Monitor registry run key modifications
#event_simpleName=RegGenericValue
| RegObjectName=/(?i).*\\(run|runonce)/
| table([timestamp, aid, UserName, RegObjectName, RegValueName, RegValueData])
```

#### T1053.005 - Scheduled Task
```
// Scheduled task creation
#event_simpleName=ProcessRollup2
| ImageFileName=/.*schtasks\.exe$/i
| CommandLine=/\/create/i
| table([timestamp, aid, UserName, CommandLine])
```

### Defense Evasion (TA0005)

#### T1027 - Obfuscated Files or Information
```
// Detect heavily obfuscated scripts
#event_simpleName=ProcessRollup2
| (ImageFileName=/(?i).*(powershell|wscript|cscript)\.exe$/ and length(CommandLine) > 1000)
| (CommandLine=/.{100,}/ and CommandLine=/([A-Za-z0-9+\/=]{50,}|[A-Fa-f0-9]{100,})/)
| table([timestamp, aid, ImageFileName, CommandLine])
```

#### T1070.001 - Clear Windows Event Logs
```
// Event log clearing detection
#event_simpleName=ProcessRollup2
| (ImageFileName=/.*wevtutil\.exe$/i and CommandLine=/(?i)(cl|clear-log)/)
  or (ImageFileName=/.*powershell\.exe$/i and CommandLine=/(?i)clear-eventlog/)
| table([timestamp, aid, UserName, ImageFileName, CommandLine])
```

### Credential Access (TA0006)

#### T1003.001 - LSASS Memory
```
// LSASS process access
#event_simpleName=ProcessRollup2
| CommandLine=/(?i)(procdump|mimikatz|dumpert|lsass)/
| table([timestamp, aid, UserName, ImageFileName, CommandLine])

// Correlate with network activity
| join({
    #event_simpleName=NetworkConnectIP4
    | timestamp >= now() - 10minutes
  }, field=aid, include=[RemoteAddressIP4])
```

#### T1110.003 - Password Spraying
```
// Failed authentication patterns
#event_simpleName=UserLogon
| LogonType in [2, 3, 10]  // Interactive, Network, RemoteInteractive
| Status != "Success"
| bucket(@timestamp, span=5m)
| groupBy([aid, _bucket, UserName], function=count())
| groupBy([aid, _bucket], function=[count(UserName, distinct=true), sum(count)])
| distinct_users > 10 and sum_attempts > 50  // Multiple users, many attempts
```

### Discovery (TA0007)

#### T1087.001 - Local Account Discovery
```
// Account enumeration commands
#event_simpleName=ProcessRollup2
| CommandLine=/(?i)(net\s+(user|localgroup|group)|whoami|quser|query\s+user)/
| table([timestamp, aid, UserName, ImageFileName, CommandLine])
```

#### T1057 - Process Discovery
```
// Process enumeration tools
#event_simpleName=ProcessRollup2
| (CommandLine=/(?i)(tasklist|get-process|ps\s)/ or ImageFileName=/(?i).*(tasklist|pslist)\.exe$/)
| table([timestamp, aid, UserName, ImageFileName, CommandLine])
```

### Lateral Movement (TA0008)

#### T1021.001 - Remote Desktop Protocol
```
// RDP lateral movement detection
#event_simpleName=UserLogon
| LogonType=10  // RemoteInteractive
| bucket(@timestamp, span=1h)
| groupBy([UserName, _bucket], function=count(aid, distinct=true))
| distinct_aid > 3  // Same user logging into multiple systems
| sort(_bucket, order=desc)
```

#### T1021.002 - SMB/Windows Admin Shares
```
// Administrative share access
#event_simpleName=NetworkConnectIP4
| RemotePort=445
| ConnectionDirection="Outbound"
| join({
    #event_simpleName=ProcessRollup2
    | CommandLine=/(?i)(\\\\.*\\[a-z]\$|net\s+use)/
  }, field=aid, include=[CommandLine])
| table([timestamp, aid, RemoteAddressIP4, CommandLine])
```

### Collection (TA0009)

#### T1005 - Data from Local System
```
// File compression and staging
#event_simpleName=ProcessRollup2
| (ImageFileName=/(?i).*(rar|7z|zip|tar)\.exe$/ 
  or CommandLine=/(?i)(compress|archive|\.zip|\.rar|\.7z)/)
| table([timestamp, aid, UserName, ImageFileName, CommandLine])
```

### Exfiltration (TA0010)

#### T1041 - Exfiltration Over C2 Channel
```
// Large data transfers to external IPs
#event_simpleName=NetworkConnectIP4
| ConnectionDirection="Outbound"
| !RemoteAddressIP4=/^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)/
| bucket(@timestamp, span=5m)
| groupBy([aid, RemoteAddressIP4, _bucket], function=sum(BytesSent))
| sum_bytes > 10485760  // > 10MB in 5 minutes
| sort(sum_bytes, order=desc)
```

---

## Advanced Investigation Techniques

### Process Tree Reconstruction

#### Building Process Ancestry
```
// Reconstruct full process tree
#event_simpleName=ProcessRollup2
| aid="YOUR_AID"
| timestamp >= "2024-01-01T00:00:00Z"
| join({
    #event_simpleName=ProcessRollup2 
    | aid="YOUR_AID"
  }, field=[aid, ParentProcessId], as=parent, include=[ImageFileName, CommandLine])
| rename(ImageFileName, as=child_process)
| rename(parent.ImageFileName, as=parent_process)
| table([timestamp, parent_process, child_process, CommandLine])
| sort(timestamp, order=asc)
```

#### Suspicious Process Chains
```
// Multi-stage process execution
#event_simpleName=ProcessRollup2
| ImageFileName=/(?i).*(cmd|powershell)\.exe$/
| join({
    #event_simpleName=ProcessRollup2
    | timestamp >= now() - 30minutes
  }, field=[aid, RawProcessId], as=children, include=[ImageFileName, CommandLine])
| groupBy([aid, RawProcessId], function=[collect(children.ImageFileName), collect(children.CommandLine)])
| array:length(collect_imagefilename) > 2  // Process spawned multiple children
```

### Memory and Behavioral Analysis

#### In-Memory Execution Detection
```
// Processes without corresponding file writes
#event_simpleName=ProcessRollup2
| !join({
    #event_simpleName=NewExecutableWritten
    | timestamp >= now() - 1hour
  }, field=[aid, SHA256HashData])
| ImageFileName!=/(?i).*\\windows\\system32\\.*/
| table([timestamp, aid, ImageFileName, SHA256HashData])
```

#### DLL Injection Indicators
```
// Unusual DLL loads in processes
#event_simpleName=ProcessRollup2
| ImageFileName=/(?i).*(svchost|explorer|winlogon)\.exe$/
| join({
    #event_simpleName=ImageHash
    | timestamp >= now() - 30minutes
  }, field=aid, include=[FileName, SHA256HashData])
| !FileName=/(?i).*\\windows\\system32\\.*/
| !FileName=/(?i).*\\program files\\.*/
| table([timestamp, aid, ImageFileName, FileName, SHA256HashData])
```

### Network Behavior Analysis

#### Command and Control Detection
```
// Regular network beaconing
#event_simpleName=NetworkConnectIP4
| ConnectionDirection="Outbound"
| !RemoteAddressIP4=/^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)/
| bucket(@timestamp, span=1m)
| groupBy([aid, RemoteAddressIP4, RemotePort, _bucket], function=count())
| groupBy([aid, RemoteAddressIP4, RemotePort], function=[count(), avg(count), stddev(count)])
| count > 10 and stddev_count < 2  // Regular intervals
| sort(count, order=desc)
```

#### Data Exfiltration Patterns
```
// Correlation between file access and network activity
#event_simpleName=ProcessRollup2
| CommandLine=/(?i)(type|copy|xcopy|robocopy).*\.(doc|pdf|xls|txt)/
| join({
    #event_simpleName=NetworkConnectIP4
    | ConnectionDirection="Outbound"
    | timestamp >= now() - 5minutes
  }, field=aid, include=[RemoteAddressIP4, BytesSent])
| BytesSent > 1048576  // > 1MB
| table([timestamp, aid, CommandLine, RemoteAddressIP4, BytesSent])
```

---

## Real-Time Response Integration

### RTR Command Mapping

#### Process Investigation
```
// LogScale query to identify suspicious process
#event_simpleName=ProcessRollup2
| aid="YOUR_AID" 
| ImageFileName=/.*malware\.exe$/i

// Follow up with RTR commands:
// ps -n malware.exe
// get "C:\temp\malware.exe"
// kill PID
```

#### File System Analysis
```
// Identify suspicious files
#event_simpleName=NewExecutableWritten
| TargetFileName=/.*\\temp\\.*/
| SHA256HashData="SUSPICIOUS_HASH"

// RTR commands:
// ls "C:\temp" -l
// cat "C:\temp\suspicious_file.txt"
// rm "C:\temp\suspicious_file.txt"
```

#### Network Artifact Collection
```
// Active network connections
#event_simpleName=NetworkConnectIP4
| aid="YOUR_AID"
| RemoteAddressIP4="SUSPICIOUS_IP"

// RTR commands:
// netstat -ano
// arp -a
// ipconfig /all
```

### Automated Response Triggers

#### Containment Actions
```
// High-confidence malware detection
#event_simpleName=ProcessRollup2
| SHA256HashData in ["KNOWN_BAD_HASH_1", "KNOWN_BAD_HASH_2"]
| table([aid, ImageFileName, CommandLine])

// Trigger containment:
// contain aid="AID_VALUE"
```

---

## Threat Intelligence Correlation

### IOC Enrichment

#### Hash-Based Analysis
```
// Correlate file hashes with threat intel
#event_simpleName=ProcessRollup2
| SHA256HashData=*
| join({
    #repo=threat_intel
    | IOCType="hash"
    | ThreatType in ["malware", "trojan", "backdoor"]
  }, field=SHA256HashData, as=ioc, include=[ThreatType, ThreatFamily, Confidence])
| table([timestamp, aid, ImageFileName, ioc.ThreatType, ioc.ThreatFamily])
```

#### Domain Reputation
```
// DNS queries to suspicious domains
#event_simpleName=DnsRequest
| join({
    #repo=threat_intel
    | IOCType="domain"
    | Reputation="malicious"
  }, field=DomainName, as=threat, include=[ThreatType, LastSeen])
| table([timestamp, aid, DomainName, threat.ThreatType, threat.LastSeen])
```

#### IP Address Intelligence
```
// Network connections to threat IPs
#event_simpleName=NetworkConnectIP4
| ConnectionDirection="Outbound"
| join({
    #repo=threat_intel
    | IOCType="ip"
    | Confidence > 80
  }, field=RemoteAddressIP4, as=intel, include=[ThreatType, Country, ASN])
| table([timestamp, aid, RemoteAddressIP4, intel.ThreatType, intel.Country])
```

### Campaign Tracking

#### Actor Attribution
```
// TTPs associated with known threat actors
#event_simpleName=ProcessRollup2
| CommandLine=/(?i)(cobalt.*strike|metasploit|empire)/
| join({
    #repo=threat_intel
    | ActorName=*
    | TTP=*
  }, field=CommandLine, include=[ActorName, Campaign])
| table([timestamp, aid, ImageFileName, CommandLine, ActorName, Campaign])
```

---

## Output Interpretation & Red Flags

### Critical Process Indicators

#### 🚩 Suspicious Process Execution
```
Process: powershell.exe, cmd.exe, wscript.exe, rundll32.exe
Parent: outlook.exe, winword.exe, excel.exe (Office spawning system tools)
Command Line: Base64 encoded, very long (>500 chars), obfuscated
User Context: SYSTEM running user-mode processes
Timing: Multiple processes within seconds
```

#### 🚩 Living off the Land
```
Process: certutil.exe with -urlcache or -decode
Process: bitsadmin.exe with /transfer
Process: regsvr32.exe with /s /u /i:http://
Process: mshta.exe with http:// URLs
Parent-Child: Unusual ancestry (service spawning browsers)
```

### Network Communication Red Flags

#### 🚩 Command and Control
```
Pattern: Regular intervals (every 60s, 5min, etc.)
Destinations: Non-standard ports (8080, 8443, 443 to non-web services)
Volume: Consistent small data transfers
Timing: Outside business hours
Geography: Connections to high-risk countries
```

#### 🚩 Data Exfiltration
```
Volume: Large outbound transfers (>10MB)
Timing: Single large transfer or multiple medium transfers
Destinations: Cloud storage, file sharing sites, personal email
Compression: Archive creation followed by network activity
Encryption: SSL/TLS to non-standard ports
```

### Authentication Anomalies

#### 🚩 Credential Abuse
```
Pattern: Multiple failed attempts followed by success
Timing: Off-hours authentication
Geography: Impossible travel (different continents within hours)
Service Accounts: Interactive logons for service accounts
Privilege: Sudden elevation or unusual admin activity
```

### File System Indicators

#### 🚩 Malicious File Activity
```
Location: Temp directories, user profiles, system32
Extensions: Double extensions (.pdf.exe), masquerading
Signatures: Unsigned executables in system directories
Size: Unusually large or small executables
Timing: File creation immediately before process execution
```

### Threshold Guidelines

#### Volume-Based Alerts
```
// Process creation rate
#event_simpleName=ProcessRollup2
| bucket(@timestamp, span=1m)
| groupBy([aid, _bucket], function=count())
| count > 50  // >50 processes per minute

// Network connection volume
#event_simpleName=NetworkConnectIP4
| bucket(@timestamp, span=5m)
| groupBy([aid, _bucket], function=count())
| count > 100  // >100 connections per 5 minutes
```

**Recommended Thresholds:**
- Process creation: >50/minute per host (adjust for build servers)
- Network connections: >100 unique destinations/hour per host
- DNS queries: >500/hour per host
- Failed authentications: >10 per user per hour
- Data transfer: >100MB outbound per host per hour

---

## Performance Optimization & Best Practices

### Query Optimization

#### Time-Based Filtering
```
// ✅ Good: Specific time ranges
#event_simpleName=ProcessRollup2
| timestamp >= now() - 1hour
| aid in ["AID1", "AID2", "AID3"]

// ❌ Bad: No time limit
#event_simpleName=ProcessRollup2
| ImageFileName=/.*powershell.*/
```

#### Field Filtering Early
```
// ✅ Good: Filter on indexed fields first
#event_simpleName=ProcessRollup2
| aid="SPECIFIC_AID"
| timestamp >= now() - 24hours
| ImageFileName=/.*powershell.*/i

// ❌ Bad: Complex regex first
#event_simpleName=ProcessRollup2
| CommandLine=/very.*complex.*regex.*pattern/i
| timestamp >= now() - 24hours
```

#### Efficient Joins
```
// ✅ Good: Join on specific time ranges
#event_simpleName=ProcessRollup2
| timestamp >= now() - 1hour
| join({
    #event_simpleName=NetworkConnectIP4
    | timestamp >= now() - 1hour
  }, field=aid)

// ❌ Bad: Open-ended join
#event_simpleName=ProcessRollup2
| join({
    #event_simpleName=NetworkConnectIP4
  }, field=aid)
```

### Memory Management

#### Result Limiting
```
// Use head() or tail() to limit results
| head(1000)  // First 1000 results
| tail(100)   // Last 100 results

// Use sampling for large datasets
| sample(0.1)  // 10% sample
```

#### Aggregation Strategies
```
// ✅ Good: Aggregate early
#event_simpleName=ProcessRollup2
| timestamp >= now() - 1hour
| groupBy([aid, ImageFileName], function=count())
| sort(count, order=desc)
| head(100)

// ❌ Bad: Aggregate after collecting all data
#event_simpleName=ProcessRollup2
| sort(timestamp)
| groupBy([aid, ImageFileName], function=count())
```

### Common Pitfalls

#### 1. Case Sensitivity
```
// ✅ Case-insensitive matching
| ImageFileName=/.*powershell.*/i

// ❌ Case-sensitive (might miss PowerShell.exe)
| ImageFileName=/.*powershell.*/
```

#### 2. Field Existence Checks
```
// ✅ Check field exists before filtering
| ?CommandLine
| CommandLine=/.*suspicious.*/

// ❌ Filter on potentially null field
| CommandLine=/.*suspicious.*/
```

#### 3. Time Zone Handling
```
// ✅ Use relative time for consistency
| timestamp >= now() - 24hours

// ❌ Absolute timestamps (time zone issues)
| timestamp >= "2024-01-01T08:00:00"
```

### Hunting Methodology Best Practices

#### 1. Hypothesis-Driven Hunting
```
// Start with specific hypothesis
// "Threat actor using PowerShell for lateral movement"

#event_simpleName=ProcessRollup2
| ImageFileName=/.*powershell.*/i
| CommandLine=/(?i)(invoke-command|enter-pssession|new-pssession)/
| join({
    #event_simpleName=NetworkConnectIP4
    | RemotePort in [5985, 5986]  // WinRM ports
  }, field=aid)
```

#### 2. Iterative Refinement
```
// Start broad, then narrow down
// Step 1: Find all PowerShell activity
#event_simpleName=ProcessRollup2
| ImageFileName=/.*powershell.*/i
| timestamp >= now() - 24hours

// Step 2: Focus on suspicious patterns
| CommandLine=/(?i)(-e[nc]*|invoke-expression|downloadstring)/

// Step 3: Correlate with network activity
| join({
    #event_simpleName=NetworkConnectIP4
    | ConnectionDirection="Outbound"
  }, field=aid, include=[RemoteAddressIP4])
```

#### 3. Baseline Establishment
```
// Establish normal behavior patterns
#event_simpleName=ProcessRollup2
| timestamp >= now() - 7days
| ImageFileName=/.*powershell.*/i
| groupBy([aid, UserName, ImageFileName], function=[count(), count(CommandLine, distinct=true)])
| avg_daily_executions = count / 7
| unique_commands = distinct_commandline
| table([aid, UserName, avg_daily_executions, unique_commands])
```

### Field Deployment Guidelines

#### Rapid Triage Queries
```
// 🚨 Emergency: Active compromise check
#event_simpleName=ProcessRollup2
| timestamp >= now() - 15minutes
| (ImageFileName=/(?i).*(mimikatz|procdump|cobalt|meterpreter|empire).*/ 
  or CommandLine=/(?i)(invoke-mimikatz|get-process.*lsass|dump.*lsass)/)
| table([timestamp, aid, UserName, ImageFileName, CommandLine])

// 🚨 Critical: C2 beacon detection (last hour)
#event_simpleName=NetworkConnectIP4
| timestamp >= now() - 1hour
| ConnectionDirection="Outbound"
| !RemoteAddressIP4=/^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)/
| bucket(@timestamp, span=1m)
| groupBy([aid, RemoteAddressIP4, _bucket], function=count())
| groupBy([aid, RemoteAddressIP4], function=[count(), stddev(count)])
| stddev_count < 1  // Very regular intervals
| count > 30  // More than 30 connections
```

#### Investigation Escalation Workflow
```
// Level 1: Basic process anomaly
#event_simpleName=ProcessRollup2
| ImageFileName=/(?i).*(cmd|powershell)\.exe$/
| ParentBaseFileName=/(?i).*(winword|excel|outlook)\.exe$/
| table([timestamp, aid, UserName, ParentBaseFileName, ImageFileName, CommandLine])

// Level 2: If suspicious, check network activity
| join({
    #event_simpleName=NetworkConnectIP4
    | timestamp >= now() - 30minutes
    | ConnectionDirection="Outbound"
  }, field=aid, include=[RemoteAddressIP4, RemotePort])

// Level 3: If network activity found, check file operations
| join({
    #event_simpleName=NewExecutableWritten
    | timestamp >= now() - 30minutes
  }, field=aid, include=[TargetFileName, SHA256HashData])
```

### Advanced Correlation Techniques

#### Multi-Vector Attack Detection
```
// Detect coordinated attacks across multiple systems
let SuspiciousProcesses = #event_simpleName=ProcessRollup2
| timestamp >= now() - 1hour
| CommandLine=/(?i)(invoke-expression|downloadstring|new-object.*webclient)/
| project aid, timestamp, UserName, CommandLine;

let NetworkActivity = #event_simpleName=NetworkConnectIP4
| timestamp >= now() - 1hour
| ConnectionDirection="Outbound"
| !RemoteAddressIP4=/^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)/
| project aid, timestamp, RemoteAddressIP4, RemotePort;

SuspiciousProcesses
| join(NetworkActivity, field=aid)
| where NetworkActivity.timestamp between (SuspiciousProcesses.timestamp .. (SuspiciousProcesses.timestamp + 5minutes))
| groupBy([RemoteAddressIP4], function=[count(aid, distinct=true), collect(UserName)])
| distinct_aid > 2  // Same IP contacted by multiple hosts
```

#### Timeline Reconstruction
```
// Build comprehensive timeline for incident response
let ProcessEvents = #event_simpleName=ProcessRollup2
| aid="COMPROMISED_AID"
| timestamp >= "2024-01-01T12:00:00Z"
| project timestamp, event_type="Process", details=strcat(ImageFileName, " - ", CommandLine);

let NetworkEvents = #event_simpleName=NetworkConnectIP4
| aid="COMPROMISED_AID"
| timestamp >= "2024-01-01T12:00:00Z"
| project timestamp, event_type="Network", details=strcat(ConnectionDirection, " ", RemoteAddressIP4, ":", RemotePort);

let FileEvents = #event_simpleName=NewExecutableWritten
| aid="COMPROMISED_AID"
| timestamp >= "2024-01-01T12:00:00Z"
| project timestamp, event_type="File", details=strcat("Write: ", TargetFileName);

union ProcessEvents, NetworkEvents, FileEvents
| sort(timestamp, order=asc)
| table([timestamp, event_type, details])
```

#### Behavioral Clustering
```
// Group similar behaviors for pattern analysis
#event_simpleName=ProcessRollup2
| timestamp >= now() - 24hours
| ?CommandLine
| regex("(?P<base_command>^[^\\s]+)", field=CommandLine)
| groupBy([aid, base_command], function=[count(), collect(CommandLine)])
| where count > 10  // Repeated commands
| table([aid, base_command, count, collect_commandline])
```

### Threat Intelligence Integration

#### Dynamic IOC Correlation
```
// Real-time IOC matching with context
#event_simpleName=ProcessRollup2
| ?SHA256HashData
| join({
    #repo=threat_intel
    | IOCType="hash"
    | LastSeen >= now() - 30days  // Recent IOCs only
  }, field=SHA256HashData, as=intel, include=[ThreatType, Confidence, FirstSeen, Tags])
| intel.Confidence > 75  // High confidence only
| table([timestamp, aid, ImageFileName, intel.ThreatType, intel.Tags])
```

#### Campaign Attribution
```
// Link activities to known campaigns
#event_simpleName=ProcessRollup2
| CommandLine=/(?i)(invoke-expression|iex).*\$[a-z0-9]{8,}/  // Obfuscated variables
| join({
    #repo=threat_intel
    | CampaignName=*
    | TTPs=*
  }, field=CommandLine, as=campaign, include=[CampaignName, ActorGroup, TTPs])
| table([timestamp, aid, CommandLine, campaign.CampaignName, campaign.ActorGroup])
```

### Custom Detection Development

#### Statistical Anomaly Detection
```
// Detect unusual process execution volumes
let Baseline = #event_simpleName=ProcessRollup2
| timestamp between (now() - 30days .. now() - 7days)
| bucket(@timestamp, span=1h)
| groupBy([aid, _bucket], function=count())
| groupBy([aid], function=[avg(count), stddev(count)])
| project aid, baseline_avg=avg_count, baseline_stddev=stddev_count;

#event_simpleName=ProcessRollup2
| timestamp >= now() - 1hour
| groupBy([aid], function=count())
| join(Baseline, field=aid)
| where count > (baseline_avg + (3 * baseline_stddev))  // 3 standard deviations
| table([aid, count, baseline_avg, threshold=(baseline_avg + (3 * baseline_stddev))])
```

#### Machine Learning Feature Extraction
```
// Extract features for ML models
#event_simpleName=ProcessRollup2
| timestamp >= now() - 1hour
| project aid, 
    ImageFileName,
    command_length=length(CommandLine),
    has_base64=if(CommandLine=/[A-Za-z0-9+\/=]{20,}/, 1, 0),
    has_obfuscation=if(CommandLine=/[\{\}\(\)\[\]]{3,}/, 1, 0),
    has_network_indicators=if(CommandLine=/(?i)(http|ftp|download)/, 1, 0),
    process_entropy=length(replace(CommandLine, regex="(.)", by="", all=true))
| groupBy([aid], function=[
    avg(command_length),
    sum(has_base64),
    sum(has_obfuscation),
    sum(has_network_indicators),
    avg(process_entropy)
  ])
```

### Response Automation

#### Automated Containment Triggers
```
// High-confidence malware execution
#event_simpleName=ProcessRollup2
| SHA256HashData in threat_intel_hashes  // Predefined list
| Confidence > 90
| table([aid, ImageFileName, SHA256HashData])
// Trigger: Automatic host containment

// Active credential dumping
#event_simpleName=ProcessRollup2
| CommandLine=/(?i)(mimikatz|lsass.*dump|procdump.*lsass)/
| table([aid, UserName, ImageFileName, CommandLine])
// Trigger: Force password reset for affected users
```

#### Enrichment Pipelines
```
// Enrich events with user context
#event_simpleName=ProcessRollup2
| join({
    #repo=user_directory
    | UserType=*
  }, field=UserName, as=user, include=[Department, Manager, UserType])
| join({
    #repo=asset_inventory
    | AssetType=*
  }, field=aid, as=asset, include=[AssetType, Owner, Criticality])
| table([timestamp, aid, UserName, user.Department, asset.Criticality, ImageFileName])
```

### Reporting and Metrics

#### Hunting Effectiveness Metrics
```
// Detection coverage by MITRE technique
#event_simpleName=ProcessRollup2
| timestamp >= now() - 7days
| project aid, technique=case(
    CommandLine=/(?i)(invoke-expression|iex)/, "T1059.001",
    CommandLine=/(?i)(schtasks.*create)/, "T1053.005",
    CommandLine=/(?i)(reg.*add.*run)/, "T1547.001",
    "Unknown"
  )
| where technique != "Unknown"
| groupBy([technique], function=count())
| sort(count, order=desc)
```

#### False Positive Analysis
```
// Track and reduce false positives
#event_simpleName=ProcessRollup2
| ImageFileName=/.*powershell.*/i
| CommandLine=/(?i)(get-executionpolicy|import-module)/  // Common legitimate commands
| groupBy([CommandLine], function=[count(), count(aid, distinct=true)])
| sort(count, order=desc)
// Use to whitelist common legitimate activities
```

### Emergency Response Procedures

#### Immediate Threat Assessment
```
// Critical indicators requiring immediate response
#event_simpleName=ProcessRollup2
| timestamp >= now() - 5minutes
| (ImageFileName=/(?i).*(mimikatz|procdump|cobalt|meterpreter).*/ 
  or CommandLine=/(?i)(invoke-mimikatz|sekurlsa|wdigest|tspkg)/)
| table([timestamp, aid, UserName, ImageFileName, CommandLine])
```

#### Rapid Scoping
```
// Determine blast radius
let InitialCompromise = #event_simpleName=ProcessRollup2
| aid="PATIENT_ZERO_AID"
| timestamp >= "2024-01-01T12:00:00Z"
| SHA256HashData="MALWARE_HASH";

#event_simpleName=ProcessRollup2
| timestamp >= "2024-01-01T12:00:00Z"
| SHA256HashData in (InitialCompromise.SHA256HashData)
| groupBy([aid], function=count())
| table([aid, infected_processes=count])
```

#### Evidence Collection
```
// Preserve evidence for forensics
#event_simpleName=ProcessRollup2
| aid="EVIDENCE_AID"
| timestamp between ("2024-01-01T12:00:00Z" .. "2024-01-01T13:00:00Z")
| project timestamp, aid, UserName, ImageFileName, CommandLine, SHA256HashData, ParentProcessId
// Export for forensic analysis

// Correlate with file system changes
| join({
    #event_simpleName=NewExecutableWritten
    | timestamp between ("2024-01-01T12:00:00Z" .. "2024-01-01T13:00:00Z")
  }, field=[aid, SHA256HashData], include=[TargetFileName])
```

---

## Quick Reference Commands

### Essential LogScale Functions
```
// Time functions
now(), bucket(@timestamp, span=1h), timestamp >= now() - 24hours

// String functions
length(), lower(), upper(), contains(), startsWith(), endsWith()
regex(), split(), replace()

// Array functions
array:length(), array:get(), collect(), make_list()

// Statistical functions
count(), count(field, distinct=true), sum(), avg(), min(), max()
percentile(), stddev(), variance()

// Conditional logic
if(), case(), ?field (field existence)
```

### Critical Event Types Quick Reference
```
ProcessRollup2          // Process execution
NetworkConnectIP4/6     // Network connections
DnsRequest             // DNS queries
NewExecutableWritten   // File writes
UserLogon             // Authentication events
RegGenericValue       // Registry changes
ImageHash             // File hashes
QuarantineFile        // Quarantined files
```

### Common Filter Patterns
```
// Process filtering
| ImageFileName=/.*\\(cmd|powershell|wscript)\.exe$/i
| CommandLine=/(?i)(download|invoke|base64|encoded)/
| !CommandLine=/(?i)(microsoft|windows|office)/

// Network filtering
| ConnectionDirection="Outbound"
| !RemoteAddressIP4=/^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)/
| RemotePort in [21, 22, 23, 80, 443, 445, 3389]

// Time filtering
| timestamp >= now() - 1hour
| bucket(@timestamp, span=5m)
```

### Investigation Templates
```
// Suspicious process investigation
#event_simpleName=ProcessRollup2
| aid="AID_HERE"
| timestamp >= "START_TIME"
| ImageFileName=/PATTERN/
| table([timestamp, UserName, ImageFileName, CommandLine])

// Network correlation
| join({
    #event_simpleName=NetworkConnectIP4
    | timestamp >= "START_TIME"
  }, field=aid, include=[RemoteAddressIP4, RemotePort])

// File system correlation  
| join({
    #event_simpleName=NewExecutableWritten
    | timestamp >= "START_TIME"
  }, field=[aid, SHA256HashData], include=[TargetFileName])
```

---

## Troubleshooting Common Issues

### Query Performance Problems
```
// Issue: Query timeout
// Solution: Add time constraints and field filters
#event_simpleName=ProcessRollup2
| timestamp >= now() - 1hour  // Limit time range
| aid in ["AID1", "AID2"]     // Specific systems
| ImageFileName=/.*powershell.*/i  // Specific processes

// Issue: Too many results
// Solution: Use aggregation and sampling
| groupBy([aid, ImageFileName], function=count())
| sort(count, order=desc)
| head(100)
```

### Data Availability Issues
```
// Check data sources
union *
| groupBy([#event_simpleName], function=[count(), max(timestamp)])
| sort(max_timestamp, order=desc)

// Verify agent connectivity
#event_simpleName=AgentOnline
| timestamp >= now() - 1hour
| groupBy([aid], function=count())
| where count == 0  // Offline agents
```

### False Positive Management
```
// Whitelist legitimate activities
#event_simpleName=ProcessRollup2
| ImageFileName=/.*powershell.*/i
| !CommandLine=/(?i)(get-executionpolicy|import-module|windows\\system32)/
| !UserName in ["SYSTEM", "admin_user"]
| !ImageFileName=/.*\\program files\\.*/i
```

---

*This comprehensive cheatsheet provides field-tested queries and techniques for effective threat hunting with CrowdStrike's next-generation SIEM platform. Always validate queries in your specific environment and adjust thresholds based on your organizational baseline.*