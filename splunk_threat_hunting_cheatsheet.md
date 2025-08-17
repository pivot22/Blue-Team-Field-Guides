# Splunk Threat Hunting Cheatsheet
*Elite Field Reference for Security Analysts*

## Quick Start & Environment Setup

### Essential Splunk Components
```bash
# Core Components for Threat Hunting
- Search Head: Query interface and dashboards
- Indexers: Data storage and search processing
- Forwarders: Data collection (Universal/Heavy)
- Deployment Server: Configuration management
- Apps: Splunk ES, SOAR, ITSI, UBA

# Key Apps for Security Operations
- Splunk Enterprise Security (ES)
- Splunk User Behavior Analytics (UBA)
- Splunk SOAR (Security Orchestration)
- Common Information Model (CIM)
```

### Initial Environment Validation
```spl
# Check data availability and sources
| metadata type=sourcetypes index=* 
| eval GB=round(totalCount/1024/1024/1024,2) 
| sort -GB

# Verify indexer health
| rest /services/server/info 
| table splunk_server, version, server_roles

# Check license usage
| rest /services/licenser/pools 
| eval used_GB=round(used_bytes/1024/1024/1024,2) 
| table title, used_GB, quota

# Validate field extractions
index=windows | fieldsummary | head 20
```

---

## Core SPL (Search Processing Language) Syntax

### Basic Search Structure
```spl
# Time range and index specification
index=windows earliest=-24h@h latest=now

# Field filtering and boolean operators
index=windows EventCode=4624 AND (user=administrator OR user=admin)
index=security NOT EventCode=4634
index=* source="WinEventLog:Security" OR source="WinEventLog:System"

# Wildcards and patterns
index=windows process_name="*powershell*"
index=network src_ip="192.168.*"
index=* CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*"

# Field existence and null checks
index=windows | where isnotnull(process_name)
index=network | where len(dest_port)>0

# Regular expressions
index=windows | regex CommandLine="(?i)invoke-(mimikatz|expression)"
index=dns | regex query="[a-z0-9]{20,}\.com"
```

### Advanced Search Operators
```spl
# Statistical operations
index=windows EventCode=4624 | stats count by user, src_ip
index=network | stats dc(dest_ip) as unique_destinations by src_ip

# Time-based analysis
index=windows | bucket _time span=1h | stats count by _time, EventCode

# Field manipulation
index=windows | eval hour=strftime(_time,"%H") 
| where hour<6 OR hour>22

# Multi-value fields
index=windows | mvexpand user_privileges
index=network | eval dest_ports=split(dest_port,",")
```

---

## Phase 1: Initial Reconnaissance & Data Validation

### Data Source Assessment
```spl
# Inventory available data sources
| metadata type=sourcetypes 
| eval MB=round(totalCount/1024/1024,2) 
| sort -MB 
| head 50

# Check data ingestion patterns
index=* earliest=-7d | timechart span=1d count by index

# Identify gaps in data collection
index=windows earliest=-24h 
| bucket _time span=1h 
| stats count by _time 
| where count<100

# Windows event log coverage
index=windows 
| stats count by source, EventCode 
| sort -count

# Network data validation
index=network 
| stats dc(src_ip) as sources, dc(dest_ip) as destinations by sourcetype
```

### Baseline System Activity
```spl
# Normal process execution patterns (last 30 days)
index=windows EventCode=4688 earliest=-30d@d latest=-1d@d
| stats count by process_name, user 
| sort -count 
| head 100

# Authentication baseline
index=windows EventCode=4624 earliest=-30d@d latest=-1d@d
| stats count by user, src_ip, logon_type 
| sort -count

# Network traffic patterns
index=network earliest=-7d@d latest=-1d@d
| stats sum(bytes) as total_bytes, count by dest_port 
| sort -total_bytes

# DNS query patterns  
index=dns earliest=-7d@d latest=-1d@d
| stats count by query 
| sort -count 
| head 1000
```

---

## Phase 2: Process Analysis & Malware Hunting

### Suspicious Process Detection (MITRE T1055 - Process Injection)
```spl
# PowerShell with suspicious parameters
index=windows EventCode=4688 process_name="*powershell.exe"
(CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*" OR 
 CommandLine="*IEX*" OR CommandLine="*Invoke-Expression*" OR
 CommandLine="*DownloadString*" OR CommandLine="*Net.WebClient*")

# Process injection indicators
index=windows EventCode=4688 
(process_name="svchost.exe" OR process_name="explorer.exe" OR process_name="winlogon.exe")
CommandLine!=""
| where NOT match(parent_process_name,"(services\.exe|userinit\.exe|dwm\.exe)")

# Living off the land binaries (LOLBins)
index=windows EventCode=4688 
(process_name="certutil.exe" OR process_name="bitsadmin.exe" OR 
 process_name="wmic.exe" OR process_name="regsvr32.exe" OR 
 process_name="rundll32.exe" OR process_name="mshta.exe")
(CommandLine="*http*" OR CommandLine="*ftp*" OR CommandLine="*download*")

# Base64 encoded PowerShell commands
index=windows EventCode=4688 process_name="*powershell.exe" CommandLine="*-enc*"
| rex field=CommandLine "-enc\s+(?<encoded_command>[A-Za-z0-9+/=]+)"
| eval decoded_command=base64decode(encoded_command)
| table _time, user, Computer, decoded_command
```

### Process Relationship Analysis
```spl
# Unusual parent-child relationships (T1134 - Access Token Manipulation)
index=windows EventCode=4688
((parent_process_name="winlogon.exe" AND process_name!="userinit.exe") OR
 (parent_process_name="csrss.exe") OR
 (parent_process_name="smss.exe" AND NOT (process_name="csrss.exe" OR 
  process_name="wininit.exe" OR process_name="winlogon.exe")))

# System processes from unusual locations
index=windows EventCode=4688 
(process_name="svchost.exe" OR process_name="lsass.exe" OR process_name="winlogon.exe")
| where NOT match(process_path,"^C:\\\\Windows\\\\(System32|SysWOW64)\\\\")

# Process tree analysis
index=windows EventCode=4688 Computer="SUSPICIOUS-HOST"
| eval process_tree=parent_process_name+"->"+process_name
| stats values(CommandLine) as commands, count by process_tree, user
| sort -count

# Multiple instances of single-instance processes
index=windows EventCode=4688 
(process_name="winlogon.exe" OR process_name="csrss.exe" OR process_name="lsass.exe")
| stats dc(process_id) as instance_count by process_name, Computer
| where instance_count>2
```

### Command Line Analysis (T1059 - Command and Scripting Interpreter)
```spl
# Obfuscated PowerShell detection
index=windows EventCode=4688 process_name="*powershell.exe"
(CommandLine="*{*}*" OR CommandLine="*[char]*" OR 
 CommandLine="*-join*" OR CommandLine="*[string]*" OR
 CommandLine="*replace*" OR CommandLine="*split*")

# WMI abuse detection  
index=windows EventCode=4688 CommandLine="*wmic*"
(CommandLine="*process*call*create*" OR CommandLine="*/node:*" OR
 CommandLine="*computersystem*get*" OR CommandLine="*useraccount*")

# Suspicious script execution
index=windows EventCode=4688 
(process_name="*cscript.exe" OR process_name="*wscript.exe")
(CommandLine="*http*" OR CommandLine="*ftp*" OR CommandLine="*.vbs" OR CommandLine="*.js")

# Long command lines (potential obfuscation)
index=windows EventCode=4688 
| eval cmd_length=len(CommandLine) 
| where cmd_length>500 
| sort -cmd_length

# Credential dumping tools
index=windows EventCode=4688 
(CommandLine="*mimikatz*" OR CommandLine="*sekurlsa*" OR 
 CommandLine="*procdump*lsass*" OR CommandLine="*pwdump*")
```

---

## Phase 3: Network Analysis & C2 Detection

### Command and Control Detection (T1071 - Application Layer Protocol)
```spl
# Unusual outbound connections
index=network action=allowed direction=outbound
| where NOT (cidrmatch("10.0.0.0/8",dest_ip) OR 
             cidrmatch("172.16.0.0/12",dest_ip) OR 
             cidrmatch("192.168.0.0/16",dest_ip))
| stats count by src_ip, dest_ip, dest_port, app
| sort -count

# Beaconing detection (regular intervals)
index=network direction=outbound
| bucket _time span=5m
| stats count by _time, src_ip, dest_ip
| eventstats avg(count) as avg_count, stdev(count) as stdev_count by src_ip, dest_ip
| where count>(avg_count+(2*stdev_count)) OR count<(avg_count-(2*stdev_count))

# DNS over HTTPS/TLS tunneling
index=network (dest_port=443 OR dest_port=853) app="dns"
| stats count by src_ip, dest_ip, query

# Suspicious user agents
index=web_proxy
| where match(user_agent,"(curl|wget|python|powershell|scanner|bot)")
| stats count by src_ip, user_agent, url

# High volume data transfers
index=network direction=outbound
| stats sum(bytes_out) as total_bytes by src_ip, dest_ip
| where total_bytes>104857600
| sort -total_bytes
```

### Domain Generation Algorithm (DGA) Detection
```spl
# Long random-looking domain names
index=dns
| rex field=query "^(?<domain>[^.]+)\."
| eval domain_length=len(domain)
| where domain_length>15
| regex domain="^[a-z0-9]{15,}$"
| stats count by query
| where count<5

# High entropy domain analysis
index=dns
| rex field=query "^(?<domain>[^.]+)\."
| eval entropy_score=case(
    match(domain,"^[a-z]{3,8}$"), 1,
    match(domain,"^[a-z0-9]{8,15}$"), 2,
    match(domain,"^[a-z0-9]{15,}$"), 3,
    1=1, 0)
| where entropy_score>=2
| stats count by query, entropy_score
| sort -entropy_score, count

# Newly observed domains (NODs)
index=dns earliest=-1h
| stats count by query
| where count<10
| append [search index=dns earliest=-30d@d latest=-1h | stats count by query]
| stats sum(count) as total_count by query
| where total_count<10
```

### TLS/SSL Certificate Anomalies
```spl
# Self-signed certificates
index=network ssl_issuer=ssl_subject
| stats count by ssl_issuer, dest_ip

# Certificate validation failures
index=network ssl_validity="invalid"
| stats count by dest_ip, ssl_subject, ssl_issuer

# Unusual certificate authorities
index=network ssl_issuer!=""
| where NOT match(ssl_issuer,"(DigiCert|Let's Encrypt|VeriSign|GlobalSign|Comodo|Sectigo)")
| stats count by ssl_issuer, dest_ip

# Short-lived certificates (potential malware)
index=network ssl_start_time=* ssl_end_time=*
| eval cert_duration=ssl_end_time-ssl_start_time
| eval days=round(cert_duration/86400,0)
| where days<30
| stats count by ssl_subject, dest_ip, days
```

---

## Phase 4: Authentication & Lateral Movement

### Authentication Anomalies (T1078 - Valid Accounts)
```spl
# Failed login brute force attempts
index=windows EventCode=4625
| stats count by src_ip, user
| where count>10
| sort -count

# Successful login after multiple failures
index=windows (EventCode=4624 OR EventCode=4625)
| eval status=case(EventCode=4624,"success",EventCode=4625,"failure",1=1,"unknown")
| stats count by status, src_ip, user
| where count>5

# Off-hours authentication
index=windows EventCode=4624
| eval hour=strftime(_time,"%H")
| where (hour<6 OR hour>22)
| stats count by user, src_ip, hour

# Geographic impossibility (requires GeoIP lookup)
index=windows EventCode=4624
| iplocation src_ip
| stats values(Country) as countries, values(City) as cities by user
| mvexpand countries
| stats dc(countries) as country_count by user
| where country_count>1

# Service account interactive logins
index=windows EventCode=4624 logon_type=2
| where match(user,"^(svc_|service|sql|backup|app)")
| stats count by user, Computer, src_ip
```

### Lateral Movement Detection (T1021 - Remote Services)
```spl
# RDP lateral movement
index=network dest_port=3389 action=allowed
| stats dc(dest_ip) as targets by src_ip, user
| where targets>5
| sort -targets

# WinRM usage
index=network (dest_port=5985 OR dest_port=5986)
| stats count by src_ip, dest_ip, user

# SMB lateral movement
index=network dest_port=445 action=allowed
| stats dc(dest_ip) as smb_targets by src_ip, user
| where smb_targets>10

# PsExec indicators
index=windows (EventCode=4688 process_name="*psexec*") OR 
              (EventCode=7045 service_name="PSEXESVC")
| stats count by Computer, user, src_ip

# Administrative share access
index=windows EventCode=5140 share_name="*$"
| where NOT share_name="IPC$"
| stats count by user, src_ip, dest_ip, share_name
| sort -count

# Pass-the-hash detection
index=windows EventCode=4624 logon_type=3 logon_process="NtLmSsp"
| where authentication_package="NTLM"
| stats count by user, src_ip, dest_ip
| where count>20
```

### Privilege Escalation (T1068 - Exploitation for Privilege Escalation)
```spl
# UAC bypass attempts
index=windows EventCode=4688
(CommandLine="*fodhelper*" OR CommandLine="*computerdefaults*" OR 
 CommandLine="*eventvwr*" OR CommandLine="*sdclt*")
parent_process_name="*cmd.exe" OR parent_process_name="*powershell.exe"

# Service creation for privilege escalation
index=windows EventCode=7045
| where match(service_file_name,"(cmd\.exe|powershell\.exe|rundll32\.exe)")
| stats count by Computer, service_name, service_file_name, user

# Token manipulation
index=windows EventCode=4688 
CommandLine="*SeDebugPrivilege*" OR CommandLine="*SeImpersonatePrivilege*"

# Scheduled task privilege escalation
index=windows EventCode=4698
| where match(task_content,"(SYSTEM|HIGHEST)")
| stats count by Computer, task_name, user
```

---

## Phase 5: Persistence Mechanisms

### Registry Persistence (T1547 - Boot or Logon Autostart Execution)
```spl
# Registry Run keys modification
index=windows EventCode=4657 object_name="*CurrentVersion\\Run*"
| stats count by Computer, process_name, object_name, new_value

# Service installation
index=windows EventCode=7045
| stats count by Computer, service_name, service_file_name, user
| sort -count

# WMI persistence
index=windows EventCode=4688 CommandLine="*wmic*"
(CommandLine="*EventFilter*" OR CommandLine="*CommandLineEventConsumer*")

# Startup folder modifications
index=windows EventCode=4663 object_name="*Startup*"
| stats count by Computer, process_name, object_name, user

# AppInit DLLs
index=windows EventCode=4657 
object_name="*Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs*"
| table _time, Computer, process_name, new_value
```

### File System Persistence
```spl
# Executable files in startup locations
index=windows EventCode=4663 object_name="*Startup*" process_name="*.exe"
| stats count by Computer, object_name, process_name

# DLL hijacking opportunities
index=windows EventCode=4663 object_name="*.dll"
(object_name="*System32*" OR object_name="*SysWOW64*")
| where NOT match(process_name,"(msiexec\.exe|setup\.exe|installer\.exe)")
| stats count by Computer, object_name, process_name

# Suspicious file modifications in system directories
index=windows EventCode=4663 
(object_name="*System32*" OR object_name="*SysWOW64*")
access_mask="0x2" OR access_mask="0x40000"
| stats count by Computer, object_name, process_name, user
```

### Scheduled Task Abuse (T1053.005 - Scheduled Task/Job)
```spl
# Suspicious scheduled task creation
index=windows EventCode=4698
| rex field=task_content "(?<task_command>cmd\.exe|powershell\.exe|wscript\.exe|cscript\.exe)"
| where isnotnull(task_command)
| stats count by Computer, task_name, task_command, user

# Tasks running as SYSTEM
index=windows EventCode=4698
| where match(task_content,"SYSTEM") OR match(task_content,"HIGHEST")
| table _time, Computer, task_name, user, task_content

# Task execution monitoring
index=windows EventCode=4688 parent_process_name="taskeng.exe"
| stats count by Computer, process_name, CommandLine, user
```

---

## Phase 6: Data Exfiltration & Impact

### Data Staging & Exfiltration (T1041 - Exfiltration Over C2 Channel)
```spl
# Large file transfers
index=network direction=outbound
| where bytes_out>10485760
| stats sum(bytes_out) as total_bytes by src_ip, dest_ip, user
| sort -total_bytes

# File archiving activities
index=windows EventCode=4688 
(process_name="*7z.exe" OR process_name="*winrar.exe" OR process_name="*zip.exe")
OR CommandLine="*compress*" OR CommandLine="*archive*"
| stats count by Computer, process_name, CommandLine, user

# Cloud storage uploads
index=web_proxy url="*amazonaws.com*" OR url="*dropbox.com*" OR 
                  url="*onedrive.com*" OR url="*drive.google.com*"
| where http_method="PUT" OR http_method="POST"
| stats sum(bytes_out) as upload_bytes by src_ip, url, user

# Unusual data access patterns
index=windows EventCode=4663 object_name="*.doc*" OR object_name="*.xls*" OR 
                             object_name="*.pdf*" OR object_name="*.txt*"
| stats dc(object_name) as files_accessed by user, Computer
| where files_accessed>100
| sort -files_accessed
```

### Ransomware Indicators (T1486 - Data Encrypted for Impact)
```spl
# High volume file modifications
index=windows EventCode=4663 access_mask="0x2"
| stats dc(object_name) as files_modified by process_name, user, Computer
| where files_modified>1000
| sort -files_modified

# Suspicious file extensions
index=windows EventCode=4663 
(object_name="*.locked" OR object_name="*.encrypted" OR 
 object_name="*.crypto" OR object_name="*.crypt" OR object_name="*.enc")
| stats count by Computer, object_name, process_name

# Volume shadow copy deletion
index=windows EventCode=4688 
(CommandLine="*vssadmin*delete*shadows*" OR 
 CommandLine="*wmic*shadowcopy*delete*" OR
 CommandLine="*bcdedit*bootstatuspolicy*ignoreallfailures*")

# Backup service termination
index=windows EventCode=4688 CommandLine="*net*stop*"
(CommandLine="*backup*" OR CommandLine="*vss*" OR CommandLine="*sql*")

# Mass file encryption patterns
index=windows EventCode=4663 access_mask="0x2"
| bucket _time span=1m
| stats dc(object_name) as files_per_minute by _time, process_name, Computer
| where files_per_minute>50
| sort -files_per_minute
```

---

## Advanced Hunting Techniques

### Threat Intelligence Integration
```spl
# IOC matching with lookups
index=network 
| lookup threat_intel_ips ip as dest_ip OUTPUT threat_level, threat_type
| where isnotnull(threat_level)

# Domain reputation checking
index=dns 
| lookup threat_intel_domains domain as query OUTPUT reputation
| where reputation="malicious"

# File hash correlation
index=windows EventCode=4663
| lookup threat_intel_hashes hash as file_hash OUTPUT malware_family
| where isnotnull(malware_family)

# Automated IOC enrichment
index=network dest_ip=*
| map search="| rest /services/threat_intel/ip/$dest_ip$" 
| where threat_score>7
```

### Behavioral Analysis
```spl
# Process execution frequency analysis (outlier detection)
index=windows EventCode=4688 earliest=-30d
| stats count by process_name, Computer
| eventstats avg(count) as avg_count, stdev(count) as stdev_count
| where count<(avg_count-(2*stdev_count))
| sort count

# Time-based anomaly detection
index=windows EventCode=4688
| bucket _time span=1h
| stats dc(process_name) as unique_processes by _time, Computer
| where unique_processes>100

# User behavior analytics
index=windows EventCode=4624 earliest=-7d
| stats dc(Computer) as hosts_accessed, 
        dc(src_ip) as source_ips,
        values(logon_type) as logon_types by user
| where hosts_accessed>10 OR source_ips>5

# Process spawning patterns
index=windows EventCode=4688
| eval process_pair=parent_process_name+"->"+process_name
| stats count by process_pair, Computer
| rare process_pair
| where count<5
```

### Statistical Analysis & Machine Learning
```spl
# Outlier detection using standard deviation
index=network direction=outbound earliest=-7d
| stats sum(bytes_out) as daily_bytes by date_mday, src_ip
| eventstats avg(daily_bytes) as avg_bytes, stdev(daily_bytes) as stdev_bytes by src_ip
| where daily_bytes>(avg_bytes+(3*stdev_bytes))

# Clustering analysis for similar behaviors
index=windows EventCode=4688 earliest=-24h
| stats values(process_name) as processes by user, Computer
| mvexpand processes
| xyseries user Computer processes
| cluster t=0.7 k=5

# Rare event analysis
index=windows EventCode=4688
| rare limit=10 process_name by Computer
| where count<5 AND probability<0.01

# Time series analysis for beaconing
index=network direction=outbound dest_ip="SUSPICIOUS_IP"
| bucket _time span=1m
| stats count by _time
| delta count as count_delta
| where abs(count_delta)<2
```

---

## Investigation Workflows by MITRE ATT&CK

### T1059 - Command and Scripting Interpreter Workflow
```spl
# Step 1: Identify suspicious script execution
index=windows EventCode=4688 
(process_name="*powershell.exe" OR process_name="*cmd.exe" OR 
 process_name="*wscript.exe" OR process_name="*cscript.exe")

# Step 2: Analyze command line patterns
| eval cmd_length=len(CommandLine)
| where cmd_length>100 OR match(CommandLine,"(-enc|-EncodedCommand|IEX|DownloadString)")

# Step 3: Check parent process context
| where match(parent_process_name,"(outlook\.exe|winword\.exe|excel\.exe|acrobat\.exe)")

# Step 4: Timeline analysis around suspicious execution
| eval search_time=_time
| map search="index=* earliest=$search_time$-300 latest=$search_time$+300 Computer=\"$Computer$\""
| sort _time

# Step 5: Network correlation
| map search="index=network src_ip=\"$src_ip$\" earliest=$search_time$-600 latest=$search_time$+600"
```

### T1003 - OS Credential Dumping Workflow
```spl
# Step 1: Look for credential dumping tools
index=windows EventCode=4688 
(process_name="*mimikatz*" OR CommandLine="*sekurlsa*" OR 
 CommandLine="*procdump*lsass*" OR CommandLine="*pwdump*")

# Step 2: Check LSASS process access
| append [search index=windows EventCode=4656 object_name="*lsass.exe*"]

# Step 3: Correlate with authentication events
| eval search_start=_time-300, search_end=_time+1800
| map search="index=windows EventCode=4624 earliest=$search_start$ latest=$search_end$ Computer=\"$Computer$\""

# Step 4: Check for privilege escalation
| append [search index=windows EventCode=4672 earliest=$search_start$ latest=$search_end$ Computer=\"$Computer$\""]

# Step 5: Look for lateral movement
| append [search index=network dest_port=445 earliest=$search_start$ latest=$search_end$ src_ip=\"$src_ip$\""]
```

### T1071 - Application Layer Protocol (C2) Workflow
```spl
# Step 1: Identify potential C2 traffic
index=network direction=outbound
| where NOT (cidrmatch("10.0.0.0/8",dest_ip) OR cidrmatch("172.16.0.0/12",dest_ip) OR cidrmatch("192.168.0.0/16",dest_ip))

# Step 2: Look for beaconing patterns
| bucket _time span=5m
| stats count by _time, src_ip, dest_ip
| eventstats avg(count) as avg_beacons by src_ip, dest_ip
| where count=avg_beacons AND avg_beacons>1

# Step 3: Check user agents and protocols
| append [search index=web_proxy src_ip="$src_ip$" earliest=$search_start$ latest=$search_end$]

# Step 4: Correlate with process execution
| append [search index=windows EventCode=4688 Computer="$Computer$" earliest=$search_start$ latest=$search_end$]

# Step 5: DNS analysis
| append [search index=dns src_ip="$src_ip$" earliest=$search_start$ latest=$search_end$]
```

---

## Advanced SPL Techniques

### Custom Commands and Macros
```spl
# Define reusable macros
[suspicious_processes]
definition = (process_name="*powershell.exe" OR process_name="*cmd.exe") AND (CommandLine="*-enc*" OR CommandLine="*IEX*")

# Usage: index=windows EventCode=4688 `suspicious_processes`

# Custom search commands
[hunt_lateral_movement(1)]
args = src_ip
definition = index=network (dest_port=445 OR dest_port=3389 OR dest_port=5985) src_ip="$src_ip$" | stats dc(dest_ip) as targets by src_ip | where targets>3

# Usage: `hunt_lateral_movement("192.168.1.100")`

# Time-based hunting macro
[hunt_timeframe(2)]
args = start_time, duration
definition = earliest="$start_time$" latest=relative_time("$start_time$","$duration$")

# Usage: index=windows `hunt_timeframe("2024-01-01T10:00:00","+2h")`
```

### Advanced Field Extraction
```spl
# Extract Base64 encoded content
index=windows CommandLine="*-enc*"
| rex field=CommandLine "-enc\s+(?<encoded_cmd>[A-Za-z0-9+/=]+)"
| eval decoded_cmd=base64decode(encoded_cmd)

# Extract IP addresses from command lines
index=windows EventCode=4688
| rex max_match=10 field=CommandLine "(?<extracted_ips>\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)"
| mvexpand extracted_ips

# Parse PowerShell script blocks
index=windows EventCode=4103
| rex field=ScriptBlock "Invoke-(?<ps_function>\w+)"
| stats count by ps_function, Computer

# Extract file paths
index=windows EventCode=4663
| rex field=object_name "(?<file_directory>.*\\)(?<file_name>[^\\]+)$"
| stats count by file_directory, file_name
```

### Performance Optimization
```spl
# Use tstats for fast statistical queries
| tstats count where index=windows by host, sourcetype
| sort -count

# Leverage data models for CIM compliance
| tstats count from datamodel=Endpoint.Processes where Processes.process_name="powershell.exe" by Processes.dest

# Accelerated data models
| pivot Endpoint Processes count(Processes) as process_count splitrow Processes.process_name

# Summary indexing for recurring searches
index=windows EventCode=4688 | sistats count by process_name, Computer
```

---

## Detection Rule Development

### Custom Correlation Searches
```spl
# Correlation search for credential dumping
index=windows EventCode=4688 (CommandLine="*mimikatz*" OR CommandLine="*sekurlsa*")
| eval key=Computer+"|"+user
| join type=left key [
    search index=windows EventCode=4624 earliest=-1h 
    | eval key=Computer+"|"+user 
    | stats count as auth_count by key]
| where auth_count>1
| eval risk_score=case(
    match(CommandLine,"mimikatz"), 95,
    match(CommandLine,"sekurlsa"), 90,
    match(CommandLine,"procdump.*lsass"), 85,
    1=1, 70)

# Multi-stage attack correlation
index=windows EventCode=4688 earliest=-1h
| transaction Computer maxspan=1h startswith=eval(match(process_name,"powershell")) endswith=eval(match(process_name,"net"))
| where eventcount>3
| eval attack_chain=mvjoin(process_name,"|")

# Behavioral baseline deviation
index=windows EventCode=4688 user="$user$"
| stats count by process_name
| append [
    search index=windows EventCode=4688 user="$user$" earliest=-30d@d latest=-1d@d
    | stats count as baseline_count by process_name]
| stats sum(count) as current_count, sum(baseline_count) as baseline by process_name
| where current_count>baseline*3 AND baseline>0
```

### Alert Throttling and Tuning
```spl
# Threshold-based alerting
index=windows EventCode=4625 earliest=-15m
| stats count by src_ip
| where count>10
| eval severity=case(count>50,"critical", count>20,"high", count>10,"medium")

# Time-window correlation
index=windows (EventCode=4624 OR EventCode=4625) earliest=-5m
| stats count(eval(EventCode=4625)) as failures, count(eval(EventCode=4624)) as successes by user, src_ip
| where failures>5 AND successes>0
| eval alert_priority=case(successes>failures,"high", 1=1,"medium")

# Geographic correlation (requires GeoIP)
index=windows EventCode=4624 earliest=-1h
| iplocation src_ip
| stats dc(Country) as countries, values(Country) as country_list by user
| where countries>1
| eval impossible_travel=if(countries>2,"true","false")
```

---

## Splunk Enterprise Security Integration

### Notable Event Creation
```spl
# Custom notable event rule
index=windows EventCode=4688 `suspicious_processes`
| eval dest=Computer, user=user, process=process_name
| `get_asset(dest)`
| `get_identity(user)`
| eval urgency=case(
    asset_priority="critical" AND identity_priority="high", "critical",
    asset_priority="high" OR identity_priority="high", "high",
    1=1, "medium")
| sendalert notable param._key_field=dest param.rule_name="Suspicious Process Execution"

# Adaptive response action
index=windows EventCode=4688 CommandLine="*mimikatz*"
| eval dest=Computer
| sendalert adaptive_response param.action_name="isolate_endpoint" param.target=dest
```

### Risk-Based Alerting
```spl
# Risk scoring framework
index=windows EventCode=4688 earliest=-24h
| eval risk_score=case(
    match(CommandLine,"mimikatz|sekurlsa"), 100,
    match(process_name,"powershell") AND match(CommandLine,"-enc"), 80,
    match(process_name,"cmd") AND match(parent_process_name,"winword|excel"), 60,
    match(process_name,"regsvr32|rundll32") AND match(CommandLine,"http"), 70,
    1=1, 0)
| where risk_score>0
| stats sum(risk_score) as total_risk by Computer, user
| where total_risk>150

# Asset and identity correlation
index=windows EventCode=4624
| `get_asset(Computer)`
| `get_identity(user)`
| eval risk_multiplier=case(
    asset_priority="critical", 3,
    asset_priority="high", 2,
    identity_priority="high", 2,
    1=1, 1)
| eval adjusted_risk=risk_score*risk_multiplier
```

### Threat Intelligence Framework
```spl
# IOC matching with ES threat intelligence
| inputlookup threat_intel_by_ip
| map search="index=network dest_ip=\"$ip$\" earliest=-24h"
| eval threat_match="true"

# Threat hunting with intelligence feeds
index=network dest_ip=*
| lookup local=true threat_intel_ips ip as dest_ip OUTPUT confidence, threat_type, first_seen
| where confidence>7
| eval days_since_first_seen=round((now()-first_seen)/86400,0)
| where days_since_first_seen<30

# Dynamic IOC generation
index=windows EventCode=4688 CommandLine="*mimikatz*"
| rex field=CommandLine "(?<extracted_urls>https?://[^\s]+)"
| outputlookup append=true threat_intel_urls
```

---

## Performance Optimization & Best Practices

### Search Optimization Techniques
```spl
# Use specific time ranges and indexes
index=windows EventCode=4688 earliest=-1h@h latest=now
NOT (process_name="explorer.exe" OR process_name="dwm.exe")

# Filter early in the search pipeline
index=windows earliest=-24h sourcetype="WinEventLog:Security"
| where EventCode=4688 AND process_name="powershell.exe"
| where match(CommandLine,"-enc")

# Use tstats for better performance on large datasets
| tstats count where index=windows AND sourcetype="WinEventLog:Security" by host, EventCode
| where EventCode=4688

# Leverage summary indexes
| loadjob savedsearch="admin:search:Hourly_Process_Summary"
| where process_name="powershell.exe"

# Use acceleration and data models
| from datamodel:"Endpoint"."Processes"
| where 'Processes.process_name'="powershell.exe"
```

### Memory and Resource Management
```spl
# Monitor search performance
| rest /services/search/jobs
| where isFinished=0
| table sid, runDuration, scanCount, resultCount

# Optimize large result sets
index=windows EventCode=4688 earliest=-7d
| fields _time, Computer, user, process_name, CommandLine
| dedup Computer, user, process_name
| head 10000

# Use streaming commands when possible
index=windows EventCode=4688
| streamstats count by Computer
| where count>100

# Efficient field extraction
index=windows EventCode=4688
| eval hour=strftime(_time,"%H")
| where hour>22 OR hour<6
| fields Computer, user, process_name
```

### Dashboard Optimization
```xml
<!-- Efficient dashboard panels -->
<dashboard>
  <row>
    <panel>
      <title>Top Suspicious Processes (Last 24h)</title>
      <table>
        <search>
          <query>
            | tstats count where index=windows AND sourcetype="WinEventLog:Security" 
              AND EventCode=4688 by host, process_name
            | lookup suspicious_processes process_name OUTPUT risk_score
            | where risk_score>5
            | sort -count
            | head 20
          </query>
          <earliest>-24h@h</earliest>
          <latest>now</latest>
          <refresh>300</refresh>
        </search>
      </table>
    </panel>
  </row>
</dashboard>
```

---

## Output Interpretation & Red Flags

### Process Analysis Red Flags
```spl
# Critical indicators to investigate immediately:

# 1. System processes with command lines
index=windows EventCode=4688 
(process_name="winlogon.exe" OR process_name="csrss.exe" OR process_name="smss.exe")
CommandLine!=""

# 2. Processes from unusual locations
index=windows EventCode=4688 
(process_name="svchost.exe" OR process_name="lsass.exe")
| where NOT match(process_path,"^C:\\\\Windows\\\\(System32|SysWOW64)")

# 3. Unsigned executables in system directories
index=windows EventCode=4688 process_path="*System32*"
| where isnull(signature_valid) OR signature_valid="false"

# 4. Processes with unusual network activity
index=windows EventCode=4688 process_name="notepad.exe"
| join Computer [search index=network src_ip=* dest_port!=80 dest_port!=443]
```

### Network Analysis Red Flags
```spl
# Critical network indicators:

# 1. Beaconing patterns (consistent intervals)
index=network direction=outbound dest_ip="EXTERNAL_IP"
| bucket _time span=1m
| stats count by _time
| where count>0
| streamstats count as sequence
| where sequence>10

# 2. Large data transfers to single destination
index=network direction=outbound
| stats sum(bytes_out) as total_bytes by dest_ip
| where total_bytes>1073741824  # 1GB
| sort -total_bytes

# 3. Connections to known-bad reputation IPs
index=network dest_ip=*
| lookup threat_intel_ips ip as dest_ip OUTPUT reputation
| where reputation="malicious"

# 4. Unusual protocols or ports
index=network 
| where NOT (dest_port=80 OR dest_port=443 OR dest_port=53 OR dest_port=22)
| stats count by dest_port, protocol
| rare dest_port
```

### Authentication Red Flags
```spl
# Authentication anomalies requiring immediate attention:

# 1. Multiple failed logins followed by success
index=windows (EventCode=4624 OR EventCode=4625) user="target_user"
| transaction user maxspan=10m
| where eventcount>10
| eval failed_attempts=mvcount(mvfilter(match(EventCode,"4625")))
| where failed_attempts>5

# 2. Service accounts with interactive logins
index=windows EventCode=4624 logon_type=2
| where match(user,"^(svc|sql|backup|app|service)")

# 3. Impossible travel scenarios
index=windows EventCode=4624 user="target_user"
| iplocation src_ip
| sort _time
| streamstats previous(Country) as prev_country, previous(_time) as prev_time by user
| eval time_diff=(_time-prev_time)/3600
| where Country!=prev_country AND time_diff<8  # Less than 8 hours between countries

# 4. Privileged account abuse
index=windows EventCode=4672 user="domain_admin"
| stats count by Computer, src_ip
| where count>1  # Domain admin logging into multiple systems
```

---

## Integration with External Tools

### SOAR Integration
```python
# Example Python script for Splunk-SOAR integration
import splunklib.client as client
import requests

# Connect to Splunk
service = client.connect(host='splunk-server', port=8089, 
                        username='api_user', password='password')

# Execute threat hunting search
search_query = '''
search index=windows EventCode=4688 CommandLine="*mimikatz*" earliest=-1h
| stats count by Computer, user, CommandLine
'''

job = service.jobs.create(search_query)
# Wait for completion and process results

# Send to SOAR platform
soar_payload = {
    "alert_type": "credential_dumping",
    "severity": "high", 
    "indicators": results
}
requests.post("https://soar-platform/api/alerts", json=soar_payload)
```

### Threat Intelligence Feeds
```spl
# Automated IOC ingestion
| inputlookup misp_indicators.csv
| eval confidence=case(
    threat_type="APT", 9,
    threat_type="malware", 8,
    threat_type="phishing", 7,
    1=1, 5)
| outputlookup threat_intel_master.csv

# STIX/TAXII integration
| rest /services/data/inputs/http/misp_feed
| spath input=value
| rename indicator{}.pattern as ioc_pattern
| outputlookup append=true threat_intel_stix.csv

# Real-time IOC matching
index=network dest_ip=*
| lookup threat_intel_master.csv ip as dest_ip OUTPUT confidence, last_seen
| where confidence>7 AND (now()-last_seen)<604800  # Week old indicators
```

### SIEM/XDR Integration
```spl
# Export to external SIEM
index=windows EventCode=4688 `suspicious_processes`
| eval alert_time=strftime(_time,"%Y-%m-%dT%H:%M:%S")
| eval siem_format="{\"timestamp\":\"".alert_time."\",\"host\":\"".Computer."\",\"event\":\"suspicious_process\",\"details\":\"".CommandLine."\"}"
| outputlookup siem_export.csv

# CEF format export for ArcSight
index=windows EventCode=4688 CommandLine="*mimikatz*"
| eval cef_event="CEF:0|Splunk|ThreatHunt|1.0|CRED_DUMP|Credential Dumping Detected|8|src=".src_ip." dst=".Computer." suser=".user." cs1=".CommandLine

# Elasticsearch integration
index=windows EventCode=4688 earliest=-1h
| eval elastic_doc="{\"@timestamp\":\"".strftime(_time,"%Y-%m-%dT%H:%M:%S")."\",\"host\":\"".Computer."\",\"process\":\"".process_name."\",\"command\":\"".CommandLine."\"}"
| outputlookup elastic_export.json
```

---

## Common Pitfalls & Troubleshooting

### Search Performance Issues
```spl
# Avoid inefficient wildcards
# BAD: index=* "*mimikatz*"
# GOOD: index=windows EventCode=4688 CommandLine="*mimikatz*"

# Use specific sourcetypes
# BAD: index=windows mimikatz
# GOOD: index=windows sourcetype="WinEventLog:Security" CommandLine="*mimikatz*"

# Limit search scope
# BAD: index=windows earliest=-30d CommandLine="*powershell*"
# GOOD: index=windows earliest=-1h CommandLine="*powershell*" EventCode=4688

# Use summary indexing for recurring searches
# Create summary: index=windows EventCode=4688 | sistats count by process_name, Computer
# Use summary: | loadjob savedsearch="Process_Summary" | where process_name="powershell.exe"
```

### Data Quality Issues
```spl
# Handle missing fields
index=windows EventCode=4688
| fillnull value="unknown" user, Computer, process_name
| where user!="unknown"

# Normalize field values
index=windows EventCode=4688
| eval process_name=lower(process_name)
| eval process_name=replace(process_name,"\.exe$","")

# Deal with multi-value fields
index=windows EventCode=4624
| mvexpand user_privileges
| where user_privileges="SeDebugPrivilege"

# Time zone normalization
index=windows EventCode=4688
| eval local_time=strftime(_time,"%Y-%m-%d %H:%M:%S %Z")
| eval utc_time=strftime(_time,"%Y-%m-%d %H:%M:%S UTC")
```

### False Positive Reduction
```spl
# Whitelist known-good processes
index=windows EventCode=4688 process_name="powershell.exe"
| lookup process_whitelist process_name, process_path OUTPUT is_approved
| where isnull(is_approved)

# Context-aware filtering
index=windows EventCode=4688 process_name="cmd.exe" 
parent_process_name="winword.exe"
| where NOT match(CommandLine,"(Microsoft|Office|Word)")

# User behavior baseline
index=windows EventCode=4688 user="target_user"
| lookup user_behavior_baseline user OUTPUT normal_processes
| where NOT match(process_name,normal_processes)

# Time-based filtering
index=windows EventCode=4624 earliest=-1h
| eval hour=strftime(_time,"%H")
| lookup business_hours hour OUTPUT is_business_hours
| where is_business_hours="false"
```

---

## Quick Reference Commands

### Most Critical Searches for Threat Hunting
```spl
# The "Essential 10" - Run these for any investigation

# 1. Suspicious process execution
index=windows EventCode=4688 (process_name="*powershell.exe" OR process_name="*cmd.exe") 
(CommandLine="*-enc*" OR CommandLine="*IEX*" OR CommandLine="*DownloadString*")

# 2. Failed authentication analysis  
index=windows EventCode=4625 | stats count by user, src_ip | where count>10

# 3. Lateral movement detection
index=network (dest_port=445 OR dest_port=3389 OR dest_port=5985) 
| stats dc(dest_ip) as targets by src_ip | where targets>5

# 4. Outbound network connections
index=network direction=outbound | where NOT cidrmatch("RFC1918",dest_ip) 
| stats count by dest_ip, dest_port | sort -count

# 5. Service creation
index=windows EventCode=7045 | stats count by service_name, service_file_name, Computer

# 6. Registry modifications
index=windows EventCode=4657 object_name="*Run*" | table _time, Computer, process_name, new_value

# 7. Scheduled task creation
index=windows EventCode=4698 | table _time, Computer, task_name, user

# 8. File system modifications
index=windows EventCode=4663 object_name="*System32*" access_mask="0x2" 
| stats count by object_name, process_name

# 9. Privilege escalation
index=windows EventCode=4672 | stats count by user, Computer | where count>1

# 10. DNS queries to suspicious domains
index=dns | lookup threat_intel_domains domain as query OUTPUT reputation 
| where reputation="suspicious"
```

### Emergency Response Queries
```spl
# Rapid IOC sweep
(index=windows OR index=network OR index=dns) 
("MALICIOUS_IP" OR "MALICIOUS_DOMAIN" OR "MALICIOUS_HASH")

# Host compromise assessment
index=windows Computer="SUSPICIOUS_HOST" earliest=-24h
| stats count by EventCode, process_name, user | sort -count

# User activity timeline
index=windows user="COMPROMISED_USER" earliest=-7d
| sort _time | table _time, EventCode, Computer, process_name, src_ip

# Network connections summary
index=network src_ip="INTERNAL_IP" direction=outbound earliest=-24h
| stats sum(bytes_out) as total_bytes, count by dest_ip | sort -total_bytes

# Process execution timeline
index=windows EventCode=4688 Computer="TARGET_HOST" earliest=-2h latest=-1h
| sort _time | table _time, process_name, parent_process_name, CommandLine, user
```

---

## Additional Resources & Training

### Essential Splunk Documentation
- **Search Reference**: https://docs.splunk.com/Documentation/Splunk/latest/SearchReference
- **Common Information Model**: https://docs.splunk.com/Documentation/CIM/latest/User/Overview
- **Enterprise Security**: https://docs.splunk.com/Documentation/ES/latest/User/Howtouse

### Community Resources
- **Splunk Security Essentials**: Pre-built security use cases and searches
- **BOTS (Boss of the SOC)**: Hands-on security dataset challenges
- **Splunk Security Research**: https://research.splunk.com/

### Certification Paths
- **Splunk Core Certified User**: Foundation knowledge
- **Splunk Enterprise Security Certified Admin**: ES-specific skills
- **Splunk Certified Cybersecurity Defense Analyst**: Advanced security analytics

### Advanced Training Resources
- **SANS FOR572**: Advanced Network Forensics (includes Splunk)
- **SANS SEC555**: SIEM with Tactical Analytics
- **Splunk .conf**: Annual conference with security tracks

---

## Troubleshooting Guide

### Search Head Issues
```spl
# Check search head performance
| rest /services/server/status/resource-usage/splunk-processes 
| where search_type="adhoc" | stats avg(mem_used) by user

# Monitor concurrent searches
| rest /services/search/jobs | where isFinished=0 | stats count by eai:acl.owner

# Check bundle replication
| rest /services/replication/configuration/receive | table replicationPolicy, status
```

### Data Ingestion Problems
```spl
# Monitor indexing rate
| rest /services/server/introspection/indexer 
| eval GB_per_day=kb_eps*86400/1024/1024 | table host, GB_per_day

# Check for parsing errors
index=_internal source="*splunkd.log*" ERROR "Failed to parse"

# Validate field extractions
index=windows | fieldsummary maxvals=5 | where count>0
```

### Performance Tuning
```spl
# Identify slow searches
index=_audit action=search | stats avg(total_run_time) by search | sort -avg(total_run_time)

# Memory usage analysis
| rest /services/server/status/resource-usage/hostwide 
| eval mem_usage_pct=round(mem_used/mem*100,2)

# Optimize knowledge objects
| rest /services/saved/searches | where cron_schedule!="" | table title, search, cron_schedule
```

---

*This cheatsheet is designed for authorized security monitoring and incident response activities. Always ensure compliance with organizational policies and legal requirements.*

**Last Updated**: August 2025 | **Version**: 4.1