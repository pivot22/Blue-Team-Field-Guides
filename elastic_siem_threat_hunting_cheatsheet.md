# Elastic SIEM/ELK Threat Hunting Cheatsheet
*Elite Field Reference for Security Analysts*

## Quick Start & Environment Setup

### Essential Elastic Stack Components
```yaml
# Core Stack (Production Minimum)
- Elasticsearch: Data storage and search engine
- Logstash: Data processing pipeline  
- Kibana: Visualization and SIEM interface
- Beats: Data shippers (Filebeat, Winlogbeat, Auditbeat, Packetbeat)
- Elastic Agent: Unified data collection platform
```

### Initial Environment Validation
```bash
# Check cluster health
GET /_cluster/health

# Verify indices and data ingestion
GET /_cat/indices?v&s=store.size:desc

# Check active data streams
GET /_data_stream

# Validate field mappings for threat hunting
GET /logs-*/_mapping/field/event.category
```

---

## Core KQL (Kibana Query Language) Syntax

### Basic Query Structure
```kql
# Simple field:value queries
event.category : "process"
source.ip : "192.168.1.1"
user.name : "administrator"

# Boolean operators (case-sensitive)
event.category : "network" AND destination.port : 443
process.name : "powershell.exe" OR process.name : "cmd.exe"
NOT event.outcome : "success"

# Wildcards and patterns
process.command_line : "*powershell*"
file.name : *.exe
source.ip : 10.0.*

# Ranges and comparisons  
@timestamp >= "2024-01-01" AND @timestamp <= "2024-01-31"
destination.port >= 1024
event.duration > 5000
```

### Advanced KQL Operators
```kql
# Exists queries
process.parent.name : *

# Regex patterns (use carefully - performance impact)
process.command_line : /.*(?i)(invoke-mimikatz|get-credential).*/

# Phrase matching
message : "failed login attempt"

# Nested field queries
process.parent.command_line : "*powershell*" AND process.name : "cmd.exe"
```

---

## Phase 1: Initial Reconnaissance & Data Validation

### Data Source Validation
```kql
# Check data ingestion patterns
event.dataset : *
| stats count by event.dataset
| sort count desc

# Validate log sources are reporting
agent.name : *
| stats count by agent.name, host.name
| sort count desc

# Check for data gaps (critical for threat hunting)
@timestamp >= "now-24h"
| stats count by event.dataset
| where count < 100
```

### Baseline System Activity
```kql
# Normal process execution patterns
event.category : "process" AND event.action : "start"
| stats count by process.name, user.name
| sort count desc
| head 50

# Network traffic baselines  
event.category : "network"
| stats count by destination.port, network.protocol
| sort count desc

# Authentication patterns
event.category : "authentication"
| stats count by event.outcome, user.name, source.ip
| sort count desc
```

---

## Phase 2: Process Analysis & Malware Hunting

### Suspicious Process Detection (MITRE T1055 - Process Injection)
```kql
# PowerShell execution with suspicious parameters
process.name : "powershell.exe" AND 
(process.command_line : "*-enc*" OR 
 process.command_line : "*-EncodedCommand*" OR
 process.command_line : "*IEX*" OR
 process.command_line : "*Invoke-Expression*" OR
 process.command_line : "*DownloadString*")

# Process injection indicators
process.name : ("svchost.exe" OR "explorer.exe" OR "winlogon.exe") AND
process.command_line : * AND
NOT process.parent.name : ("services.exe" OR "userinit.exe")

# Living off the land binaries (LOLBins)
process.name : ("certutil.exe" OR "bitsadmin.exe" OR "wmic.exe" OR 
                "regsvr32.exe" OR "rundll32.exe" OR "mshta.exe") AND
(process.command_line : "*http*" OR 
 process.command_line : "*ftp*" OR
 process.command_line : "*download*")
```

### Process Relationship Analysis
```kql
# Unusual parent-child relationships (T1134 - Access Token Manipulation)
(process.parent.name : "winlogon.exe" AND NOT process.name : "userinit.exe") OR
(process.parent.name : "csrss.exe" AND process.name : *) OR  
(process.parent.name : "smss.exe" AND NOT process.name : ("csrss.exe" OR "wininit.exe" OR "winlogon.exe"))

# System processes from unusual locations
process.name : ("svchost.exe" OR "lsass.exe" OR "winlogon.exe") AND
NOT process.executable : ("C:\\Windows\\System32\\*" OR "C:\\Windows\\SysWOW64\\*")

# Multiple instances of typically single processes
process.name : ("winlogon.exe" OR "csrss.exe" OR "lsass.exe")
| stats dc(process.pid) as process_count by process.name, host.name
| where process_count > 2
```

### Command Line Analysis (T1059 - Command and Scripting Interpreter)
```kql
# Base64 encoded commands
process.command_line : "*-enc*" OR process.command_line : "*-EncodedCommand*"
| eval decoded_command = base64decode(process.command_line)

# Obfuscated PowerShell
process.name : "powershell.exe" AND
(process.command_line : "*{*}*" OR
 process.command_line : "*[char]*" OR  
 process.command_line : "*-join*" OR
 process.command_line : "*[string]*")

# WMI abuse detection
process.command_line : "*wmic*" AND
(process.command_line : "*process*call*create*" OR
 process.command_line : "*/node:*" OR
 process.command_line : "*computersystem*get*")
```

---

## Phase 3: Network Analysis & C2 Detection

### Command and Control Detection (T1071 - Application Layer Protocol)
```kql
# Unusual outbound connections
event.category : "network" AND event.action : "connection_attempted" AND
source.ip : (10.0.0.0/8 OR 172.16.0.0/12 OR 192.168.0.0/16) AND
NOT destination.ip : (10.0.0.0/8 OR 172.16.0.0/12 OR 192.168.0.0/16 OR 127.0.0.0/8)
| stats count by destination.ip, destination.port, process.name
| sort count desc

# Beaconing detection (regular intervals)
event.category : "network" AND event.action : "connection_attempted"
| bucket span=1m @timestamp
| stats count by @timestamp, source.ip, destination.ip
| where count > 1

# DNS over HTTPS/TLS tunneling
event.category : "network" AND destination.port : (443 OR 853) AND
(dns.question.name : "*" OR network.protocol : "dns")

# Suspicious user agents
http.request.headers.user-agent : ("curl*" OR "wget*" OR "python*" OR 
                                   "powershell*" OR "*bot*" OR "scanner*")
```

### Domain Generation Algorithm (DGA) Detection
```kql
# Long random-looking domain names
dns.question.name : /.{20,}/ AND
dns.question.name : /[a-z]{8,}\./
| stats count by dns.question.name
| where count < 5

# High entropy domain names (manual analysis required)
dns.question.name : *
| stats count by dns.question.name  
| where count < 10
| eval domain_length = length(dns.question.name)
| where domain_length > 15
```

### TLS/SSL Certificate Anomalies
```kql
# Self-signed certificates
tls.server.certificate.is_ca : false AND 
tls.server.certificate.issuer : tls.server.certificate.subject

# Certificate validation failures
tls.server.certificate.verification_status : "untrusted" OR
event.outcome : "failure" AND event.category : "network"

# Unusual certificate authorities
tls.server.certificate.issuer : * AND
NOT tls.server.certificate.issuer : ("DigiCert*" OR "Let's Encrypt*" OR 
                                      "VeriSign*" OR "GlobalSign*" OR "Comodo*")
```

---

## Phase 4: Authentication & Lateral Movement

### Authentication Anomalies (T1078 - Valid Accounts)
```kql
# Failed login attempts from single source
event.category : "authentication" AND event.outcome : "failure"
| stats count by source.ip, user.name
| where count > 10
| sort count desc

# Successful login after multiple failures (potential brute force)
event.category : "authentication"
| stats count by event.outcome, source.ip, user.name
| where count > 5
| pivot index=security event.outcome

# Off-hours authentication
event.category : "authentication" AND event.outcome : "success"
| eval hour = date_hour(@timestamp)
| where hour < 6 OR hour > 22
| stats count by user.name, source.ip

# Geographic impossibility (requires GeoIP enrichment)
event.category : "authentication" AND event.outcome : "success"
| stats values(source.geo.country_name) as countries by user.name
| where length(countries) > 1
```

### Lateral Movement Detection (T1021 - Remote Services)
```kql
# RDP/Terminal Services abuse
event.category : "network" AND destination.port : 3389 AND
source.ip : (10.0.0.0/8 OR 172.16.0.0/12 OR 192.168.0.0/16)
| stats dc(destination.ip) as target_count by source.ip
| where target_count > 5

# WinRM usage
event.category : "network" AND destination.port : (5985 OR 5986)
| stats count by source.ip, destination.ip, user.name

# SMB lateral movement
event.category : "network" AND destination.port : 445 AND
event.action : "connection_attempted"
| stats dc(destination.ip) as targets by source.ip, user.name  
| where targets > 10

# PsExec indicators
process.name : "psexec.exe" OR 
process.command_line : "*psexec*" OR
file.name : "psexesvc.exe"
```

### Privilege Escalation (T1068 - Exploitation for Privilege Escalation)
```kql
# UAC bypass attempts  
event.category : "process" AND 
(process.command_line : "*fodhelper*" OR
 process.command_line : "*computerdefaults*" OR
 process.command_line : "*eventvwr*") AND
process.parent.name : ("cmd.exe" OR "powershell.exe")

# Service creation for privilege escalation
event.category : "process" AND event.action : "start" AND
process.name : "sc.exe" AND 
process.command_line : "*create*" AND
process.command_line : "*binpath*"

# Token manipulation
event.category : "process" AND
process.command_line : ("*SeDebugPrivilege*" OR "*SeImpersonatePrivilege*")
```

---

## Phase 5: Persistence Mechanisms

### Registry Persistence (T1547 - Boot or Logon Autostart Execution)
```kql
# Registry Run keys modification
event.category : "registry" AND 
registry.path : ("*\\CurrentVersion\\Run*" OR 
                 "*\\CurrentVersion\\RunOnce*" OR
                 "*\\Winlogon\\*" OR  
                 "*\\Explorer\\*")

# Service installation
event.category : "registry" AND
registry.path : "*\\CurrentControlSet\\Services\\*" AND
event.action : "creation"

# Scheduled task creation via registry
event.category : "registry" AND
registry.path : "*\\Schedule\\TaskCache\\*" AND
event.action : "creation"
```

### File System Persistence
```kql
# Startup folder modifications
event.category : "file" AND
file.path : ("*\\Startup\\*" OR "*\\Start Menu\\Programs\\Startup\\*")

# DLL hijacking opportunities
event.category : "file" AND event.action : "creation" AND
file.extension : "dll" AND
file.path : ("*\\System32\\*" OR "*\\SysWOW64\\*") AND
NOT process.name : ("msiexec.exe" OR "setup.exe" OR "installer.exe")

# WMI persistence
process.name : "wmic.exe" AND
process.command_line : "*EventFilter*" AND
process.command_line : "*CommandLineEventConsumer*"
```

### Scheduled Task Abuse (T1053.005 - Scheduled Task/Job)
```kql
# Suspicious scheduled task creation
process.name : "schtasks.exe" AND
(process.command_line : "*SYSTEM*" OR 
 process.command_line : "*HIGHEST*" OR
 process.command_line : "*powershell*" OR
 process.command_line : "*cmd*")

# Task Scheduler service manipulation
event.category : "process" AND
process.command_line : "*taskschd*" AND
event.action : "start"
```

---

## Phase 6: Data Exfiltration & Impact

### Data Staging & Exfiltration (T1041 - Exfiltration Over C2 Channel)
```kql
# Large file transfers
event.category : "network" AND network.bytes > 10485760
| stats sum(network.bytes) as total_bytes by source.ip, destination.ip
| sort total_bytes desc

# File archiving activities
process.name : ("7z.exe" OR "winrar.exe" OR "zip.exe") OR
process.command_line : ("*compress*" OR "*archive*" OR "*rar*" OR "*7z*")

# Cloud storage uploads
http.request.headers.host : ("*.amazonaws.com" OR "*.dropbox.com" OR 
                             "*.onedrive.com" OR "*.drive.google.com") AND
http.request.method : "PUT"
```

### Ransomware Indicators (T1486 - Data Encrypted for Impact)
```kql
# High volume file modifications
event.category : "file" AND event.action : ("change" OR "creation" OR "rename")
| stats dc(file.path) as file_count by process.name, user.name
| where file_count > 1000

# Suspicious file extensions
event.category : "file" AND 
file.extension : ("locked" OR "encrypted" OR "crypto" OR "crypt" OR "enc")

# Volume shadow copy deletion
process.command_line : "*vssadmin*delete*shadows*" OR
process.command_line : "*wmic*shadowcopy*delete*" OR
process.command_line : "*bcdedit*bootstatuspolicy*ignoreallfailures*"

# Backup service termination
process.command_line : "*net*stop*" AND
process.command_line : ("*backup*" OR "*vss*" OR "*sql*")
```

---

## Advanced Hunting Techniques

### Threat Intelligence Integration
```kql
# IOC matching (requires threat intel feeds)
source.ip : [threat_intel_ips] OR
destination.ip : [threat_intel_ips] OR  
dns.question.name : [threat_intel_domains] OR
file.hash.sha256 : [threat_intel_hashes]

# YARA rule hits (requires Elastic Security)
rule.name : * AND rule.category : "malware"
| stats count by rule.name, file.path, host.name
```

### Behavioral Analysis
```kql
# Process execution frequency analysis
event.category : "process" AND event.action : "start"
| stats count as exec_count by process.name, user.name, host.name
| where exec_count = 1  # Rare process executions

# Time-based analysis for APT detection
event.category : "process" 
| bucket span=1h @timestamp
| stats dc(process.name) as unique_processes by @timestamp, host.name
| where unique_processes > 50  # Unusual activity bursts
```

### Machine Learning Anomalies (Elastic Security)
```kql
# Anomaly detection jobs results
ml_anomaly_score > 75 AND 
ml_job_id : ("suspicious_process_activity" OR "network_anomaly_detection")

# Rare process-host combinations
rare by process.name, host.name
| where count < 5
```

---

## Investigation Workflows by MITRE ATT&CK

### T1059 - Command and Scripting Interpreter
```kql
# Step 1: Identify suspicious script execution
process.name : ("powershell.exe" OR "cmd.exe" OR "wscript.exe" OR "cscript.exe")

# Step 2: Analyze command lines
process.command_line : * 
| where length(process.command_line) > 100

# Step 3: Check for parent process context
process.parent.name : ("outlook.exe" OR "winword.exe" OR "excel.exe")

# Step 4: Timeline analysis
@timestamp >= "now-1d" 
| sort @timestamp asc
```

### T1003 - OS Credential Dumping  
```kql
# Step 1: Look for credential dumping tools
process.name : ("mimikatz.exe" OR "procdump.exe" OR "pwdump.exe") OR
process.command_line : ("*sekurlsa*" OR "*logonpasswords*" OR "*lsass*")

# Step 2: Check LSASS access
process.name : * AND process.command_line : "*lsass*"

# Step 3: Correlate with authentication events
event.category : "authentication" 
| where @timestamp >= "process_start_time"

# Step 4: Check for privilege escalation
user.name : * AND process.user.name : "SYSTEM"
```

### T1071 - Application Layer Protocol (C2)
```kql
# Step 1: Identify potential C2 traffic
event.category : "network" AND network.direction : "outbound"

# Step 2: Look for beaconing patterns
| bucket span=5m @timestamp
| stats count by @timestamp, destination.ip

# Step 3: Check user agents and TLS patterns  
http.request.headers.user_agent : * OR tls.server.certificate.*

# Step 4: Correlate with process execution
process.name : * AND network.community_id : *
```

---

## Detection Rule Development

### Sigma Rule Translation
```yaml
# Example Sigma rule for PowerShell execution
title: Suspicious PowerShell Execution
logsource:
    product: windows  
    service: process_creation
detection:
    selection:
        Image: '*\powershell.exe'
        CommandLine|contains:
            - '-enc'  
            - 'IEX'
            - 'DownloadString'
    condition: selection
```

### Elastic Detection Rule (KQL)
```kql
# Convert Sigma to KQL
process.name : "powershell.exe" AND 
process.command_line : ("*-enc*" OR "*IEX*" OR "*DownloadString*")
```

### Custom Detection Rules
```json
{
  "rule": {
    "name": "Suspicious PowerShell Execution",
    "description": "Detects suspicious PowerShell command execution",
    "risk_score": 75,
    "severity": "high",
    "type": "query",
    "query": "process.name : \"powershell.exe\" AND process.command_line : (\"*-enc*\" OR \"*IEX*\" OR \"*DownloadString*\")",
    "language": "kuery",
    "filters": [],
    "threat": [
      {
        "framework": "MITRE ATT&CK",
        "tactic": {
          "id": "TA0002", 
          "name": "Execution"
        },
        "technique": [
          {
            "id": "T1059.001",
            "name": "PowerShell"
          }
        ]
      }
    ]
  }
}
```

---

## Performance Optimization & Best Practices

### Query Optimization
```kql
# Use specific time ranges
@timestamp >= "now-24h" AND @timestamp <= "now"

# Filter early in the query
event.category : "process" AND @timestamp >= "now-1h"
| where process.name : "powershell.exe"  # Better performance

# Use exists queries efficiently  
process.command_line : * AND event.category : "process"

# Leverage data streams and indices
index : "logs-endpoint.events.process-*" AND process.name : "cmd.exe"
```

### Memory Management
```bash
# Monitor cluster performance
GET /_cluster/stats
GET /_nodes/stats

# Check query performance
GET /_search/template/threat_hunting_template/_profile

# Optimize field mappings for hunting
PUT /logs-custom-threat-hunting
{
  "mappings": {
    "properties": {
      "threat_score": {"type": "integer"},
      "ioc_match": {"type": "boolean"}
    }
  }
}
```

### Dashboard Creation
```json
{
  "dashboard": {
    "title": "Threat Hunting Overview",
    "panels": [
      {
        "title": "Suspicious Process Execution",
        "type": "data_table",
        "query": "process.name : (\"powershell.exe\" OR \"cmd.exe\") AND process.command_line : \"*-enc*\""
      },
      {
        "title": "Network Anomalies", 
        "type": "line_chart",
        "query": "event.category : \"network\" | stats count by destination.port"
      }
    ]
  }
}
```

---

## Output Interpretation & Red Flags

### Process Analysis Red Flags
- **Unusual parent-child relationships**: Office applications spawning cmd.exe or powershell.exe
- **System processes with command lines**: System processes typically don't have command line arguments
- **Base64 encoded commands**: Almost always indicates obfuscation or malware
- **Living off the land**: Legitimate tools used maliciously (certutil, bitsadmin, regsvr32)
- **Process injection indicators**: Processes running from unusual locations or with unexpected behavior

### Network Analysis Red Flags
- **Beaconing patterns**: Regular, consistent communication intervals
- **Unusual protocols**: DNS over HTTPS, non-standard ports
- **Geographic anomalies**: Authentication from impossible locations
- **High-entropy domains**: Random-looking domain names (DGA)
- **Certificate anomalies**: Self-signed, expired, or unusual CA certificates

### Authentication Red Flags
- **Time-based anomalies**: Logins outside business hours
- **Geographic impossibility**: Logins from multiple countries simultaneously  
- **Brute force patterns**: Multiple failed attempts followed by success
- **Service account abuse**: Interactive logins for service accounts
- **Privilege escalation**: Users gaining unexpected high-level access

---

## Integration with Security Tools

### SOAR Integration
```python
# Example Python integration for automated response
import elasticsearch
from elasticsearch import Elasticsearch

es = Elasticsearch(['localhost:9200'])

# Automated threat hunting query
hunt_query = {
    "query": {
        "bool": {
            "must": [
                {"term": {"event.category": "process"}},
                {"wildcard": {"process.command_line": "*-enc*"}}
            ]
        }
    }
}

results = es.search(index="logs-*", body=hunt_query)
```

### Threat Intelligence Feeds
```kql
# Enrich with threat intel (requires proper field mapping)
source.ip : * 
| enrich threat_intel_policy on source.ip 
| where threat.indicator.type : "malicious"

# IOC matching workflow
| eval ioc_match = case(
    source.ip in [known_bad_ips], "malicious_ip",
    dns.question.name in [known_bad_domains], "malicious_domain", 
    file.hash.sha256 in [known_bad_hashes], "malicious_hash"
)
| where ioc_match != null
```

### Alerting Configuration
```json
{
  "trigger": {
    "schedule": {
      "interval": "5m"
    }
  },
  "input": {
    "search": {
      "request": {
        "indices": ["logs-*"],
        "body": {
          "query": {
            "bool": {
              "must": [
                {"range": {"@timestamp": {"gte": "now-5m"}}},
                {"term": {"event.category": "process"}},
                {"wildcard": {"process.command_line": "*mimikatz*"}}
              ]
            }
          }
        }
      }
    }
  },
  "condition": {
    "compare": {
      "ctx.payload.hits.total": {
        "gt": 0
      }
    }
  },
  "actions": {
    "send_email": {
      "email": {
        "to": ["security@company.com"],
        "subject": "Potential Credential Dumping Activity Detected"
      }
    }
  }
}
```

---

## Common Pitfalls & Troubleshooting

### Query Performance Issues
```kql
# Avoid leading wildcards (slow)
BAD: process.command_line : "*powershell*"
GOOD: process.name : "powershell.exe" AND process.command_line : "*"

# Use specific time ranges
BAD: process.name : "cmd.exe"  # Searches all data
GOOD: @timestamp >= "now-24h" AND process.name : "cmd.exe"

# Leverage data tiers and indices
GOOD: index : "logs-endpoint.events.process-default" AND process.name : "cmd.exe"
```

### Data Normalization Issues
```kql
# Handle case sensitivity
process.name : ("PowerShell.exe" OR "powershell.exe" OR "POWERSHELL.EXE")

# Account for different log sources
(process.name : "powershell.exe" OR winlog.event_data.Image : "*powershell.exe")

# Normalize IP addresses
source.address : "192.168.1.1" OR source.ip : "192.168.1.1"
```

### False Positive Reduction
```kql
# Exclude known-good processes
process.name : "powershell.exe" AND 
process.command_line : "*-enc*" AND
NOT process.parent.name : ("Microsoft.Powershell.ConsoleHost.exe" OR "ISE.exe") AND
NOT user.name : ("svc_backup" OR "admin_user")

# Context-aware filtering
process.name : "cmd.exe" AND
process.parent.name : ("winword.exe" OR "excel.exe") AND
NOT process.command_line : "*Office*"
```

---

## Elastic Security Specific Features

### Endpoint Security Integration
```kql
# Endpoint detection events
event.module : "endpoint" AND event.category : "malware"

# Behavior protection events  
event.action : ("shellcode_thread" OR "memory_signature" OR "ransomware")

# Host isolation status
host.isolation : true

# Malware prevention
event.category : "malware" AND event.action : ("quarantine" OR "prevent")
```

### Machine Learning Jobs
```json
{
  "job_id": "threat_hunting_anomalies",
  "description": "Detects anomalous process execution patterns",
  "analysis_config": {
    "bucket_span": "15m",
    "detectors": [
      {
        "function": "rare",
        "by_field_name": "process.name",
        "over_field_name": "host.name"
      }
    ]
  },
  "data_description": {
    "time_field": "@timestamp",
    "time_format": "epoch_ms"
  }
}
```

### Timeline Investigation
```kql
# Build investigation timeline
@timestamp >= "2024-01-01T10:00:00" AND @timestamp <= "2024-01-01T12:00:00" AND
host.name : "suspicious-host"
| sort @timestamp asc
| eval event_description = case(
    event.category == "process", concat("Process: ", process.name, " executed"),
    event.category == "network", concat("Network: Connection to ", destination.ip),
    event.category == "file", concat("File: ", event.action, " ", file.path)
)
```

---

## Quick Reference Commands

### Most Critical Queries for Threat Hunting
```kql
# The "Big 5" - Run these first for any investigation
1. process.name : ("powershell.exe" OR "cmd.exe") AND process.command_line : "*"
2. event.category : "network" AND network.direction : "outbound"  
3. event.category : "authentication" AND event.outcome : "failure"
4. event.category : "file" AND event.action : "creation" AND file.extension : "exe"
5. @timestamp >= "now-24h" | stats count by event.category, event.action

# Emergency IOC hunting
source.ip : "THREAT_IP" OR destination.ip : "THREAT_IP" OR
dns.question.name : "THREAT_DOMAIN" OR file.hash.sha256 : "THREAT_HASH"
```

### Rapid Triage Queries
```kql
# Identify most active hosts (potential infection)  
event.category : "process" 
| stats dc(process.name) as unique_processes by host.name
| sort unique_processes desc
| head 10

# Find rare processes across environment
event.category : "process" AND event.action : "start"
| rare process.name by host.name
| where count < 5

# Network communication summary
event.category : "network" AND network.direction : "outbound"
| stats count by destination.ip, destination.port
| sort count desc
| head 20
```

---

## Additional Resources & Training

### Essential Elastic Documentation
- **KQL Reference**: https://www.elastic.co/guide/en/kibana/current/kuery-query.html
- **Detection Rules**: https://www.elastic.co/guide/en/security/current/detection-engine-overview.html
- **Machine Learning**: https://www.elastic.co/guide/en/machine-learning/current/ml-overview.html

### Community Resources
- **Elastic Security Labs**: Research and threat intelligence
- **Detection Rules Repository**: https://github.com/elastic/detection-rules
- **Sigma Rules**: https://github.com/SigmaHQ/sigma (convertible to KQL)

### Certification Paths
- **Elastic Certified Engineer**: Official Elastic certification
- **GCIH**: GIAC Certified Incident Handler (includes SIEM)
- **SANS FOR572**: Advanced Network Forensics and Analysis

---

*This cheatsheet is designed for authorized security monitoring and incident response activities. Always ensure compliance with organizational policies and legal requirements.*

**Last Updated**: August 2025 | **Version**: 3.2