# Azure Threat Hunting Cheatsheet
*Field-Ready Guide for Security Analysts*

## Table of Contents
1. [Core Azure Security Tools](#core-azure-security-tools)
2. [KQL (Kusto Query Language) Essentials](#kql-essentials)
3. [Microsoft Sentinel Hunting](#microsoft-sentinel-hunting)
4. [Azure Active Directory Investigations](#azure-active-directory-investigations)
5. [Azure Resource Monitoring](#azure-resource-monitoring)
6. [Network Security Analysis](#network-security-analysis)
7. [MITRE ATT&CK Mapped Queries](#mitre-attck-mapped-queries)
8. [Advanced Hunting Workflows](#advanced-hunting-workflows)
9. [Output Interpretation & Red Flags](#output-interpretation--red-flags)
10. [Practical Tips & Pitfalls](#practical-tips--pitfalls)

---

## Core Azure Security Tools

### Primary Platforms
- **Microsoft Sentinel** - SIEM/SOAR solution
- **Microsoft Defender for Cloud** - Cloud security posture management
- **Azure Monitor** - Centralized logging and monitoring
- **Microsoft Entra ID (Azure AD)** - Identity and access management
- **Azure Security Center** - Security recommendations and alerts

### Access Methods
```bash
# Azure CLI
az login
az account set --subscription "subscription-name"

# PowerShell
Connect-AzAccount
Set-AzContext -SubscriptionName "subscription-name"

# Direct Portal Access
https://portal.azure.com
https://security.microsoft.com (Microsoft 365 Defender)
```

---

## KQL (Kusto Query Language) Essentials

### Basic Syntax Structure
```kusto
TableName
| where TimeGenerated > ago(24h)
| where EventID == 4625
| project TimeGenerated, Computer, Account
| summarize count() by Computer
| order by count_ desc
```

### Core Operators & Functions

#### Time Filtering
```kusto
// Last 24 hours
| where TimeGenerated > ago(24h)

// Specific time range
| where TimeGenerated between (datetime(2024-01-01) .. datetime(2024-01-02))

// Time binning
| summarize count() by bin(TimeGenerated, 1h)
```

#### String Operations
```kusto
// Contains (case-insensitive)
| where Computer contains "web"

// Exact match (case-sensitive)
| where Computer == "WEB-01"

// Regular expressions
| where Computer matches regex @"WEB-\d+"

// String extraction
| extend Domain = extract(@"([^\\]+)\\", 1, Account)
```

#### Data Manipulation
```kusto
// Project specific columns
| project TimeGenerated, Computer, EventID

// Create new columns
| extend Severity = case(
    EventID == 4625, "High",
    EventID == 4624, "Low",
    "Medium")

// Join tables
SecurityEvent
| join kind=inner (
    Heartbeat
    | where TimeGenerated > ago(1d)
) on Computer
```

#### Aggregation Functions
```kusto
// Count events
| summarize count() by Computer

// Distinct count
| summarize dcount(Account) by Computer

// Statistical functions
| summarize avg(Duration), max(Duration), min(Duration) by Computer

// Percentiles
| summarize percentiles(ResponseTime, 50, 90, 95) by Server
```

---

## Microsoft Sentinel Hunting

### Core Tables for Threat Hunting

#### Security Events
```kusto
// Failed logon attempts (MITRE: T1110 - Brute Force)
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4625
| summarize FailedAttempts = count() by Account, Computer, IpAddress
| where FailedAttempts > 10
| order by FailedAttempts desc
```

#### Sign-in Logs
```kusto
// Suspicious sign-ins from new locations
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == 0  // Successful
| where RiskState == "atRisk"
| project TimeGenerated, UserPrincipalName, IPAddress, Location, DeviceDetail
| order by TimeGenerated desc
```

#### Azure Activity Logs
```kusto
// Privilege escalation attempts
AzureActivity
| where TimeGenerated > ago(24h)
| where OperationName contains "role"
| where ActivityStatus == "Success"
| project TimeGenerated, Caller, OperationName, ResourceGroup, Resource
```

### Advanced Hunting Queries

#### Multi-Stage Attack Detection
```kusto
// Detect potential lateral movement
let SuspiciousLogons = SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4624
| where LogonType in (3, 10)  // Network, RemoteInteractive
| project TimeGenerated, Account, Computer, IpAddress;

let ProcessCreation = SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4688
| project TimeGenerated, Account, Computer, NewProcessName;

SuspiciousLogons
| join kind=inner (ProcessCreation) on Account, Computer
| where ProcessCreation.TimeGenerated between (SuspiciousLogons.TimeGenerated .. (SuspiciousLogons.TimeGenerated + 10m))
| project TimeGenerated, Account, Computer, IpAddress, NewProcessName
```

#### Anomaly Detection
```kusto
// Detect unusual file access patterns
SecurityEvent
| where TimeGenerated > ago(30d)
| where EventID == 4663  // Object access
| where ObjectName endswith ".exe"
| summarize FileAccess = count() by bin(TimeGenerated, 1d), Account, Computer
| join kind=inner (
    // Calculate baseline
    SecurityEvent
    | where TimeGenerated between (ago(60d) .. ago(30d))
    | where EventID == 4663
    | where ObjectName endswith ".exe"
    | summarize BaselineAccess = avg(todouble(1)) by Account, Computer
) on Account, Computer
| where FileAccess > (BaselineAccess * 3)  // 3x baseline
```

---

## Azure Active Directory Investigations

### Identity-Based Hunting

#### Privileged Account Monitoring
```kusto
// Monitor admin role assignments
AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName == "Add member to role"
| where TargetResources[0].modifiedProperties[0].newValue contains "admin"
| project TimeGenerated, InitiatedBy, TargetResources, Result
```

#### Conditional Access Policy Changes
```kusto
// Detect CA policy modifications
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName contains "conditional access policy"
| where Result == "success"
| extend PolicyName = tostring(TargetResources[0].displayName)
| project TimeGenerated, InitiatedBy, OperationName, PolicyName
```

#### Risky Sign-in Analysis
```kusto
// Correlate risky sign-ins with successful authentications
let RiskySignins = SigninLogs
| where TimeGenerated > ago(24h)
| where RiskState == "atRisk"
| project TimeGenerated, UserPrincipalName, IPAddress, RiskDetail;

let SuccessfulSignins = SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, IPAddress;

RiskySignins
| join kind=leftouter (SuccessfulSignins) on UserPrincipalName
| where isnotempty(SuccessfulSignins.TimeGenerated)
| project RiskySignins.TimeGenerated, UserPrincipalName, RiskySignins.IPAddress, RiskDetail
```

---

## Azure Resource Monitoring

### Virtual Machine Security

#### Process Execution Monitoring
```kusto
// Suspicious process creation (MITRE: T1059 - Command and Scripting Interpreter)
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4688
| where NewProcessName contains "powershell" or NewProcessName contains "cmd"
| where CommandLine contains "download" or CommandLine contains "invoke"
| project TimeGenerated, Computer, Account, NewProcessName, CommandLine
```

#### File System Changes
```kusto
// Monitor critical directory modifications
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID in (4656, 4658, 4663)  // File access events
| where ObjectName startswith "C:\\Windows\\System32"
| where AccessMask contains "DELETE" or AccessMask contains "WRITE"
| project TimeGenerated, Computer, Account, ObjectName, AccessMask
```

### Network Monitoring

#### NSG Flow Analysis
```kusto
// Analyze Network Security Group flows for suspicious traffic
AzureNetworkAnalytics_CL
| where TimeGenerated > ago(1h)
| where FlowStatus_s == "A"  // Allowed traffic
| where DestPort_d in (445, 3389, 22)  // SMB, RDP, SSH
| summarize ConnectionCount = count() by SrcIP_s, DestIP_s, DestPort_d
| where ConnectionCount > 100
| order by ConnectionCount desc
```

---

## MITRE ATT&CK Mapped Queries

### Initial Access (TA0001)

#### T1078 - Valid Accounts
```kusto
// Detect account usage outside business hours
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == 0
| extend Hour = datetime_part("hour", TimeGenerated)
| where Hour < 6 or Hour > 22  // Outside 6 AM - 10 PM
| summarize SigninCount = count() by UserPrincipalName, Hour
| order by SigninCount desc
```

#### T1190 - Exploit Public-Facing Application
```kusto
// Web application attack patterns
W3CIISLog
| where TimeGenerated > ago(24h)
| where scStatus >= 400
| where csUriStem contains "admin" or csUriStem contains "login"
| summarize RequestCount = count() by cIP, csUriStem
| where RequestCount > 50
```

### Persistence (TA0003)

#### T1098 - Account Manipulation
```kusto
// Monitor for account modifications
AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName in ("Update user", "Add member to role", "Add owner to group")
| where Result == "success"
| project TimeGenerated, InitiatedBy, OperationName, TargetResources
```

### Privilege Escalation (TA0004)

#### T1548 - Abuse Elevation Control Mechanism
```kusto
// UAC bypass attempts
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4688
| where NewProcessName endswith "consent.exe"
| where ParentProcessName !endswith "consent.exe"
| project TimeGenerated, Computer, Account, NewProcessName, CommandLine
```

### Defense Evasion (TA0005)

#### T1562 - Impair Defenses
```kusto
// Security tool tampering
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID in (4688, 1102)  // Process creation, audit log cleared
| where NewProcessName contains "defender" or 
        NewProcessName contains "antivirus" or
        Channel == "Security"
| project TimeGenerated, Computer, Account, EventID, NewProcessName
```

### Credential Access (TA0006)

#### T1003 - OS Credential Dumping
```kusto
// LSASS access attempts
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4663
| where ObjectName contains "lsass.exe"
| where AccessMask contains "0x1010"  // PROCESS_VM_READ
| project TimeGenerated, Computer, Account, ProcessName, ObjectName
```

### Discovery (TA0007)

#### T1087 - Account Discovery
```kusto
// Account enumeration activities
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4798  // User's local group membership enumerated
| summarize EnumerationCount = count() by Computer, Account
| where EnumerationCount > 10
```

### Lateral Movement (TA0008)

#### T1021 - Remote Services
```kusto
// RDP lateral movement detection
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4624
| where LogonType == 10  // RemoteInteractive
| summarize RDPSessions = dcount(Computer) by Account, IpAddress
| where RDPSessions > 3  // Accessing multiple systems
```

---

## Advanced Hunting Workflows

### Multi-Vector Attack Correlation

#### Campaign Tracking
```kusto
// Correlate indicators across multiple data sources
let MaliciousIPs = externaldata(IP: string)
[@"https://raw.githubusercontent.com/example/threat-intel/ips.txt"];

let WebTraffic = W3CIISLog
| where TimeGenerated > ago(24h)
| where cIP in (MaliciousIPs);

let NetworkConnections = SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 5156  // Windows Firewall allowed connection
| where DestinationAddress in (MaliciousIPs);

union WebTraffic, NetworkConnections
| summarize EventTypes = make_set(Type) by TimeGenerated, Computer
```

#### Temporal Correlation
```kusto
// Identify attack sequences within time windows
let InitialCompromise = SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4625  // Failed logon
| where IpAddress startswith "192.168."  // Internal lateral movement
| project TimeGenerated, Computer, Account, IpAddress, Stage = "Initial";

let Execution = SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4688  // Process creation
| where NewProcessName contains "powershell"
| project TimeGenerated, Computer, Account, NewProcessName, Stage = "Execution";

union InitialCompromise, Execution
| order by TimeGenerated asc
| project TimeGenerated, Computer, Account, Stage, Details = strcat(IpAddress, NewProcessName)
```

### Behavioral Analytics

#### User Behavior Analysis
```kusto
// Detect deviation from normal user patterns
let UserBaseline = SigninLogs
| where TimeGenerated between (ago(30d) .. ago(7d))
| where ResultType == 0
| summarize
    AvgSignins = avg(todouble(1)),
    TypicalLocations = make_set(Location),
    TypicalDevices = make_set(DeviceDetail.deviceId)
    by UserPrincipalName;

SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == 0
| summarize
    CurrentSignins = count(),
    CurrentLocations = make_set(Location),
    CurrentDevices = make_set(DeviceDetail.deviceId)
    by UserPrincipalName
| join kind=inner (UserBaseline) on UserPrincipalName
| where CurrentSignins > (AvgSignins * 2)  // 2x normal activity
| project UserPrincipalName, CurrentSignins, AvgSignins, CurrentLocations, TypicalLocations
```

---

## Output Interpretation & Red Flags

### Critical Indicators

#### High-Risk Authentication Events
🚩 **Red Flags to Watch For:**
- Multiple failed logons followed by successful authentication
- Authentication from impossible travel locations
- Service account interactive logons
- After-hours administrative activity
- New device registrations for privileged accounts

#### Suspicious Process Execution
🚩 **Red Flags:**
```
ProcessName: powershell.exe, cmd.exe, wscript.exe
CommandLine containing: -encoded, -exec bypass, downloadstring, invoke-expression
ParentProcess: Non-standard processes launching system tools
User Context: System-level processes under user accounts
```

#### Network Anomalies
🚩 **Red Flags:**
- Outbound connections to non-standard ports (not 80, 443)
- Internal-to-internal SMB traffic across subnets
- DNS queries for suspicious domains
- Large data transfers to external IPs

### Threshold Guidelines

#### Volume-Based Alerts
```kusto
// Failed logon threshold calculation
SecurityEvent
| where EventID == 4625
| summarize FailedLogons = count() by bin(TimeGenerated, 5m), Account
| where FailedLogons > 5  // Adjust based on environment
```

**Recommended Thresholds:**
- Failed logons: >5 in 5 minutes
- Process creation: >100 processes/minute per host
- File access: >1000 file operations/hour per user
- Network connections: >50 unique destinations per host/hour

---

## Practical Tips & Pitfalls

### Query Optimization

#### Performance Best Practices
```kusto
// ✅ Good: Filter early and limit data
SecurityEvent
| where TimeGenerated > ago(1h)  // Time filter first
| where EventID == 4624          // Specific event filter
| where Computer == "WEB-01"     // Additional filters
| project TimeGenerated, Account, Computer  // Limit columns
| take 1000                      // Limit results

// ❌ Bad: Broad query with late filtering
SecurityEvent
| project *  // All columns
| where TimeGenerated > ago(30d)  // Large time range
| where Computer contains "WEB"   // Broad filter at end
```

#### Memory and Performance
- **Use specific time ranges** - Avoid queries spanning >30 days
- **Filter on indexed columns first** - TimeGenerated, Computer, EventID
- **Project only needed columns** - Reduces memory usage
- **Use `take` or `top`** - Limit result sets for testing

### Common Mistakes

#### 1. Case Sensitivity Issues
```kusto
// ❌ Case-sensitive exact match might miss results
| where Computer == "web-01"

// ✅ Case-insensitive search
| where Computer =~ "web-01"
// or
| where tolower(Computer) == "web-01"
```

#### 2. Time Zone Confusion
```kusto
// ✅ Always use UTC for consistency
| where TimeGenerated > ago(24h)

// ❌ Local time conversions can cause issues
| where TimeGenerated > datetime(2024-01-01 08:00:00)
```

#### 3. Join Performance Issues
```kusto
// ✅ Filter both tables before joining
let Table1 = SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4624;

let Table2 = Heartbeat
| where TimeGenerated > ago(1h);

Table1 | join kind=inner (Table2) on Computer
```

### Field Deployment Tips

#### 1. Build Query Libraries
Create reusable query templates for common scenarios:
- Incident response playbooks
- Threat hunting campaigns  
- Compliance reporting
- Performance monitoring

#### 2. Validate Data Sources
```kusto
// Check data availability and freshness
union *
| summarize LastSeen = max(TimeGenerated) by Type
| where LastSeen < ago(1h)  // Identify stale data sources
```

#### 3. Test in Stages
- Start with broad queries to understand data patterns
- Gradually add filters to reduce noise
- Validate results with known good/bad events
- Document false positive patterns

#### 4. Environment-Specific Tuning
```kusto
// Identify your environment's normal patterns
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4624
| summarize LoginsByHour = count() by bin(TimeGenerated, 1h), Computer
| summarize 
    AvgLogins = avg(LoginsByHour),
    P95Logins = percentile(LoginsByHour, 95)
    by Computer
```

### Alerting Best Practices

#### Smart Threshold Setting
```kusto
// Dynamic thresholding based on historical data
let HistoricalData = SecurityEvent
| where TimeGenerated between (ago(30d) .. ago(7d))
| where EventID == 4625
| summarize FailedLogons = count() by bin(TimeGenerated, 1h), Computer
| summarize Threshold = percentile(FailedLogons, 95) by Computer;

SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4625
| summarize CurrentFailed = count() by Computer
| join kind=inner (HistoricalData) on Computer
| where CurrentFailed > Threshold
```

#### Alert Fatigue Prevention
- **Use statistical baselines** instead of fixed thresholds
- **Implement alert suppression** for known patterns
- **Correlate multiple weak signals** rather than single strong indicators
- **Regular threshold tuning** based on false positive rates

---

## Quick Reference Commands

### Essential KQL Functions
```kusto
// Time functions
ago(1h), now(), datetime(), bin()

// String functions
contains, startswith, endswith, extract, split

// Statistical functions
count(), dcount(), sum(), avg(), max(), min(), percentile()

// Array functions
make_list(), make_set(), array_length(), mv-expand

// Conditional logic
case(), iff(), isnull(), isempty()
```

### Common Table Joins
```kusto
// Inner join (only matching records)
| join kind=inner (Table2) on CommonColumn

// Left outer join (all records from left table)
| join kind=leftouter (Table2) on CommonColumn

// Anti join (records in left table not in right)
| join kind=leftanti (Table2) on CommonColumn
```

### Emergency Response Queries
```kusto
// 🚨 Active compromise indicators
SecurityEvent
| where TimeGenerated > ago(15m)
| where EventID in (4625, 4648, 4672)  // Failed logon, explicit creds, special privileges
| summarize by Computer, Account, EventID
| order by TimeGenerated desc

// 🚨 Privilege escalation detection
AuditLogs
| where TimeGenerated > ago(30m)
| where OperationName contains "role" and Result == "success"
| project TimeGenerated, InitiatedBy, OperationName, TargetResources
```

---

*This cheatsheet is designed for active threat hunting operations. Always adapt queries to your specific environment and maintain awareness of your organization's data retention and privacy policies.*