# Sysmon & Event Viewer Threat Hunting Cheatsheet

## Context & Assumptions
**Target Environment**: Windows Enterprise with Sysmon deployed  
**Analyst Level**: SOC L2-L3, Incident Response, Threat Hunters  
**Prerequisites**: Sysmon installed with comprehensive config, administrative access to target systems  

---

## Quick Reference - Event IDs

| Event ID | Description | Threat Hunting Value | MITRE ATT&CK |
|----------|-------------|---------------------|--------------|
| **1** | Process Creation | Command execution, Living-off-the-land | T1059 |
| **2** | File Creation Time Changed | Timestomping, AV evasion | T1070.006 |
| **3** | Network Connection | C2 communications, lateral movement | T1071, T1021 |
| **4** | Sysmon Service State | Service manipulation | T1569.002 |
| **5** | Process Terminated | Process lifecycle tracking | - |
| **6** | Driver Loaded | Rootkit detection, kernel exploitation | T1014 |
| **7** | Image Loaded | DLL injection, process hollowing | T1055 |
| **8** | CreateRemoteThread | Process injection techniques | T1055.002 |
| **9** | RawAccessRead | Direct disk access, forensic tools | T1006 |
| **10** | ProcessAccess | Memory dumping, credential theft | T1003 |
| **11** | FileCreate | File system monitoring | T1105 |
| **12** | RegistryEvent (Object create/delete) | Persistence mechanisms | T1547 |
| **13** | RegistryEvent (Value Set) | Configuration changes | T1112 |
| **14** | RegistryEvent (Key/Value Rename) | Evasion techniques | T1112 |
| **15** | FileCreateStreamHash | ADS usage, file hiding | T1564.004 |
| **17** | PipeEvent (Pipe Created) | Named pipe communication | T1055.001 |
| **18** | PipeEvent (Pipe Connected) | IPC monitoring | T1055.001 |
| **19** | WmiEvent (WmiEventFilter activity) | WMI persistence | T1546.003 |
| **20** | WmiEvent (WmiEventConsumer activity) | WMI backdoors | T1546.003 |
| **21** | WmiEvent (WmiEventConsumerToFilter activity) | WMI binding | T1546.003 |
| **22** | DNSEvent (DNS query) | DNS tunneling, C2 | T1071.004 |
| **23** | FileDelete (File Delete archived) | Evidence destruction | T1070.004 |
| **24** | ClipboardChange | Data exfiltration | T1115 |
| **25** | ProcessTampering | Process modification | T1055 |
| **26** | FileDeleteDetected | File deletion monitoring | T1070.004 |

---

## Core PowerShell Commands

### Event Viewer Query Syntax
```powershell
# Basic event retrieval
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational"

# Time-based filtering (last 24 hours)
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 1000 | 
    Where-Object {$_.TimeCreated -gt (Get-Date).AddHours(-24)}

# Event ID filtering
Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; ID=1,3,7}

# Advanced XML filtering
$xmlFilter = @'
<QueryList>
  <Query Id="0" Path="Microsoft-Windows-Sysmon/Operational">
    <Select Path="Microsoft-Windows-Sysmon/Operational">
      *[System[EventID=1 or EventID=3]]
      and
      *[EventData[Data[@Name='Image'] and (contains(., 'powershell') or contains(., 'cmd'))]]
    </Select>
  </Query>
</QueryList>
'@
Get-WinEvent -FilterXml $xmlFilter
```

### Field Extraction & Analysis
```powershell
# Extract specific fields from events
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterHashtable @{ID=1} -MaxEvents 100 | 
    ForEach-Object {
        $xml = [xml]$_.ToXml()
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            ProcessId = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ProcessId'} | Select-Object -ExpandProperty '#text'
            Image = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'Image'} | Select-Object -ExpandProperty '#text'
            CommandLine = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'CommandLine'} | Select-Object -ExpandProperty '#text'
            User = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'User'} | Select-Object -ExpandProperty '#text'
        }
    }

# Export to CSV for analysis
$events | Export-Csv -Path "C:\ThreatHunt\process_events.csv" -NoTypeInformation
```

---

## Threat Hunting Workflows

### 1. Suspicious Process Execution (T1059)
```powershell
# Hunt for suspicious command line patterns
$suspiciousPatterns = @(
    'powershell.*-enc.*',                    # Encoded PowerShell
    'powershell.*-e .*',                     # Base64 encoded
    'powershell.*downloadstring.*',          # Web downloads
    'powershell.*iex.*',                     # Invoke-Expression
    'cmd.exe.*\/c.*echo.*',                  # Echo obfuscation
    'wscript.*\.js.*',                       # JavaScript execution
    'cscript.*\.vbs.*',                      # VBScript execution
    'regsvr32.*\/s.*\/u.*\/i.*',            # Squiblydoo technique
    'rundll32.*javascript.*',                # JavaScript via rundll32
    'mshta.*http.*'                          # MSHTA HTTP execution
)

$xmlQuery = @"
<QueryList>
  <Query Id="0" Path="Microsoft-Windows-Sysmon/Operational">
    <Select Path="Microsoft-Windows-Sysmon/Operational">
      *[System[EventID=1]]
      and
      *[EventData[Data[@Name='CommandLine'] and (
        contains(translate(., 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'powershell') and 
        (contains(., '-enc') or contains(., '-e ') or contains(., 'downloadstring') or contains(., 'iex'))
      )]]
    </Select>
  </Query>
</QueryList>
"@

Get-WinEvent -FilterXml $xmlQuery -MaxEvents 1000
```

### 2. Network Connections Analysis (T1071)
```powershell
# Identify unusual outbound connections
$networkEvents = Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; ID=3} -MaxEvents 5000

$suspiciousConnections = $networkEvents | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $destIP = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'DestinationIp'} | Select-Object -ExpandProperty '#text'
    $destPort = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'DestinationPort'} | Select-Object -ExpandProperty '#text'
    $process = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'Image'} | Select-Object -ExpandProperty '#text'
    
    # Flag suspicious characteristics
    $isSuspicious = $false
    $reason = @()
    
    # Non-standard ports for common processes
    if ($process -match 'explorer\.exe|notepad\.exe|calc\.exe' -and $destPort -notin @('80','443','53')) {
        $isSuspicious = $true
        $reason += "Unusual process network activity"
    }
    
    # High-numbered destination ports (potential C2)
    if ([int]$destPort -gt 8000 -and [int]$destPort -lt 65535) {
        $isSuspicious = $true
        $reason += "High port number"
    }
    
    # Check for private/internal IP ranges going external
    if ($destIP -notmatch '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)') {
        $isSuspicious = $true
        $reason += "External connection"
    }
    
    if ($isSuspicious) {
        [PSCustomObject]@{
            Time = $_.TimeCreated
            Process = $process
            DestIP = $destIP
            DestPort = $destPort
            Reason = $reason -join ", "
        }
    }
}

# Group by destination to identify beaconing
$suspiciousConnections | Group-Object DestIP | Where-Object Count -gt 10
```

### 3. Process Injection Detection (T1055)
```powershell
# CreateRemoteThread events (Event ID 8)
$injectionHunt = @"
<QueryList>
  <Query Id="0" Path="Microsoft-Windows-Sysmon/Operational">
    <Select Path="Microsoft-Windows-Sysmon/Operational">
      *[System[EventID=8]]
      and
      *[EventData[
        (Data[@Name='SourceImage'] and (contains(., 'powershell') or contains(., 'rundll32') or contains(., 'regsvr32')))
        or
        (Data[@Name='TargetImage'] and (contains(., 'explorer.exe') or contains(., 'winlogon.exe') or contains(., 'lsass.exe')))
      ]]
    </Select>
  </Query>
</QueryList>
"@

$injectionEvents = Get-WinEvent -FilterXml $injectionHunt

# Process Access events (Event ID 10) - Memory dumping
$memoryAccess = @"
<QueryList>
  <Query Id="0" Path="Microsoft-Windows-Sysmon/Operational">
    <Select Path="Microsoft-Windows-Sysmon/Operational">
      *[System[EventID=10]]
      and
      *[EventData[
        (Data[@Name='TargetImage'] and contains(., 'lsass.exe'))
        and
        (Data[@Name='GrantedAccess'] and contains(., '0x1010'))
      ]]
    </Select>
  </Query>
</QueryList>
"@

Get-WinEvent -FilterXml $memoryAccess
```

### 4. Persistence Hunting (T1547)
```powershell
# Registry modifications for persistence
$persistenceRegKeys = @(
    'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM\System\CurrentControlSet\Services'
)

# Hunt for registry modifications (Event ID 12, 13)
$regQuery = @"
<QueryList>
  <Query Id="0" Path="Microsoft-Windows-Sysmon/Operational">
    <Select Path="Microsoft-Windows-Sysmon/Operational">
      *[System[EventID=12 or EventID=13]]
      and
      *[EventData[
        Data[@Name='TargetObject'] and (
          contains(., 'CurrentVersion\Run') or
          contains(., 'CurrentControlSet\Services') or
          contains(., 'Winlogon') or
          contains(., 'Explorer\Shell') or
          contains(., 'Image File Execution Options')
        )
      ]]
    </Select>
  </Query>
</QueryList>
"@

Get-WinEvent -FilterXml $regQuery -MaxEvents 1000
```

### 5. WMI Abuse Detection (T1546.003)
```powershell
# WMI Event Consumer/Filter/Binding (Event IDs 19, 20, 21)
$wmiQuery = @"
<QueryList>
  <Query Id="0" Path="Microsoft-Windows-Sysmon/Operational">
    <Select Path="Microsoft-Windows-Sysmon/Operational">
      *[System[EventID=19 or EventID=20 or EventID=21]]
    </Select>
  </Query>
</QueryList>
"@

$wmiEvents = Get-WinEvent -FilterXml $wmiQuery

# Analyze WMI persistence
$wmiEvents | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $eventType = switch ($_.Id) {
        19 { "WMI Filter" }
        20 { "WMI Consumer" }
        21 { "WMI Binding" }
    }
    
    Write-Host "[$($_.TimeCreated)] $eventType detected"
    $xml.Event.EventData.Data | ForEach-Object {
        Write-Host "  $($_.Name): $($_.'#text')"
    }
}
```

---

## Advanced Hunting Techniques

### Timeline Analysis
```powershell
# Create timeline of events around suspicious activity
function Get-EventTimeline {
    param(
        [datetime]$StartTime,
        [datetime]$EndTime,
        [string]$ProcessName,
        [int[]]$EventIDs = @(1,3,5,7,8,10,11,12,13)
    )
    
    $timeFilter = @{
        LogName = "Microsoft-Windows-Sysmon/Operational"
        StartTime = $StartTime
        EndTime = $EndTime
        ID = $EventIDs
    }
    
    Get-WinEvent -FilterHashtable $timeFilter | 
        Sort-Object TimeCreated |
        ForEach-Object {
            $xml = [xml]$_.ToXml()
            $image = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'Image'} | Select-Object -ExpandProperty '#text'
            
            if (!$ProcessName -or $image -like "*$ProcessName*") {
                [PSCustomObject]@{
                    Time = $_.TimeCreated
                    EventID = $_.Id
                    Process = $image
                    User = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'User'} | Select-Object -ExpandProperty '#text'
                    Details = $_.Message.Split("`n")[0]
                }
            }
        }
}

# Usage example
$suspiciousTime = Get-Date "2024-01-15 14:30:00"
Get-EventTimeline -StartTime $suspiciousTime.AddMinutes(-30) -EndTime $suspiciousTime.AddMinutes(30) -ProcessName "powershell"
```

### Parent-Child Process Analysis
```powershell
# Track process lineage for investigation
function Get-ProcessLineage {
    param([string]$ProcessGuid)
    
    $allProcessEvents = Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; ID=1} -MaxEvents 10000
    $processMap = @{}
    
    # Build process tree
    $allProcessEvents | ForEach-Object {
        $xml = [xml]$_.ToXml()
        $guid = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ProcessGuid'} | Select-Object -ExpandProperty '#text'
        $parentGuid = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ParentProcessGuid'} | Select-Object -ExpandProperty '#text'
        $image = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'Image'} | Select-Object -ExpandProperty '#text'
        $commandLine = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'CommandLine'} | Select-Object -ExpandProperty '#text'
        
        $processMap[$guid] = @{
            Parent = $parentGuid
            Image = $image
            CommandLine = $commandLine
            Time = $_.TimeCreated
        }
    }
    
    # Trace lineage
    $current = $ProcessGuid
    $lineage = @()
    
    while ($current -and $processMap.ContainsKey($current)) {
        $lineage += [PSCustomObject]@{
            ProcessGuid = $current
            Image = $processMap[$current].Image
            CommandLine = $processMap[$current].CommandLine
            Time = $processMap[$current].Time
        }
        $current = $processMap[$current].Parent
    }
    
    return $lineage | Sort-Object Time
}
```

---

## Output Interpretation Guide

### Red Flags to Watch For

**Process Creation (Event ID 1)**
- ✅ **Parent-child relationships**: `winword.exe → powershell.exe → cmd.exe`
- ✅ **Unusual command lines**: Long base64 strings, obfuscated commands
- ✅ **Living-off-the-land**: System tools with suspicious parameters
- ✅ **Timing patterns**: Rapid succession of process creation

**Network Connections (Event ID 3)**
- ✅ **Beaconing patterns**: Regular intervals to same destination
- ✅ **Unusual processes**: Calculator connecting to internet
- ✅ **Non-standard ports**: Web browsers on port 8080, 9999
- ✅ **Geographic anomalies**: Connections to high-risk countries

**Registry Modifications (Event ID 12/13)**
- ✅ **Persistence locations**: Run keys, Services, Winlogon
- ✅ **Defensive evasion**: Image File Execution Options
- ✅ **Value anomalies**: Binary data in text fields

**Process Injection (Event ID 8/10)**
- ✅ **Target processes**: System processes (explorer.exe, winlogon.exe)
- ✅ **Access rights**: Specific patterns (0x1010, 0x1038, 0x143A)
- ✅ **Source processes**: Unusual injectors

### Data Quality Indicators
```powershell
# Validate Sysmon logging health
function Test-SysmonHealth {
    $last24h = (Get-Date).AddHours(-24)
    
    # Check event volume per ID
    1..26 | ForEach-Object {
        $count = (Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; ID=$_; StartTime=$last24h} -EA SilentlyContinue | Measure-Object).Count
        [PSCustomObject]@{
            EventID = $_
            Count = $count
            Status = if ($count -eq 0 -and $_ -in @(1,3,11)) { "⚠️ LOW" } elseif ($count -gt 0) { "✅ OK" } else { "ℹ️ Normal" }
        }
    } | Sort-Object EventID
}
```

---

## Performance Optimization

### Efficient Query Patterns
```powershell
# Use specific time windows
$startTime = (Get-Date).AddHours(-4)
$endTime = Get-Date

# Limit results with MaxEvents
Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; StartTime=$startTime; EndTime=$endTime} -MaxEvents 5000

# Use FilterXml for complex conditions (more efficient than PowerShell filtering)
# Index-friendly fields: EventID, TimeCreated, ProcessId
# Non-indexed: CommandLine content, registry values (slower)
```

### Memory Management
```powershell
# For large datasets, process in chunks
function Get-EventsInChunks {
    param(
        [datetime]$StartTime,
        [datetime]$EndTime,
        [int]$ChunkSizeHours = 2
    )
    
    $current = $StartTime
    while ($current -lt $EndTime) {
        $chunkEnd = $current.AddHours($ChunkSizeHours)
        if ($chunkEnd -gt $EndTime) { $chunkEnd = $EndTime }
        
        Write-Progress -Activity "Processing Events" -Status "Processing $current to $chunkEnd"
        
        Get-WinEvent -FilterHashtable @{
            LogName = "Microsoft-Windows-Sysmon/Operational"
            StartTime = $current
            EndTime = $chunkEnd
        } | Process-Events  # Your processing function
        
        $current = $chunkEnd
        [System.GC]::Collect()  # Force garbage collection
    }
}
```

---

## Common Pitfalls & Solutions

### ❌ **Pitfall**: Overwhelming data volume
**✅ Solution**: Use time-based filtering, focus on high-value events (1,3,7,8,10)

### ❌ **Pitfall**: Missing context around events
**✅ Solution**: Correlate multiple event types, build timeline views

### ❌ **Pitfall**: False positives from legitimate admin tools
**✅ Solution**: Baseline normal activity, whitelist known-good processes

### ❌ **Pitfall**: XML parsing performance issues
**✅ Solution**: Use FilterXml instead of PowerShell Where-Object for large datasets

### ❌ **Pitfall**: Incomplete Sysmon configuration
**✅ Solution**: Use SwiftOnSecurity or MITRE configurations as baseline

---

## Validation Checklist

- [ ] **Data Completeness**: All expected event types present in timeframe
- [ ] **Baseline Established**: Normal activity patterns documented
- [ ] **False Positive Rate**: <10% of alerts require no action
- [ ] **Response Time**: Initial triage completed within 15 minutes
- [ ] **Documentation**: Findings recorded with IOCs and TTPs
- [ ] **Escalation Path**: Clear criteria for L3/IR team engagement

---

## Reference Resources

**Sysmon Configuration**:
- [SwiftOnSecurity Config](https://github.com/SwiftOnSecurity/sysmon-config)
- [MITRE Sysmon Configuration](https://github.com/MITRE-ATT&CK/sysmon-configuration)

**MITRE ATT&CK Framework**: https://attack.mitre.org/

**PowerShell Documentation**: https://docs.microsoft.com/powershell/

---

*Last Updated: January 2025*  
*Tested Environment: Windows 10/11, Windows Server 2016/2019/2022, Sysmon v13+*