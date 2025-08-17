# Active Directory Threat Hunting Cheatsheet
*Field-Ready Guide for Security Analysts*

## Table of Contents
1. [Platform Overview & Tools](#platform-overview--tools)
2. [PowerShell AD Module Essentials](#powershell-ad-module-essentials)
3. [Native Windows Tools & Commands](#native-windows-tools--commands)
4. [Event Log Analysis](#event-log-analysis)
5. [LDAP Query Techniques](#ldap-query-techniques)
6. [MITRE ATT&CK Mapped Hunting](#mitre-attck-mapped-hunting)
7. [Advanced Investigation Workflows](#advanced-investigation-workflows)
8. [Kerberos & Authentication Analysis](#kerberos--authentication-analysis)
9. [Privilege Escalation Detection](#privilege-escalation-detection)
10. [Lateral Movement Indicators](#lateral-movement-indicators)
11. [Output Interpretation & Red Flags](#output-interpretation--red-flags)
12. [Forensic Artifacts & Persistence](#forensic-artifacts--persistence)

---

## Platform Overview & Tools

### Core Investigation Tools
- **PowerShell Active Directory Module** - Primary AD querying tool
- **Event Viewer / Get-WinEvent** - Windows event log analysis
- **DCDiag / RepAdmin** - Domain controller diagnostics
- **LDP.exe** - LDAP browser and editor
- **ADSIEdit** - Low-level directory service editor
- **Bloodhound** - Attack path analysis
- **PingCastle** - AD security assessment

### Essential Event Log Sources
```powershell
# Primary security logs
Security           # Authentication, privilege usage
Directory Service  # AD operations (Domain Controllers only)
DNS Server         # DNS queries and responses
File Replication Service  # SYSVOL replication
DFS Replication    # DFSR events
System             # Service starts, logons
```

### Access Requirements
```powershell
# Minimum required permissions
# - Domain Users (for basic queries)
# - Account Operators (for user management queries)
# - Domain Admins (for full access)
# - Event Log Readers (for log analysis)

# Check current permissions
whoami /groups
whoami /priv
```

---

## PowerShell AD Module Essentials

### Basic Module Setup
```powershell
# Import Active Directory module
Import-Module ActiveDirectory

# Verify module loaded
Get-Module ActiveDirectory

# Connect to specific domain controller
Get-ADDomainController -Filter * | Select-Object Name, IPv4Address, OperatingSystem

# Set default server for queries
$Server = "DC01.contoso.com"
```

### Core User Queries

#### User Enumeration & Analysis
```powershell
# Get all users with key security attributes
Get-ADUser -Filter * -Properties * | 
Select-Object Name, SamAccountName, Enabled, PasswordLastSet, LastLogonDate, 
              PasswordNeverExpires, PasswordNotRequired, AdminCount, 
              memberOf, UserAccountControl

# Find privileged users (AdminCount=1)
Get-ADUser -Filter {AdminCount -eq 1} -Properties AdminCount, LastLogonDate |
Select-Object Name, SamAccountName, LastLogonDate, Enabled

# Users with password never expires
Get-ADUser -Filter {PasswordNeverExpires -eq $true -and Enabled -eq $true} |
Select-Object Name, SamAccountName, PasswordLastSet

# Service accounts (detect by naming pattern or SPN)
Get-ADUser -Filter * -Properties ServicePrincipalName |
Where-Object {$_.ServicePrincipalName -ne $null} |
Select-Object Name, SamAccountName, ServicePrincipalName

# Recently created users (last 30 days)
$30DaysAgo = (Get-Date).AddDays(-30)
Get-ADUser -Filter {Created -gt $30DaysAgo} -Properties Created |
Select-Object Name, SamAccountName, Created | Sort-Object Created -Descending
```

#### Suspicious User Patterns
```powershell
# Users with unusual login times (outside business hours)
Get-ADUser -Filter * -Properties LastLogonDate |
Where-Object {$_.LastLogonDate -ne $null} |
ForEach-Object {
    $LogonHour = $_.LastLogonDate.Hour
    if ($LogonHour -lt 6 -or $LogonHour -gt 22) {
        [PSCustomObject]@{
            Name = $_.Name
            SamAccountName = $_.SamAccountName
            LastLogonDate = $_.LastLogonDate
            LogonHour = $LogonHour
        }
    }
}

# Disabled users with recent activity
Get-ADUser -Filter {Enabled -eq $false} -Properties LastLogonDate |
Where-Object {$_.LastLogonDate -gt (Get-Date).AddDays(-7)} |
Select-Object Name, SamAccountName, LastLogonDate, Enabled
```

### Group Analysis

#### Privileged Group Monitoring
```powershell
# Get members of high-privilege groups
$PrivilegedGroups = @(
    "Domain Admins",
    "Enterprise Admins", 
    "Schema Admins",
    "Administrators",
    "Account Operators",
    "Server Operators",
    "Backup Operators",
    "Print Operators"
)

foreach ($Group in $PrivilegedGroups) {
    try {
        $Members = Get-ADGroupMember -Identity $Group -Recursive
        Write-Host "=== $Group ===" -ForegroundColor Yellow
        $Members | Select-Object Name, SamAccountName, ObjectClass |
        Format-Table -AutoSize
    }
    catch {
        Write-Warning "Could not query group: $Group"
    }
}

# Detect recent group membership changes
Get-ADGroup -Filter * -Properties whenChanged |
Where-Object {$_.whenChanged -gt (Get-Date).AddDays(-7)} |
Select-Object Name, whenChanged | Sort-Object whenChanged -Descending
```

#### Group Nesting Analysis
```powershell
# Find nested groups (potential privilege escalation path)
function Get-NestedGroups {
    param([string]$GroupName)
    
    $Group = Get-ADGroup -Identity $GroupName
    $Members = Get-ADGroupMember -Identity $GroupName
    
    foreach ($Member in $Members) {
        if ($Member.ObjectClass -eq "group") {
            Write-Host "Nested group found: $($Member.Name) in $GroupName" -ForegroundColor Red
            Get-NestedGroups -GroupName $Member.Name
        }
    }
}

# Check privileged groups for nesting
$PrivilegedGroups | ForEach-Object { Get-NestedGroups -GroupName $_ }
```

### Computer & Service Analysis

#### Computer Account Enumeration
```powershell
# Get all domain computers with security attributes
Get-ADComputer -Filter * -Properties * |
Select-Object Name, OperatingSystem, OperatingSystemVersion, 
              LastLogonDate, PasswordLastSet, Enabled, 
              ServicePrincipalName, TrustedForDelegation

# Find computers with delegation enabled (security risk)
Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation |
Select-Object Name, OperatingSystem, TrustedForDelegation

# Computers with old passwords (potential compromise)
Get-ADComputer -Filter * -Properties PasswordLastSet |
Where-Object {$_.PasswordLastSet -lt (Get-Date).AddDays(-90)} |
Select-Object Name, PasswordLastSet | Sort-Object PasswordLastSet
```

#### Service Principal Name (SPN) Analysis
```powershell
# Find all SPNs (potential Kerberoasting targets)
Get-ADUser -Filter * -Properties ServicePrincipalName |
Where-Object {$_.ServicePrincipalName -ne $null} |
Select-Object Name, SamAccountName, @{Name="SPNs";Expression={$_.ServicePrincipalName -join ", "}}

# Find SPNs registered to user accounts (not computer accounts)
$SPNUsers = Get-ADUser -Filter * -Properties ServicePrincipalName |
Where-Object {$_.ServicePrincipalName -ne $null}

foreach ($User in $SPNUsers) {
    Write-Host "User: $($User.SamAccountName)" -ForegroundColor Yellow
    $User.ServicePrincipalName | ForEach-Object {
        Write-Host "  SPN: $_" -ForegroundColor Cyan
    }
}
```

---

## Native Windows Tools & Commands

### Net Commands for Quick Investigation

#### User and Group Information
```cmd
REM Current user context
whoami
whoami /groups
whoami /priv

REM Domain user enumeration
net user /domain
net user username /domain

REM Group membership
net group "Domain Admins" /domain
net group "Enterprise Admins" /domain
net localgroup Administrators

REM Computer accounts
net group "Domain Computers" /domain
```

#### Session and Share Enumeration
```cmd
REM Active sessions on target machine
net session \\target-computer

REM Shared resources
net share \\target-computer

REM Network connections
netstat -an | findstr :445
netstat -an | findstr :139
netstat -an | findstr :3389

REM Current domain information
echo %USERDOMAIN%
echo %LOGONSERVER%
```

### WMIC for Advanced Queries

#### Process and Service Investigation
```cmd
REM Running processes with network connections
wmic process where "Name='powershell.exe'" get ProcessId,ParentProcessId,CommandLine,CreationDate

REM Services running as specific users
wmic service where "StartName like '%admin%'" get Name,StartName,State,PathName

REM Scheduled tasks
wmic job get Name,Owner,Command,RunRepeatedly

REM Startup programs
wmic startup get Name,Command,Location,User
```

#### System and Network Information
```cmd
REM Domain controller information
wmic computersystem get Domain,DomainRole,Name,UserName

REM Network adapter configuration
wmic nicconfig where "IPEnabled=true" get IPAddress,DefaultIPGateway,DNSServerSearchOrder

REM Recently accessed files
wmic logicaldisk get DeviceID,Size,FreeSpace,FileSystem
```

### DSQuery for LDAP Operations

#### Advanced Directory Queries
```cmd
REM Find users by attributes
dsquery user -name "*admin*"
dsquery user -disabled
dsquery user -inactive 4

REM Find computers by criteria
dsquery computer -name "*server*"
dsquery computer -inactive 8
dsquery computer -stalepwd 90

REM Group membership queries
dsquery group -name "*admin*"
dsget group "CN=Domain Admins,CN=Users,DC=contoso,DC=com" -members

REM Organizational Unit enumeration
dsquery ou
dsquery * -filter "(objectCategory=organizationalUnit)"
```

---

## Event Log Analysis

### Critical Security Events

#### Authentication Events
```powershell
# Successful logons (Event ID 4624)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624; StartTime=(Get-Date).AddDays(-1)} |
ForEach-Object {
    $Event = [xml]$_.ToXml()
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        Computer = $_.MachineName
        LogonType = $Event.Event.EventData.Data[8].'#text'
        Account = $Event.Event.EventData.Data[5].'#text'
        SourceIP = $Event.Event.EventData.Data[18].'#text'
        WorkstationName = $Event.Event.EventData.Data[11].'#text'
    }
} | Where-Object {$_.LogonType -in @("2","3","10")} | Format-Table -AutoSize

# Failed logons (Event ID 4625)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625; StartTime=(Get-Date).AddDays(-1)} |
ForEach-Object {
    $Event = [xml]$_.ToXml()
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        Computer = $_.MachineName
        Account = $Event.Event.EventData.Data[5].'#text'
        FailureReason = $Event.Event.EventData.Data[8].'#text'
        SourceIP = $Event.Event.EventData.Data[19].'#text'
        WorkstationName = $Event.Event.EventData.Data[13].'#text'
    }
} | Group-Object Account | Sort-Object Count -Descending
```

#### Privilege Usage Events
```powershell
# Special privilege usage (Event ID 4672)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4672; StartTime=(Get-Date).AddDays(-1)} |
ForEach-Object {
    $Event = [xml]$_.ToXml()
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        Computer = $_.MachineName
        Account = $Event.Event.EventData.Data[1].'#text'
        Privileges = $Event.Event.EventData.Data[2].'#text'
    }
} | Where-Object {$_.Privileges -like "*SeDebugPrivilege*" -or $_.Privileges -like "*SeTcbPrivilege*"}

# Account management events (Event IDs 4720, 4722, 4724, 4728, 4732)
$AccountEvents = @(4720, 4722, 4724, 4728, 4732, 4756)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=$AccountEvents; StartTime=(Get-Date).AddDays(-7)} |
ForEach-Object {
    $Event = [xml]$_.ToXml()
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        EventID = $_.Id
        Computer = $_.MachineName
        SubjectAccount = $Event.Event.EventData.Data[4].'#text'
        TargetAccount = $Event.Event.EventData.Data[0].'#text'
        Action = switch ($_.Id) {
            4720 {"User Created"}
            4722 {"User Enabled"}
            4724 {"Password Reset"}
            4728 {"Added to Global Group"}
            4732 {"Added to Local Group"}
            4756 {"Added to Universal Group"}
        }
    }
} | Format-Table -AutoSize
```

#### Kerberos Events
```powershell
# Kerberos authentication events (Event IDs 4768, 4769, 4771)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=@(4768,4769,4771); StartTime=(Get-Date).AddDays(-1)} |
ForEach-Object {
    $Event = [xml]$_.ToXml()
    $EventType = switch ($_.Id) {
        4768 {"TGT Request"}
        4769 {"Service Ticket Request"}
        4771 {"Pre-auth Failed"}
    }
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        EventType = $EventType
        Account = $Event.Event.EventData.Data[0].'#text'
        ClientAddress = $Event.Event.EventData.Data[9].'#text'
        ServiceName = if ($_.Id -eq 4769) { $Event.Event.EventData.Data[1].'#text' } else { "N/A" }
        TicketOptions = if ($_.Id -eq 4768) { $Event.Event.EventData.Data[7].'#text' } else { "N/A" }
    }
} | Format-Table -AutoSize
```

### Domain Controller Specific Events

#### Directory Service Events
```powershell
# Directory Service events (available only on DCs)
Get-WinEvent -FilterHashtable @{LogName='Directory Service'; StartTime=(Get-Date).AddDays(-1)} |
Select-Object TimeCreated, Id, LevelDisplayName, Message |
Format-Table -AutoSize

# DNS Server events (suspicious queries)
Get-WinEvent -FilterHashtable @{LogName='DNS Server'; StartTime=(Get-Date).AddDays(-1)} |
Where-Object {$_.Message -like "*error*" -or $_.Message -like "*unusual*"} |
Select-Object TimeCreated, Id, Message
```

#### Object Access Events
```powershell
# SYSVOL access monitoring (Event ID 4663)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4663; StartTime=(Get-Date).AddDays(-1)} |
ForEach-Object {
    $Event = [xml]$_.ToXml()
    $ObjectName = $Event.Event.EventData.Data[6].'#text'
    if ($ObjectName -like "*SYSVOL*" -or $ObjectName -like "*netlogon*") {
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            Account = $Event.Event.EventData.Data[1].'#text'
            ObjectName = $ObjectName
            AccessMask = $Event.Event.EventData.Data[9].'#text'
        }
    }
} | Format-Table -AutoSize
```

---

## LDAP Query Techniques

### Direct LDAP Queries with ADSISearcher

#### Advanced User Searches
```powershell
# LDAP searcher setup
$Searcher = [ADSISearcher]""
$Searcher.SearchRoot = [ADSI]"LDAP://DC=contoso,DC=com"

# Find users with specific attributes
$Searcher.Filter = "(&(objectClass=user)(adminCount=1))"
$Searcher.PropertiesToLoad.AddRange(@("sAMAccountName","distinguishedName","lastLogon"))
$Results = $Searcher.FindAll()

foreach ($Result in $Results) {
    [PSCustomObject]@{
        SamAccountName = $Result.Properties["samaccountname"][0]
        DistinguishedName = $Result.Properties["distinguishedname"][0]
        LastLogon = if ($Result.Properties["lastlogon"][0]) { 
            [DateTime]::FromFileTime($Result.Properties["lastlogon"][0]) 
        } else { 
            "Never" 
        }
    }
}

# Find service accounts by SPN
$Searcher.Filter = "(&(objectClass=user)(servicePrincipalName=*))"
$Searcher.PropertiesToLoad.Clear()
$Searcher.PropertiesToLoad.AddRange(@("sAMAccountName","servicePrincipalName","passwordLastSet"))
$SPNUsers = $Searcher.FindAll()

foreach ($User in $SPNUsers) {
    Write-Host "User: $($User.Properties["samaccountname"][0])" -ForegroundColor Yellow
    $User.Properties["serviceprincipalname"] | ForEach-Object {
        Write-Host "  SPN: $_" -ForegroundColor Cyan
    }
    $PWDLastSet = [DateTime]::FromFileTime($User.Properties["passwordlastset"][0])
    Write-Host "  Password Last Set: $PWDLastSet" -ForegroundColor White
}
```

#### Group and Computer Queries
```powershell
# Find computers with unconstrained delegation
$Searcher.Filter = "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))"
$Searcher.PropertiesToLoad.Clear()
$Searcher.PropertiesToLoad.AddRange(@("sAMAccountName","operatingSystem","lastLogon"))
$DelegationComputers = $Searcher.FindAll()

# Find groups with adminCount=1
$Searcher.Filter = "(&(objectClass=group)(adminCount=1))"
$Searcher.PropertiesToLoad.Clear()
$Searcher.PropertiesToLoad.AddRange(@("sAMAccountName","member","whenChanged"))
$PrivilegedGroups = $Searcher.FindAll()

# Find recently modified objects
$OneWeekAgo = [DateTime]::Now.AddDays(-7).ToFileTime()
$Searcher.Filter = "(whenChanged>=$OneWeekAgo)"
$Searcher.PropertiesToLoad.Clear()
$Searcher.PropertiesToLoad.AddRange(@("distinguishedName","objectClass","whenChanged"))
$RecentChanges = $Searcher.FindAll()
```

### Complex LDAP Filters

#### Security-Focused Queries
```powershell
# Users with password not required
$Searcher.Filter = "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))"

# Computers trusted for delegation
$Searcher.Filter = "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))"

# Users with "Don't require Kerberos preauthentication"
$Searcher.Filter = "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"

# Find empty groups (potential persistence mechanism)
$Searcher.Filter = "(&(objectClass=group)(!member=*))"

# Find users with old passwords (90+ days)
$90DaysAgo = [DateTime]::Now.AddDays(-90).ToFileTime()
$Searcher.Filter = "(&(objectClass=user)(pwdLastSet<=$90DaysAgo))"
```

---

## MITRE ATT&CK Mapped Hunting

### Initial Access (TA0001)

#### T1078 - Valid Accounts
```powershell
# Hunt for compromised accounts with unusual activity patterns
# Detect accounts logging in from multiple IPs
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624; StartTime=(Get-Date).AddDays(-7)} |
ForEach-Object {
    $Event = [xml]$_.ToXml()
    [PSCustomObject]@{
        Account = $Event.Event.EventData.Data[5].'#text'
        SourceIP = $Event.Event.EventData.Data[18].'#text'
        TimeCreated = $_.TimeCreated
    }
} | Group-Object Account | Where-Object {
    ($_.Group | Select-Object -Unique SourceIP | Measure-Object).Count -gt 3
} | ForEach-Object {
    Write-Host "Account with multiple source IPs: $($_.Name)" -ForegroundColor Red
    $_.Group | Select-Object SourceIP -Unique | Format-Table
}

# Detect service accounts with interactive logons
$ServiceAccounts = Get-ADUser -Filter * -Properties ServicePrincipalName |
Where-Object {$_.ServicePrincipalName -ne $null} |
Select-Object -ExpandProperty SamAccountName

Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624; StartTime=(Get-Date).AddDays(-1)} |
ForEach-Object {
    $Event = [xml]$_.ToXml()
    $Account = $Event.Event.EventData.Data[5].'#text'
    $LogonType = $Event.Event.EventData.Data[8].'#text'
    
    if ($Account -in $ServiceAccounts -and $LogonType -in @("2","10")) {
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            Account = $Account
            LogonType = $LogonType
            SourceIP = $Event.Event.EventData.Data[18].'#text'
        }
    }
} | Format-Table -AutoSize
```

### Persistence (TA0003)

#### T1098 - Account Manipulation
```powershell
# Monitor for account modifications
$AccountModificationEvents = @(4720, 4722, 4724, 4725, 4726, 4738, 4781, 4782, 4793)

Get-WinEvent -FilterHashtable @{LogName='Security'; ID=$AccountModificationEvents; StartTime=(Get-Date).AddDays(-7)} |
ForEach-Object {
    $Event = [xml]$_.ToXml()
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        EventID = $_.Id
        SubjectAccount = $Event.Event.EventData.Data[4].'#text'
        TargetAccount = $Event.Event.EventData.Data[0].'#text'
        Computer = $_.MachineName
        Action = switch ($_.Id) {
            4720 {"User Account Created"}
            4722 {"User Account Enabled"}
            4724 {"Password Reset Attempt"}
            4725 {"User Account Disabled"}
            4726 {"User Account Deleted"}
            4738 {"User Account Changed"}
            4781 {"Account Name Changed"}
            4782 {"Password Hash Accessed"}
            4793 {"Password Policy Checking API Called"}
        }
    }
} | Sort-Object TimeCreated -Descending | Format-Table -AutoSize
```

#### T1136 - Create Account
```powershell
# Detect new account creation
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4720; StartTime=(Get-Date).AddDays(-30)} |
ForEach-Object {
    $Event = [xml]$_.ToXml()
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        NewAccount = $Event.Event.EventData.Data[0].'#text'
        CreatedBy = $Event.Event.EventData.Data[4].'#text'
        Computer = $_.MachineName
    }
} | Sort-Object TimeCreated -Descending

# Cross-reference with AD to check if accounts still exist
$RecentAccounts = Get-ADUser -Filter {Created -gt (Get-Date).AddDays(-30)} -Properties Created, CreatedBy
$RecentAccounts | Select-Object Name, SamAccountName, Created | Format-Table -AutoSize
```

### Privilege Escalation (TA0004)

#### T1484 - Domain Policy Modification
```powershell
# Monitor Group Policy modifications
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=5136; StartTime=(Get-Date).AddDays(-7)} |
ForEach-Object {
    $Event = [xml]$_.ToXml()
    $ObjectDN = $Event.Event.EventData.Data[8].'#text'
    
    if ($ObjectDN -like "*CN=Policies*" -or $ObjectDN -like "*CN=System*") {
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            SubjectAccount = $Event.Event.EventData.Data[3].'#text'
            ObjectDN = $ObjectDN
            AttributeName = $Event.Event.EventData.Data[10].'#text'
            AttributeValue = $Event.Event.EventData.Data[13].'#text'
        }
    }
} | Format-Table -AutoSize

# Check for GPO modifications using PowerShell
Get-GPO -All | ForEach-Object {
    if ($_.ModificationTime -gt (Get-Date).AddDays(-7)) {
        [PSCustomObject]@{
            Name = $_.DisplayName
            ModificationTime = $_.ModificationTime
            Id = $_.Id
            GpoStatus = $_.GpoStatus
        }
    }
} | Sort-Object ModificationTime -Descending
```

### Defense Evasion (TA0005)

#### T1562.001 - Disable or Modify Tools
```powershell
# Monitor for security tool tampering
$SecurityServiceNames = @("WinDefend", "SENS", "Winmgmt", "PolicyAgent", "BITS")

Get-WinEvent -FilterHashtable @{LogName='System'; ID=@(7034,7035,7036,7040); StartTime=(Get-Date).AddDays(-1)} |
ForEach-Object {
    $Event = [xml]$_.ToXml()
    $ServiceName = $Event.Event.EventData.Data[0].'#text'
    
    if ($ServiceName -in $SecurityServiceNames) {
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            EventID = $_.Id
            ServiceName = $ServiceName
            Action = switch ($_.Id) {
                7034 {"Service crashed unexpectedly"}
                7035 {"Service sent a control"}
                7036 {"Service entered running/stopped state"}
                7040 {"Service start type changed"}
            }
            Computer = $_.MachineName
        }
    }
} | Format-Table -AutoSize
```

### Credential Access (TA0006)

#### T1003.006 - DCSync Attack Detection
```powershell
# Monitor for DCSync attack patterns (Event ID 4662)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4662; StartTime=(Get-Date).AddDays(-1)} |
ForEach-Object {
    $Event = [xml]$_.ToXml()
    $Properties = $Event.Event.EventData.Data[11].'#text'
    
    # Look for replication permissions being used
    if ($Properties -like "*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*" -or 
        $Properties -like "*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*") {
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            Account = $Event.Event.EventData.Data[1].'#text'
            ObjectName = $Event.Event.EventData.Data[6].'#text'
            Properties = $Properties
            SourceIP = $Event.Event.EventData.Data[18].'#text'
        }
    }
} | Format-Table -AutoSize
```

#### T1558.003 - Kerberoasting Detection
```powershell
# Detect potential Kerberoasting (unusual service ticket requests)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4769; StartTime=(Get-Date).AddDays(-1)} |
ForEach-Object {
    $Event = [xml]$_.ToXml()
    $TicketEncryption = $Event.Event.EventData.Data[6].'#text'
    $ServiceName = $Event.Event.EventData.Data[1].'#text'
    
    # Look for RC4 encryption (often used in Kerberoasting)
    if ($TicketEncryption -eq "0x17") {
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            Account = $Event.Event.EventData.Data[0].'#text'
            ServiceName = $ServiceName
            ClientAddress = $Event.Event.EventData.Data[9].'#text'
            TicketEncryption = "RC4-HMAC"
        }
    }
} | Group-Object Account | Where-Object {$_.Count -gt 10} |
ForEach-Object {
    Write-Host "Potential Kerberoasting target: $($_.Name) - $($_.Count) ticket requests" -ForegroundColor Red
}
```

### Discovery (TA0007)

#### T1087 - Account Discovery
```powershell
# Monitor for account enumeration via net commands
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4798; StartTime=(Get-Date).AddDays(-1)} |
ForEach-Object {
    $Event = [xml]$_.ToXml()
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        SubjectAccount = $Event.Event.EventData.Data[4].'#text'
        TargetAccount = $Event.Event.EventData.Data[0].'#text'
        CallerProcessName = $Event.Event.EventData.Data[17].'#text'
        Computer = $_.MachineName
    }
} | Group-Object SubjectAccount | Where-Object {$_.Count -gt 20} |
ForEach-Object {
    Write-Host "Potential account enumeration by: $($_.Name)" -ForegroundColor Red
    $_.Group | Select-Object TimeCreated, TargetAccount, CallerProcessName | Format-Table
}

# Detect LDAP queries for user enumeration
Get-WinEvent -FilterHashtable @{LogName='Directory Service'; StartTime=(Get-Date).AddDays(-1)} |
Where-Object {$_.Message -like "*search*" -and $_.Message -like "*user*"} |
Select-Object TimeCreated, Id, Message | Format-Table -Wrap
```

### Lateral Movement (TA0008)

#### T1021.001 - Remote Desktop Protocol
```powershell
# Detect RDP lateral movement patterns
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624; StartTime=(Get-Date).AddDays(-1)} |
ForEach-Object {
    $Event = [xml]$_.ToXml()
    $LogonType = $Event.Event.EventData.Data[8].'#text'
    
    if ($LogonType -eq "10") {  # RemoteInteractive logon
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            Account = $Event.Event.EventData.Data[5].'#text'
            SourceIP = $Event.Event.EventData.Data[18].'#text'
            TargetComputer = $_.MachineName
            LogonId = $Event.Event.EventData.Data[7].'#text'
        }
    }
} | Group-Object Account | Where-Object {
    ($_.Group | Select-Object -Unique TargetComputer | Measure-Object).Count -gt 2
} | ForEach-Object {
    Write-Host "RDP lateral movement detected for: $($_.Name)" -ForegroundColor Red
    $_.Group | Select-Object TimeCreated, SourceIP, TargetComputer | 
    Sort-Object TimeCreated | Format-Table
}
```

#### T1021.002 - SMB/Windows Admin Shares
```powershell
# Monitor for admin share access
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=5140; StartTime=(Get-Date).AddDays(-1)} |
ForEach-Object {
    $Event = [xml]$_.ToXml()
    $ShareName = $Event.Event.EventData.Data[5].'#text'
    
    if ($ShareName -like "*$") {  # Admin shares (C$, ADMIN$, etc.)
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            Account = $Event.Event.EventData.Data[1].'#text'
            SourceIP = $Event.Event.EventData.Data[14].'#text'
            ShareName = $ShareName
            AccessMask = $Event.Event.EventData.Data[7].'#text'
            Computer = $_.MachineName
        }
    }
} | Format-Table -AutoSize
```

#### T1021.006 - Windows Remote Management
```powershell
# Detect WinRM/PowerShell remoting activity
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WinRM/Operational'; StartTime=(Get-Date).AddDays(-1)} |
Where-Object {$_.Id -in @(91, 168, 169)} |
ForEach-Object {
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        EventID = $_.Id
        Message = $_.Message
        Computer = $_.MachineName
        Action = switch ($_.Id) {
            91 {"Creating WSMan Session"}
            168 {"Authentication succeeded"}
            169 {"User authentication succeeded"}
        }
    }
} | Format-Table -AutoSize

# PowerShell remoting events
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4103; StartTime=(Get-Date).AddDays(-1)} |
Where-Object {$_.Message -like "*Enter-PSSession*" -or $_.Message -like "*Invoke-Command*"} |
Select-Object TimeCreated, Message | Format-Table -Wrap
```

---

## Advanced Investigation Workflows

### Attack Path Analysis

#### Bloodhound Data Collection
```powershell
# Collect data for Bloodhound analysis
# First, download and run SharpHound
.\SharpHound.exe -c All -d contoso.com --zipfilename bloodhound_data.zip

# Alternative: PowerShell collector
Import-Module .\BloodHound.ps1
Invoke-BloodHound -CollectionMethod All -Domain contoso.com -LDAPUser username -LDAPPass password
```

#### Manual Attack Path Discovery
```powershell
# Find shortest path to Domain Admins
function Find-PathToDomainAdmins {
    param([string]$StartUser)
    
    # Get user's groups
    $UserGroups = Get-ADUser $StartUser -Properties MemberOf | Select-Object -ExpandProperty MemberOf
    
    # Check if any groups have admin privileges
    foreach ($Group in $UserGroups) {
        $GroupMembers = Get-ADGroupMember -Identity $Group -Recursive
        $AdminGroups = @("Domain Admins", "Enterprise Admins", "Administrators")
        
        foreach ($AdminGroup in $AdminGroups) {
            try {
                $AdminMembers = Get-ADGroupMember -Identity $AdminGroup
                $Intersection = Compare-Object $GroupMembers.SamAccountName $AdminMembers.SamAccountName -IncludeEqual |
                               Where-Object {$_.SideIndicator -eq "=="}
                
                if ($Intersection) {
                    Write-Host "Path found: $StartUser -> $Group -> $AdminGroup" -ForegroundColor Red
                }
            }
            catch {
                continue
            }
        }
    }
}

# Check for common privilege escalation paths
$TestUsers = @("testuser1", "serviceaccount", "contractor")
foreach ($User in $TestUsers) {
    try {
        Find-PathToDomainAdmins -StartUser $User
    }
    catch {
        Write-Warning "Could not analyze user: $User"
    }
}
```

### Delegation Analysis

#### Unconstrained Delegation Detection
```powershell
# Find computers with unconstrained delegation
Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation,OperatingSystem,LastLogonDate |
Select-Object Name, OperatingSystem, LastLogonDate, TrustedForDelegation |
Sort-Object LastLogonDate -Descending

# Find users with unconstrained delegation
Get-ADUser -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation,LastLogonDate |
Select-Object Name, SamAccountName, LastLogonDate, TrustedForDelegation
```

#### Constrained Delegation Analysis
```powershell
# Find constrained delegation configurations
Get-ADComputer -Filter * -Properties msDS-AllowedToDelegateTo |
Where-Object {$_."msDS-AllowedToDelegateTo" -ne $null} |
ForEach-Object {
    [PSCustomObject]@{
        Computer = $_.Name
        DelegatedServices = $_."msDS-AllowedToDelegateTo" -join ", "
        OperatingSystem = $_.OperatingSystem
    }
} | Format-Table -AutoSize

# Find resource-based constrained delegation
Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity |
Where-Object {$_."msDS-AllowedToActOnBehalfOfOtherIdentity" -ne $null} |
Select-Object Name, @{Name="AllowedPrincipals";Expression={$_."msDS-AllowedToActOnBehalfOfOtherIdentity"}}
```

### Trust Relationship Analysis

#### Domain Trust Enumeration
```powershell
# Get domain trust relationships
Get-ADTrust -Filter * | Select-Object Name, Direction, TrustType, TrustAttributes, WhenCreated

# Detailed trust analysis
nltest /domain_trusts /all_trusts /v

# PowerShell method for trust analysis
$Domain = Get-ADDomain
$Trusts = Get-ADObject -Filter {objectClass -eq "trustedDomain"} -SearchBase "CN=System,$($Domain.DistinguishedName)" -Properties *

foreach ($Trust in $Trusts) {
    [PSCustomObject]@{
        TrustedDomain = $Trust.Name
        TrustDirection = $Trust.trustDirection
        TrustType = $Trust.trustType
        TrustAttributes = $Trust.trustAttributes
        WhenCreated = $Trust.whenCreated
        SecurityIdentifier = $Trust.securityIdentifier
    }
} | Format-Table -AutoSize
```

### GPO Security Analysis

#### Dangerous GPO Settings Detection
```powershell
# Analyze GPO security settings
Import-Module GroupPolicy

# Get all GPOs and check for dangerous settings
Get-GPO -All | ForEach-Object {
    $GPOReport = Get-GPOReport -Name $_.DisplayName -ReportType XML
    
    # Check for password policies
    if ($GPOReport -like "*PasswordComplexity*" -and $GPOReport -like "*Disabled*") {
        Write-Host "GPO with disabled password complexity: $($_.DisplayName)" -ForegroundColor Red
    }
    
    # Check for user rights assignments
    if ($GPOReport -like "*SeDebugPrivilege*" -or $GPOReport -like "*SeTcbPrivilege*") {
        Write-Host "GPO with dangerous privileges: $($_.DisplayName)" -ForegroundColor Red
    }
    
    # Check for software installation
    if ($GPOReport -like "*Software Installation*") {
        Write-Host "GPO with software installation: $($_.DisplayName)" -ForegroundColor Yellow
    }
}

# Check GPO permissions
Get-GPO -All | ForEach-Object {
    $Permissions = Get-GPPermission -Name $_.DisplayName -All
    
    # Look for unusual permissions
    $SuspiciousPerms = $Permissions | Where-Object {
        $_.Permission -eq "GpoEditDeleteModifySecurity" -and 
        $_.Trustee.Name -notlike "*Admin*" -and 
        $_.Trustee.Name -ne "Authenticated Users"
    }
    
    if ($SuspiciousPerms) {
        Write-Host "Suspicious GPO permissions on: $($_.DisplayName)" -ForegroundColor Red
        $SuspiciousPerms | Select-Object Trustee, Permission | Format-Table
    }
}
```

---

## Kerberos & Authentication Analysis

### Kerberos Ticket Analysis

#### Golden Ticket Detection
```powershell
# Monitor for potential Golden Ticket usage
# Look for unusual TGT requests and characteristics
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4768; StartTime=(Get-Date).AddDays(-1)} |
ForEach-Object {
    $Event = [xml]$_.ToXml()
    $ClientAddress = $Event.Event.EventData.Data[9].'#text'
    $TicketOptions = $Event.Event.EventData.Data[7].'#text'
    $Account = $Event.Event.EventData.Data[0].'#text'
    
    # Check for suspicious characteristics
    if ($ClientAddress -eq "::1" -or $ClientAddress -eq "127.0.0.1") {
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            Account = $Account
            ClientAddress = $ClientAddress
            TicketOptions = $TicketOptions
            Suspicious = "Localhost TGT request"
        }
    }
    
    # Look for TGTs with unusual lifetimes (10 hours = 36000 seconds)
    if ($TicketOptions -like "*Renewable*" -and $TicketOptions -like "*Forwardable*") {
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            Account = $Account
            ClientAddress = $ClientAddress
            TicketOptions = $TicketOptions
            Suspicious = "Renewable and Forwardable TGT"
        }
    }
} | Where-Object {$_.Suspicious} | Format-Table -AutoSize
```

#### Silver Ticket Detection
```powershell
# Monitor for Silver Ticket indicators
# Look for service tickets without corresponding TGT
$ServiceTickets = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4769; StartTime=(Get-Date).AddDays(-1)} |
ForEach-Object {
    $Event = [xml]$_.ToXml()
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        Account = $Event.Event.EventData.Data[0].'#text'
        ServiceName = $Event.Event.EventData.Data[1].'#text'
        ClientAddress = $Event.Event.EventData.Data[9].'#text'
        LogonId = $Event.Event.EventData.Data[8].'#text'
    }
}

$TGTRequests = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4768; StartTime=(Get-Date).AddDays(-1)} |
ForEach-Object {
    $Event = [xml]$_.ToXml()
    [PSCustomObject]@{
        Account = $Event.Event.EventData.Data[0].'#text'
        LogonId = $Event.Event.EventData.Data[8].'#text'
        TimeCreated = $_.TimeCreated
    }
}

# Find service tickets without corresponding TGT
$SuspiciousTickets = $ServiceTickets | Where-Object {
    $Ticket = $_
    -not ($TGTRequests | Where-Object {
        $_.Account -eq $Ticket.Account -and 
        $_.LogonId -eq $Ticket.LogonId -and
        $_.TimeCreated -lt $Ticket.TimeCreated
    })
}

if ($SuspiciousTickets) {
    Write-Host "Potential Silver Ticket usage detected:" -ForegroundColor Red
    $SuspiciousTickets | Format-Table -AutoSize
}
```

### Authentication Anomaly Detection

#### Impossible Travel Detection
```powershell
# Detect impossible travel patterns
function Test-ImpossibleTravel {
    param(
        [Parameter(Mandatory)]
        [string]$Username,
        [Parameter(Mandatory)]
        [int]$Hours = 24
    )
    
    $Events = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624; StartTime=(Get-Date).AddHours(-$Hours)} |
    ForEach-Object {
        $Event = [xml]$_.ToXml()
        $Account = $Event.Event.EventData.Data[5].'#text'
        $SourceIP = $Event.Event.EventData.Data[18].'#text'
        
        if ($Account -eq $Username -and $SourceIP -ne "-") {
            [PSCustomObject]@{
                TimeCreated = $_.TimeCreated
                Account = $Account
                SourceIP = $SourceIP
                Computer = $_.MachineName
            }
        }
    } | Sort-Object TimeCreated
    
    # Simple logic: check for logins from different IP ranges within short time
    for ($i = 0; $i -lt ($Events.Count - 1); $i++) {
        $Current = $Events[$i]
        $Next = $Events[$i + 1]
        
        $TimeDiff = ($Next.TimeCreated - $Current.TimeCreated).TotalMinutes
        
        # Different IP networks within 30 minutes
        if ($TimeDiff -lt 30 -and $Current.SourceIP -ne $Next.SourceIP) {
            $CurrentNetwork = ($Current.SourceIP -split '\.')[0..2] -join '.'
            $NextNetwork = ($Next.SourceIP -split '\.')[0..2] -join '.'
            
            if ($CurrentNetwork -ne $NextNetwork) {
                Write-Host "Impossible travel detected for $Username" -ForegroundColor Red
                Write-Host "  Time 1: $($Current.TimeCreated) from $($Current.SourceIP)"
                Write-Host "  Time 2: $($Next.TimeCreated) from $($Next.SourceIP)"
                Write-Host "  Time difference: $([math]::Round($TimeDiff, 2)) minutes"
            }
        }
    }
}

# Test for impossible travel on high-value accounts
$HighValueAccounts = Get-ADUser -Filter {AdminCount -eq 1} | Select-Object -ExpandProperty SamAccountName
foreach ($Account in $HighValueAccounts) {
    Test-ImpossibleTravel -Username $Account -Hours 24
}
```

#### Brute Force Attack Detection
```powershell
# Detect brute force attacks across multiple accounts
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625; StartTime=(Get-Date).AddHours(-1)} |
ForEach-Object {
    $Event = [xml]$_.ToXml()
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        Account = $Event.Event.EventData.Data[5].'#text'
        SourceIP = $Event.Event.EventData.Data[19].'#text'
        FailureReason = $Event.Event.EventData.Data[8].'#text'
        Computer = $_.MachineName
    }
} | Group-Object SourceIP | Where-Object {$_.Count -gt 10} |
ForEach-Object {
    Write-Host "Brute force attack from IP: $($_.Name) - $($_.Count) failed attempts" -ForegroundColor Red
    $_.Group | Group-Object Account | Select-Object Name, Count | Sort-Object Count -Descending | Format-Table
}
```

---

## Privilege Escalation Detection

### AdminSDHolder Monitoring

#### AdminSDHolder Changes
```powershell
# Monitor AdminSDHolder container for modifications
$AdminSDHolder = "CN=AdminSDHolder,CN=System," + (Get-ADDomain).DistinguishedName

# Get current ACL
$CurrentACL = Get-Acl "AD:$AdminSDHolder"

# Display current permissions
Write-Host "Current AdminSDHolder permissions:" -ForegroundColor Yellow
$CurrentACL.Access | Where-Object {$_.IdentityReference -notlike "*NT AUTHORITY*" -and $_.IdentityReference -notlike "*BUILTIN*"} |
Select-Object IdentityReference, ActiveDirectoryRights, AccessControlType | Format-Table

# Monitor for recent changes (requires historical comparison)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=5136; StartTime=(Get-Date).AddDays(-7)} |
ForEach-Object {
    $Event = [xml]$_.ToXml()
    $ObjectDN = $Event.Event.EventData.Data[8].'#text'
    
    if ($ObjectDN -like "*AdminSDHolder*") {
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            SubjectAccount = $Event.Event.EventData.Data[3].'#text'
            ObjectDN = $ObjectDN
            AttributeName = $Event.Event.EventData.Data[10].'#text'
            Computer = $_.MachineName
        }
    }
} | Format-Table -AutoSize
```

### Sensitive Privilege Monitoring

#### Dangerous Rights Assignment
```powershell
# Check for dangerous user rights assignments
$DangerousRights = @(
    "SeDebugPrivilege",
    "SeTcbPrivilege", 
    "SeCreateTokenPrivilege",
    "SeImpersonatePrivilege",
    "SeAssignPrimaryTokenPrivilege",
    "SeLoadDriverPrivilege",
    "SeRestorePrivilege",
    "SeBackupPrivilege"
)

# Monitor privilege usage events
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4672; StartTime=(Get-Date).AddDays(-1)} |
ForEach-Object {
    $Event = [xml]$_.ToXml()
    $Privileges = $Event.Event.EventData.Data[2].'#text'
    $Account = $Event.Event.EventData.Data[1].'#text'
    
    foreach ($DangerousRight in $DangerousRights) {
        if ($Privileges -like "*$DangerousRight*") {
            [PSCustomObject]@{
                TimeCreated = $_.TimeCreated
                Account = $Account
                Privilege = $DangerousRight
                Computer = $_.MachineName
                AllPrivileges = $Privileges
            }
        }
    }
} | Format-Table -AutoSize
```

### Schema Modification Detection

#### Schema Changes Monitoring
```powershell
# Monitor for schema modifications (requires Schema Admin rights to view)
try {
    Get-WinEvent -FilterHashtable @{LogName='Directory Service'; StartTime=(Get-Date).AddDays(-30)} |
    Where-Object {$_.Message -like "*schema*" -and $_.Id -eq 1216} |
    Select-Object TimeCreated, Id, Message | Format-Table -Wrap
    
    # Check for recent schema modifications
    $SchemaNC = (Get-ADRootDSE).schemaNamingContext
    Get-ADObject -SearchBase $SchemaNC -Filter {whenChanged -gt (Get-Date).AddDays(-30)} -Properties whenChanged, objectClass |
    Select-Object Name, objectClass, whenChanged | Sort-Object whenChanged -Descending
}
catch {
    Write-Warning "Insufficient privileges to check schema modifications"
}
```

---

## Lateral Movement Indicators

### Network Share Enumeration

#### Unusual Share Access Patterns
```powershell
# Monitor for share enumeration activities
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=5140; StartTime=(Get-Date).AddDays(-1)} |
ForEach-Object {
    $Event = [xml]$_.ToXml()
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        Account = $Event.Event.EventData.Data[1].'#text'
        SourceIP = $Event.Event.EventData.Data[14].'#text'
        ShareName = $Event.Event.EventData.Data[5].'#text'
        Computer = $_.MachineName
    }
} | Group-Object Account, SourceIP | Where-Object {
    ($_.Group | Select-Object -Unique ShareName | Measure-Object).Count -gt 5
} | ForEach-Object {
    Write-Host "Potential share enumeration by: $($_.Name)" -ForegroundColor Red
    $_.Group | Select-Object TimeCreated, ShareName, Computer | Format-Table
}
```

### Process Migration Detection

#### Suspicious Process Patterns
```powershell
# Look for process injection indicators in event logs
# This requires Sysmon or similar process monitoring

# Alternative: Check for unusual parent-child relationships
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Kernel-Process/Analytic'; StartTime=(Get-Date).AddHours(-1)} -ErrorAction SilentlyContinue |
Where-Object {$_.Id -eq 1} |  # Process creation
ForEach-Object {
    $Event = [xml]$_.ToXml()
    # Parse process creation events for suspicious patterns
    # This would require Sysmon Event ID 1 for detailed process information
}

# Check for suspicious scheduled tasks (potential persistence)
Get-ScheduledTask | Where-Object {
    $_.TaskPath -notlike "*Microsoft*" -and 
    $_.State -eq "Ready" -and
    $_.Date -gt (Get-Date).AddDays(-7)
} | Select-Object TaskName, TaskPath, State, Date | Format-Table
```

---

## Output Interpretation & Red Flags

### Critical Authentication Indicators

#### 🚩 High-Risk Authentication Patterns
```
Event ID 4624 (Successful Logon):
- LogonType 2: Interactive (console access)
- LogonType 3: Network (file shares, admin tools)
- LogonType 10: RemoteInteractive (RDP)

RED FLAGS:
- Service accounts with LogonType 2 or 10
- Multiple LogonType 10 from same user to different computers
- LogonType 3 to multiple admin shares rapidly
- Successful logon immediately after multiple failures
- Logons from unusual source IPs or time periods
```

#### 🚩 Privilege Escalation Indicators
```
Event ID 4672 (Special Privileges Assigned):
RED FLAGS:
- SeDebugPrivilege assigned to non-admin accounts
- SeTcbPrivilege (Act as part of OS) 
- SeCreateTokenPrivilege (Create security tokens)
- SeImpersonatePrivilege assigned to unusual processes

Event ID 4768 (Kerberos TGT Request):
RED FLAGS:
- TGT requests from localhost (127.0.0.1)
- Unusual ticket options (renewable + forwardable)
- TGT requests for service accounts
- High frequency TGT requests
```

#### 🚩 Account Manipulation Red Flags
```
Event ID 4720 (Account Created):
RED FLAGS:
- Account creation outside business hours
- Creator account is not IT/Admin
- Account created and immediately added to privileged groups

Event ID 4738 (Account Modified):
RED FLAGS:
- Password never expires flag set
- Account enabled after being disabled
- User account control flags modified
- Administrative accounts modified by non-admin users
```

### Network Activity Patterns

#### 🚩 Lateral Movement Indicators
```
SMB/CIFS Activity (Event ID 5140):
RED FLAGS:
- Access to admin shares (C$, ADMIN$) from workstations
- Multiple share access from single source IP
- Share access patterns (enum then exploit)
- Service account accessing multiple systems

RDP Activity (Event ID 4624 LogonType 10):
RED FLAGS:
- RDP chains (A->B->C->D pattern)
- Service accounts using RDP
- RDP from internal IPs (not RDS/Terminal Servers)
- Multiple RDP sessions from same user
```

### Threshold Guidelines

#### Volume-Based Alerting
```powershell
# Failed authentication thresholds
# Per user: >5 failures in 5 minutes
# Per source IP: >20 failures in 10 minutes
# Account lockouts: >3 in 1 hour

# Privilege usage thresholds  
# Administrative logons: >10 per day per admin
# Special privilege usage: Any use of SeDebugPrivilege
# Group modifications: Any change to privileged groups

# Account activity thresholds
# New account creation: >2 per day
# Account modifications: Any change to admin accounts
# Password resets: >5 per day organization-wide
```

### False Positive Patterns

#### Common Legitimate Activities
```powershell
# Whitelist legitimate patterns to reduce noise

# Legitimate RDP activity
$LegitimateRDPSources = @("10.1.100.10", "10.1.100.11")  # RDS servers
$LegitimateRDPUsers = @("rdp-admin", "helpdesk")

# Legitimate administrative activity
$LegitimateAdmins = @("domain-admin", "backup-service", "monitoring-svc")
$BusinessHours = 8..18  # 8 AM to 6 PM

# Legitimate service account behavior
$ServiceAccounts = Get-ADUser -Filter * -Properties ServicePrincipalName |
Where-Object {$_.ServicePrincipalName -ne $null} |
Select-Object -ExpandProperty SamAccountName

# Filter events to reduce false positives
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} |
ForEach-Object {
    $Event = [xml]$_.ToXml()
    $Account = $Event.Event.EventData.Data[5].'#text'
    $LogonType = $Event.Event.EventData.Data[8].'#text'
    $SourceIP = $Event.Event.EventData.Data[18].'#text'
    
    # Skip if legitimate RDP
    if ($LogonType -eq "10" -and $SourceIP -in $LegitimateRDPSources) {
        return
    }
    
    # Skip if service account network logon
    if ($Account -in $ServiceAccounts -and $LogonType -eq "3") {
        return
    }
    
    # Alert on remaining events
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        Account = $Account
        LogonType = $LogonType
        SourceIP = $SourceIP
    }
} | Format-Table
```

---

## Forensic Artifacts & Persistence

### Registry Persistence Locations

#### Common Persistence Registry Keys
```powershell
# Check common persistence locations
$PersistenceKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", 
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    "HKLM:\SYSTEM\CurrentControlSet\Services"
)

foreach ($Key in $PersistenceKeys) {
    try {
        $Items = Get-ItemProperty -Path $Key -ErrorAction SilentlyContinue
        if ($Items) {
            Write-Host "=== $Key ===" -ForegroundColor Yellow
            $Items.PSObject.Properties | Where-Object {$_.Name -notlike "PS*"} |
            ForEach-Object {
                [PSCustomObject]@{
                    Name = $_.Name
                    Value = $_.Value
                    Type = $_.TypeNameOfValue
                }
            } | Format-Table
        }
    }
    catch {
        Write-Warning "Could not access: $Key"
    }
}
```

### File System Artifacts

#### Suspicious File Locations
```powershell
# Check for files in suspicious locations
$SuspiciousLocations = @(
    "$env:TEMP",
    "$env:APPDATA",
    "$env:LOCALAPPDATA\Temp",
    "C:\Users\Public",
    "C:\ProgramData",
    "C:\Windows\Temp",
    "C:\Windows\System32\Tasks"
)

foreach ($Location in $SuspiciousLocations) {
    if (Test-Path $Location) {
        Write-Host "=== Checking $Location ===" -ForegroundColor Yellow
        
        # Look for recently created executable files
        Get-ChildItem -Path $Location -Include "*.exe", "*.dll", "*.bat", "*.ps1", "*.vbs" -Recurse -ErrorAction SilentlyContinue |
        Where-Object {$_.CreationTime -gt (Get-Date).AddDays(-30)} |
        Select-Object Name, FullName, CreationTime, LastWriteTime, Length |
        Sort-Object CreationTime -Descending |
        Format-Table -AutoSize
    }
}

# Check for hidden files and alternate data streams
Get-ChildItem -Path "C:\" -Hidden -Recurse -ErrorAction SilentlyContinue |
Where-Object {$_.Name -like "*.exe" -or $_.Name -like "*.dll"} |
Select-Object Name, FullName, Attributes | Format-Table

# Look for alternate data streams
Get-ChildItem -Path "C:\Users" -Recurse -ErrorAction SilentlyContinue |
ForEach-Object {
    $Streams = Get-Item $_.FullName -Stream * -ErrorAction SilentlyContinue 2>$null
    if ($Streams -and ($Streams | Where-Object {$_.Stream -ne ":$DATA"})) {
        [PSCustomObject]@{
            File = $_.FullName
            AlternateStreams = ($Streams | Where-Object {$_.Stream -ne ":$DATA"}).Stream -join ", "
        }
    }
}
```

### Scheduled Tasks Analysis

#### Malicious Scheduled Tasks Detection
```powershell
# Enumerate all scheduled tasks and identify suspicious ones
Get-ScheduledTask | Where-Object {$_.State -eq "Ready"} |
ForEach-Object {
    $Task = $_
    $TaskInfo = Get-ScheduledTaskInfo -TaskName $Task.TaskName -TaskPath $Task.TaskPath -ErrorAction SilentlyContinue
    
    # Get task action details
    $Actions = $Task.Actions | ForEach-Object {
        if ($_.Execute) {
            "$($_.Execute) $($_.Arguments)"
        }
    }
    
    [PSCustomObject]@{
        TaskName = $Task.TaskName
        TaskPath = $Task.TaskPath
        State = $Task.State
        LastRunTime = if ($TaskInfo) { $TaskInfo.LastRunTime } else { "Never" }
        NextRunTime = if ($TaskInfo) { $TaskInfo.NextRunTime } else { "Not Scheduled" }
        Actions = $Actions -join "; "
        Author = $Task.Author
        RunAsUser = $Task.Principal.UserId
        Description = $Task.Description
    }
} | Where-Object {
    # Filter for suspicious characteristics
    $_.Author -notlike "*Microsoft*" -and
    $_.TaskPath -notlike "*Microsoft*" -and
    ($_.Actions -like "*powershell*" -or 
     $_.Actions -like "*cmd*" -or 
     $_.Actions -like "*wscript*" -or
     $_.Actions -like "*cscript*" -or
     $_.Actions -like "*.exe*" -and $_.Actions -notlike "*Windows*")
} | Sort-Object LastRunTime -Descending | Format-Table -Wrap

# Check for tasks created recently
Get-ScheduledTask | Where-Object {
    $_.Date -gt (Get-Date).AddDays(-30) -and
    $_.Author -notlike "*Microsoft*"
} | Select-Object TaskName, TaskPath, Date, Author, State | Format-Table
```

### WMI Persistence Detection

#### WMI Event Consumers
```powershell
# Check for WMI event consumers (common persistence mechanism)
try {
    # Event consumers
    $Consumers = Get-WmiObject -Namespace root\subscription -Class __EventConsumer -ErrorAction SilentlyContinue
    if ($Consumers) {
        Write-Host "WMI Event Consumers found:" -ForegroundColor Red
        $Consumers | Select-Object Name, @{Name="ConsumerType";Expression={$_.__CLASS}} | Format-Table
    }
    
    # Event filters
    $Filters = Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue
    if ($Filters) {
        Write-Host "WMI Event Filters found:" -ForegroundColor Yellow
        $Filters | Select-Object Name, Query, QueryLanguage | Format-Table -Wrap
    }
    
    # Filter to consumer bindings
    $Bindings = Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue
    if ($Bindings) {
        Write-Host "WMI Filter-to-Consumer Bindings found:" -ForegroundColor Red
        $Bindings | Select-Object Filter, Consumer | Format-Table
    }
}
catch {
    Write-Warning "Could not enumerate WMI persistence mechanisms: $($_.Exception.Message)"
}
```

### Service Persistence Analysis

#### Suspicious Services Detection
```powershell
# Analyze Windows services for suspicious characteristics
Get-WmiObject -Class Win32_Service | Where-Object {$_.State -eq "Running"} |
ForEach-Object {
    # Check for suspicious service characteristics
    $SuspiciousIndicators = @()
    
    # Non-standard path
    if ($_.PathName -notlike "*Windows*" -and $_.PathName -notlike "*Program Files*") {
        $SuspiciousIndicators += "Non-standard path"
    }
    
    # Unusual start mode
    if ($_.StartMode -eq "Auto" -and $_.ServiceType -eq "Own Process") {
        if ($_.Name -notlike "*Microsoft*" -and $_.Name -notlike "*Windows*") {
            $SuspiciousIndicators += "Auto-start custom service"
        }
    }
    
    # Running as SYSTEM but not Microsoft service
    if ($_.StartName -eq "LocalSystem" -and $_.Name -notlike "*Microsoft*") {
        $SuspiciousIndicators += "SYSTEM service non-Microsoft"
    }
    
    # Recently created
    $ServiceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$($_.Name)"
    if (Test-Path $ServiceKey) {
        $ServiceRegData = Get-ItemProperty -Path $ServiceKey -ErrorAction SilentlyContinue
        if ($ServiceRegData -and $ServiceRegData.PSPath) {
            $KeyCreationTime = (Get-Item $ServiceKey).PSProperty.Value
            # This is a simplified check - real implementation would need registry forensics
        }
    }
    
    if ($SuspiciousIndicators.Count -gt 0) {
        [PSCustomObject]@{
            ServiceName = $_.Name
            DisplayName = $_.DisplayName
            State = $_.State
            StartMode = $_.StartMode
            PathName = $_.PathName
            StartName = $_.StartName
            SuspiciousIndicators = $SuspiciousIndicators -join ", "
        }
    }
} | Format-Table -Wrap

# Check for services with suspicious file locations
Get-WmiObject -Class Win32_Service |
Where-Object {
    $_.PathName -like "*temp*" -or
    $_.PathName -like "*appdata*" -or  
    $_.PathName -like "*programdata*" -or
    $_.PathName -like "*public*"
} | Select-Object Name, DisplayName, PathName, State, StartName | Format-Table -Wrap
```

---

## Advanced Hunting Workflows

### Automated Baseline Collection

#### Establish Normal Patterns
```powershell
# Create baseline of normal AD activity
function New-ADBaseline {
    param(
        [int]$Days = 30,
        [string]$OutputPath = "C:\AD_Baseline"
    )
    
    if (!(Test-Path $OutputPath)) {
        New-Item -Path $OutputPath -ItemType Directory -Force
    }
    
    Write-Host "Collecting AD baseline data for the last $Days days..." -ForegroundColor Green
    
    # Baseline 1: Normal authentication patterns
    $AuthBaseline = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624; StartTime=(Get-Date).AddDays(-$Days)} |
    ForEach-Object {
        $Event = [xml]$_.ToXml()
        [PSCustomObject]@{
            Hour = $_.TimeCreated.Hour
            DayOfWeek = $_.TimeCreated.DayOfWeek
            Account = $Event.Event.EventData.Data[5].'#text'
            LogonType = $Event.Event.EventData.Data[8].'#text'
            SourceIP = $Event.Event.EventData.Data[18].'#text'
        }
    }
    
    # Analyze patterns
    $HourlyPattern = $AuthBaseline | Group-Object Hour | Select-Object Name, Count
    $DailyPattern = $AuthBaseline | Group-Object DayOfWeek | Select-Object Name, Count
    $LogonTypePattern = $AuthBaseline | Group-Object LogonType | Select-Object Name, Count
    
    $HourlyPattern | Export-Csv "$OutputPath\Baseline_Hourly_Auth.csv" -NoTypeInformation
    $DailyPattern | Export-Csv "$OutputPath\Baseline_Daily_Auth.csv" -NoTypeInformation
    $LogonTypePattern | Export-Csv "$OutputPath\Baseline_LogonType.csv" -NoTypeInformation
    
    # Baseline 2: Normal user activity
    $UserBaseline = Get-ADUser -Filter * -Properties LastLogonDate, PasswordLastSet, MemberOf |
    Select-Object Name, SamAccountName, LastLogonDate, PasswordLastSet, 
                  @{Name="GroupCount";Expression={($_.MemberOf | Measure-Object).Count}}
    
    $UserBaseline | Export-Csv "$OutputPath\Baseline_Users.csv" -NoTypeInformation
    
    # Baseline 3: Normal computer activity  
    $ComputerBaseline = Get-ADComputer -Filter * -Properties LastLogonDate, PasswordLastSet, OperatingSystem |
    Select-Object Name, LastLogonDate, PasswordLastSet, OperatingSystem
    
    $ComputerBaseline | Export-Csv "$OutputPath\Baseline_Computers.csv" -NoTypeInformation
    
    # Baseline 4: Group membership baseline
    $GroupBaseline = Get-ADGroup -Filter * -Properties Members |
    Select-Object Name, @{Name="MemberCount";Expression={($_.Members | Measure-Object).Count}}
    
    $GroupBaseline | Export-Csv "$OutputPath\Baseline_Groups.csv" -NoTypeInformation
    
    Write-Host "Baseline collection completed. Files saved to: $OutputPath" -ForegroundColor Green
}

# Run baseline collection
New-ADBaseline -Days 30
```

### Anomaly Detection Against Baseline

#### Compare Current Activity to Baseline
```powershell
function Compare-ADActivity {
    param(
        [string]$BaselinePath = "C:\AD_Baseline",
        [int]$ComparisonHours = 24
    )
    
    # Load baseline data
    $BaselineAuth = Import-Csv "$BaselinePath\Baseline_Hourly_Auth.csv"
    $BaselineUsers = Import-Csv "$BaselinePath\Baseline_Users.csv"
    
    # Get current activity
    $CurrentAuth = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624; StartTime=(Get-Date).AddHours(-$ComparisonHours)} |
    ForEach-Object {
        $Event = [xml]$_.ToXml()
        [PSCustomObject]@{
            Hour = $_.TimeCreated.Hour
            Account = $Event.Event.EventData.Data[5].'#text'
            LogonType = $Event.Event.EventData.Data[8].'#text'
        }
    } | Group-Object Hour | Select-Object Name, Count
    
    # Compare patterns
    Write-Host "Authentication Anomalies Detected:" -ForegroundColor Red
    foreach ($Hour in $CurrentAuth) {
        $BaselineCount = ($BaselineAuth | Where-Object {$_.Name -eq $Hour.Name}).Count
        if ($BaselineCount) {
            $Variance = ([int]$Hour.Count - [int]$BaselineCount) / [int]$BaselineCount
            if ($Variance -gt 0.5) {  # 50% increase
                Write-Host "  Hour $($Hour.Name): $($Hour.Count) vs baseline $BaselineCount ($(($Variance * 100).ToString('0.0'))% increase)" -ForegroundColor Yellow
            }
        }
    }
    
    # Check for new users with activity
    $ActiveUsers = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624; StartTime=(Get-Date).AddHours(-$ComparisonHours)} |
    ForEach-Object {
        $Event = [xml]$_.ToXml()
        $Event.Event.EventData.Data[5].'#text'
    } | Select-Object -Unique
    
    $NewActiveUsers = $ActiveUsers | Where-Object {$_ -notin $BaselineUsers.SamAccountName}
    if ($NewActiveUsers) {
        Write-Host "New users with authentication activity:" -ForegroundColor Red
        $NewActiveUsers | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
    }
}

# Run anomaly detection
Compare-ADActivity
```

### Incident Response Workflows

#### Rapid Compromise Assessment
```powershell
function Start-ADCompromiseAssessment {
    param(
        [string[]]$SuspiciousUsers,
        [string[]]$SuspiciousComputers,
        [datetime]$IncidentStartTime = (Get-Date).AddDays(-1)
    )
    
    Write-Host "=== AD Compromise Assessment Starting ===" -ForegroundColor Red
    Write-Host "Incident timeframe: $IncidentStartTime to $(Get-Date)" -ForegroundColor Yellow
    
    # 1. Check authentication activity for suspicious users
    if ($SuspiciousUsers) {
        Write-Host "`n1. Analyzing authentication activity for suspicious users..." -ForegroundColor Cyan
        
        foreach ($User in $SuspiciousUsers) {
            Write-Host "  Analyzing user: $User" -ForegroundColor Yellow
            
            # Get all authentication events
            $UserAuth = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=@(4624,4625); StartTime=$IncidentStartTime} |
            ForEach-Object {
                $Event = [xml]$_.ToXml()
                $Account = $Event.Event.EventData.Data[5].'#text'
                
                if ($Account -eq $User) {
                    [PSCustomObject]@{
                        TimeCreated = $_.TimeCreated
                        EventID = $_.Id
                        LogonType = $Event.Event.EventData.Data[8].'#text'
                        SourceIP = $Event.Event.EventData.Data[18].'#text'
                        Computer = $_.MachineName
                        Result = if ($_.Id -eq 4624) { "Success" } else { "Failed" }
                    }
                }
            }
            
            if ($UserAuth) {
                $UserAuth | Sort-Object TimeCreated | Format-Table -AutoSize
                
                # Check for privilege escalation
                $PrivEscalation = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4672; StartTime=$IncidentStartTime} |
                ForEach-Object {
                    $Event = [xml]$_.ToXml()
                    if ($Event.Event.EventData.Data[1].'#text' -eq $User) {
                        [PSCustomObject]@{
                            TimeCreated = $_.TimeCreated
                            Privileges = $Event.Event.EventData.Data[2].'#text'
                        }
                    }
                }
                
                if ($PrivEscalation) {
                    Write-Host "    Privilege usage detected:" -ForegroundColor Red
                    $PrivEscalation | Format-Table
                }
            }
        }
    }
    
    # 2. Check for lateral movement indicators
    Write-Host "`n2. Checking for lateral movement indicators..." -ForegroundColor Cyan
    
    # Look for RDP lateral movement
    $RDPMovement = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624; StartTime=$IncidentStartTime} |
    ForEach-Object {
        $Event = [xml]$_.ToXml()
        $LogonType = $Event.Event.EventData.Data[8].'#text'
        
        if ($LogonType -eq "10") {
            [PSCustomObject]@{
                TimeCreated = $_.TimeCreated
                Account = $Event.Event.EventData.Data[5].'#text'
                SourceIP = $Event.Event.EventData.Data[18].'#text'
                TargetComputer = $_.MachineName
            }
        }
    } | Group-Object Account | Where-Object {
        ($_.Group | Select-Object -Unique TargetComputer | Measure-Object).Count -gt 2
    }
    
    if ($RDPMovement) {
        Write-Host "  RDP lateral movement detected:" -ForegroundColor Red
        $RDPMovement | ForEach-Object {
            Write-Host "    User: $($_.Name) accessed $($_.Count) computers via RDP" -ForegroundColor Yellow
        }
    }
    
    # 3. Check for persistence mechanisms
    Write-Host "`n3. Checking for persistence mechanisms..." -ForegroundColor Cyan
    
    # Check for new scheduled tasks
    $NewTasks = Get-ScheduledTask | Where-Object {
        $_.Date -gt $IncidentStartTime -and
        $_.Author -notlike "*Microsoft*"
    }
    
    if ($NewTasks) {
        Write-Host "  New scheduled tasks found:" -ForegroundColor Red
        $NewTasks | Select-Object TaskName, Author, Date | Format-Table
    }
    
    # Check for new services
    $Services = Get-WmiObject -Class Win32_Service | Where-Object {$_.Name -notlike "*Microsoft*"}
    # Note: Service creation time requires registry analysis for accurate detection
    
    # 4. Generate summary report
    Write-Host "`n=== ASSESSMENT SUMMARY ===" -ForegroundColor Red
    Write-Host "Analysis period: $IncidentStartTime to $(Get-Date)" -ForegroundColor White
    Write-Host "Suspicious users analyzed: $($SuspiciousUsers.Count)" -ForegroundColor White
    Write-Host "Suspicious computers analyzed: $($SuspiciousComputers.Count)" -ForegroundColor White
    Write-Host "RDP lateral movement instances: $(if ($RDPMovement) { $RDPMovement.Count } else { 0 })" -ForegroundColor White
    Write-Host "New scheduled tasks: $(if ($NewTasks) { $NewTasks.Count } else { 0 })" -ForegroundColor White
    
    Write-Host "`nRecommended next steps:" -ForegroundColor Yellow
    Write-Host "1. Reset passwords for all suspicious users" -ForegroundColor White
    Write-Host "2. Review and remove any unauthorized scheduled tasks" -ForegroundColor White
    Write-Host "3. Check for additional IOCs across the environment" -ForegroundColor White
    Write-Host "4. Consider isolating affected systems" -ForegroundColor White
}

# Example usage
# Start-ADCompromiseAssessment -SuspiciousUsers @("john.doe", "admin.service") -IncidentStartTime (Get-Date).AddDays(-2)
```

---

## Quick Reference Commands

### Essential PowerShell AD Commands
```powershell
# User queries
Get-ADUser -Filter * -Properties *
Get-ADUser -Identity username -Properties *
Get-ADUser -Filter {AdminCount -eq 1}
Get-ADUser -Filter {PasswordNeverExpires -eq $true}

# Group queries  
Get-ADGroup -Filter * -Properties *
Get-ADGroupMember -Identity "Domain Admins" -Recursive
Get-ADPrincipalGroupMembership -Identity username

# Computer queries
Get-ADComputer -Filter * -Properties *
Get-ADComputer -Filter {TrustedForDelegation -eq $true}

# Organizational Unit queries
Get-ADOrganizationalUnit -Filter *
Get-ADObject -Filter {objectClass -eq "organizationalUnit"}

# Domain and forest information
Get-ADDomain
Get-ADForest  
Get-ADDomainController -Filter *
Get-ADTrust -Filter *
```

### Critical Event IDs Quick Reference
```powershell
# Authentication Events
4624 - Successful logon
4625 - Failed logon  
4634 - Account logoff
4647 - User initiated logoff
4648 - Logon with explicit credentials

# Account Management
4720 - User account created
4722 - User account enabled
4724 - Password reset attempt
4725 - User account disabled
4726 - User account deleted
4738 - User account changed

# Privilege Usage
4672 - Special privileges assigned
4673 - Privileged service called
4674 - Operation attempted on privileged object

# Kerberos Events  
4768 - Kerberos TGT requested
4769 - Kerberos service ticket requested
4771 - Kerberos pre-authentication failed

# Object Access
4662 - Operation performed on object
4663 - Attempt to access object
5136 - Directory service object modified
5137 - Directory service object created
5139 - Directory service object moved
5141 - Directory service object deleted
```

### Emergency Response One-Liners
```powershell
# Quick compromise indicators
Get-ADUser -Filter {AdminCount -eq 1} | Where-Object {$_.LastLogonDate -gt (Get-Date).AddDays(-1)}

# Recent failed logons
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625; StartTime=(Get-Date).AddHours(-1)} | Group-Object {([xml]$_.ToXml()).Event.EventData.Data[5].'#text'} | Sort-Object Count -Descending

# Privileged group changes  
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=@(4728,4732,4756); StartTime=(Get-Date).AddDays(-1)}

# Service account interactive logons
$ServiceAccounts = Get-ADUser -Filter * -Properties ServicePrincipalName | Where-Object {$_.ServicePrincipalName} | Select-Object -ExpandProperty SamAccountName
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} | Where-Object {([xml]$_.ToXml()).Event.EventData.Data[8].'#text' -in @("2","10") -and ([xml]$_.ToXml()).Event.EventData.Data[5].'#text' -in $ServiceAccounts}
```

---

## Troubleshooting & Best Practices

### Common Issues and Solutions

#### Permission Problems
```powershell
# Check current permissions
whoami /groups | findstr /i admin
Get-ADDomain | Select-Object PDCEmulator

# Test connectivity to domain controller
Test-ComputerSecureChannel -Verbose
nltest /sc_query:domain.com

# Alternative authentication
$Credential = Get-Credential
Get-ADUser -Filter * -Credential $Credential -Server dc01.domain.com
```

#### Performance Optimization
```powershell
# Limit properties returned
Get-ADUser -Filter * -Properties Name, LastLogonDate, AdminCount

# Use specific search base
Get-ADUser -Filter * -SearchBase "OU=Users,DC=domain,DC=com"

# Page results for large queries
Get-ADUser -Filter * -ResultPageSize 500 -ResultSetSize $null

# Use LDAP filters for complex queries
Get-ADUser -LDAPFilter "(&(objectClass=user)(adminCount=1))"
```

#### Event Log Management
```powershell
# Check log sizes and retention
Get-WinEvent -ListLog Security | Select-Object LogName, MaximumSizeInBytes, RecordCount

# Set log retention (requires admin)
wevtutil sl Security /ms:1073741824  # 1GB
wevtutil sl Security /rt:false       # Disable log wrapping

# Archive logs before analysis
wevtutil epl Security C:\Logs\Security_$(Get-Date -Format 'yyyyMMdd').evtx
```

### Field Deployment Tips

#### Creating Portable Investigation Kit
```powershell
# Create investigation script bundle
$InvestigationKit = @"
# AD Threat Hunting Investigation Kit
Import-Module ActiveDirectory

# Quick compromise assessment
function Quick-ADCheck {
    Write-Host "=== Quick AD Security Check ===" -ForegroundColor Green
    
    # Check 1: Recent admin logons
    Write-Host "Recent administrative logons:" -ForegroundColor Yellow
    Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624; StartTime=(Get-Date).AddHours(-24)} |
    ForEach-Object {
        \$Event = [xml]\$_.ToXml()
        \$Account = \$Event.Event.EventData.Data[5].'#text'
        \$LogonType = \$Event.Event.EventData.Data[8].'#text'
        if (\$Account -like "*admin*" -and \$LogonType -in @("2","10")) {
            [PSCustomObject]@{
                Time = \$_.TimeCreated
                Account = \$Account
                Computer = \$_.MachineName
                LogonType = \$LogonType
            }
        }
    } | Format-Table
    
    # Check 2: Failed logons
    Write-Host "Recent failed logons (top 10):" -ForegroundColor Yellow
    Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625; StartTime=(Get-Date).AddHours(-4)} |
    ForEach-Object {
        \$Event = [xml]\$_.ToXml()
        \$Event.Event.EventData.Data[5].'#text'
    } | Group-Object | Sort-Object Count -Descending | Select-Object -First 10 | Format-Table
    
    # Check 3: Privileged group memberships
    Write-Host "Current Domain Admins:" -ForegroundColor Yellow
    Get-ADGroupMember -Identity "Domain Admins" | Select-Object Name, SamAccountName | Format-Table
}

Quick-ADCheck
"@

$InvestigationKit | Out-File -FilePath "ADThreatHuntKit.ps1" -Encoding UTF8
Write-Host "Investigation kit created: ADThreatHuntKit.ps1" -ForegroundColor Green
```

---

*This comprehensive Active Directory threat hunting cheatsheet provides field-tested techniques for real-world security operations. Always ensure you have proper authorization before running these commands in production environments and validate findings through multiple sources.*