# Volatility Threat Hunting Cheatsheet
*Elite Field Reference for Security Analysts*

## Quick Start & Environment Setup

### Installation & Dependencies
```bash
# Volatility 3 (Recommended for new investigations)
pip3 install volatility3
vol -h

# Volatility 2.6 (Legacy, still widely used)
git clone https://github.com/volatilityfoundation/volatility.git
python vol.py -h

# Essential symbol tables
mkdir symbols && cd symbols
wget https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip
wget https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip
```

### Memory Image Validation
```bash
# Always validate image integrity first
vol -f memory.dmp windows.info
vol -f memory.dmp banners.Banners  # Check for hypervisor artifacts
```

---

## Core Command Structure & Syntax

### Volatility 3 Syntax
```bash
vol [global-options] -f <memory-image> <plugin> [plugin-options]

# Global Options:
-v, --verbosity     # 0-3, increase for debugging
-q, --quiet         # Suppress banner
-r, --renderer      # Output format (table, json, csv)
-o, --output-dir    # Save output to directory
--cache-dir         # Symbol cache location
```

### Volatility 2.6 Syntax  
```bash
python vol.py [global-options] -f <memory-image> --profile=<profile> <plugin> [plugin-options]

# Profile Detection (Critical for Vol2)
python vol.py -f memory.dmp imageinfo
python vol.py -f memory.dmp kdbgscan
```

---

## Phase 1: Initial Reconnaissance & Profiling

### System Information Gathering
```bash
# Vol3 - System Overview
vol -f memory.dmp windows.info
vol -f memory.dmp windows.registry.hivelist
vol -f memory.dmp windows.envars

# Vol2 - System Overview  
python vol.py -f memory.dmp --profile=Win10x64_19041 printenv
python vol.py -f memory.dmp --profile=Win10x64_19041 hivelist
```

### Timeline Creation (Critical for Threat Hunting)
```bash
# Vol3 - Comprehensive timeline
vol -f memory.dmp -o timeline/ timeliner

# Vol2 - Multiple timeline sources
python vol.py -f memory.dmp --profile=Win10x64_19041 timeliner \
  --output=body --output-file=timeline.body
```

**🔍 Analyst Tip**: Always create timeline first - it provides chronological context for all subsequent findings.

---

## Phase 2: Process Analysis & Malware Detection

### Process Enumeration & Analysis
```bash
# Vol3 - Process tree with command lines
vol -f memory.dmp windows.pstree
vol -f memory.dmp windows.pslist
vol -f memory.dmp windows.cmdline

# Vol2 - Process analysis
python vol.py -f memory.dmp --profile=Win10x64_19041 pstree
python vol.py -f memory.dmp --profile=Win10x64_19041 pslist
python vol.py -f memory.dmp --profile=Win10x64_19041 cmdline
```

### Malware Process Detection
```bash
# Hidden/Unlisted processes (MITRE T1055 - Process Injection)
vol -f memory.dmp windows.pslist > pslist.txt
vol -f memory.dmp windows.psscan > psscan.txt
diff pslist.txt psscan.txt  # Look for processes only in psscan

# Process hollowing detection (MITRE T1055.012)
vol -f memory.dmp windows.malfind -p <PID>
vol -f memory.dmp windows.hollowfind  # Vol3 specific

# Code injection indicators
vol -f memory.dmp windows.vadinfo -p <PID> | grep -E "(EXECUTE|PAGE_EXECUTE)"
```

### Process Memory Dumps
```bash
# Dump suspicious process memory
vol -f memory.dmp windows.memmap -p <PID> --dump
vol -f memory.dmp windows.procdump -p <PID>

# Extract specific VADs (Virtual Address Descriptors)  
vol -f memory.dmp windows.vadinfo -p <PID>
vol -f memory.dmp windows.vadyarascan -p <PID> -Y <yara-rule>
```

---

## Phase 3: Network Analysis & C2 Detection

### Network Connections (MITRE T1071 - Application Layer Protocol)
```bash
# Vol3 - Active connections
vol -f memory.dmp windows.netstat
vol -f memory.dmp windows.netscan

# Vol2 - Network analysis
python vol.py -f memory.dmp --profile=Win10x64_19041 netscan
python vol.py -f memory.dmp --profile=Win10x64_19041 connections
```

### DNS Cache Analysis (C2 Domain Detection)
```bash
# Vol2 only - DNS cache extraction
python vol.py -f memory.dmp --profile=Win10x64_19041 dnscache
```

**🚨 Red Flags in Network Analysis:**
- Connections to non-standard ports (8080, 4444, 31337)
- Processes with network connections but no visible windows
- Multiple connections to same external IP with different ports
- Connections from system processes (winlogon.exe, csrss.exe)

---

## Phase 4: Persistence & Registry Analysis

### Registry Hive Analysis (MITRE T1547 - Boot/Logon Autostart)
```bash
# Vol3 - Registry analysis
vol -f memory.dmp windows.registry.printkey -K "Microsoft\Windows\CurrentVersion\Run"
vol -f memory.dmp windows.registry.printkey -K "Microsoft\Windows\CurrentVersion\RunOnce"
vol -f memory.dmp windows.registry.printkey -K "Microsoft\Windows NT\CurrentVersion\Winlogon"

# Vol2 - Registry analysis
python vol.py -f memory.dmp --profile=Win10x64_19041 printkey \
  -K "Microsoft\Windows\CurrentVersion\Run"
```

### Service Analysis (MITRE T1543.003 - Windows Service)
```bash
# Vol3 - Service enumeration
vol -f memory.dmp windows.services

# Vol2 - Service analysis  
python vol.py -f memory.dmp --profile=Win10x64_19041 svcscan
```

### Critical Registry Locations to Check
```bash
# Autostart locations
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon

# Service installations
HKLM\SYSTEM\CurrentControlSet\Services

# AppInit DLLs (T1546.010)
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs
```

---

## Phase 5: Credential & Authentication Analysis

### Password Hash Extraction (MITRE T1003 - OS Credential Dumping)
```bash
# Vol3 - Hash extraction
vol -f memory.dmp windows.hashdump
vol -f memory.dmp windows.lsadump
vol -f memory.dmp windows.cachedump

# Vol2 - Credential analysis
python vol.py -f memory.dmp --profile=Win10x64_19041 hashdump
python vol.py -f memory.dmp --profile=Win10x64_19041 lsadump
```

### LSASS Process Analysis
```bash
# Target LSASS specifically (Critical for credential theft detection)
vol -f memory.dmp windows.pslist | grep lsass
vol -f memory.dmp windows.handles -p <LSASS_PID>
vol -f memory.dmp windows.vadinfo -p <LSASS_PID>
```

---

## Phase 6: File System & Artifact Analysis

### File System Timeline
```bash
# Vol3 - MFT analysis
vol -f memory.dmp windows.mftscan
vol -f memory.dmp windows.filescan

# Vol2 - File system analysis
python vol.py -f memory.dmp --profile=Win10x64_19041 mftparser
python vol.py -f memory.dmp --profile=Win10x64_19041 filescan
```

### File Extraction & Analysis
```bash
# Extract specific files by offset
vol -f memory.dmp windows.dumpfiles --virtaddr <virtual_address>
vol -f memory.dmp windows.dumpfiles --physaddr <physical_address>

# Extract files by pattern
vol -f memory.dmp windows.filescan | grep -i ".exe$" | grep -i temp
```

### Browser Artifact Analysis
```bash
# Chrome/Edge history (Vol2)
python vol.py -f memory.dmp --profile=Win10x64_19041 chromehistory
python vol.py -f memory.dmp --profile=Win10x64_19041 iehistory

# Browser cookie extraction
python vol.py -f memory.dmp --profile=Win10x64_19041 chromecookies
```

---

## Phase 7: Advanced Threat Hunting Techniques

### YARA Rule Integration
```bash
# Scan with custom YARA rules
vol -f memory.dmp windows.vadyarascan -Y /path/to/rules.yar
vol -f memory.dmp yarascan -Y /path/to/rules.yar

# Common YARA rule categories for threat hunting:
# - Cobalt Strike beacons
# - Metasploit payloads  
# - Common RAT families
# - Cryptocurrency miners
```

### API Hook Detection (MITRE T1056 - Input Capture)
```bash
# Vol2 - API hook detection
python vol.py -f memory.dmp --profile=Win10x64_19041 apihooks
python vol.py -f memory.dmp --profile=Win10x64_19041 idt
python vol.py -f memory.dmp --profile=Win10x64_19041 ssdt
```

### Driver Analysis (MITRE T1014 - Rootkit)
```bash
# Vol3 - Driver enumeration
vol -f memory.dmp windows.modules
vol -f memory.dmp windows.driverscan

# Vol2 - Driver analysis
python vol.py -f memory.dmp --profile=Win10x64_19041 modules
python vol.py -f memory.dmp --profile=Win10x64_19041 modscan
python vol.py -f memory.dmp --profile=Win10x64_19041 driverscan
```

---

## MITRE ATT&CK Mapping & Hunting Workflows

### T1055 - Process Injection Workflow
```bash
# 1. Identify suspicious processes
vol -f memory.dmp windows.malfind

# 2. Check for process hollowing
vol -f memory.dmp windows.vadinfo -p <PID> | grep -E "EXECUTE.*WRITE"

# 3. Memory dump for analysis
vol -f memory.dmp windows.procdump -p <PID>

# 4. YARA scan for injection artifacts
vol -f memory.dmp windows.vadyarascan -p <PID> -Y injection_rules.yar
```

### T1003 - Credential Dumping Detection
```bash
# 1. Check LSASS access
vol -f memory.dmp windows.handles -p <LSASS_PID> | grep -E "Process|Thread"

# 2. Look for credential dumping tools
vol -f memory.dmp windows.cmdline | grep -iE "mimikatz|pwdump|fgdump"

# 3. Check for unusual LSASS child processes
vol -f memory.dmp windows.pstree | grep -A5 -B5 lsass.exe
```

### T1071 - Application Layer Protocol (C2)
```bash
# 1. Network connection analysis
vol -f memory.dmp windows.netscan > connections.txt

# 2. Cross-reference with process list
vol -f memory.dmp windows.pslist | while read line; do
    PID=$(echo $line | awk '{print $3}')
    grep $PID connections.txt
done

# 3. Check for beaconing patterns (manual analysis required)
# Look for regular intervals in timeline data
```

---

## Output Interpretation & Red Flags

### Process Analysis Red Flags
- **Unusual parent-child relationships**: svchost.exe spawning cmd.exe
- **System processes from wrong locations**: explorer.exe from System32
- **Processes with no command line**: Often indicates process hollowing
- **Multiple instances of normally single processes**: Multiple winlogon.exe
- **High privilege processes with network connections**: System-level processes communicating externally

### Memory Analysis Red Flags  
- **RWX memory regions**: Read-Write-Execute permissions indicate injected code
- **Unbacked memory sections**: Memory not backed by files on disk
- **Suspicious DLL loads**: Unusual libraries loaded into common processes
- **API hooks in critical processes**: Modifications to system call tables

### Network Analysis Red Flags
- **Connections from system processes**: winlogon.exe, csrss.exe with external connections
- **Non-standard ports**: Communication on unusual port numbers
- **Multiple connections to single IP**: Potential C2 communication
- **Processes with connections but no GUI**: Background network activity

---

## Performance Optimization & Best Practices

### Memory Management
```bash
# Use specific PIDs to reduce processing time
vol -f memory.dmp windows.pslist | grep -i suspicious
vol -f memory.dmp windows.vadinfo -p <TARGET_PID>

# Cache symbols to improve performance
export VOLATILITY_CACHE_PATH=/path/to/cache
```

### Parallel Processing
```bash
# Run multiple analyses simultaneously (different terminals)
vol -f memory.dmp windows.netscan > network.txt &
vol -f memory.dmp windows.pslist > processes.txt &
vol -f memory.dmp windows.filescan > files.txt &
```

### Output Management
```bash
# Structure output for analysis
mkdir investigation_$(date +%Y%m%d)
cd investigation_$(date +%Y%m%d)

# Save all outputs with timestamps
vol -f ../memory.dmp windows.pslist > pslist_$(date +%H%M).txt
vol -f ../memory.dmp windows.netscan > netscan_$(date +%H%M).txt
```

---

## Common Pitfalls & Troubleshooting

### Profile Detection Issues (Vol2)
```bash
# If imageinfo fails, try:
python vol.py -f memory.dmp kdbgscan
python vol.py -f memory.dmp kpcrscan

# For unusual systems:
python vol.py -f memory.dmp --profile=Win10x64_19041 pslist --help
```

### Large Memory Images
```bash
# Use specific address ranges for faster processing
vol -f memory.dmp windows.vadinfo -p <PID> --address <START_ADDR>

# Process in chunks for very large images
dd if=memory.dmp of=chunk1.dmp bs=1G count=1 skip=0
dd if=memory.dmp of=chunk2.dmp bs=1G count=1 skip=1
```

### False Positive Reduction
- Cross-reference multiple data sources (process list + network + timeline)
- Validate findings with additional plugins
- Consider legitimate administrative tools (PsExec, PowerShell, WMI)
- Check for known-good signatures and certificates

---

## Integration with SIEM/SOAR

### JSON Output for Automated Processing
```bash
# Export in machine-readable format
vol -f memory.dmp -r json windows.pslist > processes.json
vol -f memory.dmp -r json windows.netscan > network.json

# Parse with jq for specific indicators
cat processes.json | jq '.[] | select(.ImageFileName | contains("powershell"))'
```

### Indicator Extraction
```bash
# Extract IPs for threat intel lookup
vol -f memory.dmp windows.netscan | awk '{print $3}' | cut -d: -f1 | sort -u

# Extract file hashes for VirusTotal lookup  
vol -f memory.dmp windows.filescan | grep -E "\\.exe$|\\.dll$" > executables.txt
```

---

## Quick Reference Commands

### Most Critical Commands for Threat Hunting
```bash
# The "Big 5" - Run these first
vol -f memory.dmp windows.pslist        # Process enumeration
vol -f memory.dmp windows.netscan       # Network connections
vol -f memory.dmp windows.malfind       # Code injection detection
vol -f memory.dmp windows.filescan      # File system artifacts
vol -f memory.dmp timeliner            # Timeline creation

# Follow-up analysis based on findings
vol -f memory.dmp windows.cmdline       # Command line arguments
vol -f memory.dmp windows.handles       # Open handles analysis
vol -f memory.dmp windows.registry.hivelist  # Registry investigation
```

### Emergency IOC Extraction
```bash
# Quick indicators for immediate blocking
vol -f memory.dmp windows.netscan | awk '{print $3}' | cut -d: -f1 | sort -u > ips.txt
vol -f memory.dmp windows.pslist | awk '{print $2}' | sort -u > processes.txt
vol -f memory.dmp windows.cmdline | grep -oE '[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}' | sort -u > domains.txt
```

---

## Additional Resources & References

### Essential YARA Rule Collections
- **Florian Roth's signature-base**: https://github.com/Neo23x0/signature-base
- **YARA-Rules Project**: https://github.com/Yara-Rules/rules  
- **Elastic Security YARA**: https://github.com/elastic/protections-artifacts

### Volatility Plugin Extensions
- **Vol3 Community Plugins**: https://github.com/volatilityfoundation/community3
- **Rekall Framework**: Alternative memory analysis framework
- **MemProcFS**: Virtual file system for memory analysis

### Training & Certification Paths
- **SANS FOR508**: Advanced Digital Forensics and Incident Response
- **Volatility Training**: Official Volatility Foundation courses
- **GCIH**: GIAC Certified Incident Handler (includes memory forensics)

---

*This cheatsheet is designed for authorized security testing and incident response activities only. Always ensure proper legal authorization before analyzing memory images.*

**Last Updated**: August 2025 | **Version**: 2.1