# Wireshark Threat Hunting Cheatsheet - Field Operations Guide

## General
- **Target Audience**: SOC analysts, threat hunters, incident responders
- **Scope**: Active threat hunting in enterprise networks
- **Prerequisites**: Basic TCP/IP knowledge, familiarity with MITRE ATT&CK framework
- **Environment**: Wireshark 4.x with appropriate capture privileges

---

## Core Display Filters - Essential Syntax

### Basic Protocol Filtering
```bash
# Protocol isolation
tcp                          # TCP traffic only
udp                          # UDP traffic only
http or https               # Web traffic
dns                         # DNS queries/responses
icmp                        # ICMP packets (ping, traceroute)
arp                         # ARP traffic (network discovery)

# Layer combinations
tcp.port == 80 or tcp.port == 443    # Web ports
udp.port == 53                       # DNS queries
tcp.port == 22                       # SSH connections
```

### IP Address & Subnet Filtering
```bash
# Host-specific
ip.addr == 192.168.1.100           # Any traffic to/from host
ip.src == 192.168.1.100            # Traffic from host
ip.dst == 192.168.1.100            # Traffic to host

# Network ranges
ip.addr in {192.168.1.0/24}        # Subnet filtering
not ip.addr in {10.0.0.0/8}        # Exclude RFC1918 space
ip.addr in {192.168.1.1..192.168.1.50}  # IP range
```

### Time-Based Filtering
```bash
# Timestamp filtering (critical for incident response)
frame.time >= "2024-01-15 14:30:00"
frame.time_relative >= 300          # Last 5 minutes from start
frame.time_delta > 0.1              # Packets with >100ms delay
```

---

## Threat Hunting Use Cases by MITRE ATT&CK

### Initial Access (T1190, T1078)

**Suspicious Login Patterns**
```bash
# Failed authentication attempts
http contains "401" or http contains "403"
kerberos.error_code != 0
ldap.resultCode != 0

# Brute force detection
tcp.stream eq X and tcp.flags.reset == 1    # Multiple connection resets
http.request.method == "POST" and http contains "login"
```

**Web Exploitation (T1190)**
```bash
# SQL injection attempts
http contains "union select" or http contains "' or 1=1"
http contains "xp_cmdshell" or http contains "sp_executesql"

# Command injection
http contains "cmd.exe" or http contains "/bin/sh"
http contains "powershell" or http contains "wget"

# Directory traversal
http contains "../" or http contains "..%2F"
```

### Persistence (T1053, T1547)

**Scheduled Tasks & Services**
```bash
# Windows RPC calls for task scheduling
dcerpc.cn_call_id and dcerpc contains "atsvc"
smb2.cmd == 5 and smb2 contains "Tasks"

# Service installation
smb2 contains "system32" and smb2 contains ".exe"
```

### Defense Evasion (T1027, T1055)

**Encoded/Obfuscated Traffic**
```bash
# Base64 encoded content
http contains "TVqQAAMAAAAEAAAA"        # PE header base64
tcp contains "===" or tcp contains "=="  # Base64 padding

# PowerShell encoded commands
http contains "powershell" and http contains "-enc"
tcp contains "JAB" or tcp contains "SQB"  # PowerShell Unicode markers

# Packed/encrypted payloads
tcp[tcp.len-1:1] == 00:00               # Null padding
frame.len > 1400 and entropy(tcp.payload) > 7.5  # High entropy
```

### Command & Control (T1071, T1572)

**C2 Channel Detection**
```bash
# Beaconing behavior
tcp.stream eq X and tcp.len < 100        # Small, regular packets
http.user_agent contains "Mozilla" and http.content_length < 50

# DNS tunneling
dns.qry.name matches "^[a-f0-9]{20,}\..*"  # Long hex subdomains
dns.flags.response == 1 and dns.resp.len > 100

# HTTPS C2 (certificate anomalies)
tls.handshake.certificate and x509ce.dNSName matches ".*\.tk$"
ssl.handshake.type == 11 and ssl.handshake.certificate_length < 1000
```

**Protocol Abuse**
```bash
# HTTP tunneling
http.request.method == "POST" and http.content_length > 1000
http contains "CONNECT" and tcp.port != 443

# ICMP tunneling
icmp.type == 8 and icmp.data_len > 64
icmp and data.len > 100
```

### Exfiltration (T1041, T1567)

**Data Staging & Transfer**
```bash
# Large uploads
http.request.method == "POST" and http.content_length > 10000
ftp-data and tcp.len > 1000

# Compression indicators
tcp contains "PK" or tcp contains "Rar!"     # ZIP/RAR headers
http.content_type contains "application/zip"

# Cloud storage abuse
http.host contains "dropbox" or http.host contains "drive.google"
dns.qry.name contains "amazonaws" or dns.qry.name contains "azure"
```

---

## Advanced Filtering Techniques

### Statistical Analysis
```bash
# Connection analysis
tcp.analysis.retransmission           # Network issues or evasion
tcp.analysis.fast_retransmission     # Potential packet manipulation
tcp.analysis.duplicate_ack           # Network anomalies

# Protocol statistics
tcp.window_size_scalefactor != 0     # Window scaling (advanced stacks)
ip.ttl < 64                          # Potentially spoofed/proxied
```

### Content Inspection
```bash
# Regex pattern matching
tcp matches "(?i)(password|passwd|pwd)"
http.request.uri matches ".*\.(exe|zip|rar)$"
dns.qry.name matches "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$"  # IP as domain

# Binary pattern searching
tcp contains 4d:5a:90:00              # PE executable header
tcp contains 50:4b:03:04              # ZIP file header
tcp contains ff:d8:ff:e0              # JPEG file header
```

### Stream Analysis
```bash
# Follow specific conversations
tcp.stream eq 42                     # Follow TCP stream #42
udp.stream eq 15                     # Follow UDP conversation

# Stream reassembly
tcp.reassembled_in eq 100            # Multi-packet reassembly
tcp.segment.count > 10               # Fragmented communications
```

---

## Practical Command-Line Operations

### Capture Commands
```bash
# Live capture with filters
tshark -i eth0 -f "port 80 or port 443" -w web_traffic.pcap

# Capture with ring buffer (continuous monitoring)
tshark -i eth0 -b files:100 -b filesize:100000 -w capture

# Remote capture via SSH
ssh user@host "tcpdump -U -s0 -w -" | wireshark -k -i -
```

### Analysis Commands
```bash
# Quick statistics
tshark -r capture.pcap -q -z conv,tcp        # TCP conversations
tshark -r capture.pcap -q -z io,phs          # Protocol hierarchy
tshark -r capture.pcap -q -z hosts           # Host statistics

# Extract specific data
tshark -r capture.pcap -Y "http" -T fields -e http.host -e http.request.uri
tshark -r capture.pcap -Y "dns" -T fields -e dns.qry.name -e dns.resp.addr
```

### Automation Scripts
```bash
# Automated IOC extraction
tshark -r capture.pcap -Y "http" -T fields -e ip.src -e http.host | sort -u

# Suspicious activity detection
tshark -r capture.pcap -Y "tcp.flags.syn==1 and tcp.flags.ack==0" -T fields -e ip.src | sort | uniq -c | sort -nr
```

---

## Output Interpretation & Red Flags

### Network Behavior Anomalies

**Connection Patterns**
- **Beaconing**: Regular intervals in C2 traffic (check Statistics → I/O Graph)
- **Port hopping**: Sequential connections across ports
- **Geographic anomalies**: Connections to unusual countries
- **Time-based patterns**: Activity outside business hours

**Protocol Abuse Indicators**
- **DNS**: Unusually long queries, non-standard record types, high query volume
- **HTTP**: Unusual User-Agent strings, POST to image files, binary content in text protocols
- **TLS**: Certificate mismatches, weak ciphers, unusual certificate chains

### Traffic Volume Analysis
```bash
# Identify top talkers
Statistics → Conversations → Sort by Bytes
Statistics → Endpoints → Sort by Packets

# Timeline analysis
Statistics → I/O Graph → Set interval to 1 second
Look for: Burst patterns, regular intervals, unusual volume spikes
```

### Certificate & Encryption Analysis
```bash
# Certificate inspection
tls.handshake.certificate and x509ce.dNSName
ssl.handshake.type == 11

# Cipher suite analysis
ssl.handshake.ciphersuite == 0x0035    # TLS_RSA_WITH_AES_256_SHA
ssl.handshake.version < 0x0303         # TLS < 1.2 (potential downgrade)
```

---

## Field-Tested Tips & Pitfalls

### Performance Optimization
- **Use capture filters** (`-f`) to reduce data volume at capture time
- **Ring buffers** prevent disk space issues during long captures
- **Disable name resolution** (View → Name Resolution) for faster analysis
- **Custom columns** for frequently used fields (Edit → Preferences → Columns)

### Common Pitfalls
1. **Clock synchronization**: Ensure accurate timestamps across systems
2. **Encrypted traffic**: Modern networks heavily use TLS - focus on metadata
3. **Load balancers**: Can fragment sessions across multiple streams
4. **NAT/Proxy**: May obscure true source addresses
5. **Fragmentation**: Large packets may span multiple frames

### Memory & Storage Management
- **Large captures**: Use `editcap` to split files before analysis
- **Memory usage**: Close unused capture files, use filters early
- **Archive strategy**: Compress old captures, maintain chain of custody

### Detection Evasion Awareness
- **Protocol manipulation**: Attackers may fragment, delay, or tunnel traffic
- **Mimicry**: Legitimate-looking traffic patterns and user agents
- **Timing attacks**: Slow, low-volume exfiltration to avoid detection
- **Encrypted channels**: Focus on connection patterns, not content

---

## Validation Checklist

### Before Analysis
- [ ] Time synchronization verified across network devices
- [ ] Capture points strategically positioned (network choke points)
- [ ] Sufficient storage and processing capacity available
- [ ] Legal authorization and data handling procedures followed

### During Investigation
- [ ] Multiple capture points correlated for complete picture
- [ ] Statistical analysis performed (not just individual packets)
- [ ] False positives ruled out through additional validation
- [ ] Timeline reconstruction maintains chain of custody

### Post-Analysis
- [ ] Findings documented with supporting evidence
- [ ] IOCs extracted and formatted for sharing
- [ ] Recommendations provided for detection/prevention
- [ ] Lessons learned captured for future investigations

---

## References & Further Reading

- **NIST SP 800-86**: Guide to Integrating Forensic Techniques into Incident Response
- **SANS ICS515**: Active Defense and Incident Response
- **Wireshark User's Guide**: https://www.wireshark.org/docs/wsug_html_chunked/
- **MITRE ATT&CK**: https://attack.mitre.org/
- **Zeek/Suricata Integration**: Complement Wireshark with IDS logs for context

---

**Version**: 2024.1 | **Last Updated**: April 2025 