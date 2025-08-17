# AWS CloudTrail/CloudWatch/VPC Flow Logs Threat Hunting Cheatsheet
*Elite Field Reference for Cloud Security Analysts*

## Quick Start & Environment Setup

### Essential AWS Logging Components
```bash
# Core Logging Services for Threat Hunting
- CloudTrail: API call logging and management events
- CloudWatch Logs: Application and system logs aggregation
- VPC Flow Logs: Network traffic metadata
- GuardDuty: Managed threat detection (optional but recommended)
- Config: Configuration change tracking
- Security Hub: Centralized security findings

# Key Log Types by Service
CloudTrail:     Management events, data events, insight events
CloudWatch:     Application logs, Lambda logs, EC2 system logs
VPC Flow Logs:  Network connections, traffic metadata, DNS queries
```

### Initial Environment Validation
```bash
# Check CloudTrail status
aws cloudtrail describe-trails --region us-east-1
aws cloudtrail get-trail-status --name <trail-name>

# Verify log delivery
aws logs describe-log-groups --region us-east-1
aws logs describe-log-streams --log-group-name CloudTrail/logs

# Check VPC Flow Logs configuration
aws ec2 describe-flow-logs --region us-east-1
aws ec2 describe-vpc-endpoints --region us-east-1

# Validate S3 bucket access
aws s3 ls s3://cloudtrail-bucket-name/AWSLogs/
aws s3api get-bucket-notification-configuration --bucket cloudtrail-bucket-name
```

---

## Core AWS CLI & Query Syntax

### CloudTrail Analysis Commands
```bash
# Basic CloudTrail log querying
aws logs filter-log-events \
  --log-group-name CloudTrail/logs \
  --start-time $(date -d "1 hour ago" +%s)000 \
  --filter-pattern "{ $.eventName = ConsoleLogin }"

# Advanced filtering with multiple conditions
aws logs filter-log-events \
  --log-group-name CloudTrail/logs \
  --start-time $(date -d "24 hours ago" +%s)000 \
  --filter-pattern "{ ($.eventName = AssumeRole) && ($.sourceIPAddress != 192.168.*) }"

# Error events filtering
aws logs filter-log-events \
  --log-group-name CloudTrail/logs \
  --filter-pattern "{ $.errorCode EXISTS }"

# User activity tracking
aws logs filter-log-events \
  --log-group-name CloudTrail/logs \
  --filter-pattern "{ $.userIdentity.type = IAMUser && $.userIdentity.userName = suspicious-user }"
```

### CloudWatch Insights Queries
```sql
-- Basic CloudTrail event analysis
fields @timestamp, eventName, sourceIPAddress, userIdentity.userName, errorCode
| filter eventTime > date_sub(now(), interval 1 hour)
| stats count() by eventName
| sort count desc

-- Failed authentication attempts
fields @timestamp, eventName, sourceIPAddress, userIdentity, errorCode, errorMessage
| filter eventName like /ConsoleLogin|AssumeRole/
| filter errorCode exists
| stats count() by sourceIPAddress, errorCode
| sort count desc

-- Privilege escalation detection
fields @timestamp, eventName, userIdentity.userName, sourceIPAddress
| filter eventName in ["AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy", "PutRolePolicy", "CreateRole", "AddUserToGroup"]
| stats count() by userIdentity.userName, eventName
| sort count desc
```

### VPC Flow Logs Analysis
```bash
# Query VPC Flow Logs via CloudWatch Insights
aws logs start-query \
  --log-group-name VPCFlowLogs \
  --start-time $(date -d "1 hour ago" +%s) \
  --end-time $(date +%s) \
  --query-string 'fields @timestamp, srcaddr, dstaddr, srcport, dstport, protocol, action
                  | filter action = "REJECT"
                  | stats count() by srcaddr, dstaddr
                  | sort count desc'

# Network anomaly detection
aws logs start-query \
  --log-group-name VPCFlowLogs \
  --start-time $(date -d "24 hours ago" +%s) \
  --end-time $(date +%s) \
  --query-string 'fields srcaddr, dstaddr, bytes, packets
                  | stats sum(bytes) as total_bytes by srcaddr, dstaddr
                  | sort total_bytes desc
                  | limit 20'
```

---

## Phase 1: Initial Reconnaissance & Environment Assessment

### Account and Resource Discovery
```sql
-- CloudWatch Insights: Account activity overview
fields @timestamp, eventName, awsRegion, userIdentity.userName, sourceIPAddress
| filter @timestamp > date_sub(now(), interval 24 hour)
| stats count() by awsRegion, eventName
| sort count desc
| limit 50

-- Resource enumeration activities
fields @timestamp, eventName, userIdentity.userName, sourceIPAddress, requestParameters
| filter eventName like /Describe|List|Get/
| filter @timestamp > date_sub(now(), interval 1 hour)
| stats count() by userIdentity.userName, sourceIPAddress
| sort count desc

-- New user/role creation
fields @timestamp, eventName, userIdentity.userName, responseElements, sourceIPAddress
| filter eventName in ["CreateUser", "CreateRole", "CreateAccessKey", "CreateLoginProfile"]
| sort @timestamp desc
```

### Baseline Activity Analysis
```bash
# Most common API calls (30-day baseline)
aws logs start-query \
  --log-group-name CloudTrail/logs \
  --start-time $(date -d "30 days ago" +%s) \
  --end-time $(date -d "1 day ago" +%s) \
  --query-string 'stats count() by eventName | sort count desc | limit 100'

# Normal user activity patterns
aws logs start-query \
  --log-group-name CloudTrail/logs \
  --start-time $(date -d "7 days ago" +%s) \
  --end-time $(date +%s) \
  --query-string 'fields userIdentity.userName, sourceIPAddress, userAgent
                  | stats count() by userIdentity.userName, sourceIPAddress
                  | sort count desc'

# Geographic distribution analysis
aws logs start-query \
  --log-group-name CloudTrail/logs \
  --start-time $(date -d "24 hours ago" +%s) \
  --end-time $(date +%s) \
  --query-string 'fields sourceIPAddress, awsRegion, eventName
                  | stats count() by sourceIPAddress, awsRegion
                  | sort count desc'
```

---

## Phase 2: Authentication & Access Analysis

### Suspicious Authentication Patterns (MITRE T1078 - Valid Accounts)
```sql
-- Failed console logins
fields @timestamp, sourceIPAddress, userIdentity.userName, errorCode, errorMessage, userAgent
| filter eventName = "ConsoleLogin"
| filter errorCode exists
| stats count() as failed_attempts by sourceIPAddress, userIdentity.userName
| sort failed_attempts desc

-- Successful logins after failures (potential brute force)
fields @timestamp, sourceIPAddress, userIdentity.userName, errorCode
| filter eventName = "ConsoleLogin"
| sort @timestamp asc
| stats count() as total_attempts, 
        sum(case errorCode exists when 1 else 0 end) as failed_attempts,
        sum(case errorCode exists when 0 else 1 end) as successful_attempts
        by sourceIPAddress, userIdentity.userName
| filter failed_attempts > 5 and successful_attempts > 0

-- Unusual login times
fields @timestamp, sourceIPAddress, userIdentity.userName, userAgent
| filter eventName = "ConsoleLogin"
| filter errorCode not exists
| filter datefloor(@timestamp, 1h) in [0,1,2,3,4,5,22,23]  -- Off hours
| stats count() by userIdentity.userName, sourceIPAddress
| sort count desc

-- Multiple IP addresses for single user
fields @timestamp, sourceIPAddress, userIdentity.userName
| filter eventName = "ConsoleLogin" and errorCode not exists
| filter @timestamp > date_sub(now(), interval 24 hour)
| stats count() as login_count, count_distinct(sourceIPAddress) as unique_ips by userIdentity.userName
| filter unique_ips > 3
| sort unique_ips desc
```

### Privilege Escalation Detection (T1484 - Group Policy Modification)
```sql
-- IAM policy modifications
fields @timestamp, eventName, userIdentity.userName, sourceIPAddress, requestParameters, responseElements
| filter eventName in ["AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy", "PutRolePolicy", "CreateRole", "CreatePolicy"]
| filter requestParameters.policyDocument like /\*/ or responseElements.policy.policyDocument like /\*/
| sort @timestamp desc

-- Administrative privilege assignment
fields @timestamp, eventName, userIdentity.userName, sourceIPAddress, requestParameters
| filter eventName in ["AttachUserPolicy", "AttachRolePolicy", "AddUserToGroup"]
| filter requestParameters.policyArn like /Administrator/ 
       or requestParameters.groupName like /Admin/
       or requestParameters.policyArn like /PowerUser/
| sort @timestamp desc

-- Root account usage
fields @timestamp, eventName, userIdentity.type, sourceIPAddress, userAgent
| filter userIdentity.type = "Root"
| filter eventName != "HeadObject"  -- Exclude health checks
| sort @timestamp desc

-- Cross-account role assumptions
fields @timestamp, eventName, userIdentity, sourceIPAddress, requestParameters, responseElements
| filter eventName = "AssumeRole"
| filter requestParameters.roleArn like /::.*:role/ 
| parse requestParameters.roleArn "arn:aws:iam::*:role/*" as account_id, role_name
| stats count() by userIdentity.userName, account_id, role_name, sourceIPAddress
| sort count desc
```

### Access Key Abuse (T1098 - Account Manipulation)
```sql
-- Access key creation and usage
fields @timestamp, eventName, userIdentity.userName, sourceIPAddress, responseElements
| filter eventName in ["CreateAccessKey", "DeleteAccessKey", "UpdateAccessKey"]
| sort @timestamp desc

-- Programmatic access from unusual locations
fields @timestamp, sourceIPAddress, userIdentity.accessKeyId, eventName, userAgent
| filter userIdentity.accessKeyId exists
| filter userAgent not like /aws-cli/ and userAgent not like /aws-sdk/
| stats count() as api_calls, count_distinct(eventName) as unique_actions by sourceIPAddress, userIdentity.accessKeyId
| sort api_calls desc

-- Access key usage after creation
fields @timestamp, eventName, userIdentity.accessKeyId, sourceIPAddress
| filter userIdentity.accessKeyId exists
| sort @timestamp asc
| stats min(@timestamp) as first_seen, max(@timestamp) as last_seen, count() as usage_count by userIdentity.accessKeyId
| filter usage_count > 100  -- High usage access keys
```

---

## Phase 3: Network Analysis & C2 Detection

### VPC Flow Logs Analysis (T1071 - Application Layer Protocol)
```sql
-- Unusual outbound connections
fields @timestamp, srcaddr, dstaddr, srcport, dstport, protocol, action, bytes
| filter action = "ACCEPT" and dstaddr not like /^10\./ and dstaddr not like /^172\./ and dstaddr not like /^192\.168\./
| stats sum(bytes) as total_bytes, count() as connection_count by srcaddr, dstaddr, dstport
| sort total_bytes desc

-- High volume data transfers
fields @timestamp, srcaddr, dstaddr, bytes, packets
| filter action = "ACCEPT"
| stats sum(bytes) as total_bytes, sum(packets) as total_packets by srcaddr, dstaddr
| filter total_bytes > 1073741824  -- Greater than 1GB
| sort total_bytes desc

-- Beaconing detection (regular intervals)
fields @timestamp, srcaddr, dstaddr, dstport
| filter action = "ACCEPT" and dstaddr not like /^10\./
| filter @timestamp > date_sub(now(), interval 2 hour)
| bin(@timestamp, 5m) as time_bucket
| stats count() by time_bucket, srcaddr, dstaddr, dstport
| sort time_bucket asc

-- Denied connections analysis (potential scanning)
fields @timestamp, srcaddr, dstaddr, dstport, protocol
| filter action = "REJECT"
| stats count() as denied_attempts, count_distinct(dstport) as unique_ports by srcaddr, dstaddr
| filter denied_attempts > 10 or unique_ports > 10
| sort denied_attempts desc

-- DNS tunneling detection
fields @timestamp, srcaddr, dstaddr, srcport, dstport, bytes
| filter dstport = 53 and action = "ACCEPT"
| stats avg(bytes) as avg_bytes, max(bytes) as max_bytes, count() as query_count by srcaddr, dstaddr
| filter avg_bytes > 100 or max_bytes > 500  -- Unusually large DNS queries
| sort avg_bytes desc
```

### Security Group Changes (T1562.007 - Disable or Modify Cloud Firewall)
```sql
-- Security group modifications
fields @timestamp, eventName, userIdentity.userName, sourceIPAddress, requestParameters, responseElements
| filter eventName in ["AuthorizeSecurityGroupIngress", "RevokeSecurityGroupIngress", "AuthorizeSecurityGroupEgress", "RevokeSecurityGroupEgress"]
| filter requestParameters.ipPermissions.0.ipRanges.0.cidrIp = "0.0.0.0/0"
| sort @timestamp desc

-- Security group rule additions with wide access
fields @timestamp, eventName, userIdentity.userName, requestParameters
| filter eventName = "AuthorizeSecurityGroupIngress"
| filter requestParameters.ipPermissions.0.fromPort = 0 
       or requestParameters.ipPermissions.0.toPort = 65535
       or requestParameters.ipPermissions.0.ipRanges.0.cidrIp = "0.0.0.0/0"
| sort @timestamp desc

-- NACL modifications
fields @timestamp, eventName, userIdentity.userName, sourceIPAddress, requestParameters
| filter eventName like /NetworkAcl/
| filter eventName in ["CreateNetworkAclEntry", "ReplaceNetworkAclEntry", "DeleteNetworkAclEntry"]
| sort @timestamp desc
```

---

## Phase 4: Resource Manipulation & Persistence

### EC2 Instance Analysis (T1078.004 - Cloud Accounts)
```sql
-- EC2 instance launches
fields @timestamp, eventName, userIdentity.userName, sourceIPAddress, responseElements.instancesSet.items.0.instanceId, requestParameters.instanceType
| filter eventName = "RunInstances"
| sort @timestamp desc

-- Instance metadata service access
fields @timestamp, sourceIPAddress, userAgent, requestParameters
| filter eventName = "GetMetadata" or requestParameters.url like /169.254.169.254/
| stats count() by sourceIPAddress, userAgent
| sort count desc

-- Unusual instance types or regions
fields @timestamp, eventName, awsRegion, requestParameters.instanceType, userIdentity.userName
| filter eventName = "RunInstances"
| filter requestParameters.instanceType like /xlarge|metal/ or awsRegion not in ["us-east-1", "us-west-2"]
| sort @timestamp desc

-- Instance termination activities
fields @timestamp, eventName, userIdentity.userName, requestParameters, responseElements
| filter eventName in ["TerminateInstances", "StopInstances", "RebootInstances"]
| sort @timestamp desc
```

### S3 Bucket Security (T1530 - Data from Cloud Storage Object)
```sql
-- S3 bucket policy changes
fields @timestamp, eventName, userIdentity.userName, sourceIPAddress, requestParameters.bucketName, requestParameters.policy
| filter eventName in ["PutBucketPolicy", "DeleteBucketPolicy", "PutBucketAcl"]
| sort @timestamp desc

-- Public bucket access
fields @timestamp, eventName, sourceIPAddress, requestParameters.bucketName, requestParameters.policy
| filter eventName = "PutBucketPolicy"
| filter requestParameters.policy like /\*/ and requestParameters.policy like /s3:GetObject/
| sort @timestamp desc

-- Unusual S3 access patterns
fields @timestamp, eventName, sourceIPAddress, requestParameters.bucketName, userIdentity.userName
| filter eventName in ["GetObject", "PutObject", "DeleteObject"]
| filter sourceIPAddress not like /^10\./ and sourceIPAddress not like /^172\./ and sourceIPAddress not like /^192\.168\./
| stats count() as access_count, count_distinct(requestParameters.key) as unique_objects by sourceIPAddress, requestParameters.bucketName
| sort access_count desc

-- Data exfiltration indicators
fields @timestamp, eventName, sourceIPAddress, requestParameters.bucketName, requestParameters.key
| filter eventName = "GetObject"
| filter @timestamp > date_sub(now(), interval 1 hour)
| stats count() as downloads, count_distinct(requestParameters.key) as unique_files by sourceIPAddress, requestParameters.bucketName
| filter downloads > 100
| sort downloads desc
```

### Lambda Function Security (T1505.003 - Web Shell)
```sql
-- Lambda function creation and modification
fields @timestamp, eventName, userIdentity.userName, sourceIPAddress, requestParameters.functionName, requestParameters.code
| filter eventName in ["CreateFunction", "UpdateFunctionCode", "UpdateFunctionConfiguration"]
| sort @timestamp desc

-- Lambda execution anomalies
fields @timestamp, eventName, sourceIPAddress, requestParameters, errorCode
| filter eventName = "Invoke" and errorCode exists
| stats count() as error_count by requestParameters.functionName, errorCode
| sort error_count desc

-- Lambda environment variable changes
fields @timestamp, eventName, userIdentity.userName, requestParameters.functionName, requestParameters.environment
| filter eventName = "UpdateFunctionConfiguration"
| filter requestParameters.environment exists
| sort @timestamp desc
```

---

## Phase 5: Data Access & Exfiltration

### Database Access Patterns (T1530 - Data from Cloud Storage Object)
```sql
-- RDS connection anomalies
fields @timestamp, eventName, sourceIPAddress, requestParameters, userIdentity.userName
| filter eventName like /RDS/ and eventName like /Connect|Modify|Delete/
| stats count() by eventName, sourceIPAddress, userIdentity.userName
| sort count desc

-- DynamoDB access patterns
fields @timestamp, eventName, sourceIPAddress, requestParameters.tableName, userIdentity.userName
| filter eventName in ["GetItem", "BatchGetItem", "Scan", "Query"]
| filter @timestamp > date_sub(now(), interval 24 hour)
| stats count() as access_count by sourceIPAddress, requestParameters.tableName, userIdentity.userName
| filter access_count > 1000
| sort access_count desc

-- Database modification events
fields @timestamp, eventName, userIdentity.userName, requestParameters, responseElements
| filter eventName in ["PutItem", "UpdateItem", "DeleteItem", "BatchWriteItem"]
| stats count() by userIdentity.userName, requestParameters.tableName
| sort count desc
```

### Cross-Service Data Access
```sql
-- CloudFormation stack activities
fields @timestamp, eventName, userIdentity.userName, sourceIPAddress, requestParameters.stackName
| filter eventName like /Stack/
| filter eventName in ["CreateStack", "UpdateStack", "DeleteStack"]
| sort @timestamp desc

-- Secrets Manager access
fields @timestamp, eventName, userIdentity.userName, sourceIPAddress, requestParameters.secretId
| filter eventName in ["GetSecretValue", "UpdateSecret", "CreateSecret", "DeleteSecret"]
| sort @timestamp desc

-- Parameter Store access
fields @timestamp, eventName, sourceIPAddress, requestParameters.name, userIdentity.userName
| filter eventName in ["GetParameter", "GetParameters", "PutParameter", "DeleteParameter"]
| filter requestParameters.name like /password|secret|key|token/
| sort @timestamp desc
```

---

## Advanced Hunting Techniques

### Threat Intelligence Integration
```bash
# IOC matching with AWS CLI
# Create IOC list file
echo "malicious-ip-1
malicious-ip-2
suspicious-domain.com" > ioc_list.txt

# Search CloudTrail for IOC matches
while read ioc; do
  aws logs filter-log-events \
    --log-group-name CloudTrail/logs \
    --start-time $(date -d "24 hours ago" +%s)000 \
    --filter-pattern "{ $.sourceIPAddress = $ioc }" \
    --output json >> ioc_matches.json
done < ioc_list.txt

# VPC Flow Logs IOC matching
aws logs start-query \
  --log-group-name VPCFlowLogs \
  --start-time $(date -d "24 hours ago" +%s) \
  --end-time $(date +%s) \
  --query-string 'fields srcaddr, dstaddr, action
                  | filter srcaddr in ["MALICIOUS_IP_1", "MALICIOUS_IP_2"] 
                         or dstaddr in ["MALICIOUS_IP_1", "MALICIOUS_IP_2"]'
```

### Behavioral Analysis & Anomaly Detection
```sql
-- User behavior baseline deviation
fields @timestamp, userIdentity.userName, eventName, sourceIPAddress, awsRegion
| filter @timestamp > date_sub(now(), interval 24 hour)
| stats count() as current_activity, 
        count_distinct(eventName) as unique_actions,
        count_distinct(sourceIPAddress) as unique_ips,
        count_distinct(awsRegion) as unique_regions
        by userIdentity.userName
| filter unique_actions > 50 or unique_ips > 5 or unique_regions > 3

-- Time-based anomaly detection
fields @timestamp, userIdentity.userName, eventName
| bin(@timestamp, 1h) as hour_bucket
| stats count() as hourly_activity by hour_bucket, userIdentity.userName
| sort @timestamp asc

-- Rare API call analysis
fields @timestamp, eventName, userIdentity.userName, sourceIPAddress
| filter @timestamp > date_sub(now(), interval 7 day)
| stats count() as call_count by eventName
| sort call_count asc
| limit 20  -- Focus on rarest API calls

-- Service enumeration detection
fields @timestamp, eventName, userIdentity.userName, sourceIPAddress
| filter eventName like /Describe|List|Get/
| filter @timestamp > date_sub(now(), interval 1 hour)
| stats count() as recon_calls, count_distinct(eventName) as unique_recon by userIdentity.userName, sourceIPAddress
| filter recon_calls > 50 or unique_recon > 20
| sort recon_calls desc
```

### Cross-Service Correlation
```sql
-- EC2 and VPC Flow Logs correlation
-- Step 1: Get recent EC2 launches
fields @timestamp, responseElements.instancesSet.items.0.instanceId, responseElements.instancesSet.items.0.privateIpAddress
| filter eventName = "RunInstances"
| filter @timestamp > date_sub(now(), interval 2 hour)

-- Step 2: Correlate with VPC Flow Logs (manual correlation needed)
-- Use the private IP addresses from Step 1 in VPC Flow Logs queries

-- CloudTrail and GuardDuty correlation
fields @timestamp, eventName, userIdentity.userName, sourceIPAddress, awsRegion
| filter sourceIPAddress in ["GUARDDUTY_FLAGGED_IP_1", "GUARDDUTY_FLAGGED_IP_2"]
| sort @timestamp desc

-- Multi-region activity correlation
fields @timestamp, awsRegion, userIdentity.userName, sourceIPAddress, eventName
| filter @timestamp > date_sub(now(), interval 6 hour)
| stats count() as activity_count, count_distinct(awsRegion) as regions by userIdentity.userName, sourceIPAddress
| filter regions > 2
| sort regions desc
```

---

## Investigation Workflows by MITRE ATT&CK

### T1078 - Valid Accounts Workflow
```bash
# Step 1: Identify suspicious authentication
aws logs start-query \
  --log-group-name CloudTrail/logs \
  --start-time $(date -d "24 hours ago" +%s) \
  --end-time $(date +%s) \
  --query-string 'fields @timestamp, sourceIPAddress, userIdentity.userName, errorCode
                  | filter eventName = "ConsoleLogin"
                  | stats count() as attempts, 
                          sum(case errorCode exists when 1 else 0 end) as failures
                          by sourceIPAddress, userIdentity.userName
                  | filter failures > 5'

# Step 2: Analyze successful logins from suspicious IPs
aws logs start-query \
  --log-group-name CloudTrail/logs \
  --start-time $(date -d "24 hours ago" +%s) \
  --end-time $(date +%s) \
  --query-string 'fields @timestamp, eventName, sourceIPAddress, userIdentity.userName
                  | filter sourceIPAddress = "SUSPICIOUS_IP"
                  | filter errorCode not exists
                  | sort @timestamp asc'

# Step 3: Track post-authentication activity
aws logs start-query \
  --log-group-name CloudTrail/logs \
  --start-time $(date -d "2 hours ago" +%s) \
  --end-time $(date +%s) \
  --query-string 'fields @timestamp, eventName, requestParameters, responseElements
                  | filter userIdentity.userName = "COMPROMISED_USER"
                  | sort @timestamp asc'

# Step 4: Check for privilege escalation
aws logs start-query \
  --log-group-name CloudTrail/logs \
  --start-time $(date -d "2 hours ago" +%s) \
  --end-time $(date +%s) \
  --query-string 'fields @timestamp, eventName, requestParameters
                  | filter userIdentity.userName = "COMPROMISED_USER"
                  | filter eventName in ["AttachUserPolicy", "CreateRole", "AssumeRole"]'
```

### T1562.007 - Disable or Modify Cloud Firewall Workflow
```sql
-- Step 1: Identify security control modifications
fields @timestamp, eventName, userIdentity.userName, sourceIPAddress, requestParameters
| filter eventName in ["AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress", 
                       "CreateNetworkAclEntry", "ReplaceNetworkAclEntry"]
| filter requestParameters.ipPermissions.0.ipRanges.0.cidrIp = "0.0.0.0/0"
| sort @timestamp desc

-- Step 2: Check subsequent network activity
-- (Correlate with VPC Flow Logs using affected security group IDs)

-- Step 3: Analyze user behavior around security changes
fields @timestamp, eventName, userIdentity.userName, sourceIPAddress
| filter userIdentity.userName = "SUSPICIOUS_USER"
| filter @timestamp > date_sub(now(), interval 2 hour)
| sort @timestamp asc

-- Step 4: Check for data access after security changes
fields @timestamp, eventName, requestParameters.bucketName, sourceIPAddress
| filter eventName in ["GetObject", "ListObjects"]
| filter @timestamp > "SECURITY_CHANGE_TIME"
| stats count() by sourceIPAddress, requestParameters.bucketName
```

### T1530 - Data from Cloud Storage Object Workflow
```sql
-- Step 1: Identify unusual S3 access patterns
fields @timestamp, eventName, sourceIPAddress, requestParameters.bucketName, userIdentity.userName
| filter eventName in ["GetObject", "ListObjects", "GetBucketLocation"]
| filter @timestamp > date_sub(now(), interval 24 hour)
| stats count() as access_count, count_distinct(requestParameters.key) as unique_objects 
        by sourceIPAddress, requestParameters.bucketName, userIdentity.userName
| filter access_count > 100
| sort access_count desc

-- Step 2: Check for bucket enumeration
fields @timestamp, eventName, sourceIPAddress, userIdentity.userName
| filter eventName = "ListBuckets"
| filter @timestamp > date_sub(now(), interval 2 hour)
| stats count() by sourceIPAddress, userIdentity.userName
| sort count desc

-- Step 3: Analyze access patterns timing
fields @timestamp, eventName, requestParameters.bucketName, requestParameters.key
| filter eventName = "GetObject"
| filter requestParameters.bucketName = "SENSITIVE_BUCKET"
| bin(@timestamp, 1m) as time_bucket
| stats count() by time_bucket
| sort time_bucket asc

-- Step 4: Check for data staging/compression
fields @timestamp, eventName, sourceIPAddress, userIdentity.userName, requestParameters
| filter eventName = "PutObject"
| filter requestParameters.key like /\.zip|\.tar|\.gz|backup/
| sort @timestamp desc
```

---

## Detection Rule Development

### CloudWatch Alarms
```bash
# Failed login alarm
aws cloudwatch put-metric-alarm \
  --alarm-name "Multiple-Failed-Logins" \
  --alarm-description "Alert on multiple failed console logins" \
  --metric-name "ConsoleLoginFailures" \
  --namespace "AWS/CloudTrail" \
  --statistic "Sum" \
  --period 300 \
  --threshold 5 \
  --comparison-operator "GreaterThanThreshold" \
  --evaluation-periods 1

# Root account usage alarm
aws cloudwatch put-metric-alarm \
  --alarm-name "Root-Account-Usage" \
  --alarm-description "Alert on root account API usage" \
  --metric-name "RootAccountUsage" \
  --namespace "AWS/CloudTrail" \
  --statistic "Sum" \
  --period 60 \
  --threshold 1 \
  --comparison-operator "GreaterThanOrEqualToThreshold" \
  --evaluation-periods 1

# Security group modification alarm
aws cloudwatch put-metric-alarm \
  --alarm-name "Security-Group-Changes" \
  --alarm-description "Alert on security group modifications" \
  --metric-name "SecurityGroupChanges" \
  --namespace "AWS/CloudTrail" \
  --statistic "Sum" \
  --period 300 \
  --threshold 1 \
  --comparison-operator "GreaterThanOrEqualToThreshold" \
  --evaluation-periods 1
```

### Custom Metric Filters
```bash
# Create metric filter for security group changes
aws logs put-metric-filter \
  --log-group-name CloudTrail/logs \
  --filter-name "SecurityGroupChanges" \
  --filter-pattern '{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) }' \
  --metric-transformations \
    metricName=SecurityGroupChanges,metricNamespace=AWS/CloudTrail,metricValue=1

# Create metric filter for privilege escalation
aws logs put-metric-filter \
  --log-group-name CloudTrail/logs \
  --filter-name "PrivilegeEscalation" \
  --filter-pattern '{ ($.eventName = AttachUserPolicy) || ($.eventName = AttachRolePolicy) || ($.eventName = CreateRole) || ($.eventName = PutUserPolicy) || ($.eventName = PutRolePolicy) }' \
  --metric-transformations \
    metricName=PrivilegeEscalation,metricNamespace=AWS/CloudTrail,metricValue=1
```

### EventBridge Rules for Real-time Detection
```bash
# EventBridge rule for suspicious API activity
aws events put-rule \
  --name "SuspiciousAPIActivity" \
  --description "Detect suspicious API calls" \
  --event-pattern '{
    "source": ["aws.iam"],
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {
      "eventName": ["AttachUserPolicy", "CreateUser", "CreateRole"],
      "errorCode": { "exists": false },
      "sourceIPAddress": [{ "anything-but": { "prefix": "10." } }]
    }
  }'

# Target for SNS notification
aws events put-targets \
  --rule "SuspiciousAPIActivity" \
  --targets "Id"="1","Arn"="arn:aws:sns:us-east-1:123456789012:security-alerts"

# EventBridge rule for off-hours activity
aws events put-rule \
  --name "OffHoursActivity" \
  --description "Detect activity during off hours" \
  --schedule-expression "cron(0 22-6 * * ? *)" \
  --event-pattern '{
    "source": ["aws.ec2", "aws.s3"],
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {
      "eventName": ["RunInstances", "GetObject", "PutObject"]
    }
  }'
```

---

## Performance Optimization & Best Practices

### Query Optimization Techniques
```sql
-- Use time filters early in queries
fields @timestamp, eventName, sourceIPAddress
| filter @timestamp > date_sub(now(), interval 1 hour)  -- Filter first
| filter eventName = "ConsoleLogin"
| stats count() by sourceIPAddress

-- Limit result sets for performance
fields @timestamp, eventName, userIdentity.userName
| filter eventName like /Describe/
| stats count() by userIdentity.userName
| sort count desc
| limit 20  -- Always limit large result sets

-- Use specific field selections
fields @timestamp, eventName, sourceIPAddress  -- Only select needed fields
| filter @timestamp > date_sub(now(), interval 24 hour)
| filter eventName = "RunInstances"

-- Optimize VPC Flow Logs queries
fields @timestamp, srcaddr, dstaddr, action
| filter action = "ACCEPT"  -- Filter early
| filter @timestamp > date_sub(now(), interval 1 hour)
| stats sum(bytes) by srcaddr, dstaddr
| sort sum(bytes) desc
| limit 50
```

### Cost Management
```bash
# Monitor CloudWatch Logs usage
aws logs describe-log-groups \
  --query 'logGroups[?storedBytes>`10737418240`].[logGroupName,storedBytes]' \
  --output table

# Set log retention policies
aws logs put-retention-policy \
  --log-group-name CloudTrail/logs \
  --retention-in-days 90

# Estimate query costs
aws logs estimate-query-costs \
  --log-group-name VPCFlowLogs \
  --start-time $(date -d "24 hours ago" +%s) \
  --end-time $(date +%s) \
  --query-string 'fields @timestamp, srcaddr, dstaddr | limit 10000'

# Use S3 for long-term storage
aws s3 cp s3://cloudtrail-bucket/exported-logs/ ./local-analysis/ --recursive
```

### Automated Analysis Scripts
```python
#!/usr/bin/env python3
# AWS Threat Hunting Automation Script
import boto3
import json
from datetime import datetime, timedelta

def hunt_failed_logins(hours_back=24):
    """Hunt for failed login attempts"""
    client = boto3.client('logs')
    
    start_time = int((datetime.now() - timedelta(hours=hours_back)).timestamp() * 1000)
    end_time = int(datetime.now().timestamp() * 1000)
    
    query = '''
    fields @timestamp, sourceIPAddress, userIdentity.userName, errorCode
    | filter eventName = "ConsoleLogin"
    | filter errorCode exists
    | stats count() as failures by sourceIPAddress, userIdentity.userName
    | sort failures desc
    '''
    
    response = client.start_query(
        logGroupName='CloudTrail/logs',
        startTime=start_time,
        endTime=end_time,
        queryString=query
    )
    
    return response['queryId']

def hunt_privilege_escalation(hours_back=6):
    """Hunt for privilege escalation activities"""
    client = boto3.client('logs')
    
    start_time = int((datetime.now() - timedelta(hours=hours_back)).timestamp() * 1000)
    end_time = int(datetime.now().timestamp() * 1000)
    
    query = '''
    fields @timestamp, eventName, userIdentity.userName, sourceIPAddress, requestParameters
    | filter eventName in ["AttachUserPolicy", "AttachRolePolicy", "CreateRole", "PutUserPolicy"]
    | filter requestParameters.policyArn like /Administrator/ or requestParameters.policyDocument like /\*/
    | sort @timestamp desc
    '''
    
    response = client.start_query(
        logGroupName='CloudTrail/logs',
        startTime=start_time,
        endTime=end_time,
        queryString=query
    )
    
    return response['queryId']

def get_query_results(query_id):
    """Get results from CloudWatch Logs Insights query"""
    client = boto3.client('logs')
    
    response = client.get_query_results(queryId=query_id)
    
    while response['status'] == 'Running':
        time.sleep(2)
        response = client.get_query_results(queryId=query_id)
    
    return response['results']

# Usage example
if __name__ == "__main__":
    # Hunt for failed logins
    login_query_id = hunt_failed_logins(24)
    print(f"Started failed login hunt: {login_query_id}")
    
    # Hunt for privilege escalation
    privesc_query_id = hunt_privilege_escalation(6)
    print(f"Started privilege escalation hunt: {privesc_query_id}")
    
    # Get results (add proper error handling in production)
    import time
    time.sleep(10)  # Wait for queries to complete
    
    login_results = get_query_results(login_query_id)
    privesc_results = get_query_results(privesc_query_id)
    
    print("Failed Login Results:", json.dumps(login_results, indent=2))
    print("Privilege Escalation Results:", json.dumps(privesc_results, indent=2))
```

---

## Output Interpretation & Red Flags

### CloudTrail Analysis Red Flags
```sql
-- Critical indicators requiring immediate investigation:

-- 1. Root account usage outside of account setup
fields @timestamp, eventName, sourceIPAddress, userAgent
| filter userIdentity.type = "Root"
| filter eventName not in ["GetSessionToken", "GetCallerIdentity"]
| filter @timestamp > date_sub(now(), interval 24 hour)

-- 2. API calls from unusual geographic locations
fields @timestamp, eventName, sourceIPAddress, userIdentity.userName
| filter sourceIPAddress not like /^10\./ and sourceIPAddress not like /^172\./ and sourceIPAddress not like /^192\.168\./
| stats count() as api_calls, count_distinct(eventName) as unique_apis by sourceIPAddress
| filter api_calls > 100 or unique_apis > 20

-- 3. Multiple failed authentications followed by success
fields @timestamp, sourceIPAddress, userIdentity.userName, errorCode
| filter eventName = "ConsoleLogin"
| sort @timestamp asc
| stats list(@timestamp) as timestamps, list(errorCode) as error_codes by sourceIPAddress, userIdentity.userName
| filter len(error_codes) > 5

-- 4. Privilege escalation patterns
fields @timestamp, eventName, userIdentity.userName, requestParameters
| filter eventName in ["AttachUserPolicy", "CreateRole", "AssumeRole"]
| filter requestParameters.policyArn like /Administrator|PowerUser/
| stats count() by userIdentity.userName, eventName
| sort count desc

-- 5. Unusual service enumeration
fields @timestamp, eventName, userIdentity.userName, sourceIPAddress
| filter eventName like /Describe|List|Get/
| filter @timestamp > date_sub(now(), interval 1 hour)
| stats count() as recon_calls, count_distinct(eventName) as unique_apis by userIdentity.userName, sourceIPAddress
| filter recon_calls > 50
```

### VPC Flow Logs Red Flags
```sql
-- Network-based threat indicators:

-- 1. High volume outbound connections
fields srcaddr, dstaddr, bytes, packets
| filter action = "ACCEPT" and dstaddr not like /^10\./
| stats sum(bytes) as total_bytes, count() as connections by srcaddr, dstaddr
| filter total_bytes > 1073741824  -- > 1GB
| sort total_bytes desc

-- 2. Suspicious port usage
fields srcaddr, dstaddr, dstport, protocol
| filter action = "ACCEPT"
| filter dstport in [4444, 5555, 6666, 8080, 9999, 31337, 54321]  -- Common backdoor ports
| stats count() by srcaddr, dstport

-- 3. Internal scanning activity
fields srcaddr, dstaddr, dstport
| filter action = "REJECT"
| filter srcaddr like /^10\./ or srcaddr like /^172\./ or srcaddr like /^192\.168\./
| stats count() as rejected_connections, count_distinct(dstport) as unique_ports by srcaddr, dstaddr
| filter rejected_connections > 20 or unique_ports > 10

-- 4. DNS tunneling indicators
fields srcaddr, dstaddr, srcport, dstport, bytes
| filter dstport = 53 and action = "ACCEPT"
| stats avg(bytes) as avg_query_size, max(bytes) as max_query_size by srcaddr, dstaddr
| filter avg_query_size > 100 or max_query_size > 500

-- 5. Beaconing behavior
fields @timestamp, srcaddr, dstaddr, dstport
| filter action = "ACCEPT" and dstaddr not like /^10\./
| bin(@timestamp, 5m) as time_bucket
| stats count() by time_bucket, srcaddr, dstaddr, dstport
| eventstats avg(count) as avg_connections by srcaddr, dstaddr, dstport
| filter count = avg_connections and avg_connections > 1  -- Regular intervals
```

### CloudWatch Logs Red Flags
```sql
-- Application and system log indicators:

-- 1. Error patterns indicating compromise
fields @timestamp, @message
| filter @message like /authentication failed|access denied|unauthorized/
| stats count() by bin(@timestamp, 5m)
| sort @timestamp desc

-- 2. Lambda function anomalies
fields @timestamp, @message
| filter @logGroup like /aws/lambda/
| filter @message like /error|exception|timeout/
| stats count() by @logGroup
| sort count desc

-- 3. Application security events
fields @timestamp, @message, @logStream
| filter @message like /sql injection|xss|command injection|path traversal/
| sort @timestamp desc

-- 4. High privilege operations
fields @timestamp, @message
| filter @message like /sudo|admin|root|privilege/
| stats count() by bin(@timestamp, 1h)
| sort @timestamp desc
```

---

## Integration with Security Tools

### SIEM Integration
```bash
# Export CloudTrail logs to SIEM (Splunk example)
aws logs create-export-task \
  --log-group-name CloudTrail/logs \
  --from $(date -d "1 hour ago" +%s)000 \
  --to $(date +%s)000 \
  --destination s3://siem-export-bucket \
  --destination-prefix cloudtrail-export/

# Stream logs to external SIEM via Kinesis
aws logs put-subscription-filter \
  --log-group-name CloudTrail/logs \
  --filter-name "SIEMStream" \
  --filter-pattern "" \
  --destination-arn arn:aws:kinesis:us-east-1:123456789012:stream/siem-stream

# ElasticSearch integration
aws logs put-subscription-filter \
  --log-group-name VPCFlowLogs \
  --filter-name "ESStream" \
  --filter-pattern "[version, account_id, interface_id, srcaddr, dstaddr, srcport, dstport, protocol, packets, bytes, windowstart, windowend, action, flowlogstatus]" \
  --destination-arn arn:aws:es:us-east-1:123456789012:domain/security-logs/*
```

### Threat Intelligence Integration
```python
#!/usr/bin/env python3
# Threat Intelligence Integration Script
import boto3
import requests
import json

def check_ip_reputation(ip_address):
    """Check IP reputation using threat intel feeds"""
    # Example using VirusTotal API
    vt_api_key = "YOUR_VT_API_KEY"
    url = f"https://www.virustotal.com/vtapi/v2/ip-address/report"
    params = {'apikey': vt_api_key, 'ip': ip_address}
    
    response = requests.get(url, params=params)
    return response.json()

def enrich_cloudtrail_events():
    """Enrich CloudTrail events with threat intelligence"""
    logs_client = boto3.client('logs')
    
    # Get recent external IP connections
    query = '''
    fields @timestamp, sourceIPAddress, eventName, userIdentity.userName
    | filter sourceIPAddress not like /^10\./ and sourceIPAddress not like /^172\./ and sourceIPAddress not like /^192\.168\./
    | filter @timestamp > date_sub(now(), interval 1 hour)
    | stats count() by sourceIPAddress
    | sort count desc
    | limit 20
    '''
    
    start_time = int((datetime.now() - timedelta(hours=1)).timestamp() * 1000)
    end_time = int(datetime.now().timestamp() * 1000)
    
    response = logs_client.start_query(
        logGroupName='CloudTrail/logs',
        startTime=start_time,
        endTime=end_time,
        queryString=query
    )
    
    # Wait for query completion and get results
    query_id = response['queryId']
    time.sleep(10)
    
    results = logs_client.get_query_results(queryId=query_id)
    
    # Enrich with threat intelligence
    enriched_results = []
    for result in results['results']:
        ip = result[0]['value']  # sourceIPAddress
        count = result[1]['value']  # count
        
        reputation = check_ip_reputation(ip)
        
        enriched_results.append({
            'ip': ip,
            'activity_count': count,
            'reputation': reputation.get('response_code', 0),
            'malicious_detections': reputation.get('positives', 0)
        })
    
    return enriched_results

# Store enriched data for analysis
def store_threat_intel(enriched_data):
    """Store enriched threat intelligence data"""
    s3_client = boto3.client('s3')
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"threat_intel_{timestamp}.json"
    
    s3_client.put_object(
        Bucket='threat-intel-bucket',
        Key=filename,
        Body=json.dumps(enriched_data, indent=2)
    )
```

### SOAR Integration
```python
#!/usr/bin/env python3
# SOAR Integration for Automated Response
import boto3
import json

def isolate_compromised_instance(instance_id):
    """Isolate EC2 instance by applying restrictive security group"""
    ec2_client = boto3.client('ec2')
    
    # Create isolation security group if it doesn't exist
    try:
        isolation_sg = ec2_client.create_security_group(
            GroupName='isolation-sg',
            Description='Security group for isolating compromised instances'
        )
        sg_id = isolation_sg['GroupId']
    except:
        # Security group already exists
        response = ec2_client.describe_security_groups(
            Filters=[{'Name': 'group-name', 'Values': ['isolation-sg']}]
        )
        sg_id = response['SecurityGroups'][0]['GroupId']
    
    # Apply isolation security group
    ec2_client.modify_instance_attribute(
        InstanceId=instance_id,
        Groups=[sg_id]
    )
    
    return f"Instance {instance_id} isolated with security group {sg_id}"

def disable_compromised_user(username):
    """Disable IAM user and revoke active sessions"""
    iam_client = boto3.client('iam')
    
    # Attach deny-all policy
    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*"
            }
        ]
    }
    
    iam_client.put_user_policy(
        UserName=username,
        PolicyName='EmergencyDenyAll',
        PolicyDocument=json.dumps(deny_policy)
    )
    
    # Delete access keys
    response = iam_client.list_access_keys(UserName=username)
    for key in response['AccessKeyMetadata']:
        iam_client.delete_access_key(
            UserName=username,
            AccessKeyId=key['AccessKeyId']
        )
    
    return f"User {username} disabled and access keys revoked"

def create_forensic_snapshot(instance_id):
    """Create forensic snapshot of compromised instance"""
    ec2_client = boto3.client('ec2')
    
    # Get instance details
    response = ec2_client.describe_instances(InstanceIds=[instance_id])
    instance = response['Reservations'][0]['Instances'][0]
    
    # Create snapshots of all attached volumes
    snapshots = []
    for bdm in instance['BlockDeviceMappings']:
        volume_id = bdm['Ebs']['VolumeId']
        
        snapshot = ec2_client.create_snapshot(
            VolumeId=volume_id,
            Description=f'Forensic snapshot of {volume_id} from instance {instance_id}'
        )
        snapshots.append(snapshot['SnapshotId'])
    
    return f"Created forensic snapshots: {snapshots}"

# Example automated response workflow
def automated_incident_response(alert_data):
    """Automated incident response based on alert data"""
    alert_type = alert_data.get('alert_type')
    severity = alert_data.get('severity')
    
    response_actions = []
    
    if alert_type == 'compromised_instance' and severity == 'high':
        instance_id = alert_data.get('instance_id')
        
        # Create forensic snapshot
        snapshot_result = create_forensic_snapshot(instance_id)
        response_actions.append(snapshot_result)
        
        # Isolate instance
        isolation_result = isolate_compromised_instance(instance_id)
        response_actions.append(isolation_result)
    
    elif alert_type == 'compromised_user' and severity in ['high', 'critical']:
        username = alert_data.get('username')
        
        # Disable user
        disable_result = disable_compromised_user(username)
        response_actions.append(disable_result)
    
    return response_actions
```

---

## Common Pitfalls & Troubleshooting

### CloudWatch Logs Insights Limitations
```sql
-- Avoid these common mistakes:

-- 1. DON'T use overly broad time ranges without filters
-- BAD: fields @timestamp, eventName | filter eventName = "ConsoleLogin"
-- GOOD: fields @timestamp, eventName | filter @timestamp > date_sub(now(), interval 1 hour) | filter eventName = "ConsoleLogin"

-- 2. DON'T forget to limit large result sets
-- BAD: fields * | filter eventName like /Describe/
-- GOOD: fields @timestamp, eventName, userIdentity.userName | filter eventName like /Describe/ | limit 100

-- 3. DON'T use inefficient regex patterns
-- BAD: fields @message | filter @message =~ /.*error.*/
-- GOOD: fields @message | filter @message like /error/

-- 4. DO use specific field selections
-- BAD: fields *
-- GOOD: fields @timestamp, eventName, sourceIPAddress, userIdentity.userName
```

### Data Quality Issues
```bash
# Handle missing or incomplete logs
aws logs describe-log-streams \
  --log-group-name CloudTrail/logs \
  --order-by LastEventTime \
  --descending \
  --max-items 10

# Check for log ingestion delays
aws cloudtrail get-trail-status --name <trail-name>

# Verify S3 bucket permissions
aws s3api get-bucket-policy --bucket cloudtrail-bucket-name

# Test CloudTrail configuration
aws cloudtrail validate-log-integrity \
  --trail-arn arn:aws:cloudtrail:us-east-1:123456789012:trail/management-events \
  --start-time 2024-01-01T00:00:00Z \
  --end-time 2024-01-02T00:00:00Z
```

### Performance Optimization
```sql
-- Optimize query performance:

-- 1. Use time-based partitioning
fields @timestamp, eventName
| filter @timestamp >= date_sub(now(), interval 1 hour)  -- Always filter time first
| filter eventName = "RunInstances"

-- 2. Leverage field indexing
fields eventName, sourceIPAddress  -- Select only needed fields
| filter eventName in ["ConsoleLogin", "AssumeRole", "RunInstances"]  -- Use IN for multiple values
| stats count() by sourceIPAddress

-- 3. Use sampling for large datasets
fields @timestamp, eventName
| filter @timestamp > date_sub(now(), interval 24 hour)
| limit 10000  -- Sample large datasets
| stats count() by eventName

-- 4. Optimize VPC Flow Logs queries
fields srcaddr, dstaddr, action, bytes
| filter action = "ACCEPT"  -- Filter early
| filter bytes > 1000000  -- Filter on numeric fields efficiently
| stats sum(bytes) by srcaddr
```

---

## Quick Reference Commands

### Most Critical Queries for Cloud Threat Hunting
```bash
# The "Essential 10" - Run these for any cloud investigation

# 1. Recent authentication failures
aws logs start-query \
  --log-group-name CloudTrail/logs \
  --start-time $(date -d "1 hour ago" +%s) \
  --end-time $(date +%s) \
  --query-string 'fields @timestamp, sourceIPAddress, userIdentity.userName, errorCode | filter eventName = "ConsoleLogin" | filter errorCode exists | stats count() by sourceIPAddress'

# 2. Root account usage
aws logs start-query \
  --log-group-name CloudTrail/logs \
  --start-time $(date -d "24 hours ago" +%s) \
  --end-time $(date +%s) \
  --query-string 'fields @timestamp, eventName, sourceIPAddress | filter userIdentity.type = "Root" | filter eventName != "HeadObject"'

# 3. Privilege escalation activities
aws logs start-query \
  --log-group-name CloudTrail/logs \
  --start-time $(date -d "6 hours ago" +%s) \
  --end-time $(date +%s) \
  --query-string 'fields @timestamp, eventName, userIdentity.userName, requestParameters | filter eventName in ["AttachUserPolicy", "CreateRole", "AssumeRole"]'

# 4. Security group modifications
aws logs start-query \
  --log-group-name CloudTrail/logs \
  --start-time $(date -d "24 hours ago" +%s) \
  --end-time $(date +%s) \
  --query-string 'fields @timestamp, eventName, userIdentity.userName, requestParameters | filter eventName like /SecurityGroup/'

# 5. Unusual API activity
aws logs start-query \
  --log-group-name CloudTrail/logs \
  --start-time $(date -d "2 hours ago" +%s) \
  --end-time $(date +%s) \
  --query-string 'fields eventName, userIdentity.userName, sourceIPAddress | stats count() by eventName | sort count asc | limit 10'

# 6. VPC Flow Logs - External connections
aws logs start-query \
  --log-group-name VPCFlowLogs \
  --start-time $(date -d "1 hour ago" +%s) \
  --end-time $(date +%s) \
  --query-string 'fields srcaddr, dstaddr, dstport, action | filter action = "ACCEPT" | filter dstaddr not like /^10\./ | stats count() by dstaddr, dstport | sort count desc'

# 7. High volume data transfers
aws logs start-query \
  --log-group-name VPCFlowLogs \
  --start-time $(date -d "6 hours ago" +%s) \
  --end-time $(date +%s) \
  --query-string 'fields srcaddr, dstaddr, bytes | filter action = "ACCEPT" | stats sum(bytes) as total_bytes by srcaddr, dstaddr | filter total_bytes > 1073741824 | sort total_bytes desc'

# 8. S3 access anomalies
aws logs start-query \
  --log-group-name CloudTrail/logs \
  --start-time $(date -d "24 hours ago" +%s) \
  --end-time $(date +%s) \
  --query-string 'fields @timestamp, eventName, sourceIPAddress, requestParameters.bucketName | filter eventName = "GetObject" | stats count() by sourceIPAddress, requestParameters.bucketName | filter count > 100'

# 9. New resource creation
aws logs start-query \
  --log-group-name CloudTrail/logs \
  --start-time $(date -d "6 hours ago" +%s) \
  --end-time $(date +%s) \
  --query-string 'fields @timestamp, eventName, userIdentity.userName, awsRegion | filter eventName in ["RunInstances", "CreateUser", "CreateRole", "CreateBucket"]'

# 10. Cross-region activity
aws logs start-query \
  --log-group-name CloudTrail/logs \
  --start-time $(date -d "24 hours ago" +%s) \
  --end-time $(date +%s) \
  --query-string 'fields userIdentity.userName, awsRegion, sourceIPAddress | stats count() by userIdentity.userName, awsRegion | stats count_distinct(awsRegion) as regions by userIdentity.userName | filter regions > 2'
```

### Emergency Response Queries
```bash
# Rapid IOC sweep across all AWS logs
MALICIOUS_IP="1.2.3.4"
aws logs start-query \
  --log-group-name CloudTrail/logs \
  --start-time $(date -d "24 hours ago" +%s) \
  --end-time $(date +%s) \
  --query-string "fields @timestamp, eventName, userIdentity.userName | filter sourceIPAddress = \"$MALICIOUS_IP\""

# Compromise assessment for specific user
COMPROMISED_USER="suspicious-user"
aws logs start-query \
  --log-group-name CloudTrail/logs \
  --start-time $(date -d "7 days ago" +%s) \
  --end-time $(date +%s) \
  --query-string "fields @timestamp, eventName, sourceIPAddress, requestParameters | filter userIdentity.userName = \"$COMPROMISED_USER\" | sort @timestamp asc"

# Network activity for compromised instance
INSTANCE_IP="10.0.1.100"
aws logs start-query \
  --log-group-name VPCFlowLogs \
  --start-time $(date -d "24 hours ago" +%s) \
  --end-time $(date +%s) \
  --query-string "fields @timestamp, srcaddr, dstaddr, dstport, action, bytes | filter srcaddr = \"$INSTANCE_IP\" or dstaddr = \"$INSTANCE_IP\" | sort @timestamp asc"

# Rapid privilege escalation check
aws logs start-query \
  --log-group-name CloudTrail/logs \
  --start-time $(date -d "2 hours ago" +%s) \
  --end-time $(date +%s) \
  --query-string 'fields @timestamp, eventName, userIdentity.userName, requestParameters | filter eventName in ["AttachUserPolicy", "CreateRole", "AssumeRole", "PutUserPolicy"] | sort @timestamp desc'
```

---

## Additional Resources & Training

### Essential AWS Documentation
- **CloudTrail User Guide**: https://docs.aws.amazon.com/cloudtrail/latest/userguide/
- **VPC Flow Logs Guide**: https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html
- **CloudWatch Logs Insights**: https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/AnalyzingLogData.html

### Security Best Practices
- **AWS Security Best Practices**: https://aws.amazon.com/architecture/security-identity-compliance/
- **AWS Well-Architected Security Pillar**: https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/
- **AWS Security Incident Response**: https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/

### Community Resources
- **AWS Security Blog**: https://aws.amazon.com/blogs/security/
- **AWS Security Workshops**: https://awssecworkshops.com/
- **Cloud Security Alliance**: https://cloudsecurityalliance.org/

### Certification Paths
- **AWS Certified Security - Specialty**: Advanced cloud security knowledge
- **AWS Certified Solutions Architect**: Foundation for cloud architecture understanding
- **SANS FOR509**: Enterprise Cloud Forensics and Incident Response

### Advanced Training Resources
- **SANS FOR509**: Enterprise Cloud Forensics and Incident Response
- **SANS SEC540**: Cloud Security and DevOps Automation
- **AWS re:Inforce**: Annual security conference with hands-on workshops
- **Cloud Security Alliance Training**: Industry-standard cloud security education

---

## Troubleshooting Guide

### CloudTrail Issues
```bash
# Check CloudTrail service status
aws cloudtrail get-trail-status --name <trail-name>

# Verify trail configuration
aws cloudtrail describe-trails --trail-name-list <trail-name>

# Test log file integrity
aws cloudtrail validate-log-integrity \
  --trail-arn <trail-arn> \
  --start-time 2024-01-01T00:00:00Z \
  --end-time 2024-01-02T00:00:00Z

# Check S3 bucket permissions
aws s3api get-bucket-policy --bucket <cloudtrail-bucket>
aws s3api get-bucket-acl --bucket <cloudtrail-bucket>

# Verify KMS key permissions (if encrypted)
aws kms describe-key --key-id <kms-key-id>
aws kms get-key-policy --key-id <kms-key-id> --policy-name default
```

### CloudWatch Logs Issues
```bash
# Check log group retention and size
aws logs describe-log-groups --log-group-name-prefix CloudTrail

# Verify log stream activity
aws logs describe-log-streams \
  --log-group-name CloudTrail/logs \
  --order-by LastEventTime \
  --descending

# Test log delivery
aws logs put-log-events \
  --log-group-name test-group \
  --log-stream-name test-stream \
  --log-events timestamp=$(date +%s)000,message="Test message"

# Check subscription filters
aws logs describe-subscription-filters --log-group-name CloudTrail/logs
```

### VPC Flow Logs Issues
```bash
# Check Flow Logs status
aws ec2 describe-flow-logs

# Verify IAM role permissions
aws iam get-role --role-name flowlogsRole
aws iam list-attached-role-policies --role-name flowlogsRole

# Test Flow Logs delivery
aws logs describe-log-groups --log-group-name-prefix VPC

# Check for delivery errors
aws logs filter-log-events \
  --log-group-name VPCFlowLogs \
  --filter-pattern "ERROR"
```

### Query Performance Issues
```sql
-- Troubleshoot slow queries:

-- 1. Check query execution time
fields @timestamp, @message
| filter @timestamp > date_sub(now(), interval 15 minute)
| limit 100  -- Start with small limits

-- 2. Verify field existence before filtering
fields @timestamp, eventName
| filter ispresent(eventName)
| filter eventName = "ConsoleLogin"

-- 3. Use efficient time ranges
fields @timestamp, eventName
| filter @timestamp >= date_sub(now(), interval 1 hour)  -- Use >= instead of >
| filter @timestamp < now()

-- 4. Optimize field selection
fields @timestamp, eventName, sourceIPAddress  -- Only select needed fields
| filter eventName in ["ConsoleLogin", "AssumeRole"]
| stats count() by sourceIPAddress
```

---

## Advanced Automation Scripts

### Multi-Account Threat Hunting
```python
#!/usr/bin/env python3
# Multi-Account AWS Threat Hunting Script
import boto3
import json
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor

class AWSMultiAccountHunter:
    def __init__(self, role_name='ThreatHuntingRole'):
        self.role_name = role_name
        self.results = {}
    
    def assume_role(self, account_id, region='us-east-1'):
        """Assume role in target account"""
        sts_client = boto3.client('sts')
        
        role_arn = f"arn:aws:iam::{account_id}:role/{self.role_name}"
        
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName=f'ThreatHunt-{account_id}'
        )
        
        credentials = response['Credentials']
        
        return boto3.client(
            'logs',
            region_name=region,
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )
    
    def hunt_failed_logins(self, account_id, hours_back=24):
        """Hunt for failed logins in specific account"""
        try:
            logs_client = self.assume_role(account_id)
            
            start_time = int((datetime.now() - timedelta(hours=hours_back)).timestamp() * 1000)
            end_time = int(datetime.now().timestamp() * 1000)
            
            query = '''
            fields @timestamp, sourceIPAddress, userIdentity.userName, errorCode
            | filter eventName = "ConsoleLogin"
            | filter errorCode exists
            | stats count() as failures by sourceIPAddress, userIdentity.userName
            | filter failures > 5
            | sort failures desc
            '''
            
            response = logs_client.start_query(
                logGroupName='CloudTrail/logs',
                startTime=start_time,
                endTime=end_time,
                queryString=query
            )
            
            return {
                'account_id': account_id,
                'query_id': response['queryId'],
                'hunt_type': 'failed_logins'
            }
            
        except Exception as e:
            return {
                'account_id': account_id,
                'error': str(e),
                'hunt_type': 'failed_logins'
            }
    
    def hunt_privilege_escalation(self, account_id, hours_back=6):
        """Hunt for privilege escalation in specific account"""
        try:
            logs_client = self.assume_role(account_id)
            
            start_time = int((datetime.now() - timedelta(hours=hours_back)).timestamp() * 1000)
            end_time = int(datetime.now().timestamp() * 1000)
            
            query = '''
            fields @timestamp, eventName, userIdentity.userName, sourceIPAddress, requestParameters
            | filter eventName in ["AttachUserPolicy", "AttachRolePolicy", "CreateRole", "PutUserPolicy"]
            | filter requestParameters.policyArn like /Administrator/ or requestParameters.policyDocument like /\*/
            | sort @timestamp desc
            '''
            
            response = logs_client.start_query(
                logGroupName='CloudTrail/logs',
                startTime=start_time,
                endTime=end_time,
                queryString=query
            )
            
            return {
                'account_id': account_id,
                'query_id': response['queryId'],
                'hunt_type': 'privilege_escalation'
            }
            
        except Exception as e:
            return {
                'account_id': account_id,
                'error': str(e),
                'hunt_type': 'privilege_escalation'
            }
    
    def hunt_cross_account(self, account_ids, max_workers=5):
        """Execute threat hunting across multiple accounts"""
        results = []
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit failed login hunts
            login_futures = {
                executor.submit(self.hunt_failed_logins, account_id): account_id 
                for account_id in account_ids
            }
            
            # Submit privilege escalation hunts
            privesc_futures = {
                executor.submit(self.hunt_privilege_escalation, account_id): account_id 
                for account_id in account_ids
            }
            
            # Collect results
            for future in login_futures:
                results.append(future.result())
            
            for future in privesc_futures:
                results.append(future.result())
        
        return results
    
    def get_hunt_results(self, query_info):
        """Get results from completed hunt queries"""
        if 'error' in query_info:
            return query_info
        
        try:
            logs_client = self.assume_role(query_info['account_id'])
            
            response = logs_client.get_query_results(
                queryId=query_info['query_id']
            )
            
            return {
                'account_id': query_info['account_id'],
                'hunt_type': query_info['hunt_type'],
                'status': response['status'],
                'results': response.get('results', [])
            }
            
        except Exception as e:
            return {
                'account_id': query_info['account_id'],
                'hunt_type': query_info['hunt_type'],
                'error': str(e)
            }

# Usage example
if __name__ == "__main__":
    # Define target accounts
    account_ids = ['123456789012', '234567890123', '345678901234']
    
    # Initialize hunter
    hunter = AWSMultiAccountHunter()
    
    # Execute hunts across all accounts
    hunt_results = hunter.hunt_cross_account(account_ids)
    
    # Wait for queries to complete
    import time
    time.sleep(30)
    
    # Collect results
    final_results = []
    for hunt_info in hunt_results:
        if 'query_id' in hunt_info:
            result = hunter.get_hunt_results(hunt_info)
            final_results.append(result)
        else:
            final_results.append(hunt_info)
    
    # Output results
    print(json.dumps(final_results, indent=2, default=str))
```

### Real-time Threat Detection
```python
#!/usr/bin/env python3
# Real-time AWS Threat Detection using Lambda
import json
import boto3
import gzip
import base64
from datetime import datetime

def lambda_handler(event, context):
    """
    Lambda function for real-time CloudTrail analysis
    Triggered by CloudWatch Logs subscription filter
    """
    
    # Decode CloudWatch Logs data
    compressed_payload = base64.b64decode(event['awslogs']['data'])
    uncompressed_payload = gzip.decompress(compressed_payload)
    log_data = json.loads(uncompressed_payload)
    
    threat_indicators = []
    
    for log_event in log_data['logEvents']:
        try:
            # Parse CloudTrail event
            ct_event = json.loads(log_event['message'])
            
            # Analyze for threats
            threat_score = analyze_cloudtrail_event(ct_event)
            
            if threat_score > 70:  # High threat threshold
                threat_indicators.append({
                    'timestamp': ct_event.get('eventTime'),
                    'event_name': ct_event.get('eventName'),
                    'user': ct_event.get('userIdentity', {}).get('userName'),
                    'source_ip': ct_event.get('sourceIPAddress'),
                    'threat_score': threat_score,
                    'indicators': get_threat_indicators(ct_event)
                })
        
        except json.JSONDecodeError:
            continue
        except Exception as e:
            print(f"Error processing log event: {e}")
            continue
    
    # Send alerts for high-threat events
    if threat_indicators:
        send_security_alert(threat_indicators)
    
    return {
        'statusCode': 200,
        'body': json.dumps({
            'processed_events': len(log_data['logEvents']),
            'threat_indicators': len(threat_indicators)
        })
    }

def analyze_cloudtrail_event(event):
    """Analyze CloudTrail event for threat indicators"""
    threat_score = 0
    
    event_name = event.get('eventName', '')
    source_ip = event.get('sourceIPAddress', '')
    user_identity = event.get('userIdentity', {})
    error_code = event.get('errorCode')
    
    # Root account usage
    if user_identity.get('type') == 'Root':
        threat_score += 80
    
    # Failed authentication
    if event_name == 'ConsoleLogin' and error_code:
        threat_score += 30
    
    # Privilege escalation actions
    privilege_actions = [
        'AttachUserPolicy', 'AttachRolePolicy', 'CreateRole',
        'PutUserPolicy', 'PutRolePolicy', 'AssumeRole'
    ]
    if event_name in privilege_actions:
        threat_score += 50
    
    # Security control modifications
    security_actions = [
        'AuthorizeSecurityGroupIngress', 'RevokeSecurityGroupIngress',
        'PutBucketPolicy', 'DeleteTrail', 'StopLogging'
    ]
    if event_name in security_actions:
        threat_score += 60
    
    # External IP address (basic check)
    if source_ip and not any(source_ip.startswith(prefix) for prefix in ['10.', '172.', '192.168.']):
        threat_score += 20
    
    # Off-hours activity (simplified)
    event_time = event.get('eventTime', '')
    if event_time:
        try:
            dt = datetime.fromisoformat(event_time.replace('Z', '+00:00'))
            hour = dt.hour
            if hour < 6 or hour > 22:  # Off hours
                threat_score += 15
        except:
            pass
    
    # Unusual user agent
    user_agent = event.get('userAgent', '')
    suspicious_agents = ['curl', 'wget', 'python', 'boto3']
    if any(agent in user_agent.lower() for agent in suspicious_agents):
        threat_score += 25
    
    return min(threat_score, 100)  # Cap at 100

def get_threat_indicators(event):
    """Extract specific threat indicators from event"""
    indicators = []
    
    # Check for specific indicators
    if event.get('userIdentity', {}).get('type') == 'Root':
        indicators.append('ROOT_ACCOUNT_USAGE')
    
    if event.get('errorCode'):
        indicators.append('AUTHENTICATION_FAILURE')
    
    event_name = event.get('eventName', '')
    if event_name in ['AttachUserPolicy', 'CreateRole']:
        indicators.append('PRIVILEGE_ESCALATION')
    
    if event_name in ['AuthorizeSecurityGroupIngress']:
        request_params = event.get('requestParameters', {})
        ip_permissions = request_params.get('ipPermissions', [])
        for permission in ip_permissions:
            ip_ranges = permission.get('ipRanges', [])
            for ip_range in ip_ranges:
                if ip_range.get('cidrIp') == '0.0.0.0/0':
                    indicators.append('SECURITY_GROUP_OPEN_ACCESS')
    
    source_ip = event.get('sourceIPAddress', '')
    if source_ip and not any(source_ip.startswith(prefix) for prefix in ['10.', '172.', '192.168.']):
        indicators.append('EXTERNAL_IP_ACCESS')
    
    return indicators

def send_security_alert(threat_indicators):
    """Send security alert via SNS"""
    sns_client = boto3.client('sns')
    
    alert_message = {
        'alert_type': 'AWS_THREAT_DETECTION',
        'timestamp': datetime.utcnow().isoformat(),
        'threat_count': len(threat_indicators),
        'threats': threat_indicators
    }
    
    try:
        sns_client.publish(
            TopicArn='arn:aws:sns:us-east-1:123456789012:security-alerts',
            Message=json.dumps(alert_message, indent=2),
            Subject=f'AWS Threat Detection Alert - {len(threat_indicators)} threats detected'
        )
    except Exception as e:
        print(f"Error sending SNS alert: {e}")

# Example CloudFormation template for deployment
cloudformation_template = """
AWSTemplateFormatVersion: '2010-09-09'
Description: Real-time AWS threat detection system

Resources:
  ThreatDetectionFunction:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: aws-threat-detection
      Runtime: python3.9
      Handler: index.lambda_handler
      Code:
        ZipFile: |
          # Lambda function code here
      Role: !GetAtt ThreatDetectionRole.Arn
      Timeout: 300
      
  ThreatDetectionRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
      Policies:
        - PolicyName: SNSPublishPolicy
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action: sns:Publish
                Resource: !Ref SecurityAlertsTopicArn
                
  CloudTrailLogSubscription:
    Type: AWS::Logs::SubscriptionFilter
    Properties:
      LogGroupName: CloudTrail/logs
      FilterPattern: ''
      DestinationArn: !GetAtt ThreatDetectionFunction.Arn
      
  SecurityAlertsTopic:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: security-alerts
      DisplayName: AWS Security Alerts

Parameters:
  SecurityAlertsTopicArn:
    Type: String
    Description: ARN of SNS topic for security alerts
"""
```

---

*This cheatsheet is designed for authorized cloud security monitoring and incident response activities. Always ensure compliance with organizational policies, AWS Terms of Service, and legal requirements.*

**Last Updated**: August 2025 | **Version**: 2.3
**Tested Environment**: AWS CLI v2.x, CloudWatch Logs Insights, Boto3 v1.26+ 

