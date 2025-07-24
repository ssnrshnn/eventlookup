# Windows Event ID Investigation Guide

## Events with Investigation Playbooks

This directory contains detailed information about Windows Event IDs that have comprehensive investigation playbooks available in the main dashboard.

## Available Events (15 total)

### Critical Events
- [4904 - Security Event Log Was Cleared](4904.md) - An attempt was made to read the security event log. Critical for detecting log t...
- [4782 - Password Hash Accessed](4782.md) - The password hash for an account was accessed. Critical for detecting credential...

### High Priority Events
- [4625 - Failed Logon](4625.md) - An account failed to log on. This is a critical event for detecting brute force ...
- [1102 - Audit Log Cleared](1102.md) - The audit log was cleared. Critical indicator of evidence destruction....
- [4697 - Service Installed](4697.md) - A service was installed on the system. Critical for detecting malware persistenc...

### Medium Priority Events
- [4624 - Successful Logon](4624.md) - An account was successfully logged on. This event is generated when a logon sess...
- [4688 - Process Created](4688.md) - A new process has been created. Critical for monitoring process execution....
- [4672 - Special Privileges Assigned](4672.md) - Special privileges were assigned to a new logon. Important for privilege escalat...
- [4720 - User Account Created](4720.md) - A user account was created. Important for monitoring unauthorized account creati...
- [4740 - User Account Locked Out](4740.md) - A user account was locked out due to multiple failed logon attempts....
- [4648 - Logon Using Explicit Credentials](4648.md) - A logon was attempted using explicit credentials. Often indicates RunAs or crede...
- [4663 - Attempt to Access Object](4663.md) - An attempt was made to access an object. Critical for monitoring unauthorized ac...
- [4768 - Kerberos TGT Requested](4768.md) - A Kerberos authentication ticket (TGT) was requested. Initial domain authenticat...
- [4776 - NTLM Authentication](4776.md) - Computer attempted to validate credentials for an account using NTLM....

### Low Priority Events
- [4769 - Kerberos Service Ticket Requested](4769.md) - A Kerberos service ticket was requested. Service access authentication....


## Statistics
- **Total Events with Playbooks:** 15
- **Critical Events:** 2
- **High Priority Events:** 3
- **Medium Priority Events:** 9
- **Low Priority Events:** 1

## Coverage by Category
- **Account Management:** 3 events
- **Authentication:** 6 events
- **File & Registry:** 1 events
- **Log Management:** 2 events
- **Privilege Management:** 1 events
- **Process:** 2 events


## Investigation Capabilities
Each event includes:
- ✅ **Professional Investigation Playbooks** - Step-by-step procedures
- ✅ **SIEM Integration** - Ready-to-use Splunk/ELK queries
- ✅ **PowerShell Automation** - Investigation scripts
- ✅ **MITRE ATT&CK Mapping** - Tactic and technique alignment
- ✅ **Tool Recommendations** - Specific tools for each step

## Access the Interactive Dashboard
🌐 **[Launch Event ID Dashboard](../index.html)** for full interactive investigation capabilities.

---
*Generated on 2025-07-24 19:56:32 | Coverage: 15 events with comprehensive playbooks*
