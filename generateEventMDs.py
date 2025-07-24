#!/usr/bin/env python3
import os
import re
import json
from datetime import datetime

def get_microsoft_doc_url(event_id):
    """Get the appropriate Microsoft documentation URL for an event ID"""
    try:
        id_num = int(event_id)
    except ValueError:
        return "https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-events"
    
    # Standard Windows Security Events (4xxx series)
    if 4608 <= id_num <= 4999:
        return f"https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-{event_id}"
    
    # System Events (1xxx series)
    if 1000 <= id_num <= 1999:
        if id_num in [1000, 1001]:
            return "https://learn.microsoft.com/en-us/windows/win32/eventlog/event-logging-elements"
        if id_num in [1100, 1101, 1102, 1104]:
            return "https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-events"
        return "https://learn.microsoft.com/en-us/windows/win32/eventlog/system-event-log"
    
    # Sysmon Events (1-50)
    if 1 <= id_num <= 50:
        return "https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#events"
    
    # Service Events (7xxx series)
    if 7000 <= id_num <= 7999:
        return "https://learn.microsoft.com/en-us/windows/win32/services/service-control-manager"
    
    # Network Events (5xxx series)
    if 5000 <= id_num <= 5999:
        return f"https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-{event_id}"
    
    # Boot Events (6xxx series)
    if 6000 <= id_num <= 6999:
        return "https://learn.microsoft.com/en-us/windows/win32/eventlog/eventlog-key"
    
    # Default to general Windows Security Audit Events documentation
    return "https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-events"

def get_mitre_attack_url(tactic_name):
    """Get MITRE ATT&CK URL for a tactic"""
    tactic_mapping = {
        "Initial Access": "https://attack.mitre.org/tactics/TA0001/",
        "Execution": "https://attack.mitre.org/tactics/TA0002/",
        "Persistence": "https://attack.mitre.org/tactics/TA0003/",
        "Privilege Escalation": "https://attack.mitre.org/tactics/TA0004/",
        "Defense Evasion": "https://attack.mitre.org/tactics/TA0005/",
        "Credential Access": "https://attack.mitre.org/tactics/TA0006/",
        "Discovery": "https://attack.mitre.org/tactics/TA0007/",
        "Lateral Movement": "https://attack.mitre.org/tactics/TA0008/",
        "Collection": "https://attack.mitre.org/tactics/TA0009/",
        "Command and Control": "https://attack.mitre.org/tactics/TA0011/",
        "Exfiltration": "https://attack.mitre.org/tactics/TA0010/",
        "Impact": "https://attack.mitre.org/tactics/TA0040/",
    }
    
    return tactic_mapping.get(tactic_name, f"https://attack.mitre.org/search/?q={tactic_name.replace(' ', '%20')}")

def get_events_with_playbooks():
    """Return the list of events that currently have investigation playbooks"""
    events_with_playbooks = [
        {
            "id": "4625",
            "name": "Failed Logon",
            "description": "An account failed to log on. This is a critical event for detecting brute force attacks.",
            "category": "Authentication",
            "criticality": "High",
            "logSource": "Security",
            "investigationTips": [
                "Multiple failures from same source = potential brute force",
                "Check failure reason (wrong password vs account locked)",
                "Monitor for patterns (timing, source IPs)",
                "Investigate successful logons after multiple failures"
            ],
            "relatedEvents": ["4624", "4740", "4771"],
            "mitreTactics": ["Credential Access"],
            "commonCauses": ["Password attacks", "Account enumeration", "Mistyped passwords"],
            "falsePositives": ["User password mistakes", "Cached credential issues"],
            "hasPlaybook": True
        },
        {
            "id": "4624",
            "name": "Successful Logon",
            "description": "An account was successfully logged on. This event is generated when a logon session is created.",
            "category": "Authentication",
            "criticality": "Medium",
            "logSource": "Security",
            "investigationTips": [
                "Monitor for unusual logon times (outside business hours)",
                "Check logon type - Type 10 (RDP) especially critical",
                "Correlate with failed logon attempts",
                "Review source IP addresses for external connections"
            ],
            "relatedEvents": ["4625", "4634", "4647", "4648"],
            "mitreTactics": ["Initial Access", "Lateral Movement"],
            "commonCauses": ["User authentication", "Service account logon", "Scheduled tasks"],
            "falsePositives": ["Normal user activity", "Service account operations"],
            "hasPlaybook": True
        },
        {
            "id": "4688",
            "name": "Process Created",
            "description": "A new process has been created. Critical for monitoring process execution.",
            "category": "Process",
            "criticality": "Medium",
            "logSource": "Security",
            "investigationTips": [
                "Monitor for suspicious process names and paths",
                "Check command line arguments",
                "Review parent-child process relationships",
                "Identify unsigned or unusual executables"
            ],
            "relatedEvents": ["4689", "4656"],
            "mitreTactics": ["Execution", "Defense Evasion"],
            "commonCauses": ["Application launches", "Script execution", "System processes"],
            "falsePositives": ["Normal application operations"],
            "hasPlaybook": True
        },
        {
            "id": "4904",
            "name": "Security Event Log Was Cleared",
            "description": "An attempt was made to read the security event log. Critical for detecting log tampering.",
            "category": "Log Management",
            "criticality": "Critical",
            "logSource": "Security",
            "investigationTips": [
                "Immediately investigate who cleared the logs",
                "Check for concurrent suspicious activities",
                "Review backup logs if available",
                "Look for evidence of attack before log clearing"
            ],
            "relatedEvents": ["1102"],
            "mitreTactics": ["Defense Evasion"],
            "commonCauses": ["Manual log clearing", "Automated log rotation"],
            "falsePositives": ["Legitimate maintenance"],
            "hasPlaybook": True
        },
        {
            "id": "4782",
            "name": "Password Hash Accessed",
            "description": "The password hash for an account was accessed. Critical for detecting credential dumping.",
            "category": "Account Management",
            "criticality": "Critical",
            "logSource": "Security",
            "investigationTips": [
                "Immediately investigate the accessing process",
                "Check for signs of Mimikatz or similar tools",
                "Review concurrent authentication activities",
                "Monitor for lateral movement attempts"
            ],
            "relatedEvents": ["4648", "4624"],
            "mitreTactics": ["Credential Access"],
            "commonCauses": ["Credential dumping tools", "System processes"],
            "falsePositives": ["Legitimate system operations"],
            "hasPlaybook": True
        },
        {
            "id": "4672",
            "name": "Special Privileges Assigned",
            "description": "Special privileges were assigned to a new logon. Important for privilege escalation detection.",
            "category": "Privilege Management",
            "criticality": "Medium",
            "logSource": "Security",
            "investigationTips": [
                "Review which privileges were assigned",
                "Check if user normally has these privileges",
                "Monitor subsequent high-privilege activities",
                "Correlate with other authentication events"
            ],
            "relatedEvents": ["4624", "4648"],
            "mitreTactics": ["Privilege Escalation"],
            "commonCauses": ["Administrative logon", "Service accounts"],
            "falsePositives": ["Normal administrative activity"],
            "hasPlaybook": True
        },
        {
            "id": "1102",
            "name": "Audit Log Cleared",
            "description": "The audit log was cleared. Critical indicator of evidence destruction.",
            "category": "Log Management",
            "criticality": "High",
            "logSource": "System",
            "investigationTips": [
                "Immediately investigate the account that cleared logs",
                "Check system activities before log clearing",
                "Review available backup or forwarded logs",
                "Look for signs of malicious activity"
            ],
            "relatedEvents": ["4904"],
            "mitreTactics": ["Defense Evasion"],
            "commonCauses": ["Manual intervention", "Automated cleanup"],
            "falsePositives": ["Scheduled maintenance"],
            "hasPlaybook": True
        },
        {
            "id": "4720",
            "name": "User Account Created",
            "description": "A user account was created. Important for monitoring unauthorized account creation.",
            "category": "Account Management",
            "criticality": "Medium",
            "logSource": "Security",
            "investigationTips": [
                "Verify authorization for account creation",
                "Check account privileges and group memberships",
                "Monitor initial account activities",
                "Review who created the account"
            ],
            "relatedEvents": ["4722", "4738"],
            "mitreTactics": ["Persistence"],
            "commonCauses": ["HR processes", "Administrative tasks"],
            "falsePositives": ["Normal user provisioning"],
            "hasPlaybook": True
        },
        {
            "id": "4740",
            "name": "User Account Locked Out",
            "description": "A user account was locked out due to multiple failed logon attempts.",
            "category": "Account Management",
            "criticality": "Medium",
            "logSource": "Security",
            "investigationTips": [
                "Investigate source of failed logon attempts",
                "Check for brute force attack patterns",
                "Review account lockout policies",
                "Monitor for password spray campaigns"
            ],
            "relatedEvents": ["4625", "4767"],
            "mitreTactics": ["Credential Access"],
            "commonCauses": ["Password attacks", "User password mistakes"],
            "falsePositives": ["Legitimate user errors", "Application misconfigurations"],
            "hasPlaybook": True
        },
        {
            "id": "4648",
            "name": "Logon Using Explicit Credentials",
            "description": "A logon was attempted using explicit credentials. Often indicates RunAs or credential delegation.",
            "category": "Authentication",
            "criticality": "Medium",
            "logSource": "Security",
            "investigationTips": [
                "Monitor for privilege escalation attempts",
                "Check if credentials match current user context",
                "Review target account privileges",
                "Correlate with process creation events"
            ],
            "relatedEvents": ["4624", "4688"],
            "mitreTactics": ["Privilege Escalation", "Lateral Movement"],
            "commonCauses": ["RunAs commands", "Scheduled tasks", "Service operations"],
            "falsePositives": ["Legitimate admin operations", "Service account usage"],
            "hasPlaybook": True
        },
        {
            "id": "4697",
            "name": "Service Installed",
            "description": "A service was installed on the system. Critical for detecting malware persistence.",
            "category": "Process",
            "criticality": "High",
            "logSource": "Security",
            "investigationTips": [
                "Verify legitimacy of new service",
                "Check service binary location and signature",
                "Review service permissions and configuration",
                "Monitor for suspicious service names"
            ],
            "relatedEvents": ["7034", "7036"],
            "mitreTactics": ["Persistence", "Privilege Escalation"],
            "commonCauses": ["Software installation", "System updates"],
            "falsePositives": ["Legitimate software installations"],
            "hasPlaybook": True
        },
        {
            "id": "4663",
            "name": "Attempt to Access Object",
            "description": "An attempt was made to access an object. Critical for monitoring unauthorized access attempts.",
            "category": "File & Registry",
            "criticality": "Medium",
            "logSource": "Security",
            "investigationTips": [
                "Focus on failed access attempts",
                "Monitor access to sensitive resources",
                "Check access permissions and rights",
                "Review unauthorized access patterns"
            ],
            "relatedEvents": ["4656", "4658"],
            "mitreTactics": ["Discovery", "Privilege Escalation"],
            "commonCauses": ["Permission errors", "Unauthorized access attempts"],
            "falsePositives": ["Application permission issues"],
            "hasPlaybook": True
        },
        {
            "id": "4768",
            "name": "Kerberos TGT Requested",
            "description": "A Kerberos authentication ticket (TGT) was requested. Initial domain authentication.",
            "category": "Authentication",
            "criticality": "Medium",
            "logSource": "Security",
            "investigationTips": [
                "Monitor for unusual requesting times",
                "Check encryption types used",
                "Correlate with subsequent service ticket requests",
                "Review pre-authentication status"
            ],
            "relatedEvents": ["4769", "4771", "4776"],
            "mitreTactics": ["Initial Access"],
            "commonCauses": ["Domain logon", "Service authentication"],
            "falsePositives": ["Normal domain operations"],
            "hasPlaybook": True
        },
        {
            "id": "4769",
            "name": "Kerberos Service Ticket Requested",
            "description": "A Kerberos service ticket was requested. Service access authentication.",
            "category": "Authentication",
            "criticality": "Low",
            "logSource": "Security",
            "investigationTips": [
                "Monitor for unusual service access patterns",
                "Check requested service names",
                "Review encryption types",
                "Correlate with network access events"
            ],
            "relatedEvents": ["4768", "4771"],
            "mitreTactics": ["Lateral Movement"],
            "commonCauses": ["Service access", "Network resource access"],
            "falsePositives": ["Normal service operations"],
            "hasPlaybook": True
        },
        {
            "id": "4776",
            "name": "NTLM Authentication",
            "description": "Computer attempted to validate credentials for an account using NTLM.",
            "category": "Authentication",
            "criticality": "Medium",
            "logSource": "Security",
            "investigationTips": [
                "NTLM usage may indicate legacy systems",
                "Monitor for pass-the-hash attacks",
                "Review authentication sources",
                "Check for downgrade attacks from Kerberos"
            ],
            "relatedEvents": ["4768", "4625"],
            "mitreTactics": ["Lateral Movement", "Credential Access"],
            "commonCauses": ["Legacy system access", "Local authentication"],
            "falsePositives": ["Normal legacy application usage"],
            "hasPlaybook": True
        }
    ]
    
    return events_with_playbooks

def generate_markdown(event):
    """Generate markdown content for an event"""
    microsoft_url = get_microsoft_doc_url(event['id'])
    
    # Generate MITRE tactics with links
    mitre_tactics = []
    for tactic in event.get('mitreTactics', []):
        mitre_url = get_mitre_attack_url(tactic)
        mitre_tactics.append(f"- [{tactic}]({mitre_url})")
    mitre_tactics_text = '\n'.join(mitre_tactics) if mitre_tactics else "- None specified"
    
    # Generate investigation tips
    tips = []
    for tip in event.get('investigationTips', []):
        tips.append(f"- {tip}")
    tips_text = '\n'.join(tips) if tips else "- No specific tips available"
    
    # Generate related events
    related = []
    for rel_event in event.get('relatedEvents', []):
        related.append(f"- Event {rel_event}")
    related_text = '\n'.join(related) if related else "- None specified"
    
    # Generate common causes
    causes = []
    for cause in event.get('commonCauses', []):
        causes.append(f"- {cause}")
    causes_text = '\n'.join(causes) if causes else "- No common causes specified"
    
    # Generate false positives
    fps = []
    for fp in event.get('falsePositives', []):
        fps.append(f"- {fp}")
    fps_text = '\n'.join(fps) if fps else "- No false positives specified"
    
    # Add playbook note
    playbook_note = ""
    if event.get('hasPlaybook', False):
        playbook_note = """
## 📋 Investigation Playbook Available

**This event has a comprehensive investigation playbook available in the main dashboard.**

The playbook includes:
- ✅ **Immediate Actions** - Critical first steps for investigation
- ✅ **Short-term Analysis** - Detailed investigation procedures  
- ✅ **Long-term Hardening** - Prevention and security improvements
- ✅ **SIEM Queries** - Ready-to-use detection queries for Splunk/ELK
- ✅ **PowerShell Commands** - Investigation automation scripts
- ✅ **Tool Recommendations** - Specific tools for each investigation step

**Access the full interactive playbook at:** [Event ID Dashboard](../index.html)
"""
    
    markdown_content = f"""# Event {event['id']}: {event['name']}

## Overview
**Event ID:** {event['id']}  
**Event Name:** {event['name']}  
**Log Source:** {event['logSource']}  
**Criticality:** {event['criticality']}  
**Category:** {event['category']}  

## Description
{event['description']}

## Investigation Tips
{tips_text}

## MITRE ATT&CK Tactics
{mitre_tactics_text}

## Related Events
{related_text}

## Common Causes
{causes_text}

## False Positives
{fps_text}
{playbook_note}
## Additional Resources
- [Microsoft Documentation]({microsoft_url})
- [Windows Security Auditing](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-events)
- [Event ID Dashboard](../index.html)

---
*Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | [Back to Main Dashboard](../index.html)*
"""
    
    return markdown_content

def main():
    # Create events directory
    os.makedirs('events', exist_ok=True)
    
    # Get events with playbooks
    events = get_events_with_playbooks()
    
    print(f"Generating markdown files for {len(events)} events with investigation playbooks...")
    
    # Generate individual markdown files
    for event in events:
        filename = f"events/{event['id']}.md"
        with open(filename, 'w') as f:
            f.write(generate_markdown(event))
        print(f"Generated: {event['id']}.md")
    
    # Generate index file
    index_content = f"""# Windows Event ID Investigation Guide

## Events with Investigation Playbooks

This directory contains detailed information about Windows Event IDs that have comprehensive investigation playbooks available in the main dashboard.

## Available Events ({len(events)} total)

### Critical Events
"""
    
    # Group events by criticality
    critical_events = [e for e in events if e['criticality'] == 'Critical']
    high_events = [e for e in events if e['criticality'] == 'High']
    medium_events = [e for e in events if e['criticality'] == 'Medium']
    low_events = [e for e in events if e['criticality'] == 'Low']
    
    # Add critical events
    for event in critical_events:
        index_content += f"- [{event['id']} - {event['name']}]({event['id']}.md) - {event['description'][:80]}...\n"
    
    index_content += "\n### High Priority Events\n"
    for event in high_events:
        index_content += f"- [{event['id']} - {event['name']}]({event['id']}.md) - {event['description'][:80]}...\n"
    
    index_content += "\n### Medium Priority Events\n"
    for event in medium_events:
        index_content += f"- [{event['id']} - {event['name']}]({event['id']}.md) - {event['description'][:80]}...\n"
    
    if low_events:
        index_content += "\n### Low Priority Events\n"
        for event in low_events:
            index_content += f"- [{event['id']} - {event['name']}]({event['id']}.md) - {event['description'][:80]}...\n"
    
    # Add statistics
    index_content += f"""

## Statistics
- **Total Events with Playbooks:** {len(events)}
- **Critical Events:** {len(critical_events)}
- **High Priority Events:** {len(high_events)}
- **Medium Priority Events:** {len(medium_events)}
- **Low Priority Events:** {len(low_events)}

## Coverage by Category
"""
    
    # Count by category
    categories = {}
    for event in events:
        cat = event['category']
        categories[cat] = categories.get(cat, 0) + 1
    
    for category, count in sorted(categories.items()):
        index_content += f"- **{category}:** {count} events\n"
    
    index_content += f"""

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
*Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Coverage: {len(events)} events with comprehensive playbooks*
"""
    
    with open('events/README.md', 'w') as f:
        f.write(index_content)
    print("Generated: README.md (index file)")
    
    print(f"\n✅ Successfully generated {len(events)} markdown files in the 'events' directory!")

if __name__ == "__main__":
    main() 