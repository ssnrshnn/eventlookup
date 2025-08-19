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

def get_events_data():
    """Return the list of events data"""
    events_data = [
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

        }
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

        }
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

        }
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

        }
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

        }
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

        }
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

        }
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

        }
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

        }
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

        }
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

        }
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

        }
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

        }
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

        }
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

        }
        # Missing Sysmon Events
        {
            "id": "2",
            "name": "File Creation Time Changed",
            "description": "Sysmon detected a file creation time modification. Critical for detecting timestomping anti-forensics techniques.",
            "category": "File System",
            "criticality": "High",
            "logSource": "Sysmon",
            "investigationTips": [
                "Investigate processes that modified file timestamps",
                "Check for patterns of timestamp manipulation",
                "Review files in system directories for unusual timestamps",
                "Correlate with other anti-forensics activities"
            ],
            "relatedEvents": ["1", "11", "15"],
            "mitreTactics": ["Defense Evasion"],
            "commonCauses": ["Timestomping attacks", "System file modifications", "Backup software operations"],
            "falsePositives": ["Legitimate backup operations", "System maintenance"],

        }
        {
            "id": "4",
            "name": "Sysmon Service State Changed",
            "description": "Sysmon service state has changed. Critical for monitoring security tool tampering.",
            "category": "Service Management",
            "criticality": "Critical",
            "logSource": "Sysmon",
            "investigationTips": [
                "Immediately investigate who stopped/started Sysmon",
                "Check for concurrent malicious activities",
                "Review system integrity after service changes",
                "Monitor for repeated service manipulation attempts"
            ],
            "relatedEvents": ["4697", "7034", "7036"],
            "mitreTactics": ["Defense Evasion"],
            "commonCauses": ["Administrative maintenance", "Security tool tampering", "System updates"],
            "falsePositives": ["Scheduled maintenance", "Software updates"],

        }
        {
            "id": "6",
            "name": "Driver Loaded",
            "description": "Sysmon detected a driver being loaded. Critical for detecting rootkits and malicious drivers.",
            "category": "Driver Management",
            "criticality": "High",
            "logSource": "Sysmon",
            "investigationTips": [
                "Verify driver signatures and certificates",
                "Check driver loading location and path",
                "Monitor for unsigned or suspicious drivers",
                "Correlate with system instability or unusual behavior"
            ],
            "relatedEvents": ["1", "7", "22"],
            "mitreTactics": ["Persistence", "Defense Evasion"],
            "commonCauses": ["Legitimate software installation", "System updates", "Rootkit installation"],
            "falsePositives": ["Hardware driver installations", "System updates"],

        }
        {
            "id": "7",
            "name": "Image Loaded",
            "description": "Sysmon detected a DLL or executable image being loaded. Essential for detecting DLL injection and hijacking.",
            "category": "Process Management",
            "criticality": "Medium",
            "logSource": "Sysmon",
            "investigationTips": [
                "Monitor for unsigned DLLs being loaded",
                "Check for DLL injection into critical processes",
                "Review DLL load paths for hijacking attempts",
                "Analyze process-DLL relationships for anomalies"
            ],
            "relatedEvents": ["1", "8", "10"],
            "mitreTactics": ["Defense Evasion", "Execution"],
            "commonCauses": ["Normal application operations", "DLL injection attacks", "Software loading"],
            "falsePositives": ["Normal application DLL loading", "System operations"],

        }
        {
            "id": "8",
            "name": "CreateRemoteThread",
            "description": "Sysmon detected a process creating a thread in another process. Critical for detecting code injection.",
            "category": "Process Management",
            "criticality": "High",
            "logSource": "Sysmon",
            "investigationTips": [
                "Identify source and target processes for injection",
                "Monitor for cross-process thread creation patterns",
                "Check for known injection techniques (DLL injection, process hollowing)",
                "Correlate with other process manipulation events"
            ],
            "relatedEvents": ["1", "7", "10", "25"],
            "mitreTactics": ["Defense Evasion", "Execution"],
            "commonCauses": ["Code injection attacks", "Legitimate debugging", "System processes"],
            "falsePositives": ["Legitimate debugging tools", "System operations"],

        }
        {
            "id": "9",
            "name": "RawAccessRead",
            "description": "Sysmon detected a process performing raw access read operations. Important for detecting credential dumping.",
            "category": "File System",
            "criticality": "High",
            "logSource": "Sysmon",
            "investigationTips": [
                "Monitor raw disk access for credential dumping tools",
                "Check for access to sensitive system files",
                "Review processes accessing raw volumes",
                "Correlate with credential access attempts"
            ],
            "relatedEvents": ["1", "10", "11"],
            "mitreTactics": ["Credential Access"],
            "commonCauses": ["Credential dumping tools", "System backup utilities", "Disk analysis tools"],
            "falsePositives": ["Legitimate backup software", "System utilities"],

        }
        {
            "id": "10",
            "name": "ProcessAccess",
            "description": "Sysmon detected a process accessing another process. Critical for detecting credential harvesting and process injection.",
            "category": "Process Management",
            "criticality": "High",
            "logSource": "Sysmon",
            "investigationTips": [
                "Monitor access to sensitive processes (lsass.exe, winlogon.exe)",
                "Check for credential dumping tool signatures",
                "Review process access patterns for anomalies",
                "Correlate with authentication events"
            ],
            "relatedEvents": ["1", "8", "4776", "4624"],
            "mitreTactics": ["Credential Access", "Defense Evasion"],
            "commonCauses": ["Credential dumping attacks", "System monitoring tools", "Debugging operations"],
            "falsePositives": ["Legitimate monitoring tools", "System operations"],

        }
        {
            "id": "12",
            "name": "RegistryEvent (Object create and delete)",
            "description": "Sysmon detected registry key or value creation/deletion. Important for detecting persistence mechanisms.",
            "category": "Registry",
            "criticality": "Medium",
            "logSource": "Sysmon",
            "investigationTips": [
                "Monitor changes to autostart registry locations",
                "Check for suspicious registry key creation patterns",
                "Review registry modifications in system areas",
                "Correlate with malware persistence techniques"
            ],
            "relatedEvents": ["1", "13", "14"],
            "mitreTactics": ["Persistence", "Defense Evasion"],
            "commonCauses": ["Software installation", "System configuration", "Persistence mechanisms"],
            "falsePositives": ["Normal software operations", "System updates"],

        }
        {
            "id": "13",
            "name": "RegistryEvent (Value Set)",
            "description": "Sysmon detected registry value modifications. Critical for detecting configuration tampering.",
            "category": "Registry",
            "criticality": "Medium",
            "logSource": "Sysmon",
            "investigationTips": [
                "Monitor changes to security-related registry values",
                "Check for unusual configuration modifications",
                "Review registry value changes in critical system areas",
                "Correlate with system behavior changes"
            ],
            "relatedEvents": ["1", "12", "14"],
            "mitreTactics": ["Defense Evasion", "Persistence"],
            "commonCauses": ["System configuration changes", "Software settings", "Malware modifications"],
            "falsePositives": ["Normal configuration changes", "Software installations"],

        }
        {
            "id": "14",
            "name": "RegistryEvent (Key and Value Rename)",
            "description": "Sysmon detected registry key or value rename operations. Important for detecting evasion techniques.",
            "category": "Registry",
            "criticality": "Medium",
            "logSource": "Sysmon",
            "investigationTips": [
                "Monitor registry renames in critical system areas",
                "Check for patterns indicating evasion attempts",
                "Review registry operations around malware activities",
                "Correlate with other defensive evasion techniques"
            ],
            "relatedEvents": ["1", "12", "13"],
            "mitreTactics": ["Defense Evasion"],
            "commonCauses": ["Software operations", "System maintenance", "Evasion techniques"],
            "falsePositives": ["Normal software operations", "System utilities"],

        }
        {
            "id": "15",
            "name": "FileCreateStreamHash",
            "description": "Sysmon detected creation of alternate data streams. Critical for detecting hidden malware.",
            "category": "File System",
            "criticality": "High",
            "logSource": "Sysmon",
            "investigationTips": [
                "Monitor for files with alternate data streams",
                "Check stream contents for malicious code",
                "Review files in system directories for hidden streams",
                "Correlate with malware hiding techniques"
            ],
            "relatedEvents": ["1", "2", "11"],
            "mitreTactics": ["Defense Evasion", "Persistence"],
            "commonCauses": ["Malware hiding techniques", "Legitimate software features", "System operations"],
            "falsePositives": ["Normal NTFS features", "Some applications"],

        }
        {
            "id": "22",
            "name": "DNS Query",
            "description": "Sysmon detected a DNS query. Essential for detecting C2 communication and malicious domain access.",
            "category": "Network",
            "criticality": "Medium",
            "logSource": "Sysmon",
            "investigationTips": [
                "Monitor queries to suspicious or malicious domains",
                "Check for DNS tunneling patterns",
                "Review domain reputation and categorization",
                "Correlate with network connections and process activity"
            ],
            "relatedEvents": ["1", "3", "6"],
            "mitreTactics": ["Command and Control", "Exfiltration"],
            "commonCauses": ["Normal browsing", "Application communications", "C2 communications"],
            "falsePositives": ["Normal internet activity", "Application updates"],

        }
        {
            "id": "25",
            "name": "Process Tampering",
            "description": "Sysmon detected process memory tampering. Critical for detecting advanced injection techniques.",
            "category": "Process Management",
            "criticality": "Critical",
            "logSource": "Sysmon",
            "investigationTips": [
                "Investigate process hollowing and tampering attempts",
                "Monitor for advanced injection techniques",
                "Check for memory manipulation patterns",
                "Correlate with other process-related events"
            ],
            "relatedEvents": ["1", "7", "8", "10"],
            "mitreTactics": ["Defense Evasion", "Execution"],
            "commonCauses": ["Process hollowing attacks", "Advanced malware", "Memory manipulation"],
            "falsePositives": ["Some legitimate debugging tools", "Security software"],

        }
        # Additional Missing Sysmon Events
        {
            "id": "16",
            "name": "ServiceConfigurationChange",
            "description": "Sysmon detected changes to service configuration. Important for monitoring service tampering.",
            "category": "Service Management",
            "criticality": "Medium",
            "logSource": "Sysmon",
            "investigationTips": [
                "Monitor changes to critical service configurations",
                "Check for unauthorized service modifications",
                "Review service permission changes",
                "Correlate with other system modifications"
            ],
            "relatedEvents": ["4", "4697", "7034"],
            "mitreTactics": ["Persistence", "Defense Evasion"],
            "commonCauses": ["Service updates", "Administrative changes", "Malware persistence"],
            "falsePositives": ["Legitimate service updates", "System maintenance"],

        }
        {
            "id": "17",
            "name": "PipeEvent (Pipe Created)",
            "description": "Sysmon detected named pipe creation. Important for monitoring inter-process communication.",
            "category": "Communication",
            "criticality": "Medium",
            "logSource": "Sysmon",
            "investigationTips": [
                "Monitor suspicious named pipe creation patterns",
                "Check for malware communication channels",
                "Review pipe names for suspicious patterns",
                "Correlate with process activity"
            ],
            "relatedEvents": ["1", "18", "8"],
            "mitreTactics": ["Command and Control", "Execution"],
            "commonCauses": ["Normal IPC", "Application communication", "Malware C2"],
            "falsePositives": ["Normal application operations", "System processes"],

        }
        {
            "id": "18",
            "name": "PipeEvent (Pipe Connected)",
            "description": "Sysmon detected named pipe connection. Critical for monitoring malware communication.",
            "category": "Communication",
            "criticality": "Medium",
            "logSource": "Sysmon",
            "investigationTips": [
                "Monitor unexpected pipe connections",
                "Check connecting processes for legitimacy",
                "Review pipe communication patterns",
                "Correlate with network activity"
            ],
            "relatedEvents": ["1", "17", "3"],
            "mitreTactics": ["Command and Control", "Lateral Movement"],
            "commonCauses": ["Normal IPC", "Application communication", "C2 channels"],
            "falsePositives": ["Normal application operations", "System services"],

        }
        {
            "id": "19",
            "name": "WmiEvent (WmiEventFilter activity detected)",
            "description": "Sysmon detected WMI event filter registration. Critical for detecting WMI-based persistence.",
            "category": "WMI",
            "criticality": "High",
            "logSource": "Sysmon",
            "investigationTips": [
                "Investigate WMI filter creation for persistence",
                "Check filter conditions and targets",
                "Monitor for suspicious WMI activity",
                "Correlate with other WMI events"
            ],
            "relatedEvents": ["20", "21", "1"],
            "mitreTactics": ["Persistence", "Execution"],
            "commonCauses": ["Legitimate WMI operations", "System monitoring", "Malware persistence"],
            "falsePositives": ["System management tools", "Monitoring software"],

        }
        {
            "id": "20",
            "name": "WmiEvent (WmiEventConsumer activity detected)",
            "description": "Sysmon detected WMI event consumer registration. Critical for detecting WMI-based execution.",
            "category": "WMI",
            "criticality": "High",
            "logSource": "Sysmon",
            "investigationTips": [
                "Investigate WMI consumer registration",
                "Check consumer actions and destinations",
                "Monitor for malicious WMI execution",
                "Review WMI persistence mechanisms"
            ],
            "relatedEvents": ["19", "21", "1"],
            "mitreTactics": ["Persistence", "Execution"],
            "commonCauses": ["System management", "Monitoring tools", "WMI-based malware"],
            "falsePositives": ["Legitimate WMI operations", "System tools"],

        }
        {
            "id": "21",
            "name": "WmiEvent (WmiEventConsumerToFilter activity detected)",
            "description": "Sysmon detected WMI consumer-to-filter binding. Critical for detecting WMI attack chains.",
            "category": "WMI",
            "criticality": "High",
            "logSource": "Sysmon",
            "investigationTips": [
                "Investigate WMI filter-consumer binding",
                "Check for complete WMI attack chains",
                "Monitor for persistent WMI triggers",
                "Review WMI subscription abuse"
            ],
            "relatedEvents": ["19", "20", "1"],
            "mitreTactics": ["Persistence", "Execution"],
            "commonCauses": ["WMI management operations", "System monitoring", "WMI-based attacks"],
            "falsePositives": ["Legitimate WMI subscriptions", "System management"],

        }
        {
            "id": "23",
            "name": "FileDelete (File Delete archived)",
            "description": "Sysmon detected file deletion with archiving. Important for monitoring data destruction.",
            "category": "File System",
            "criticality": "Medium",
            "logSource": "Sysmon",
            "investigationTips": [
                "Monitor deletion of critical files",
                "Check for evidence destruction attempts",
                "Review deleted file patterns",
                "Correlate with other file system events"
            ],
            "relatedEvents": ["11", "2", "1"],
            "mitreTactics": ["Defense Evasion", "Impact"],
            "commonCauses": ["Normal file operations", "Cleanup activities", "Evidence destruction"],
            "falsePositives": ["Normal file deletion", "System cleanup"],

        }
        {
            "id": "24",
            "name": "ClipboardChange (New content in the clipboard)",
            "description": "Sysmon detected clipboard content changes. Important for monitoring data exfiltration.",
            "category": "Data Access",
            "criticality": "Low",
            "logSource": "Sysmon",
            "investigationTips": [
                "Monitor for sensitive data in clipboard",
                "Check for automated clipboard access",
                "Review clipboard content patterns",
                "Correlate with data access events"
            ],
            "relatedEvents": ["1", "11", "3"],
            "mitreTactics": ["Collection", "Exfiltration"],
            "commonCauses": ["Normal user operations", "Application functionality", "Data theft"],
            "falsePositives": ["Normal copy-paste operations", "Application features"],

        }
        # Missing Critical Windows Security Events
        {
            "id": "4659",
            "name": "A handle to an object was requested with intent to delete",
            "description": "An attempt was made to access an object with delete intent. Critical for monitoring file/object deletion attempts.",
            "category": "Object Access",
            "criticality": "Medium",
            "logSource": "Security",
            "investigationTips": [
                "Monitor deletion attempts on critical files",
                "Check for unauthorized deletion patterns",
                "Review object access with delete intent",
                "Correlate with actual deletion events"
            ],
            "relatedEvents": ["4656", "4658", "4663"],
            "mitreTactics": ["Defense Evasion", "Impact"],
            "commonCauses": ["Normal file operations", "Application behavior", "Evidence destruction"],
            "falsePositives": ["Normal application operations", "File management"],

        }
        {
            "id": "4703",
            "name": "A user right was adjusted",
            "description": "A user privilege/right was modified. Critical for monitoring privilege changes.",
            "category": "Policy Change",
            "criticality": "High",
            "logSource": "Security",
            "investigationTips": [
                "Monitor privilege escalation attempts",
                "Check for unauthorized right assignments",
                "Review privilege modification patterns",
                "Correlate with other policy changes"
            ],
            "relatedEvents": ["4672", "4704", "4738"],
            "mitreTactics": ["Privilege Escalation", "Persistence"],
            "commonCauses": ["Administrative changes", "Policy updates", "Privilege escalation"],
            "falsePositives": ["Legitimate administrative tasks", "Policy updates"],

        }
        {
            "id": "4706",
            "name": "A new trust was created to a domain",
            "description": "A domain trust relationship was established. Critical for monitoring trust relationship abuse.",
            "category": "Policy Change",
            "criticality": "High",
            "logSource": "Security",
            "investigationTips": [
                "Investigate unauthorized trust creation",
                "Check trust relationship legitimacy",
                "Monitor for domain trust abuse",
                "Review trust configuration changes"
            ],
            "relatedEvents": ["4707", "4716", "4865"],
            "mitreTactics": ["Persistence", "Lateral Movement"],
            "commonCauses": ["Domain administration", "Infrastructure changes", "Trust abuse"],
            "falsePositives": ["Legitimate domain operations", "Infrastructure updates"],

        }
        {
            "id": "4707",
            "name": "A trust to a domain was removed",
            "description": "A domain trust relationship was removed. Important for monitoring trust changes.",
            "category": "Policy Change",
            "criticality": "Medium",
            "logSource": "Security",
            "investigationTips": [
                "Monitor trust relationship changes",
                "Check for unauthorized trust removal",
                "Review trust configuration modifications",
                "Correlate with domain policy changes"
            ],
            "relatedEvents": ["4706", "4716", "4865"],
            "mitreTactics": ["Defense Evasion", "Impact"],
            "commonCauses": ["Domain administration", "Security hardening", "Attack cleanup"],
            "falsePositives": ["Legitimate domain operations", "Security improvements"],

        }
        # Additional Missing Sysmon Events (26-29, 255)
        {
            "id": "26",
            "name": "FileDeleteDetected",
            "description": "Sysmon detected file deletion operation. Important for monitoring data destruction and evidence removal.",
            "category": "File System",
            "criticality": "Medium",
            "logSource": "Sysmon",
            "investigationTips": [
                "Monitor deletion of critical files",
                "Check for evidence destruction patterns",
                "Review file deletion in sensitive directories",
                "Correlate with other file system events"
            ],
            "relatedEvents": ["23", "11", "2"],
            "mitreTactics": ["Defense Evasion", "Impact"],
            "commonCauses": ["Normal file cleanup", "Evidence destruction", "System maintenance"],
            "falsePositives": ["Normal file operations", "Automated cleanup"],

        }
        {
            "id": "27",
            "name": "FileBlockExecutable",
            "description": "Sysmon detected an executable file being blocked. Critical for monitoring malware prevention.",
            "category": "File System",
            "criticality": "High",
            "logSource": "Sysmon",
            "investigationTips": [
                "Investigate blocked executable attempts",
                "Check file signatures and origins",
                "Review security policy effectiveness",
                "Monitor for bypass attempts"
            ],
            "relatedEvents": ["1", "11", "6"],
            "mitreTactics": ["Defense Evasion", "Execution"],
            "commonCauses": ["Security policy enforcement", "Malware blocking", "Unsigned executables"],
            "falsePositives": ["Legitimate software blocks", "Policy misconfigurations"],

        }
        {
            "id": "28",
            "name": "FileBlockShredding",
            "description": "Sysmon detected file shredding/secure deletion attempts. Important for monitoring evidence destruction.",
            "category": "File System",
            "criticality": "High",
            "logSource": "Sysmon",
            "investigationTips": [
                "Investigate secure deletion attempts",
                "Check for anti-forensics tools",
                "Monitor for evidence destruction",
                "Review file shredding patterns"
            ],
            "relatedEvents": ["23", "26", "2"],
            "mitreTactics": ["Defense Evasion"],
            "commonCauses": ["Anti-forensics tools", "Secure file deletion", "Evidence destruction"],
            "falsePositives": ["Legitimate secure deletion", "Privacy tools"],

        }
        {
            "id": "29",
            "name": "FileExecutableDetected",
            "description": "Sysmon detected executable file creation or modification. Critical for monitoring malware deployment.",
            "category": "File System",
            "criticality": "Medium",
            "logSource": "Sysmon",
            "investigationTips": [
                "Monitor executable file creation",
                "Check file signatures and certificates",
                "Review executable file locations",
                "Correlate with process execution events"
            ],
            "relatedEvents": ["1", "11", "27"],
            "mitreTactics": ["Persistence", "Execution"],
            "commonCauses": ["Software installation", "Malware deployment", "System updates"],
            "falsePositives": ["Normal software operations", "System updates"],

        }
        {
            "id": "255",
            "name": "Sysmon Error",
            "description": "Sysmon service error occurred. Critical for monitoring security tool health and integrity.",
            "category": "Service Management",
            "criticality": "High",
            "logSource": "Sysmon",
            "investigationTips": [
                "Investigate Sysmon service health",
                "Check for service tampering",
                "Review error patterns and frequency",
                "Monitor for security tool evasion"
            ],
            "relatedEvents": ["4", "7034", "7036"],
            "mitreTactics": ["Defense Evasion"],
            "commonCauses": ["Service overload", "Configuration errors", "Security tool tampering"],
            "falsePositives": ["System resource issues", "Configuration problems"],

        }
        # Critical Missing Windows Security Events
        {
            "id": "4698",
            "name": "Scheduled Task Created",
            "description": "A scheduled task was created. Critical for detecting persistence mechanisms and automated malware execution.",
            "category": "Task Scheduler",
            "criticality": "High",
            "logSource": "Security",
            "investigationTips": [
                "Investigate unauthorized scheduled task creation",
                "Check task actions and triggers",
                "Review task permissions and user context",
                "Monitor for persistence mechanisms"
            ],
            "relatedEvents": ["4702", "4699", "4700"],
            "mitreTactics": ["Persistence", "Execution"],
            "commonCauses": ["Legitimate automation", "System tasks", "Malware persistence"],
            "falsePositives": ["Normal system operations", "Software installations"],

        }
        {
            "id": "4657",
            "name": "Registry Value Modified",
            "description": "A registry value was modified. Critical for monitoring system configuration changes and malware modifications.",
            "category": "Registry",
            "criticality": "High",
            "logSource": "Security",
            "investigationTips": [
                "Monitor changes to critical registry values",
                "Check for unauthorized system modifications",
                "Review registry modification patterns",
                "Correlate with malware activity"
            ],
            "relatedEvents": ["12", "13", "14"],
            "mitreTactics": ["Persistence", "Defense Evasion"],
            "commonCauses": ["System configuration", "Software installation", "Malware modifications"],
            "falsePositives": ["Normal system operations", "Software updates"],

        }
        {
            "id": "4674",
            "name": "Operation on Privileged Object",
            "description": "An operation was attempted on a privileged object. Important for monitoring privilege abuse.",
            "category": "Privilege Management",
            "criticality": "Medium",
            "logSource": "Security",
            "investigationTips": [
                "Monitor privileged object access",
                "Check for privilege escalation attempts",
                "Review unauthorized access patterns",
                "Correlate with other privilege events"
            ],
            "relatedEvents": ["4672", "4673", "4703"],
            "mitreTactics": ["Privilege Escalation"],
            "commonCauses": ["Administrative operations", "Privilege escalation", "System access"],
            "falsePositives": ["Normal administrative tasks", "System operations"],

        }
        {
            "id": "4781",
            "name": "Account Name Changed",
            "description": "An account name was changed. Critical for monitoring account manipulation and identity changes.",
            "category": "Account Management",
            "criticality": "High",
            "logSource": "Security",
            "investigationTips": [
                "Investigate unauthorized account name changes",
                "Check for account manipulation attempts",
                "Review identity modification patterns",
                "Monitor for evasion techniques"
            ],
            "relatedEvents": ["4720", "4738", "4781"],
            "mitreTactics": ["Defense Evasion", "Persistence"],
            "commonCauses": ["Account management", "Identity changes", "Attack evasion"],
            "falsePositives": ["Legitimate account updates", "HR processes"],

        }
        {
            "id": "4702",
            "name": "Scheduled Task Modified",
            "description": "A scheduled task was modified. Important for detecting persistence mechanism changes.",
            "category": "Task Scheduler",
            "criticality": "Medium",
            "logSource": "Security",
            "investigationTips": [
                "Monitor scheduled task modifications",
                "Check for unauthorized task changes",
                "Review task modification patterns",
                "Correlate with persistence activities"
            ],
            "relatedEvents": ["4698", "4699", "4700"],
            "mitreTactics": ["Persistence", "Defense Evasion"],
            "commonCauses": ["Task updates", "System maintenance", "Persistence modifications"],
            "falsePositives": ["Normal task management", "System updates"],

        }
        {
            "id": "4704",
            "name": "User Right Assigned",
            "description": "A user right was assigned to an account. Critical for monitoring privilege escalation.",
            "category": "Policy Change",
            "criticality": "High",
            "logSource": "Security",
            "investigationTips": [
                "Monitor privilege assignments",
                "Check for unauthorized right grants",
                "Review privilege escalation attempts",
                "Correlate with other policy changes"
            ],
            "relatedEvents": ["4703", "4705", "4672"],
            "mitreTactics": ["Privilege Escalation", "Persistence"],
            "commonCauses": ["Administrative changes", "Privilege escalation", "Policy updates"],
            "falsePositives": ["Legitimate administrative tasks", "Policy management"],

        }
        {
            "id": "4705",
            "name": "User Right Removed",
            "description": "A user right was removed from an account. Important for monitoring privilege changes.",
            "category": "Policy Change",
            "criticality": "Medium",
            "logSource": "Security",
            "investigationTips": [
                "Monitor privilege removals",
                "Check for unauthorized right revocations",
                "Review privilege modification patterns",
                "Correlate with security hardening"
            ],
            "relatedEvents": ["4703", "4704", "4672"],
            "mitreTactics": ["Defense Evasion", "Impact"],
            "commonCauses": ["Security hardening", "Policy changes", "Access control"],
            "falsePositives": ["Legitimate policy updates", "Security improvements"],

        }
        {
            "id": "4716",
            "name": "Trusted Domain Information Modified",
            "description": "Trusted domain information was modified. Critical for monitoring domain trust changes.",
            "category": "Policy Change",
            "criticality": "High",
            "logSource": "Security",
            "investigationTips": [
                "Investigate domain trust modifications",
                "Check for unauthorized trust changes",
                "Review domain security policies",
                "Monitor for lateral movement preparation"
            ],
            "relatedEvents": ["4706", "4707", "4865"],
            "mitreTactics": ["Persistence", "Lateral Movement"],
            "commonCauses": ["Domain administration", "Trust management", "Infrastructure changes"],
            "falsePositives": ["Legitimate domain operations", "Infrastructure updates"],

        }
        {
            "id": "4717",
            "name": "System Security Access Granted",
            "description": "System security access was granted to an account. Important for monitoring security privilege grants.",
            "category": "Policy Change",
            "criticality": "Medium",
            "logSource": "Security",
            "investigationTips": [
                "Monitor security access grants",
                "Check for unauthorized access privileges",
                "Review security policy changes",
                "Correlate with privilege escalation"
            ],
            "relatedEvents": ["4672", "4703", "4718"],
            "mitreTactics": ["Privilege Escalation"],
            "commonCauses": ["Administrative tasks", "Security policy changes", "Access management"],
            "falsePositives": ["Normal administrative operations", "Policy updates"],

        }
        {
            "id": "4718",
            "name": "System Security Package Loaded",
            "description": "A security package was loaded by the Local Security Authority. Important for monitoring security subsystem changes.",
            "category": "System Security",
            "criticality": "Medium",
            "logSource": "Security",
            "investigationTips": [
                "Monitor security package loading",
                "Check for unauthorized security modules",
                "Review security subsystem changes",
                "Correlate with authentication events"
            ],
            "relatedEvents": ["4717", "4624", "4625"],
            "mitreTactics": ["Defense Evasion", "Persistence"],
            "commonCauses": ["System startup", "Security updates", "Authentication changes"],
            "falsePositives": ["Normal system operations", "Security updates"],

        }
        # Additional Critical Missing Events - Group Management
        {
            "id": "4735",
            "name": "Security-Enabled Local Group Changed",
            "description": "A security-enabled local group was changed. Critical for monitoring group privilege modifications.",
            "category": "Group Management",
            "criticality": "High",
            "logSource": "Security",
            "investigationTips": [
                "Monitor unauthorized group modifications",
                "Check for privilege escalation attempts",
                "Review group membership changes",
                "Correlate with account management events"
            ],
            "relatedEvents": ["4731", "4734", "4732"],
            "mitreTactics": ["Privilege Escalation", "Persistence"],
            "commonCauses": ["Administrative changes", "Privilege escalation", "Group management"],
            "falsePositives": ["Legitimate administrative tasks", "Group management"],

        }
        {
            "id": "4737",
            "name": "Security-Enabled Global Group Changed",
            "description": "A security-enabled global group was changed. Critical for monitoring domain group modifications.",
            "category": "Group Management",
            "criticality": "High",
            "logSource": "Security",
            "investigationTips": [
                "Monitor domain group modifications",
                "Check for unauthorized privilege changes",
                "Review global group membership",
                "Correlate with domain policy changes"
            ],
            "relatedEvents": ["4727", "4730", "4728"],
            "mitreTactics": ["Privilege Escalation", "Lateral Movement"],
            "commonCauses": ["Domain administration", "Group management", "Privilege changes"],
            "falsePositives": ["Legitimate domain operations", "Administrative tasks"],

        }
        {
            "id": "4739",
            "name": "Domain Policy Changed",
            "description": "Domain policy was changed. Critical for monitoring security policy modifications.",
            "category": "Policy Change",
            "criticality": "Critical",
            "logSource": "Security",
            "investigationTips": [
                "Investigate policy change authorization",
                "Check for security policy weakening",
                "Review policy modification patterns",
                "Monitor for domain compromise"
            ],
            "relatedEvents": ["4713", "4714", "4715"],
            "mitreTactics": ["Defense Evasion", "Persistence"],
            "commonCauses": ["Domain administration", "Security updates", "Policy attacks"],
            "falsePositives": ["Legitimate policy updates", "Administrative changes"],

        }
        {
            "id": "4741",
            "name": "Computer Account Changed",
            "description": "A computer account was changed. Important for monitoring computer object modifications.",
            "category": "Account Management",
            "criticality": "Medium",
            "logSource": "Security",
            "investigationTips": [
                "Monitor computer account modifications",
                "Check for unauthorized system changes",
                "Review computer object properties",
                "Correlate with system events"
            ],
            "relatedEvents": ["4742", "4743", "4738"],
            "mitreTactics": ["Persistence", "Defense Evasion"],
            "commonCauses": ["System administration", "Computer management", "Domain operations"],
            "falsePositives": ["Normal system operations", "Administrative tasks"],

        }
        {
            "id": "4742",
            "name": "Computer Account Modified",
            "description": "A computer account was modified. Important for monitoring system account changes.",
            "category": "Account Management",
            "criticality": "Medium",
            "logSource": "Security",
            "investigationTips": [
                "Monitor computer account modifications",
                "Check for unauthorized changes",
                "Review account property changes",
                "Correlate with computer events"
            ],
            "relatedEvents": ["4741", "4743", "4738"],
            "mitreTactics": ["Persistence", "Defense Evasion"],
            "commonCauses": ["System management", "Computer operations", "Administrative changes"],
            "falsePositives": ["Normal computer operations", "System updates"],

        }
        {
            "id": "4743",
            "name": "Computer Account Deleted",
            "description": "A computer account was deleted. Important for monitoring system account removal.",
            "category": "Account Management",
            "criticality": "Medium",
            "logSource": "Security",
            "investigationTips": [
                "Monitor computer account deletions",
                "Check for unauthorized removals",
                "Review account deletion patterns",
                "Correlate with system decommissioning"
            ],
            "relatedEvents": ["4741", "4742", "4726"],
            "mitreTactics": ["Impact", "Defense Evasion"],
            "commonCauses": ["System decommissioning", "Computer management", "Administrative cleanup"],
            "falsePositives": ["Legitimate decommissioning", "Administrative tasks"],

        }
        # Account Management Events
        {
            "id": "4713",
            "name": "Kerberos Policy Changed",
            "description": "Kerberos policy was changed. Critical for monitoring authentication policy modifications.",
            "category": "Policy Change",
            "criticality": "High",
            "logSource": "Security",
            "investigationTips": [
                "Monitor Kerberos policy changes",
                "Check for authentication weakening",
                "Review policy modification authorization",
                "Correlate with authentication issues"
            ],
            "relatedEvents": ["4739", "4714", "4715"],
            "mitreTactics": ["Defense Evasion", "Credential Access"],
            "commonCauses": ["Security updates", "Policy administration", "Authentication attacks"],
            "falsePositives": ["Legitimate policy updates", "Security improvements"],

        }
        {
            "id": "4714",
            "name": "Encrypted Data Recovery Policy Changed",
            "description": "Encrypted data recovery policy was changed. Important for monitoring encryption policy modifications.",
            "category": "Policy Change",
            "criticality": "High",
            "logSource": "Security",
            "investigationTips": [
                "Monitor encryption policy changes",
                "Check for data protection weakening",
                "Review recovery policy modifications",
                "Correlate with data access events"
            ],
            "relatedEvents": ["4713", "4715", "4739"],
            "mitreTactics": ["Defense Evasion", "Impact"],
            "commonCauses": ["Security updates", "Encryption management", "Policy administration"],
            "falsePositives": ["Legitimate policy updates", "Security improvements"],

        }
        {
            "id": "4715",
            "name": "Audit Policy (SACL) Changed",
            "description": "Audit policy (SACL) was changed. Critical for monitoring audit configuration modifications.",
            "category": "Policy Change",
            "criticality": "Critical",
            "logSource": "Security",
            "investigationTips": [
                "Monitor audit policy changes",
                "Check for audit weakening or disabling",
                "Review SACL modifications",
                "Correlate with evasion attempts"
            ],
            "relatedEvents": ["4713", "4714", "4739"],
            "mitreTactics": ["Defense Evasion"],
            "commonCauses": ["Security configuration", "Audit management", "Evasion attempts"],
            "falsePositives": ["Legitimate audit configuration", "Security updates"],

        }
        {
            "id": "4727",
            "name": "Security-Enabled Global Group Created",
            "description": "A security-enabled global group was created. Important for monitoring group creation.",
            "category": "Group Management",
            "criticality": "Medium",
            "logSource": "Security",
            "investigationTips": [
                "Monitor unauthorized group creation",
                "Check group creation authorization",
                "Review group permissions and members",
                "Correlate with privilege escalation"
            ],
            "relatedEvents": ["4730", "4737", "4728"],
            "mitreTactics": ["Persistence", "Privilege Escalation"],
            "commonCauses": ["Administrative tasks", "Group management", "Privilege escalation"],
            "falsePositives": ["Legitimate group creation", "Administrative operations"],

        }
        {
            "id": "4730",
            "name": "Security-Enabled Global Group Deleted",
            "description": "A security-enabled global group was deleted. Important for monitoring group removal.",
            "category": "Group Management",
            "criticality": "Medium",
            "logSource": "Security",
            "investigationTips": [
                "Monitor unauthorized group deletion",
                "Check group deletion authorization",
                "Review group cleanup patterns",
                "Correlate with administrative changes"
            ],
            "relatedEvents": ["4727", "4737", "4729"],
            "mitreTactics": ["Impact", "Defense Evasion"],
            "commonCauses": ["Administrative cleanup", "Group management", "Security hardening"],
            "falsePositives": ["Legitimate group cleanup", "Administrative operations"],

        }
        {
            "id": "4731",
            "name": "Security-Enabled Local Group Created",
            "description": "A security-enabled local group was created. Important for monitoring local group creation.",
            "category": "Group Management",
            "criticality": "Medium",
            "logSource": "Security",
            "investigationTips": [
                "Monitor local group creation",
                "Check group creation authorization",
                "Review local group permissions",
                "Correlate with local privilege escalation"
            ],
            "relatedEvents": ["4734", "4735", "4732"],
            "mitreTactics": ["Persistence", "Privilege Escalation"],
            "commonCauses": ["Administrative tasks", "Local group management", "System configuration"],
            "falsePositives": ["Legitimate group creation", "System operations"],

        }
        {
            "id": "4734",
            "name": "Security-Enabled Local Group Deleted",
            "description": "A security-enabled local group was deleted. Important for monitoring local group removal.",
            "category": "Group Management",
            "criticality": "Medium",
            "logSource": "Security",
            "investigationTips": [
                "Monitor local group deletion",
                "Check group deletion authorization",
                "Review group cleanup patterns",
                "Correlate with system changes"
            ],
            "relatedEvents": ["4731", "4735", "4733"],
            "mitreTactics": ["Impact", "Defense Evasion"],
            "commonCauses": ["Administrative cleanup", "Group management", "System maintenance"],
            "falsePositives": ["Legitimate group cleanup", "System operations"],

        }
        # Service Management Events
        {
            "id": "7030",
            "name": "Service Control Manager - Service Startup Failure",
            "description": "Service Control Manager reported a service startup failure. Critical for monitoring service integrity.",
            "category": "Service Management",
            "criticality": "High",
            "logSource": "System",
            "investigationTips": [
                "Investigate service startup failures",
                "Check for service tampering",
                "Review service integrity and configuration",
                "Monitor for malware affecting services"
            ],
            "relatedEvents": ["7031", "7032", "7034"],
            "mitreTactics": ["Defense Evasion", "Impact"],
            "commonCauses": ["Service corruption", "System issues", "Malware interference"],
            "falsePositives": ["Configuration issues", "System resource problems"],

        }
        {
            "id": "7031",
            "name": "Service Control Manager - Service Crashed",
            "description": "Service Control Manager reported a service crash. Critical for monitoring service stability and attacks.",
            "category": "Service Management",
            "criticality": "High",
            "logSource": "System",
            "investigationTips": [
                "Investigate service crashes",
                "Check for malware causing crashes",
                "Review service crash patterns",
                "Monitor for targeted service attacks"
            ],
            "relatedEvents": ["7030", "7032", "7034"],
            "mitreTactics": ["Impact", "Defense Evasion"],
            "commonCauses": ["Service attacks", "System instability", "Malware activity"],
            "falsePositives": ["System resource issues", "Software bugs"],

        }
        {
            "id": "7032",
            "name": "Service Control Manager - Service Failed to Start",
            "description": "Service Control Manager reported a service failed to start. Important for monitoring service availability.",
            "category": "Service Management",
            "criticality": "Medium",
            "logSource": "System",
            "investigationTips": [
                "Monitor service start failures",
                "Check for service tampering",
                "Review service dependencies",
                "Correlate with system changes"
            ],
            "relatedEvents": ["7030", "7031", "7034"],
            "mitreTactics": ["Impact", "Defense Evasion"],
            "commonCauses": ["Configuration issues", "Service corruption", "System problems"],
            "falsePositives": ["Normal startup issues", "Configuration problems"],

        }
        {
            "id": "7040",
            "name": "Service Control Manager - Service Start Type Changed",
            "description": "Service Control Manager reported a service start type change. Critical for monitoring service persistence modifications.",
            "category": "Service Management",
            "criticality": "High",
            "logSource": "System",
            "investigationTips": [
                "Monitor service start type changes",
                "Check for persistence modifications",
                "Review unauthorized service changes",
                "Correlate with malware activity"
            ],
            "relatedEvents": ["4697", "7034", "7036"],
            "mitreTactics": ["Persistence", "Defense Evasion"],
            "commonCauses": ["Administrative changes", "Malware persistence", "System configuration"],
            "falsePositives": ["Legitimate administrative changes", "System updates"]
        },
        # Final Missing Critical Events
        {
            "id": "4721",
            "name": "User Account Enabled",
            "description": "A user account was enabled. Critical for monitoring account activation and access management.",
            "category": "Account Management",
            "criticality": "Medium",
            "logSource": "Security",
            "investigationTips": [
                "Monitor account enablement patterns",
                "Check for unauthorized account activation",
                "Review account enable authorization",
                "Correlate with administrative activities"
            ],
            "relatedEvents": ["4720", "4722", "4723", "4725"],
            "mitreTactics": ["Persistence", "Initial Access"],
            "commonCauses": ["Administrative tasks", "Account management", "User onboarding"],
            "falsePositives": ["Legitimate account management", "Administrative operations"]
        },
        {
            "id": "4736",
            "name": "Computer Account Changed",
            "description": "A computer account was changed. Important for monitoring computer object modifications in Active Directory.",
            "category": "Account Management",
            "criticality": "Medium",
            "logSource": "Security",
            "investigationTips": [
                "Monitor computer account modifications",
                "Check for unauthorized computer changes",
                "Review computer object attribute changes",
                "Correlate with domain administration"
            ],
            "relatedEvents": ["4741", "4742", "4743"],
            "mitreTactics": ["Persistence", "Defense Evasion"],
            "commonCauses": ["Domain administration", "Computer management", "System updates"],
            "falsePositives": ["Normal domain operations", "Administrative tasks"]
        },
        # Critical Missing Events - Workstation Security
        {
            "id": "4800",
            "name": "Workstation Locked",
            "description": "The workstation was locked. Critical for monitoring user session security and physical access control.",
            "category": "Session Management",
            "criticality": "Low",
            "logSource": "Security",
            "investigationTips": [
                "Monitor workstation lock patterns",
                "Check for unusual lock timing",
                "Review session security compliance",
                "Correlate with user activity"
            ],
            "relatedEvents": ["4801", "4802", "4803"],
            "mitreTactics": ["Defense Evasion"],
            "commonCauses": ["User security practice", "Policy enforcement", "Automatic locking"],
            "falsePositives": ["Normal user behavior", "Security policy compliance"],

        }
        {
            "id": "4801",
            "name": "Workstation Unlocked",
            "description": "The workstation was unlocked. Important for monitoring session resumption and access control.",
            "category": "Session Management",
            "criticality": "Low",
            "logSource": "Security",
            "investigationTips": [
                "Monitor unlock patterns and timing",
                "Check for unauthorized access",
                "Review unlock methods used",
                "Correlate with user presence"
            ],
            "relatedEvents": ["4800", "4802", "4803"],
            "mitreTactics": ["Initial Access"],
            "commonCauses": ["Normal user activity", "Session resumption", "Authentication"],
            "falsePositives": ["Normal user behavior", "Legitimate access"],

        }
        {
            "id": "4802",
            "name": "Screen Saver Invoked",
            "description": "The screen saver was invoked. Useful for monitoring workstation activity and security compliance.",
            "category": "Session Management",
            "criticality": "Low",
            "logSource": "Security",
            "investigationTips": [
                "Monitor screen saver activation patterns",
                "Check for security policy compliance",
                "Review workstation activity timing",
                "Correlate with user productivity"
            ],
            "relatedEvents": ["4800", "4801", "4803"],
            "mitreTactics": ["Defense Evasion"],
            "commonCauses": ["User inactivity", "Security policy", "Power management"],
            "falsePositives": ["Normal system behavior", "Policy compliance"],

        }
        {
            "id": "4803",
            "name": "Screen Saver Dismissed",
            "description": "The screen saver was dismissed. Important for monitoring workstation activity resumption.",
            "category": "Session Management",
            "criticality": "Low",
            "logSource": "Security",
            "investigationTips": [
                "Monitor screen saver dismissal patterns",
                "Check for unauthorized activity",
                "Review workstation usage patterns",
                "Correlate with authentication events"
            ],
            "relatedEvents": ["4800", "4801", "4802"],
            "mitreTactics": ["Initial Access"],
            "commonCauses": ["User activity resumption", "Input detection", "Normal usage"],
            "falsePositives": ["Normal user behavior", "Legitimate activity"],

        }
        # Windows Firewall Events
        {
            "id": "4946",
            "name": "Windows Firewall Exception List Rule Added",
            "description": "A rule was added to the Windows Firewall exception list. Critical for monitoring network security changes.",
            "category": "Firewall Management",
            "criticality": "High",
            "logSource": "Security",
            "investigationTips": [
                "Monitor firewall rule additions",
                "Check for unauthorized exceptions",
                "Review rule configurations and scope",
                "Correlate with malware activity"
            ],
            "relatedEvents": ["4947", "4948", "4949"],
            "mitreTactics": ["Defense Evasion", "Command and Control"],
            "commonCauses": ["Software installation", "Administrative changes", "Malware activity"],
            "falsePositives": ["Legitimate software", "Administrative tasks"],

        }
        {
            "id": "4947",
            "name": "Windows Firewall Exception List Rule Modified",
            "description": "A rule in the Windows Firewall exception list was modified. Important for monitoring firewall security changes.",
            "category": "Firewall Management",
            "criticality": "High",
            "logSource": "Security",
            "investigationTips": [
                "Monitor firewall rule modifications",
                "Check for security weakening changes",
                "Review rule parameter changes",
                "Correlate with system compromise"
            ],
            "relatedEvents": ["4946", "4948", "4949"],
            "mitreTactics": ["Defense Evasion", "Persistence"],
            "commonCauses": ["Configuration updates", "Security adjustments", "Malicious modifications"],
            "falsePositives": ["Legitimate updates", "Security improvements"],

        }
        {
            "id": "4948",
            "name": "Windows Firewall Exception List Rule Deleted",
            "description": "A rule was deleted from the Windows Firewall exception list. Important for monitoring security policy changes.",
            "category": "Firewall Management",
            "criticality": "Medium",
            "logSource": "Security",
            "investigationTips": [
                "Monitor firewall rule deletions",
                "Check for security hardening or weakening",
                "Review deleted rule configurations",
                "Correlate with administrative activities"
            ],
            "relatedEvents": ["4946", "4947", "4949"],
            "mitreTactics": ["Defense Evasion", "Impact"],
            "commonCauses": ["Security cleanup", "Configuration changes", "Administrative tasks"],
            "falsePositives": ["Security improvements", "Legitimate cleanup"],

        }
        {
            "id": "4949",
            "name": "Windows Firewall Settings Restored to Default",
            "description": "Windows Firewall settings were restored to default values. Critical for monitoring major security changes.",
            "category": "Firewall Management",
            "criticality": "High",
            "logSource": "Security",
            "investigationTips": [
                "Investigate firewall reset events",
                "Check for unauthorized configuration changes",
                "Review security impact of default settings",
                "Correlate with system compromise or recovery"
            ],
            "relatedEvents": ["4946", "4947", "4948"],
            "mitreTactics": ["Defense Evasion", "Impact"],
            "commonCauses": ["System recovery", "Security reset", "Administrative action"],
            "falsePositives": ["Legitimate system recovery", "Security hardening"],

        }
        # Security Enumeration Events
        {
            "id": "4798",
            "name": "User's Local Group Membership Enumerated",
            "description": "A user's local group membership was enumerated. Critical for detecting reconnaissance activities.",
            "category": "Reconnaissance",
            "criticality": "Medium",
            "logSource": "Security",
            "investigationTips": [
                "Monitor group enumeration activities",
                "Check for unauthorized reconnaissance",
                "Review enumeration patterns and frequency",
                "Correlate with privilege escalation attempts"
            ],
            "relatedEvents": ["4799", "4732", "4756"],
            "mitreTactics": ["Discovery", "Reconnaissance"],
            "commonCauses": ["Administrative tools", "Security audits", "Malicious reconnaissance"],
            "falsePositives": ["Legitimate administration", "Security tools"],

        }
        {
            "id": "4799",
            "name": "Security-Enabled Local Group Membership Enumerated",
            "description": "A security-enabled local group membership was enumerated. Important for detecting privilege reconnaissance.",
            "category": "Reconnaissance",
            "criticality": "Medium",
            "logSource": "Security",
            "investigationTips": [
                "Monitor security group enumeration",
                "Check for privilege escalation reconnaissance",
                "Review enumeration tools and methods",
                "Correlate with attack progression"
            ],
            "relatedEvents": ["4798", "4735", "4732"],
            "mitreTactics": ["Discovery", "Privilege Escalation"],
            "commonCauses": ["Security audits", "Administrative tools", "Attack reconnaissance"],
            "falsePositives": ["Legitimate security tools", "Administrative tasks"],

        }
        # System Events
        {
            "id": "1076",
            "name": "System Shutdown Initiated by User",
            "description": "The system shutdown was initiated by a user. Important for monitoring system availability and user actions.",
            "category": "System Management",
            "criticality": "Low",
            "logSource": "System",
            "investigationTips": [
                "Monitor shutdown patterns and timing",
                "Check for unauthorized shutdowns",
                "Review shutdown initiation methods",
                "Correlate with user activity and presence"
            ],
            "relatedEvents": ["1074", "6005", "6006"],
            "mitreTactics": ["Impact"],
            "commonCauses": ["Normal user activity", "Maintenance", "Emergency shutdown"],
            "falsePositives": ["Normal operations", "Scheduled maintenance"],

        }
        {
            "id": "7045",
            "name": "Service Installed in System",
            "description": "A service was installed in the system. Critical for monitoring service-based persistence and malware.",
            "category": "Service Management",
            "criticality": "High",
            "logSource": "System",
            "investigationTips": [
                "Monitor service installation activities",
                "Check for unauthorized or suspicious services",
                "Review service configurations and executables",
                "Correlate with malware installation patterns"
            ],
            "relatedEvents": ["4697", "7034", "7036"],
            "mitreTactics": ["Persistence", "Defense Evasion"],
            "commonCauses": ["Software installation", "System updates", "Malware persistence"],
            "falsePositives": ["Legitimate software", "System updates"]
        }
    ]
    
    return events_data

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
    
    # Get events data
    events = get_events_data()
    
    print(f"Generating markdown files for {len(events)} events...")
    
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