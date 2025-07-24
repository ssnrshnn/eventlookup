// Comprehensive Windows Event ID Database
const eventDatabase = [
    // Authentication Events
    {
        id: "4624",
        name: "Successful Logon",
        description: "An account was successfully logged on. This event is generated when a logon session is created.",
        category: "Authentication",
        criticality: "Medium",
        logSource: "Security",
        investigationTips: [
            "Monitor for unusual logon times (outside business hours)",
            "Check logon type - Type 10 (RDP) especially critical",
            "Correlate with failed logon attempts",
            "Review source IP addresses for external connections"
        ],
        relatedEvents: ["4625", "4634", "4647", "4648"],
        mitreTactics: ["Initial Access", "Lateral Movement"],
        commonCauses: ["User authentication", "Service account logon", "Scheduled tasks"],
        falsePositives: ["Normal user activity", "Service account operations"],
        investigationPlaybook: {
            immediate: {
                title: "Immediate Triage (0-15 minutes)",
                priority: "Medium",
                steps: [
                    {
                        action: "Check logon type and method",
                        tool: "Event log analysis",
                        expected: "Identify logon type (2=Interactive, 3=Network, 10=RDP, 4=Batch, 5=Service)",
                        query: "Examine LogonType field in event details"
                    },
                    {
                        action: "Verify source IP legitimacy",
                        tool: "Network analysis, GeoIP",
                        expected: "Confirm if source location matches expected user location",
                        query: "geoiplookup [source_ip] and compare with user's typical locations"
                    },
                    {
                        action: "Check for preceding failed attempts",
                        tool: "SIEM correlation",
                        expected: "Identify if successful logon followed multiple failures",
                        query: "index=security EventCode=4625 user=[username] earliest=-1h | head 10"
                    },
                    {
                        action: "Review logon timing",
                        tool: "Time analysis",
                        expected: "Determine if logon occurred during expected hours",
                        query: "Compare logon time with user's typical work schedule"
                    }
                ]
            },
            shortTerm: {
                title: "Context Analysis (15-60 minutes)",
                priority: "Medium",
                steps: [
                    {
                        action: "Profile user's typical logon pattern",
                        tool: "User behavior analytics",
                        expected: "Establish baseline for comparison",
                        query: "index=security EventCode=4624 user=[username] earliest=-30d | stats count by src_ip, hour"
                    },
                    {
                        action: "Check for privilege escalation",
                        tool: "Security log correlation",
                        expected: "Identify any administrative actions post-logon",
                        query: "index=security EventCode=4672 user=[username] earliest=[logon_time]"
                    },
                    {
                        action: "Review concurrent sessions",
                        tool: "Session monitoring",
                        expected: "Identify multiple active sessions from different locations",
                        query: "index=security EventCode=4624 user=[username] earliest=-1h | stats dc(src_ip)"
                    },
                    {
                        action: "Analyze post-logon activity",
                        tool: "Process monitoring, file access",
                        expected: "Review actions taken immediately after logon",
                        query: "index=sysmon EventCode=1 user=[username] earliest=[logon_time]"
                    }
                ]
            },
            longTerm: {
                title: "Extended Investigation (1+ hours)",
                priority: "Low",
                steps: [
                    {
                        action: "Historical pattern analysis",
                        tool: "UEBA, analytics platform",
                        expected: "Identify long-term behavioral anomalies",
                        query: "Analyze 90-day user behavior patterns for deviations"
                    },
                    {
                        action: "Cross-reference with threat intelligence",
                        tool: "Threat feeds, IOC databases",
                        expected: "Link source IPs/patterns to known threats",
                        query: "Search for source IP in threat intelligence feeds"
                    },
                    {
                        action: "Document normal vs suspicious patterns",
                        tool: "Case management",
                        expected: "Update user profile and detection rules if needed",
                        query: "Create documentation for future reference"
                    }
                ]
            }
        }
    },
    {
        id: "4625",
        name: "Failed Logon",
        description: "An account failed to log on. This is a critical event for detecting brute force attacks.",
        category: "Authentication",
        criticality: "High",
        logSource: "Security",
        investigationTips: [
            "Multiple failures from same source = potential brute force",
            "Check failure reason (wrong password vs account locked)",
            "Monitor for patterns (timing, source IPs)",
            "Investigate successful logons after multiple failures"
        ],
        relatedEvents: ["4624", "4740", "4771"],
        mitreTactics: ["Credential Access"],
        commonCauses: ["Password attacks", "Account enumeration", "Mistyped passwords"],
        falsePositives: ["User password mistakes", "Cached credential issues"],
        investigationPlaybook: {
            immediate: {
                title: "Immediate Response (0-15 minutes)",
                priority: "Critical",
                steps: [
                    {
                        action: "Check source IP reputation",
                        tool: "VirusTotal, AbuseIPDB, Threat Intel",
                        expected: "Determine if source IP is known malicious",
                        query: "Search IP in threat intelligence feeds"
                    },
                    {
                        action: "Verify target account status",
                        tool: "Active Directory, LDAP",
                        expected: "Confirm account exists and is active",
                        query: "Get-ADUser -Identity [username] -Properties *"
                    },
                    {
                        action: "Check failure reason code",
                        tool: "Event log analysis",
                        expected: "Identify specific failure type (0xC000006D = bad password, 0xC0000234 = account locked)",
                        query: "Status code analysis from event details"
                    },
                    {
                        action: "Count recent failures from same source",
                        tool: "SIEM, Event Logs",
                        expected: "Identify if this is part of a pattern (>5 failures = potential attack)",
                        query: "index=security EventCode=4625 src_ip=[IP] | stats count by user"
                    }
                ]
            },
            shortTerm: {
                title: "Short-term Analysis (15-60 minutes)",
                priority: "High",
                steps: [
                    {
                        action: "Search for successful logons from same source",
                        tool: "SIEM query",
                        expected: "Determine if attack was successful",
                        query: "index=security EventCode=4624 src_ip=[IP] earliest=-4h"
                    },
                    {
                        action: "Analyze time patterns",
                        tool: "Timeline analysis",
                        expected: "Identify attack duration and frequency",
                        query: "Plot failure attempts over time for pattern recognition"
                    },
                    {
                        action: "Check for account lockouts",
                        tool: "Security logs",
                        expected: "Verify if account was locked due to failures",
                        query: "index=security EventCode=4740 user=[username]"
                    },
                    {
                        action: "Review other targeted accounts",
                        tool: "Log correlation",
                        expected: "Identify if multiple accounts targeted (indicates scanning)",
                        query: "index=security EventCode=4625 src_ip=[IP] | stats dc(user) as unique_users"
                    }
                ]
            },
            longTerm: {
                title: "Long-term Investigation (1+ hours)",
                priority: "Medium",
                steps: [
                    {
                        action: "Geolocation analysis",
                        tool: "IP geolocation services",
                        expected: "Verify if login location matches user's typical pattern",
                        query: "Compare source location with user's historical login patterns"
                    },
                    {
                        action: "Correlate with threat intelligence",
                        tool: "MISP, threat feeds",
                        expected: "Link to known campaigns or threat actors",
                        query: "Search for IOCs related to source IP or attack pattern"
                    },
                    {
                        action: "Document incident",
                        tool: "SOAR platform, ticketing",
                        expected: "Create incident record with findings and recommendations",
                        query: "Generate incident report with timeline and IOCs"
                    },
                    {
                        action: "Implement containment measures",
                        tool: "Firewall, EDR",
                        expected: "Block malicious IPs and strengthen affected accounts",
                        query: "Add IP to blocklist, force password reset if needed"
                    }
                ]
            }
        }
    },
    {
        id: "4634",
        name: "Account Logged Off",
        description: "An account was logged off. Indicates session termination.",
        category: "Authentication",
        criticality: "Low",
        logSource: "Security",
        investigationTips: [
            "Correlate with logon events for session duration",
            "Unexpected logoffs may indicate compromise",
            "Review for administrative account usage patterns"
        ],
        relatedEvents: ["4624", "4647"],
        mitreTactics: [],
        commonCauses: ["Normal user logoff", "Session timeout", "System restart"],
        falsePositives: ["Automatic logoffs", "Network disconnections"]
    },
    {
        id: "4647",
        name: "User Initiated Logoff",
        description: "User initiated logoff. Normal user activity indicator.",
        category: "Authentication",
        criticality: "Low",
        logSource: "Security",
        investigationTips: [
            "Normal behavior baseline",
            "Unexpected patterns may indicate compromise",
            "Compare with automated logoffs (4634)"
        ],
        relatedEvents: ["4624", "4634"],
        mitreTactics: [],
        commonCauses: ["User action", "Application shutdown"],
        falsePositives: ["None - normal activity"]
    },
    {
        id: "4648",
        name: "Logon Using Explicit Credentials",
        description: "A logon was attempted using explicit credentials. Often indicates RunAs or credential delegation.",
        category: "Authentication",
        criticality: "Medium",
        logSource: "Security",
        investigationTips: [
            "Monitor for privilege escalation attempts",
            "Check if credentials match current user context",
            "Review target account privileges",
            "Correlate with process creation events"
        ],
        relatedEvents: ["4624", "4688"],
        mitreTactics: ["Privilege Escalation", "Lateral Movement"],
        commonCauses: ["RunAs commands", "Scheduled tasks", "Service operations"],
        falsePositives: ["Legitimate admin operations", "Service account usage"],
        investigationPlaybook: {
            immediate: {
                title: "Explicit Credential Usage Investigation",
                priority: "Medium",
                steps: [
                    {
                        action: "Identify the explicit credential usage details",
                        tool: "Windows Event Viewer, SIEM",
                        expected: "Find who used explicit credentials and what target account was used",
                        query: "Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4648} | Select-Object TimeCreated, SubjectUserName, TargetUserName, ProcessName"
                    },
                    {
                        action: "Check if credential usage is authorized",
                        tool: "Active Directory, privilege analysis",
                        expected: "Verify if the user should have access to the target account credentials",
                        query: "Get-ADUser [subject_user] -Properties MemberOf | Compare-Object with target account permissions"
                    },
                    {
                        action: "Analyze the process that used explicit credentials",
                        tool: "Process monitoring, security logs",
                        expected: "Understand what application or command triggered the credential usage",
                        query: "Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} | Where-Object {$_.TimeCreated -eq '[event_time]'}"
                    },
                    {
                        action: "Look for pass-the-hash indicators",
                        tool: "Authentication analysis, credential monitoring",
                        expected: "Detect if credentials were obtained through credential dumping",
                        query: "index=security (EventCode=4624 OR EventCode=4648) LogonType=9 | stats count by user, src_ip"
                    }
                ]
            },
            shortTerm: {
                title: "Credential Delegation and Lateral Movement Analysis",
                priority: "Medium",
                steps: [
                    {
                        action: "Check for concurrent authentication activities",
                        tool: "Authentication logs, correlation analysis",
                        expected: "Find related logon events that might indicate lateral movement",
                        query: "index=security EventCode=4624 (user=[subject_user] OR user=[target_user]) earliest=-30m latest=+30m"
                    },
                    {
                        action: "Analyze target system access patterns",
                        tool: "Network logs, system monitoring",
                        expected: "Understand what resources were accessed with explicit credentials",
                        query: "Search for network connections and file access following credential usage"
                    },
                    {
                        action: "Review privilege escalation attempts",
                        tool: "Security logs, privilege monitoring",
                        expected: "Identify if explicit credentials led to elevated privileges",
                        query: "index=security EventCode=4672 user=[target_user] earliest=[event_time]"
                    },
                    {
                        action: "Check for persistence mechanisms",
                        tool: "System logs, persistence analysis",
                        expected: "Find if explicit credentials were used to create persistence",
                        query: "index=system EventCode=7045 earliest=[event_time] | search [target_user]"
                    }
                ]
            },
            longTerm: {
                title: "Credential Security Assessment",
                priority: "Low",
                steps: [
                    {
                        action: "Review credential delegation policies",
                        tool: "Group Policy, security policy analysis",
                        expected: "Ensure proper controls for credential delegation",
                        query: "Audit policies for credential delegation and RunAs permissions"
                    },
                    {
                        action: "Implement enhanced credential monitoring",
                        tool: "SIEM rules, credential protection",
                        expected: "Detect future unauthorized credential usage",
                        query: "Create alerts for unusual explicit credential usage patterns"
                    },
                    {
                        action: "Consider implementing Credential Guard",
                        tool: "Windows Defender Credential Guard",
                        expected: "Protect against credential theft and pass-the-hash attacks",
                        query: "Evaluate and implement Windows Defender Credential Guard"
                    },
                    {
                        action: "Conduct credential hygiene review",
                        tool: "Password management, access review",
                        expected: "Improve overall credential security posture",
                        query: "Review shared accounts, service accounts, and credential policies"
                    }
                ]
            }
        }
    },
    {
        id: "4768",
        name: "Kerberos TGT Requested",
        description: "A Kerberos authentication ticket (TGT) was requested. Initial domain authentication.",
        category: "Authentication",
        criticality: "Medium",
        logSource: "Security",
        investigationTips: [
            "Monitor for unusual requesting times",
            "Check encryption types used",
            "Correlate with subsequent service ticket requests",
            "Review pre-authentication status"
        ],
        relatedEvents: ["4769", "4771", "4776"],
        mitreTactics: ["Initial Access"],
        commonCauses: ["Domain logon", "Service authentication"],
        falsePositives: ["Normal domain operations"],
        investigationPlaybook: {
            immediate: {
                title: "Kerberos TGT and Golden Ticket Investigation",
                priority: "High",
                steps: [
                    {
                        action: "Analyze TGT request details and anomalies",
                        tool: "Windows Event Viewer, SIEM",
                        expected: "Find unusual TGT requests, encryption types, and timing patterns",
                        query: "Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4768} | Select-Object TimeCreated, TargetUserName, IpAddress, TicketEncryptionType"
                    },
                    {
                        action: "Check for Golden Ticket indicators",
                        tool: "Kerberos analysis, anomaly detection",
                        expected: "Identify signs of forged TGT tickets and unusual encryption",
                        query: "index=security EventCode=4768 | eval lifetime=case(TicketOptions=\"0x40810010\",\"10hours\",TicketOptions=\"0x60810010\",\"7days\") | where lifetime=\"7days\""
                    },
                    {
                        action: "Verify user account legitimacy and status",
                        tool: "Active Directory, account validation",
                        expected: "Confirm account exists and is not disabled or suspicious",
                        query: "Get-ADUser [target_user] -Properties LastLogonDate, PasswordLastSet, AccountExpirationDate, Enabled"
                    },
                    {
                        action: "Analyze source IP and client information",
                        tool: "Network analysis, IP reputation",
                        expected: "Verify if TGT request comes from expected location",
                        query: "Check client IP against known user workstations and geographic location"
                    }
                ]
            },
            shortTerm: {
                title: "Kerberoasting and Domain Compromise Analysis",
                priority: "High",
                steps: [
                    {
                        action: "Search for Kerberoasting attack patterns",
                        tool: "Service ticket correlation, attack detection",
                        expected: "Find mass service ticket requests following TGT",
                        query: "index=security EventCode=4769 user=[target_user] earliest=-1h | stats dc(ServiceName) as services by user | where services > 10"
                    },
                    {
                        action: "Check for domain controller compromise indicators",
                        tool: "DC security analysis, krbtgt account monitoring",
                        expected: "Identify signs of DC compromise or krbtgt password issues",
                        query: "Search for krbtgt password changes and DC security events"
                    },
                    {
                        action: "Analyze encryption downgrade attempts",
                        tool: "Encryption analysis, security degradation",
                        expected: "Detect attempts to use weaker encryption for cracking",
                        query: "index=security EventCode=4768 TicketEncryptionType=0x17 | stats count by user"
                    },
                    {
                        action: "Review concurrent authentication activities",
                        tool: "Timeline analysis, multi-event correlation",
                        expected: "Understand full authentication flow and anomalies",
                        query: "index=security (EventCode=4768 OR EventCode=4769 OR EventCode=4624) user=[target_user] earliest=-2h | sort _time"
                    }
                ]
            },
            longTerm: {
                title: "Kerberos Security Hardening and Monitoring",
                priority: "Medium",
                steps: [
                    {
                        action: "Implement enhanced Kerberos monitoring",
                        tool: "SIEM rules, Kerberos analysis tools",
                        expected: "Create alerts for suspicious Kerberos activities",
                        query: "Configure alerts for unusual TGT requests, encryption downgrades, and mass service tickets"
                    },
                    {
                        action: "Review and rotate krbtgt account passwords",
                        tool: "Domain controller management, password rotation",
                        expected: "Invalidate any potential Golden Tickets",
                        query: "Reset krbtgt password twice to invalidate all existing tickets"
                    },
                    {
                        action: "Implement Kerberos security best practices",
                        tool: "Group Policy, Kerberos configuration",
                        expected: "Strengthen Kerberos authentication security",
                        query: "Enable Kerberos armoring, enforce strong encryption, implement PAC validation"
                    },
                    {
                        action: "Deploy advanced Kerberos protection",
                        tool: "Microsoft Defender for Identity, privileged access",
                        expected: "Detect advanced Kerberos attacks in real-time",
                        query: "Implement Microsoft Defender for Identity and configure Kerberos attack detection"
                    }
                ]
            }
        }
    },
    {
        id: "4769",
        name: "Kerberos Service Ticket Requested",
        description: "A Kerberos service ticket was requested. Service access authentication.",
        category: "Authentication",
        criticality: "Low",
        logSource: "Security",
        investigationTips: [
            "Monitor for unusual service access patterns",
            "Check requested service names",
            "Review encryption types",
            "Correlate with network access events"
        ],
        relatedEvents: ["4768", "4771"],
        mitreTactics: ["Lateral Movement"],
        commonCauses: ["Service access", "Network resource access"],
        falsePositives: ["Normal service operations"],
        investigationPlaybook: {
            immediate: {
                title: "Kerberos Service Ticket and Silver Ticket Investigation",
                priority: "Medium",
                steps: [
                    {
                        action: "Analyze service ticket request details",
                        tool: "Windows Event Viewer, SIEM",
                        expected: "Find service name, user, and unusual access patterns",
                        query: "Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4769} | Select-Object TimeCreated, TargetUserName, ServiceName, TicketEncryptionType, IpAddress"
                    },
                    {
                        action: "Check for Silver Ticket attack indicators",
                        tool: "Service ticket analysis, anomaly detection",
                        expected: "Identify forged service tickets and suspicious service access",
                        query: "index=security EventCode=4769 | where ServiceName!=\"krbtgt\" AND (match(ServiceName,\"^[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12}$\") OR len(ServiceName)>50)"
                    },
                    {
                        action: "Verify service account legitimacy",
                        tool: "Active Directory, service account validation",
                        expected: "Confirm requested service exists and user should have access",
                        query: "Get-ADComputer [service_computer] -Properties ServicePrincipalNames | Select-Object ServicePrincipalNames"
                    },
                    {
                        action: "Analyze Kerberoasting patterns",
                        tool: "Service ticket correlation, mass request detection",
                        expected: "Detect bulk service ticket requests indicating Kerberoasting",
                        query: "index=security EventCode=4769 user=[target_user] earliest=-1h | stats dc(ServiceName) as unique_services, count by user | where unique_services > 5"
                    }
                ]
            },
            shortTerm: {
                title: "Lateral Movement and Service Account Analysis",
                priority: "Medium",
                steps: [
                    {
                        action: "Track lateral movement via service tickets",
                        tool: "Network correlation, service access tracking",
                        expected: "Map user movement across domain services and systems",
                        query: "index=security EventCode=4769 user=[target_user] earliest=-4h | stats values(ServiceName) by IpAddress | sort IpAddress"
                    },
                    {
                        action: "Investigate service account privilege abuse",
                        tool: "Privilege analysis, service account monitoring",
                        expected: "Identify if service accounts are being misused for privilege escalation",
                        query: "Search for service accounts accessing unusual resources or elevated privileges"
                    },
                    {
                        action: "Check for encryption downgrade attacks",
                        tool: "Encryption analysis, security assessment",
                        expected: "Detect attempts to request weaker encryption for offline cracking",
                        query: "index=security EventCode=4769 TicketEncryptionType=0x17 | stats count by ServiceName, user"
                    },
                    {
                        action: "Correlate with network and logon activities",
                        tool: "Multi-log correlation, timeline analysis",
                        expected: "Understand full attack chain and service access context",
                        query: "index=security (EventCode=4624 OR EventCode=4769) user=[target_user] earliest=-2h | sort _time"
                    }
                ]
            },
            longTerm: {
                title: "Service Security and Kerberoasting Prevention",
                priority: "Low",
                steps: [
                    {
                        action: "Audit and secure service accounts",
                        tool: "Service account management, password policy",
                        expected: "Strengthen service account security against Kerberoasting",
                        query: "Review service account passwords, implement managed service accounts (MSA/gMSA)"
                    },
                    {
                        action: "Implement service ticket monitoring",
                        tool: "SIEM rules, service access analytics",
                        expected: "Detect suspicious service ticket request patterns",
                        query: "Configure alerts for bulk service ticket requests and unusual service access"
                    },
                    {
                        action: "Deploy service account protection",
                        tool: "Privileged Access Management, service hardening",
                        expected: "Protect high-value service accounts from compromise",
                        query: "Implement least privilege for service accounts and regular password rotation"
                    },
                    {
                        action: "Monitor for advanced Kerberos attacks",
                        tool: "Advanced threat detection, behavior analytics",
                        expected: "Detect sophisticated Kerberos-based lateral movement",
                        query: "Deploy behavioral analytics for Kerberos ticket usage patterns"
                    }
                ]
            }
        }
    },
    {
        id: "4771",
        name: "Kerberos Pre-authentication Failed",
        description: "Kerberos pre-authentication failed. Often indicates password attacks on domain accounts.",
        category: "Authentication",
        criticality: "High",
        logSource: "Security",
        investigationTips: [
            "High indicator of password spray/brute force attacks",
            "Monitor for multiple failures across different accounts",
            "Check source IP addresses",
            "Review targeted account names for patterns"
        ],
        relatedEvents: ["4768", "4625"],
        mitreTactics: ["Credential Access"],
        commonCauses: ["Password attacks", "Expired passwords", "Clock skew"],
        falsePositives: ["Time synchronization issues", "Password changes"]
    },
    {
        id: "4776",
        name: "NTLM Authentication",
        description: "Computer attempted to validate credentials for an account using NTLM.",
        category: "Authentication",
        criticality: "Medium",
        logSource: "Security",
        investigationTips: [
            "NTLM usage may indicate legacy systems",
            "Monitor for pass-the-hash attacks",
            "Review authentication sources",
            "Check for downgrade attacks from Kerberos"
        ],
        relatedEvents: ["4768", "4625"],
        mitreTactics: ["Lateral Movement", "Credential Access"],
        commonCauses: ["Legacy system access", "Local authentication"],
        falsePositives: ["Normal legacy application usage"],
        investigationPlaybook: {
            immediate: {
                title: "NTLM and Pass-the-Hash Investigation",
                priority: "High",
                steps: [
                    {
                        action: "Analyze NTLM authentication details",
                        tool: "Windows Event Viewer, SIEM",
                        expected: "Find user, source workstation, and authentication context",
                        query: "Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4776} | Select-Object TimeCreated, TargetUserName, Workstation, Status"
                    },
                    {
                        action: "Check for pass-the-hash attack indicators",
                        tool: "NTLM analysis, attack pattern detection",
                        expected: "Identify suspicious NTLM usage patterns and source systems",
                        query: "index=security EventCode=4776 | stats dc(Workstation) as systems, count by TargetUserName | where systems > 3 AND count > 10"
                    },
                    {
                        action: "Verify source workstation legitimacy",
                        tool: "Network analysis, asset management",
                        expected: "Confirm source workstation is authorized and known",
                        query: "Check if source workstation is in asset inventory and verify user normally uses this system"
                    },
                    {
                        action: "Analyze authentication success/failure patterns",
                        tool: "Authentication correlation, pattern analysis",
                        expected: "Understand if NTLM auth was successful and any related failures",
                        query: "index=security (EventCode=4776 OR EventCode=4625) user=[target_user] earliest=-1h | stats count by Status, EventCode"
                    }
                ]
            },
            shortTerm: {
                title: "Lateral Movement and Credential Theft Analysis",
                priority: "High",
                steps: [
                    {
                        action: "Track lateral movement via NTLM",
                        tool: "Network correlation, lateral movement detection",
                        expected: "Map user movement across systems using NTLM authentication",
                        query: "index=security EventCode=4776 user=[target_user] earliest=-4h | stats values(Workstation) by hour | sort hour"
                    },
                    {
                        action: "Search for credential dumping activities",
                        tool: "Process monitoring, credential access detection",
                        expected: "Find evidence of tools like Mimikatz or credential dumping",
                        query: "index=security EventCode=4688 (CommandLine=\"*mimikatz*\" OR CommandLine=\"*sekurlsa*\" OR CommandLine=\"*lsadump*\") earliest=-24h"
                    },
                    {
                        action: "Check for NTLM relay attack indicators",
                        tool: "Network traffic analysis, SMB monitoring",
                        expected: "Detect NTLM relay attacks and suspicious SMB authentication",
                        query: "Analyze SMB traffic for NTLM relay patterns and authentication forwarding"
                    },
                    {
                        action: "Review privileged account usage",
                        tool: "Privilege monitoring, admin account tracking",
                        expected: "Identify if high-privilege accounts are being accessed via NTLM",
                        query: "index=security EventCode=4776 user=[admin_account] | stats count by Workstation, hour"
                    }
                ]
            },
            longTerm: {
                title: "NTLM Security Hardening and Legacy Migration",
                priority: "Medium",
                steps: [
                    {
                        action: "Audit and reduce NTLM usage",
                        tool: "Network analysis, protocol audit",
                        expected: "Identify systems still using NTLM and plan migration to Kerberos",
                        query: "Conduct NTLM usage audit and create migration plan to modern authentication"
                    },
                    {
                        action: "Implement NTLM monitoring and restrictions",
                        tool: "Group Policy, network security",
                        expected: "Restrict NTLM usage and enhance monitoring",
                        query: "Configure NTLM auditing policies and restrict NTLM in domain"
                    },
                    {
                        action: "Deploy credential protection mechanisms",
                        tool: "Windows Defender Credential Guard, LSASS protection",
                        expected: "Protect against credential theft and pass-the-hash attacks",
                        query: "Enable Credential Guard, LSASS protection, and credential delegation restrictions"
                    },
                    {
                        action: "Enhance network segmentation",
                        tool: "Network security, micro-segmentation",
                        expected: "Limit lateral movement capabilities through network controls",
                        query: "Implement network segmentation to limit NTLM-based lateral movement"
                    }
                ]
            }
        }
    },

    // Account Management Events
    {
        id: "4720",
        name: "User Account Created",
        description: "A user account was created. Critical for monitoring unauthorized account creation.",
        category: "Account Management",
        criticality: "High",
        logSource: "Security",
        investigationTips: [
            "Verify authorization for account creation",
            "Check account privileges and group memberships",
            "Review creator account permissions",
            "Monitor for immediate privileged access"
        ],
        relatedEvents: ["4722", "4728", "4732"],
        mitreTactics: ["Persistence", "Privilege Escalation"],
        commonCauses: ["New employee onboarding", "Service account creation"],
        falsePositives: ["Authorized HR processes", "Legitimate admin operations"],
        investigationPlaybook: {
            immediate: {
                title: "Unauthorized Account Creation Investigation",
                priority: "High",
                steps: [
                    {
                        action: "Identify the created account and creator",
                        tool: "Windows Event Viewer, SIEM",
                        expected: "Find details of new account and who created it",
                        query: "Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4720} | Select-Object TimeCreated, TargetUserName, SubjectUserName"
                    },
                    {
                        action: "Check authorization for account creation",
                        tool: "HR system, change management",
                        expected: "Verify if account creation was authorized and follows proper procedures",
                        query: "Cross-reference with HR onboarding tickets and change requests"
                    },
                    {
                        action: "Review account attributes and group memberships",
                        tool: "Active Directory, LDAP queries",
                        expected: "Examine account settings, groups, and initial privileges",
                        query: "Get-ADUser [new_username] -Properties * | Select-Object Name, Enabled, MemberOf, Created"
                    },
                    {
                        action: "Check creator account privileges",
                        tool: "Active Directory, privilege analysis",
                        expected: "Verify if creator has authority to create accounts",
                        query: "Get-ADUser [creator_username] -Properties MemberOf | Select-Object Name, MemberOf"
                    }
                ]
            },
            shortTerm: {
                title: "Account Activity and Privilege Analysis",
                priority: "Medium",
                steps: [
                    {
                        action: "Monitor immediate account usage",
                        tool: "Authentication logs, SIEM",
                        expected: "Check if new account was used immediately after creation",
                        query: "index=security EventCode=4624 TargetUserName=[new_username] earliest=[creation_time]"
                    },
                    {
                        action: "Check for privilege escalation attempts",
                        tool: "Security logs, privilege monitoring",
                        expected: "Identify if account was immediately given additional privileges",
                        query: "index=security (EventCode=4728 OR EventCode=4732) TargetUserName=[new_username]"
                    },
                    {
                        action: "Review password setting and policies",
                        tool: "Active Directory, password policy",
                        expected: "Verify password was set securely and follows policy",
                        query: "Get-ADUser [new_username] -Properties PasswordLastSet, PasswordNeverExpires"
                    },
                    {
                        action: "Examine account naming conventions",
                        tool: "AD analysis, naming policy review",
                        expected: "Check if account follows organizational naming standards",
                        query: "Review account name against organizational naming conventions"
                    }
                ]
            },
            longTerm: {
                title: "Account Lifecycle and Governance Review",
                priority: "Low",
                steps: [
                    {
                        action: "Implement account creation monitoring",
                        tool: "SIEM rules, identity governance",
                        expected: "Create alerts for all new account creation activities",
                        query: "Configure real-time alerting for EventID 4720 and related events"
                    },
                    {
                        action: "Review account provisioning process",
                        tool: "Identity management system, workflow analysis",
                        expected: "Ensure proper approval workflows for account creation",
                        query: "Audit account provisioning workflows and approval processes"
                    },
                    {
                        action: "Conduct account access review",
                        tool: "Identity governance, access certification",
                        expected: "Validate all recent account creations and their access rights",
                        query: "Perform quarterly review of all newly created accounts"
                    },
                    {
                        action: "Update account creation policies",
                        tool: "Policy management, governance framework",
                        expected: "Strengthen controls around account creation procedures",
                        query: "Review and update account creation policies and procedures"
                    }
                ]
            }
        }
    },
    {
        id: "4722",
        name: "User Account Enabled",
        description: "A user account was enabled. Monitor for unauthorized account activation.",
        category: "Account Management",
        criticality: "High",
        logSource: "Security",
        investigationTips: [
            "Verify business justification for enabling",
            "Check if account was previously disabled for security reasons",
            "Review account permissions after enabling",
            "Monitor subsequent logon activity"
        ],
        relatedEvents: ["4720", "4725"],
        mitreTactics: ["Persistence"],
        commonCauses: ["Employee return", "Account maintenance"],
        falsePositives: ["Routine account management", "Service restoration"]
    },
    {
        id: "4723",
        name: "Password Change Attempt",
        description: "An attempt was made to change an account's password.",
        category: "Account Management",
        criticality: "Medium",
        logSource: "Security",
        investigationTips: [
            "Monitor for unauthorized password changes",
            "Check who initiated the change",
            "Review timing patterns",
            "Correlate with security incidents"
        ],
        relatedEvents: ["4724", "4738"],
        mitreTactics: ["Credential Access", "Persistence"],
        commonCauses: ["User password updates", "Security policies"],
        falsePositives: ["Normal password maintenance"]
    },
    {
        id: "4724",
        name: "Password Reset Attempt",
        description: "An attempt was made to reset an account's password.",
        category: "Account Management",
        criticality: "Medium",
        logSource: "Security",
        investigationTips: [
            "Verify authorization for password reset",
            "Check if reset was requested by account owner",
            "Monitor for immediate account usage after reset",
            "Review reset frequency patterns"
        ],
        relatedEvents: ["4723", "4738"],
        mitreTactics: ["Credential Access"],
        commonCauses: ["Forgotten passwords", "Security incidents"],
        falsePositives: ["Help desk operations", "Self-service resets"]
    },
    {
        id: "4725",
        name: "User Account Disabled",
        description: "A user account was disabled. Important for tracking account lifecycle.",
        category: "Account Management",
        criticality: "Medium",
        logSource: "Security",
        investigationTips: [
            "Verify business justification for disabling",
            "Check for employee departure or security incident",
            "Monitor for attempts to re-enable",
            "Review associated access rights"
        ],
        relatedEvents: ["4722", "4726"],
        mitreTactics: [],
        commonCauses: ["Employee departure", "Security policy enforcement"],
        falsePositives: ["Routine account maintenance"]
    },
    {
        id: "4726",
        name: "User Account Deleted",
        description: "A user account was deleted. Critical for monitoring unauthorized account removal.",
        category: "Account Management",
        criticality: "High",
        logSource: "Security",
        investigationTips: [
            "Verify authorization for account deletion",
            "Check for data backup/transfer procedures",
            "Monitor for deletion of critical service accounts",
            "Review deletion timing patterns"
        ],
        relatedEvents: ["4725", "4720"],
        mitreTactics: ["Defense Evasion"],
        commonCauses: ["Employee departure cleanup", "Account housekeeping"],
        falsePositives: ["Authorized cleanup processes"]
    },
    {
        id: "4728",
        name: "Member Added to Global Group",
        description: "A member was added to a security-enabled global group.",
        category: "Account Management",
        criticality: "High",
        logSource: "Security",
        investigationTips: [
            "Monitor additions to privileged groups",
            "Verify authorization for group membership changes",
            "Check added account's previous privileges",
            "Review timing of membership changes"
        ],
        relatedEvents: ["4729", "4732", "4733"],
        mitreTactics: ["Privilege Escalation", "Persistence"],
        commonCauses: ["Role changes", "Project assignments"],
        falsePositives: ["Authorized access management"]
    },
    {
        id: "4729",
        name: "Member Removed from Global Group",
        description: "A member was removed from a security-enabled global group.",
        category: "Account Management",
        criticality: "High",
        logSource: "Security",
        investigationTips: [
            "Verify authorization for membership removal",
            "Check for security incident response",
            "Monitor for privilege escalation attempts",
            "Review removal timing and context"
        ],
        relatedEvents: ["4728", "4732", "4733"],
        mitreTactics: [],
        commonCauses: ["Role changes", "Access rights cleanup"],
        falsePositives: ["Routine access management"]
    },
    {
        id: "4732",
        name: "Member Added to Local Group",
        description: "A member was added to a security-enabled local group.",
        category: "Account Management",
        criticality: "High",
        logSource: "Security",
        investigationTips: [
            "Critical for local administrator additions",
            "Monitor for unauthorized privilege escalation",
            "Check group type and permissions",
            "Review justification for local access"
        ],
        relatedEvents: ["4733", "4728", "4729"],
        mitreTactics: ["Privilege Escalation"],
        commonCauses: ["Local admin assignments", "Service account setup"],
        falsePositives: ["Authorized system administration"]
    },
    {
        id: "4733",
        name: "Member Removed from Local Group",
        description: "A member was removed from a security-enabled local group.",
        category: "Account Management",
        criticality: "High",
        logSource: "Security",
        investigationTips: [
            "Monitor removals from admin groups",
            "Verify authorization for access changes",
            "Check for incident response actions",
            "Review timing and context"
        ],
        relatedEvents: ["4732", "4728", "4729"],
        mitreTactics: [],
        commonCauses: ["Access rights cleanup", "Role changes"],
        falsePositives: ["Routine access management"]
    },
    {
        id: "4740",
        name: "User Account Locked Out",
        description: "A user account was locked out due to multiple failed logon attempts.",
        category: "Account Management",
        criticality: "Medium",
        logSource: "Security",
        investigationTips: [
            "Investigate source of failed logon attempts",
            "Check for brute force attack patterns",
            "Review account lockout policies",
            "Monitor for password spray campaigns"
        ],
        relatedEvents: ["4625", "4767"],
        mitreTactics: ["Credential Access"],
        commonCauses: ["Password attacks", "User password mistakes"],
        falsePositives: ["Legitimate user errors", "Application misconfigurations"],
        investigationPlaybook: {
            immediate: {
                title: "Account Lockout and Brute Force Investigation",
                priority: "High",
                steps: [
                    {
                        action: "Identify the locked account and lockout source",
                        tool: "Windows Event Viewer, SIEM",
                        expected: "Find which account was locked and the source of failed attempts",
                        query: "Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4740} | Select-Object TimeCreated, TargetUserName, CallerComputerName"
                    },
                    {
                        action: "Analyze failed logon attempts leading to lockout",
                        tool: "Security logs correlation",
                        expected: "Find the pattern of failed logons before the lockout",
                        query: "index=security EventCode=4625 TargetUserName=[locked_account] earliest=-2h | stats count by src_ip, FailureReason"
                    },
                    {
                        action: "Check for brute force attack patterns",
                        tool: "SIEM analysis, timeline correlation",
                        expected: "Identify if this is part of a larger brute force campaign",
                        query: "index=security EventCode=4625 earliest=-4h | stats count by src_ip | where count > 10"
                    },
                    {
                        action: "Verify account legitimacy and importance",
                        tool: "Active Directory, user directory",
                        expected: "Determine if this is a high-value target account",
                        query: "Get-ADUser [locked_account] -Properties MemberOf, LastLogonDate | Select-Object Name, MemberOf, LastLogonDate"
                    }
                ]
            },
            shortTerm: {
                title: "Attack Pattern Analysis and Scope Assessment",
                priority: "Medium",
                steps: [
                    {
                        action: "Search for password spray indicators",
                        tool: "SIEM correlation, authentication logs",
                        expected: "Identify if attacker is trying multiple accounts with common passwords",
                        query: "index=security EventCode=4625 earliest=-4h | stats dc(TargetUserName) as users by src_ip | where users > 5"
                    },
                    {
                        action: "Check for successful logons from same source",
                        tool: "Authentication logs, correlation analysis",
                        expected: "Determine if any attempts were successful before lockout",
                        query: "index=security EventCode=4624 src_ip=[attack_ip] earliest=-6h | head 10"
                    },
                    {
                        action: "Analyze attack timing and frequency",
                        tool: "Timeline analysis, attack pattern recognition",
                        expected: "Understand the attack methodology and automation level",
                        query: "index=security EventCode=4625 src_ip=[attack_ip] earliest=-24h | bucket _time span=1h | stats count by _time"
                    },
                    {
                        action: "Check for lateral movement attempts",
                        tool: "Network logs, authentication monitoring",
                        expected: "Identify if attacker tried to access other systems",
                        query: "index=security EventCode=4624 LogonType=3 src_ip=[attack_ip] earliest=-24h"
                    }
                ]
            },
            longTerm: {
                title: "Threat Hunting and Security Hardening",
                priority: "Medium",
                steps: [
                    {
                        action: "Hunt for additional compromised accounts",
                        tool: "Threat hunting, user behavior analysis",
                        expected: "Find other accounts that may have been compromised",
                        query: "Search for unusual logon patterns and privilege changes across environment"
                    },
                    {
                        action: "Review and strengthen account lockout policies",
                        tool: "Group Policy, security policy analysis",
                        expected: "Optimize lockout thresholds and monitoring",
                        query: "Review account lockout policy settings and consider lowering thresholds"
                    },
                    {
                        action: "Implement enhanced brute force detection",
                        tool: "SIEM rules, intrusion detection",
                        expected: "Create alerts for rapid detection of future attacks",
                        query: "Configure alerts for multiple failed logons and account lockouts"
                    },
                    {
                        action: "Consider implementing additional protections",
                        tool: "Multi-factor authentication, conditional access",
                        expected: "Prevent future brute force attacks",
                        query: "Evaluate MFA implementation and conditional access policies"
                    }
                ]
            }
        }
    },
    {
        id: "4767",
        name: "User Account Unlocked",
        description: "A user account was unlocked by an administrator.",
        category: "Account Management",
        criticality: "Medium",
        logSource: "Security",
        investigationTips: [
            "Verify business justification for unlock",
            "Check if underlying security issue was resolved",
            "Monitor subsequent account activity",
            "Review unlock frequency patterns"
        ],
        relatedEvents: ["4740", "4625"],
        mitreTactics: [],
        commonCauses: ["Help desk operations", "Admin intervention"],
        falsePositives: ["Routine support operations"]
    },

    // System & Boot Events
    {
        id: "1074",
        name: "System Shutdown/Restart",
        description: "The system has been shutdown or restarted. Contains information about who initiated the shutdown.",
        category: "System",
        criticality: "Medium",
        logSource: "System",
        investigationTips: [
            "Check who initiated the shutdown",
            "Review shutdown reason codes",
            "Monitor for unexpected or frequent restarts",
            "Correlate with maintenance windows"
        ],
        relatedEvents: ["6005", "6006", "6008"],
        mitreTactics: ["Impact"],
        commonCauses: ["Planned maintenance", "Software updates", "Hardware issues"],
        falsePositives: ["Scheduled maintenance", "Normal updates"]
    },
    {
        id: "6005",
        name: "Event Log Service Started",
        description: "The Event Log service was started. Indicates system boot completion.",
        category: "System",
        criticality: "Medium",
        logSource: "System",
        investigationTips: [
            "Correlate with shutdown events",
            "Monitor boot time patterns",
            "Check for unexpected restarts",
            "Review system stability"
        ],
        relatedEvents: ["6006", "1074"],
        mitreTactics: [],
        commonCauses: ["System startup", "Service restart"],
        falsePositives: ["Normal system operations"]
    },
    {
        id: "6006",
        name: "Event Log Service Stopped",
        description: "The Event Log service was stopped. Often indicates system shutdown.",
        category: "System",
        criticality: "Medium",
        logSource: "System",
        investigationTips: [
            "Check for graceful vs unexpected shutdown",
            "Monitor shutdown patterns",
            "Correlate with user activity",
            "Review system stability"
        ],
        relatedEvents: ["6005", "1074"],
        mitreTactics: [],
        commonCauses: ["System shutdown", "Service maintenance"],
        falsePositives: ["Planned maintenance"]
    },
    {
        id: "6008",
        name: "Unexpected Shutdown",
        description: "The previous system shutdown was unexpected. May indicate system crash or power loss.",
        category: "System",
        criticality: "High",
        logSource: "System",
        investigationTips: [
            "Investigate cause of unexpected shutdown",
            "Check for hardware failures",
            "Review system crash dumps",
            "Monitor for pattern of crashes"
        ],
        relatedEvents: ["1074", "6005"],
        mitreTactics: ["Impact"],
        commonCauses: ["Power failures", "Hardware issues", "System crashes"],
        falsePositives: ["Infrastructure maintenance"]
    },
    {
        id: "7034",
        name: "Service Crashed",
        description: "A service terminated unexpectedly. May indicate system instability or attacks.",
        category: "System",
        criticality: "Medium",
        logSource: "System",
        investigationTips: [
            "Identify which service crashed",
            "Check service crash frequency",
            "Review service dependencies",
            "Monitor for malicious service termination"
        ],
        relatedEvents: ["7035", "7036"],
        mitreTactics: ["Defense Evasion", "Impact"],
        commonCauses: ["Service bugs", "Resource exhaustion", "Attacks"],
        falsePositives: ["Known application issues"]
    },
    {
        id: "7035",
        name: "Service Control Message",
        description: "A service received a control message (start, stop, pause, etc.).",
        category: "System",
        criticality: "Low",
        logSource: "System",
        investigationTips: [
            "Monitor for unauthorized service control",
            "Check who sent the control message",
            "Review service management patterns",
            "Correlate with administrative activity"
        ],
        relatedEvents: ["7036", "7034"],
        mitreTactics: [],
        commonCauses: ["Service management", "System administration"],
        falsePositives: ["Normal service operations"]
    },
    {
        id: "7036",
        name: "Service Started/Stopped",
        description: "A service was started or stopped. Normal service lifecycle event.",
        category: "System",
        criticality: "Low",
        logSource: "System",
        investigationTips: [
            "Monitor critical service state changes",
            "Check for unauthorized service modifications",
            "Review service startup patterns",
            "Correlate with system performance"
        ],
        relatedEvents: ["7035", "7034"],
        mitreTactics: [],
        commonCauses: ["Service management", "System startup/shutdown"],
        falsePositives: ["Normal operations"]
    },

    // Process & Application Events
    {
        id: "4688",
        name: "Process Created",
        description: "A new process has been created. Critical for monitoring process execution.",
        category: "Process",
        criticality: "Medium",
        logSource: "Security",
        investigationTips: [
            "Monitor for suspicious process names and paths",
            "Check command line arguments",
            "Review parent-child process relationships",
            "Identify unsigned or unusual executables"
        ],
        relatedEvents: ["4689", "4656"],
        mitreTactics: ["Execution", "Defense Evasion"],
        commonCauses: ["Application launches", "Script execution", "System processes"],
        falsePositives: ["Normal application operations"],
        investigationPlaybook: {
            immediate: {
                title: "Immediate Process Analysis (0-15 minutes)",
                priority: "High",
                steps: [
                    {
                        action: "Examine process path and name",
                        tool: "Process analysis, EDR",
                        expected: "Identify if process path is legitimate or suspicious",
                        query: "Check if process is in expected directory (System32, Program Files, etc.)"
                    },
                    {
                        action: "Review command line arguments",
                        tool: "Command line analysis",
                        expected: "Detect malicious switches, obfuscated commands, or suspicious parameters",
                        query: "Analyze full command line for encoded strings, unusual flags"
                    },
                    {
                        action: "Check file hash reputation",
                        tool: "VirusTotal, threat intelligence",
                        expected: "Determine if file hash is known malicious",
                        query: "Submit file hash to threat intelligence feeds"
                    },
                    {
                        action: "Verify digital signature",
                        tool: "Code signing analysis",
                        expected: "Confirm if binary is signed by trusted publisher",
                        query: "signtool verify /pa [file_path] or Get-AuthenticodeSignature"
                    }
                ]
            },
            shortTerm: {
                title: "Process Context Investigation (15-60 minutes)",
                priority: "Medium",
                steps: [
                    {
                        action: "Analyze parent process relationship",
                        tool: "Process tree analysis",
                        expected: "Verify if parent-child relationship is legitimate",
                        query: "index=sysmon EventCode=1 | eval process_tree=parent_process+\">\"+process"
                    },
                    {
                        action: "Check process behavior patterns",
                        tool: "Behavioral analysis, sandbox",
                        expected: "Identify network connections, file modifications, registry changes",
                        query: "Monitor process for network activity, file writes, registry modifications"
                    },
                    {
                        action: "Review concurrent process creation",
                        tool: "Timeline analysis",
                        expected: "Identify if part of larger execution chain",
                        query: "index=security EventCode=4688 earliest=-5m latest=+5m | stats count by process"
                    },
                    {
                        action: "Search for similar processes",
                        tool: "SIEM correlation",
                        expected: "Find other instances of same process across environment",
                        query: "index=security EventCode=4688 process_name=[process] earliest=-24h"
                    }
                ]
            },
            longTerm: {
                title: "Advanced Threat Analysis (1+ hours)",
                priority: "Medium",
                steps: [
                    {
                        action: "Perform static malware analysis",
                        tool: "Malware analysis tools, reverse engineering",
                        expected: "Understand malware capabilities and indicators",
                        query: "Use strings, PE analysis, disassemblers for detailed examination"
                    },
                    {
                        action: "Hunt for persistence mechanisms",
                        tool: "Registry, scheduled tasks, services",
                        expected: "Identify how malware maintains persistence",
                        query: "Check autorun locations, services, scheduled tasks for persistence"
                    },
                    {
                        action: "Threat attribution and IOC extraction",
                        tool: "Threat intelligence, YARA rules",
                        expected: "Link to known threat actors and extract IOCs",
                        query: "Compare TTPs with known threat actor patterns"
                    },
                    {
                        action: "Containment and remediation",
                        tool: "EDR, antivirus, network controls",
                        expected: "Remove threat and prevent spread",
                        query: "Quarantine file, block network IOCs, update detection rules"
                    }
                ]
            }
        }
    },
    {
        id: "4689",
        name: "Process Terminated",
        description: "A process has terminated. Useful for process lifecycle tracking.",
        category: "Process",
        criticality: "Low",
        logSource: "Security",
        investigationTips: [
            "Correlate with process creation events",
            "Monitor for abnormal process termination",
            "Check process execution duration",
            "Review termination patterns"
        ],
        relatedEvents: ["4688"],
        mitreTactics: [],
        commonCauses: ["Normal process completion", "Application shutdown"],
        falsePositives: ["Normal application lifecycle"]
    },
    {
        id: "4697",
        name: "Service Installed",
        description: "A service was installed on the system. Critical for detecting malware persistence.",
        category: "Process",
        criticality: "High",
        logSource: "Security",
        investigationTips: [
            "Verify legitimacy of new service",
            "Check service binary location and signature",
            "Review service permissions and configuration",
            "Monitor for suspicious service names"
        ],
        relatedEvents: ["7034", "7036"],
        mitreTactics: ["Persistence", "Privilege Escalation"],
        commonCauses: ["Software installation", "System updates"],
        falsePositives: ["Legitimate software installations"],
        investigationPlaybook: {
            immediate: {
                title: "Malicious Service Installation Investigation",
                priority: "High",
                steps: [
                    {
                        action: "Identify the newly installed service details",
                        tool: "Windows Event Viewer, Services Console",
                        expected: "Find service name, binary path, and installation account",
                        query: "Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4697} | Select-Object TimeCreated, ServiceName, ServiceFileName, SubjectUserName"
                    },
                    {
                        action: "Verify the service binary legitimacy",
                        tool: "File analysis, digital signature verification",
                        expected: "Check if the service binary is signed and from a trusted publisher",
                        query: "Get-AuthenticodeSignature '[service_binary_path]' | Select-Object Status, SignerCertificate"
                    },
                    {
                        action: "Analyze service binary location and name",
                        tool: "File system analysis, suspicious path detection",
                        expected: "Identify if service is in unusual location or has suspicious naming",
                        query: "Test-Path '[service_binary_path]' and analyze path for suspicious indicators"
                    },
                    {
                        action: "Check who installed the service",
                        tool: "Security logs, user context analysis",
                        expected: "Verify if the installing user has legitimate authority",
                        query: "Get-ADUser [installing_user] -Properties MemberOf | Select-Object Name, MemberOf"
                    }
                ]
            },
            shortTerm: {
                title: "Service Behavior and Persistence Analysis",
                priority: "High",
                steps: [
                    {
                        action: "Monitor service startup and execution",
                        tool: "System logs, process monitoring",
                        expected: "Understand service behavior and resource usage",
                        query: "Get-WinEvent -FilterHashtable @{LogName='System'; ID=7036} | Where-Object {$_.Message -match '[service_name]'}"
                    },
                    {
                        action: "Analyze service configuration and permissions",
                        tool: "Service Control Manager, registry analysis",
                        expected: "Review service configuration for malicious settings",
                        query: "Get-Service [service_name] | Select-Object * ; Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\[service_name]'"
                    },
                    {
                        action: "Check for network connections from service",
                        tool: "Network monitoring, netstat analysis",
                        expected: "Identify if service establishes suspicious network connections",
                        query: "netstat -ano | findstr [service_process_id] or monitor network traffic"
                    },
                    {
                        action: "Search for similar services across environment",
                        tool: "Remote system analysis, domain-wide service enumeration",
                        expected: "Find if this service was installed on other systems",
                        query: "Use remote PowerShell to check for same service across domain computers"
                    }
                ]
            },
            longTerm: {
                title: "Threat Hunting and Prevention",
                priority: "Medium",
                steps: [
                    {
                        action: "Conduct behavioral analysis of service binary",
                        tool: "Malware analysis, sandbox testing",
                        expected: "Understand full capabilities and potential impact",
                        query: "Submit binary to sandbox analysis and conduct static/dynamic analysis"
                    },
                    {
                        action: "Search for additional persistence mechanisms",
                        tool: "Persistence hunting, registry analysis",
                        expected: "Find other ways attacker may have established persistence",
                        query: "Check autorun locations, scheduled tasks, and registry persistence keys"
                    },
                    {
                        action: "Implement service installation monitoring",
                        tool: "SIEM rules, Windows Event Forwarding",
                        expected: "Detect future unauthorized service installations",
                        query: "Configure alerts for EventID 4697 and suspicious service names"
                    },
                    {
                        action: "Harden service installation policies",
                        tool: "Group Policy, application control",
                        expected: "Prevent unauthorized service installations",
                        query: "Review and implement policies to restrict service installation privileges"
                    }
                ]
            }
        }
    },
    {
        id: "4698",
        name: "Scheduled Task Created",
        description: "A scheduled task was created. Important for detecting persistence mechanisms.",
        category: "Process",
        criticality: "High",
        logSource: "Security",
        investigationTips: [
            "Review task executable and arguments",
            "Check task scheduling and frequency",
            "Verify authorization for task creation",
            "Monitor for suspicious task names"
        ],
        relatedEvents: ["4699", "4700", "4701"],
        mitreTactics: ["Persistence", "Execution"],
        commonCauses: ["System maintenance", "Application scheduling"],
        falsePositives: ["Legitimate automation tasks"]
    },
    {
        id: "4699",
        name: "Scheduled Task Deleted",
        description: "A scheduled task was deleted. May indicate cleanup after compromise.",
        category: "Process",
        criticality: "Medium",
        logSource: "Security",
        investigationTips: [
            "Check which task was deleted",
            "Verify authorization for deletion",
            "Monitor for attack cleanup activities",
            "Review deletion timing patterns"
        ],
        relatedEvents: ["4698", "4700", "4701"],
        mitreTactics: ["Defense Evasion"],
        commonCauses: ["Task maintenance", "Attack cleanup"],
        falsePositives: ["Routine task management"]
    },
    {
        id: "4700",
        name: "Scheduled Task Enabled",
        description: "A scheduled task was enabled. Monitor for unauthorized task activation.",
        category: "Process",
        criticality: "Medium",
        logSource: "Security",
        investigationTips: [
            "Check task configuration and permissions",
            "Verify business justification",
            "Monitor subsequent task execution",
            "Review task modification history"
        ],
        relatedEvents: ["4698", "4701"],
        mitreTactics: ["Persistence"],
        commonCauses: ["Task maintenance", "System administration"],
        falsePositives: ["Routine task management"]
    },
    {
        id: "4701",
        name: "Scheduled Task Disabled",
        description: "A scheduled task was disabled. May indicate security response or maintenance.",
        category: "Process",
        criticality: "Medium",
        logSource: "Security",
        investigationTips: [
            "Verify reason for disabling task",
            "Check if part of incident response",
            "Monitor for re-enabling attempts",
            "Review task configuration"
        ],
        relatedEvents: ["4698", "4700"],
        mitreTactics: [],
        commonCauses: ["Task maintenance", "Security response"],
        falsePositives: ["Routine maintenance"]
    },
    {
        id: "1000",
        name: "Application Error",
        description: "An application error occurred. May indicate system instability or exploitation attempts.",
        category: "Process",
        criticality: "Medium",
        logSource: "Application",
        investigationTips: [
            "Identify failing application and error details",
            "Check for exploitation attempts",
            "Monitor error frequency and patterns",
            "Review application security patches"
        ],
        relatedEvents: ["1001"],
        mitreTactics: ["Defense Evasion"],
        commonCauses: ["Application bugs", "Resource issues", "Exploitation"],
        falsePositives: ["Known application issues"]
    },
    {
        id: "1001",
        name: "Windows Error Reporting",
        description: "Windows Error Reporting generated a report. Indicates application or system issues.",
        category: "Process",
        criticality: "Low",
        logSource: "Application",
        investigationTips: [
            "Review error report details",
            "Check for crash exploitation",
            "Monitor crash frequency",
            "Correlate with security events"
        ],
        relatedEvents: ["1000"],
        mitreTactics: [],
        commonCauses: ["Application crashes", "System errors"],
        falsePositives: ["Normal error reporting"]
    },

    // File & Registry Events
    {
        id: "4656",
        name: "Handle to Object Requested",
        description: "A handle to an object was requested. Useful for tracking file and registry access.",
        category: "File & Registry",
        criticality: "Low",
        logSource: "Security",
        investigationTips: [
            "Monitor access to sensitive files and registry keys",
            "Check requested access permissions",
            "Review access patterns for anomalies",
            "Correlate with process creation events"
        ],
        relatedEvents: ["4658", "4663"],
        mitreTactics: ["Discovery", "Collection"],
        commonCauses: ["File access", "Registry operations", "Application activity"],
        falsePositives: ["Normal application operations"]
    },
    {
        id: "4658",
        name: "Handle to Object Closed",
        description: "A handle to an object was closed. Indicates completion of file or registry access.",
        category: "File & Registry",
        criticality: "Low",
        logSource: "Security",
        investigationTips: [
            "Correlate with handle request events",
            "Monitor access duration patterns",
            "Check for proper resource cleanup",
            "Review access completion status"
        ],
        relatedEvents: ["4656", "4663"],
        mitreTactics: [],
        commonCauses: ["Normal file/registry operations"],
        falsePositives: ["Standard application behavior"]
    },
    {
        id: "4663",
        name: "Attempt to Access Object",
        description: "An attempt was made to access an object. Critical for monitoring unauthorized access attempts.",
        category: "File & Registry",
        criticality: "Medium",
        logSource: "Security",
        investigationTips: [
            "Focus on failed access attempts",
            "Monitor access to sensitive resources",
            "Check access permissions and rights",
            "Review unauthorized access patterns"
        ],
        relatedEvents: ["4656", "4658"],
        mitreTactics: ["Discovery", "Privilege Escalation"],
        commonCauses: ["Permission errors", "Unauthorized access attempts"],
        falsePositives: ["Application permission issues"],
        investigationPlaybook: {
            immediate: {
                title: "Unauthorized Object Access Investigation",
                priority: "Medium",
                steps: [
                    {
                        action: "Identify the object and access attempt details",
                        tool: "Windows Event Viewer, SIEM",
                        expected: "Find what object was accessed, by whom, and access type",
                        query: "Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4663} | Select-Object TimeCreated, SubjectUserName, ObjectName, AccessMask"
                    },
                    {
                        action: "Determine if access was successful or failed",
                        tool: "Security log analysis, access result correlation",
                        expected: "Understand if unauthorized access was actually achieved",
                        query: "Check AccessMask and related 4656/4658 events for access success/failure"
                    },
                    {
                        action: "Verify user authorization for object access",
                        tool: "File permissions, Active Directory",
                        expected: "Confirm if user should have access to the requested object",
                        query: "Get-Acl '[object_path]' | Select-Object Access; Get-ADUser [username] -Properties MemberOf"
                    },
                    {
                        action: "Analyze the sensitivity of accessed object",
                        tool: "Data classification, file analysis",
                        expected: "Determine criticality and sensitivity of the accessed resource",
                        query: "Analyze file path and content for sensitive data indicators"
                    }
                ]
            },
            shortTerm: {
                title: "Access Pattern and Context Analysis",
                priority: "Medium",
                steps: [
                    {
                        action: "Review user's historical access patterns",
                        tool: "SIEM analysis, user behavior analytics",
                        expected: "Identify if this access deviates from normal user behavior",
                        query: "index=security EventCode=4663 user=[username] earliest=-30d | stats count by ObjectName | sort -count"
                    },
                    {
                        action: "Check for bulk or systematic access attempts",
                        tool: "Timeline analysis, pattern recognition",
                        expected: "Detect if this is part of larger data exploration activity",
                        query: "index=security EventCode=4663 user=[username] earliest=-4h | stats count by hour | sort -count"
                    },
                    {
                        action: "Analyze concurrent system activities",
                        tool: "Process monitoring, system correlation",
                        expected: "Understand what application or process triggered the access",
                        query: "index=security EventCode=4688 user=[username] earliest=-30m latest=+30m"
                    },
                    {
                        action: "Search for privilege escalation attempts",
                        tool: "Security logs, privilege monitoring",
                        expected: "Check if user attempted to gain additional permissions",
                        query: "index=security EventCode=4672 user=[username] earliest=-2h"
                    }
                ]
            },
            longTerm: {
                title: "Data Protection and Access Monitoring",
                priority: "Low",
                steps: [
                    {
                        action: "Review and strengthen object permissions",
                        tool: "Access control management, permission audit",
                        expected: "Ensure appropriate access controls on sensitive objects",
                        query: "Audit file and registry permissions for overly permissive access"
                    },
                    {
                        action: "Implement enhanced object access monitoring",
                        tool: "SIEM rules, Data Loss Prevention",
                        expected: "Create alerts for sensitive data access attempts",
                        query: "Configure monitoring for access to classified/sensitive file locations"
                    },
                    {
                        action: "Conduct data access review",
                        tool: "Access governance, data classification",
                        expected: "Validate all data access patterns and user permissions",
                        query: "Perform quarterly review of data access patterns and user permissions"
                    },
                    {
                        action: "Improve data loss prevention controls",
                        tool: "DLP solutions, data classification tools",
                        expected: "Prevent unauthorized access to sensitive data",
                        query: "Implement DLP rules and data classification for better protection"
                    }
                ]
            }
        }
    },
    {
        id: "4670",
        name: "Permissions Changed on Object",
        description: "Permissions on an object were changed. Critical for monitoring security descriptor modifications.",
        category: "File & Registry",
        criticality: "High",
        logSource: "Security",
        investigationTips: [
            "Monitor changes to critical file/registry permissions",
            "Check who made the permission changes",
            "Review new vs old permission settings",
            "Verify authorization for permission changes"
        ],
        relatedEvents: ["4656", "4663"],
        mitreTactics: ["Defense Evasion", "Privilege Escalation"],
        commonCauses: ["Administrative changes", "Application installations"],
        falsePositives: ["Authorized system administration"]
    },

    // Network Events
    {
        id: "5140",
        name: "Network Share Accessed",
        description: "A network share object was accessed. Important for monitoring file share activity.",
        category: "Network",
        criticality: "Medium",
        logSource: "Security",
        investigationTips: [
            "Monitor access to sensitive shares",
            "Check source IP addresses and users",
            "Review accessed file names and paths",
            "Identify unusual access patterns"
        ],
        relatedEvents: ["5142", "5144", "5145"],
        mitreTactics: ["Lateral Movement", "Collection"],
        commonCauses: ["File sharing", "Application data access"],
        falsePositives: ["Normal business file access"]
    },
    {
        id: "5142",
        name: "Network Share Added",
        description: "A network share object was added. Monitor for unauthorized share creation.",
        category: "Network",
        criticality: "Medium",
        logSource: "Security",
        investigationTips: [
            "Verify authorization for new share creation",
            "Check share permissions and access rights",
            "Monitor share usage patterns",
            "Review business justification"
        ],
        relatedEvents: ["5140", "5144"],
        mitreTactics: ["Lateral Movement", "Exfiltration"],
        commonCauses: ["Administrative share creation", "Application requirements"],
        falsePositives: ["Authorized network administration"]
    },
    {
        id: "5144",
        name: "Network Share Deleted",
        description: "A network share object was deleted. May indicate cleanup or defensive actions.",
        category: "Network",
        criticality: "Medium",
        logSource: "Security",
        investigationTips: [
            "Check which share was deleted",
            "Verify authorization for deletion",
            "Monitor for data exfiltration before deletion",
            "Review deletion timing"
        ],
        relatedEvents: ["5140", "5142"],
        mitreTactics: ["Defense Evasion"],
        commonCauses: ["Administrative cleanup", "Security response"],
        falsePositives: ["Routine maintenance"]
    },
    {
        id: "5145",
        name: "Network Share Checked for Access",
        description: "A network share object was checked to see whether client can be granted desired access.",
        category: "Network",
        criticality: "Low",
        logSource: "Security",
        investigationTips: [
            "Monitor for share enumeration activities",
            "Check for unauthorized access attempts",
            "Review access check patterns",
            "Correlate with actual access events"
        ],
        relatedEvents: ["5140", "5142"],
        mitreTactics: ["Discovery"],
        commonCauses: ["Share enumeration", "Access validation"],
        falsePositives: ["Normal application behavior"]
    },
    {
        id: "5156",
        name: "Windows Filtering Platform Connection",
        description: "Windows Filtering Platform has permitted a connection. Network connection monitoring.",
        category: "Network",
        criticality: "Medium",
        logSource: "Security",
        investigationTips: [
            "Monitor for suspicious outbound connections",
            "Check destination IPs and ports",
            "Review connection patterns and frequency",
            "Identify command and control communications"
        ],
        relatedEvents: ["5158"],
        mitreTactics: ["Command and Control", "Exfiltration"],
        commonCauses: ["Network applications", "System communications"],
        falsePositives: ["Normal network activity"]
    },

    // Audit Policy Events
    {
        id: "4719",
        name: "System Audit Policy Changed",
        description: "System audit policy was changed. Critical for monitoring audit configuration tampering.",
        category: "Audit Policy",
        criticality: "High",
        logSource: "Security",
        investigationTips: [
            "Monitor for unauthorized audit policy changes",
            "Check which policies were modified",
            "Verify authorization for changes",
            "Review impact on security monitoring"
        ],
        relatedEvents: ["4817", "4902"],
        mitreTactics: ["Defense Evasion"],
        commonCauses: ["Administrative configuration", "Compliance requirements"],
        falsePositives: ["Authorized policy management"]
    },
    {
        id: "4817",
        name: "Auditing Settings Changed",
        description: "Auditing settings on an object were changed. Monitor for audit tampering.",
        category: "Audit Policy",
        criticality: "High",
        logSource: "Security",
        investigationTips: [
            "Check which object's auditing was modified",
            "Verify authorization for audit changes",
            "Review new vs old audit settings",
            "Monitor for defensive evasion tactics"
        ],
        relatedEvents: ["4719", "4902"],
        mitreTactics: ["Defense Evasion"],
        commonCauses: ["Security configuration", "Compliance requirements"],
        falsePositives: ["Authorized audit management"]
    },
    {
        id: "4902",
        name: "Per-user Audit Policy Table Created",
        description: "The Per-user audit policy table was created. Advanced audit policy configuration.",
        category: "Audit Policy",
        criticality: "Medium",
        logSource: "Security",
        investigationTips: [
            "Monitor advanced audit policy usage",
            "Check per-user audit configurations",
            "Review policy table contents",
            "Verify configuration authorization"
        ],
        relatedEvents: ["4719", "4817"],
        mitreTactics: [],
        commonCauses: ["Advanced audit configuration", "Granular monitoring"],
        falsePositives: ["Normal audit policy management"]
    },
    {
        id: "4904",
        name: "Security Event Log Cleared",
        description: "An attempt was made to clear the Security log. Critical indicator of log tampering.",
        category: "Audit Policy",
        criticality: "Critical",
        logSource: "Security",
        investigationTips: [
            "Immediate investigation required",
            "Check who cleared the log and when",
            "Review backup logs if available",
            "Investigate potential cover-up activities"
        ],
        relatedEvents: ["1102"],
        mitreTactics: ["Defense Evasion"],
        commonCauses: ["Attack cleanup", "Unauthorized log management"],
        falsePositives: ["Authorized log rotation", "Maintenance activities"],
        investigationPlaybook: {
            immediate: {
                title: "Critical Response - Log Tampering Detection",
                priority: "Critical",
                steps: [
                    {
                        action: "Identify who cleared the security log",
                        tool: "Windows Event Viewer, SIEM",
                        expected: "Find the user account and process that cleared the log",
                        query: "Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4904} | Select-Object TimeCreated, UserId, ProcessName"
                    },
                    {
                        action: "Check if log clearing was authorized",
                        tool: "Change management, Admin verification",
                        expected: "Verify if this was a scheduled/authorized maintenance activity",
                        query: "Cross-reference with change management tickets and maintenance schedules"
                    },
                    {
                        action: "Examine time correlation with other security events",
                        tool: "SIEM correlation analysis",
                        expected: "Identify if log clearing happened after suspicious activities",
                        query: "index=security earliest=-4h latest=now | stats count by EventCode | sort -count"
                    },
                    {
                        action: "Check for backup or forwarded logs",
                        tool: "Log management system, SIEM",
                        expected: "Locate copies of security events before clearing",
                        query: "Check syslog servers, SIEM retention, and Windows Event Forwarding"
                    }
                ]
            },
            shortTerm: {
                title: "Evidence Preservation and Timeline Analysis",
                priority: "High",
                steps: [
                    {
                        action: "Preserve remaining forensic evidence",
                        tool: "Disk imaging, memory dump",
                        expected: "Capture system state before evidence is lost",
                        query: "Create forensic image and memory dump of affected system"
                    },
                    {
                        action: "Analyze preceding security events",
                        tool: "SIEM, backup logs",
                        expected: "Reconstruct events leading up to log clearing",
                        query: "Search backup logs for events 1-4 hours before log clearing"
                    },
                    {
                        action: "Check for signs of lateral movement",
                        tool: "Network monitoring, authentication logs",
                        expected: "Identify if attacker moved to other systems",
                        query: "index=security EventCode=4624 user=[suspected_user] earliest=-24h"
                    },
                    {
                        action: "Review file system changes",
                        tool: "File integrity monitoring, USN journal",
                        expected: "Find files modified around the time of log clearing",
                        query: "fsutil usn readjournal C: | findstr [timeframe]"
                    }
                ]
            },
            longTerm: {
                title: "Full Investigation and Recovery",
                priority: "Medium",
                steps: [
                    {
                        action: "Conduct comprehensive timeline analysis",
                        tool: "Timeline analysis tools, forensic software",
                        expected: "Create complete timeline of attack and cleanup activities",
                        query: "Use plaso/log2timeline for comprehensive timeline reconstruction"
                    },
                    {
                        action: "Implement enhanced logging and monitoring",
                        tool: "Log forwarding, SIEM tuning",
                        expected: "Prevent future log tampering attempts",
                        query: "Configure real-time log forwarding and tamper detection"
                    },
                    {
                        action: "Assess security control effectiveness",
                        tool: "Security audit, policy review",
                        expected: "Identify gaps that allowed log tampering",
                        query: "Review log management policies and access controls"
                    },
                    {
                        action: "Create incident report and lessons learned",
                        tool: "Incident management system",
                        expected: "Document findings and improve security posture",
                        query: "Generate comprehensive incident report with IOCs and recommendations"
                    }
                ]
            }
        }
    },
    {
        id: "4906",
        name: "CrashOnAuditFail Value Changed",
        description: "The CrashOnAuditFail value has changed. Critical audit system configuration.",
        category: "Audit Policy",
        criticality: "High",
        logSource: "Security",
        investigationTips: [
            "Monitor changes to audit failure handling",
            "Check new configuration value",
            "Verify authorization for change",
            "Review system audit reliability"
        ],
        relatedEvents: ["4719"],
        mitreTactics: ["Defense Evasion"],
        commonCauses: ["System hardening", "Audit policy configuration"],
        falsePositives: ["Authorized security configuration"]
    },

    // Security Events
    {
        id: "4672",
        name: "Special Privileges Assigned",
        description: "Special privileges were assigned to a new logon. Indicates administrative access.",
        category: "Security",
        criticality: "High",
        logSource: "Security",
        investigationTips: [
            "Monitor for unauthorized administrative access",
            "Check assigned privilege levels",
            "Verify business justification for privileges",
            "Review privilege usage patterns"
        ],
        relatedEvents: ["4624", "4648"],
        mitreTactics: ["Privilege Escalation"],
        commonCauses: ["Administrative logons", "Service account access"],
        falsePositives: ["Authorized admin operations"],
        investigationPlaybook: {
            immediate: {
                title: "Privilege Escalation Investigation",
                priority: "High",
                steps: [
                    {
                        action: "Identify the user and privileges assigned",
                        tool: "Windows Event Viewer, SIEM",
                        expected: "Determine which user received privileges and what specific privileges were granted",
                        query: "Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4672} | Select-Object TimeCreated, SubjectUserName, PrivilegeList"
                    },
                    {
                        action: "Check if user should have administrative privileges",
                        tool: "Active Directory, RBAC system",
                        expected: "Verify if user is authorized for administrative access",
                        query: "Get-ADUser [username] -Properties MemberOf | Select-Object MemberOf"
                    },
                    {
                        action: "Review logon session details",
                        tool: "Security logs correlation",
                        expected: "Understand how the user obtained the privileged session",
                        query: "index=security EventCode=4624 user=[username] earliest=-30m | head 5"
                    },
                    {
                        action: "Check for privilege abuse activities",
                        tool: "Security logs, process monitoring",
                        expected: "Identify what actions were taken with elevated privileges",
                        query: "index=security EventCode=4673 SubjectUserName=[username] earliest=[logon_time]"
                    }
                ]
            },
            shortTerm: {
                title: "Administrative Activity Analysis",
                priority: "Medium",
                steps: [
                    {
                        action: "Analyze administrative actions performed",
                        tool: "Security logs, command history",
                        expected: "Document all activities performed with elevated privileges",
                        query: "Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} | Where-Object {$_.Properties[5].Value -eq '[username]'}"
                    },
                    {
                        action: "Check for lateral movement attempts",
                        tool: "Network logs, authentication logs",
                        expected: "Identify if privileges were used to access other systems",
                        query: "index=security EventCode=4624 LogonType=3 user=[username] earliest=[privilege_time]"
                    },
                    {
                        action: "Review file and registry access",
                        tool: "Object access logs, SIEM",
                        expected: "Identify sensitive resources accessed with privileges",
                        query: "index=security EventCode=4663 SubjectUserName=[username] earliest=[privilege_time]"
                    },
                    {
                        action: "Examine service and scheduled task creation",
                        tool: "System logs, security logs",
                        expected: "Check for persistence mechanisms created with admin privileges",
                        query: "index=system EventCode=7045 earliest=[privilege_time] | search [username]"
                    }
                ]
            },
            longTerm: {
                title: "Privilege Management Review",
                priority: "Low",
                steps: [
                    {
                        action: "Review privilege assignment policies",
                        tool: "Active Directory, PAM solution",
                        expected: "Ensure proper controls for administrative access",
                        query: "Review privileged access management policies and just-in-time access"
                    },
                    {
                        action: "Implement enhanced monitoring",
                        tool: "SIEM rules, privileged access monitoring",
                        expected: "Detect future unauthorized privilege usage",
                        query: "Create alerts for unusual administrative activities and privilege escalation"
                    },
                    {
                        action: "Conduct privilege access review",
                        tool: "Identity governance, access review",
                        expected: "Validate all current administrative assignments",
                        query: "Perform quarterly review of all privileged accounts and access"
                    },
                    {
                        action: "Update security awareness training",
                        tool: "Training platform, security education",
                        expected: "Educate users on proper privilege usage",
                        query: "Include privilege escalation scenarios in security training"
                    }
                ]
            }
        }
    },
    {
        id: "4673",
        name: "Privileged Service Called",
        description: "A privileged service was called. Monitor for abuse of system privileges.",
        category: "Security",
        criticality: "Medium",
        logSource: "Security",
        investigationTips: [
            "Monitor for unusual privileged service usage",
            "Check which service was called",
            "Review caller permissions and context",
            "Identify potential privilege abuse"
        ],
        relatedEvents: ["4672"],
        mitreTactics: ["Privilege Escalation"],
        commonCauses: ["System operations", "Administrative tasks"],
        falsePositives: ["Normal system operations"]
    },
    {
        id: "4738",
        name: "User Account Changed",
        description: "A user account was changed. Monitor for unauthorized account modifications.",
        category: "Security",
        criticality: "Medium",
        logSource: "Security",
        investigationTips: [
            "Check what account attributes were changed",
            "Verify authorization for account changes",
            "Monitor for privilege escalation",
            "Review change frequency patterns"
        ],
        relatedEvents: ["4720", "4723", "4724"],
        mitreTactics: ["Persistence", "Privilege Escalation"],
        commonCauses: ["Account maintenance", "Role changes"],
        falsePositives: ["Authorized account management"]
    },

    // PowerShell Events
    {
        id: "4103",
        name: "PowerShell Module Logging",
        description: "PowerShell module logging captured cmdlet execution. Important for PowerShell monitoring.",
        category: "PowerShell",
        criticality: "Medium",
        logSource: "PowerShell",
        investigationTips: [
            "Monitor for malicious PowerShell cmdlets",
            "Check command execution context",
            "Review module and function usage",
            "Identify obfuscated commands"
        ],
        relatedEvents: ["4104", "4105", "4106"],
        mitreTactics: ["Execution", "Defense Evasion"],
        commonCauses: ["PowerShell scripts", "Administrative tasks"],
        falsePositives: ["Legitimate PowerShell usage"]
    },
    {
        id: "4104",
        name: "PowerShell Script Block Logging",
        description: "PowerShell script block logging captured script content. Critical for PowerShell attack detection.",
        category: "PowerShell",
        criticality: "High",
        logSource: "PowerShell",
        investigationTips: [
            "Analyze script content for malicious activity",
            "Check for obfuscation techniques",
            "Monitor for encoded commands",
            "Review script execution context"
        ],
        relatedEvents: ["4103", "4105", "4106"],
        mitreTactics: ["Execution", "Defense Evasion"],
        commonCauses: ["PowerShell scripts", "Automated tasks"],
        falsePositives: ["Legitimate script execution"]
    },
    {
        id: "4105",
        name: "PowerShell Script Start",
        description: "PowerShell script execution started. Monitor script initiation.",
        category: "PowerShell",
        criticality: "Medium",
        logSource: "PowerShell",
        investigationTips: [
            "Monitor script execution timing",
            "Check script source and path",
            "Review execution context",
            "Correlate with other PowerShell events"
        ],
        relatedEvents: ["4104", "4106"],
        mitreTactics: ["Execution"],
        commonCauses: ["Script automation", "Administrative tasks"],
        falsePositives: ["Normal script operations"]
    },
    {
        id: "4106",
        name: "PowerShell Script Stop",
        description: "PowerShell script execution stopped. Monitor script completion.",
        category: "PowerShell",
        criticality: "Medium",
        logSource: "PowerShell",
        investigationTips: [
            "Correlate with script start events",
            "Check script execution duration",
            "Review completion status",
            "Monitor for abnormal termination"
        ],
        relatedEvents: ["4104", "4105"],
        mitreTactics: [],
        commonCauses: ["Normal script completion"],
        falsePositives: ["Standard script operations"]
    },

    // Sysmon Events
    {
        id: "1",
        name: "Sysmon Process Creation",
        description: "Sysmon detected process creation. Enhanced process monitoring with command line details.",
        category: "Sysmon",
        criticality: "High",
        logSource: "Sysmon",
        investigationTips: [
            "Analyze command line arguments for malicious activity",
            "Check process hashes and signatures",
            "Review parent-child process relationships",
            "Monitor for living-off-the-land techniques"
        ],
        relatedEvents: ["3", "5", "11"],
        mitreTactics: ["Execution"],
        commonCauses: ["Process execution", "Application launches"],
        falsePositives: ["Normal application operations"]
    },
    {
        id: "3",
        name: "Sysmon Network Connection",
        description: "Sysmon detected network connection. Detailed network activity monitoring.",
        category: "Sysmon",
        criticality: "Medium",
        logSource: "Sysmon",
        investigationTips: [
            "Monitor for suspicious outbound connections",
            "Check destination IPs and domains",
            "Review connection timing and frequency",
            "Identify command and control activity"
        ],
        relatedEvents: ["1", "5"],
        mitreTactics: ["Command and Control", "Exfiltration"],
        commonCauses: ["Network applications", "System updates"],
        falsePositives: ["Normal network activity"]
    },
    {
        id: "5",
        name: "Sysmon Process Terminated",
        description: "Sysmon detected process termination. Monitor for unusual process lifecycle.",
        category: "Sysmon",
        criticality: "Low",
        logSource: "Sysmon",
        investigationTips: [
            "Correlate with process creation events",
            "Monitor for defensive process termination",
            "Check termination timing patterns",
            "Review process execution duration"
        ],
        relatedEvents: ["1", "3"],
        mitreTactics: ["Defense Evasion"],
        commonCauses: ["Normal process completion"],
        falsePositives: ["Standard application lifecycle"]
    },
    {
        id: "11",
        name: "Sysmon File Created",
        description: "Sysmon detected file creation. Monitor for malicious file drops.",
        category: "Sysmon",
        criticality: "Medium",
        logSource: "Sysmon",
        investigationTips: [
            "Monitor file creation in sensitive directories",
            "Check file hashes and signatures",
            "Review file names for suspicious patterns",
            "Correlate with process creation events"
        ],
        relatedEvents: ["1", "3"],
        mitreTactics: ["Defense Evasion", "Persistence"],
        commonCauses: ["Application files", "System operations"],
        falsePositives: ["Normal file operations"]
    },

    // Microsoft Official High Priority Events
    {
        id: "4618",
        name: "Monitored Security Event Pattern",
        description: "A monitored security event pattern has occurred. This indicates a security monitoring rule was triggered.",
        category: "Security",
        criticality: "High",
        logSource: "Security",
        investigationTips: [
            "Immediate investigation required - this is a custom security pattern alert",
            "Check which specific pattern was triggered",
            "Review the context and timing of the alert",
            "Correlate with other security events"
        ],
        relatedEvents: ["4719", "4904"],
        mitreTactics: ["Defense Evasion", "Persistence"],
        commonCauses: ["Security rule triggers", "Monitoring system alerts"],
        falsePositives: ["Misconfigured monitoring rules", "False positive patterns"]
    },
    {
        id: "4649",
        name: "Replay Attack Detected",
        description: "A replay attack was detected. May be a harmless false positive due to misconfiguration error.",
        category: "Authentication",
        criticality: "High",
        logSource: "Security",
        investigationTips: [
            "Investigate potential Kerberos replay attacks",
            "Check for time synchronization issues",
            "Review authentication patterns and timing",
            "Verify if this is a configuration error"
        ],
        relatedEvents: ["4768", "4771"],
        mitreTactics: ["Credential Access"],
        commonCauses: ["Time synchronization issues", "Kerberos attacks", "Network delays"],
        falsePositives: ["Clock skew", "Network latency", "Legitimate retransmissions"]
    },
    {
        id: "4765",
        name: "SID History Added to Account",
        description: "SID History was added to an account. Critical for detecting privilege escalation through SID history abuse.",
        category: "Account Management",
        criticality: "High",
        logSource: "Security",
        investigationTips: [
            "Immediate investigation required - potential privilege escalation",
            "Check which SIDs were added to SID history",
            "Verify authorization for SID history modification",
            "Review account permissions after change"
        ],
        relatedEvents: ["4766", "4728"],
        mitreTactics: ["Privilege Escalation", "Persistence"],
        commonCauses: ["Domain migrations", "Account transitions"],
        falsePositives: ["Authorized domain migrations", "Administrative account management"]
    },
    {
        id: "4766",
        name: "Failed SID History Addition",
        description: "An attempt to add SID History to an account failed. May indicate attempted privilege escalation.",
        category: "Account Management",
        criticality: "High",
        logSource: "Security",
        investigationTips: [
            "Investigate failed SID history modification attempts",
            "Check who attempted the modification",
            "Review account permissions and authorization",
            "Monitor for subsequent successful attempts"
        ],
        relatedEvents: ["4765", "4728"],
        mitreTactics: ["Privilege Escalation"],
        commonCauses: ["Unauthorized privilege escalation attempts", "Configuration errors"],
        falsePositives: ["Permission errors", "Administrative mistakes"]
    },
    {
        id: "4794",
        name: "Directory Services Restore Mode Attempt",
        description: "An attempt was made to set the Directory Services Restore Mode. Critical for domain controller security.",
        category: "System",
        criticality: "High",
        logSource: "Security",
        investigationTips: [
            "Critical - DSRM access on domain controller",
            "Verify authorization for DSRM access",
            "Check if this is planned maintenance",
            "Monitor for unauthorized DC access"
        ],
        relatedEvents: ["4608", "4609"],
        mitreTactics: ["Persistence", "Defense Evasion"],
        commonCauses: ["DC maintenance", "Emergency recovery"],
        falsePositives: ["Authorized DC maintenance", "Planned recovery operations"]
    },
    {
        id: "4897",
        name: "Role Separation Enabled",
        description: "Role separation was enabled. Important for administrator account security monitoring.",
        category: "Security",
        criticality: "High",
        logSource: "Security",
        investigationTips: [
            "Monitor role separation configuration changes",
            "Verify authorization for security policy changes",
            "Review impact on administrative operations",
            "Check for policy bypass attempts"
        ],
        relatedEvents: ["4719", "4817"],
        mitreTactics: ["Defense Evasion"],
        commonCauses: ["Security policy updates", "Compliance requirements"],
        falsePositives: ["Authorized policy changes", "Security hardening"]
    },
    {
        id: "4964",
        name: "Special Groups Assigned to Logon",
        description: "Special groups have been assigned to a new logon. Monitors high-privilege group assignments.",
        category: "Authentication",
        criticality: "High",
        logSource: "Security",
        investigationTips: [
            "Monitor special privilege group assignments",
            "Check which privileged groups were assigned",
            "Verify business justification for privileges",
            "Review group membership policies"
        ],
        relatedEvents: ["4624", "4672"],
        mitreTactics: ["Privilege Escalation"],
        commonCauses: ["Administrative logons", "Service account access"],
        falsePositives: ["Normal privileged access", "Service operations"]
    },
    {
        id: "5124",
        name: "OCSP Responder Service Security Update",
        description: "A security setting was updated on the OCSP Responder Service. Certificate validation security changes.",
        category: "Security",
        criticality: "High",
        logSource: "Security",
        investigationTips: [
            "Monitor OCSP service configuration changes",
            "Verify authorization for certificate service changes",
            "Check impact on certificate validation",
            "Review PKI security policies"
        ],
        relatedEvents: ["4719"],
        mitreTactics: ["Defense Evasion"],
        commonCauses: ["PKI maintenance", "Certificate policy updates"],
        falsePositives: ["Authorized PKI administration", "Security updates"]
    },
    {
        id: "4621",
        name: "CrashOnAuditFail Recovery",
        description: "Administrator recovered system from CrashOnAuditFail. Some auditable activity might not have been recorded.",
        category: "Audit Policy",
        criticality: "Medium",
        logSource: "Security",
        investigationTips: [
            "Check for audit system failures",
            "Review what events may have been missed",
            "Verify audit system integrity",
            "Monitor for audit tampering"
        ],
        relatedEvents: ["4906", "4719"],
        mitreTactics: ["Defense Evasion"],
        commonCauses: ["Audit system recovery", "System maintenance"],
        falsePositives: ["Normal system recovery", "Maintenance procedures"]
    },
    {
        id: "4675",
        name: "SIDs Filtered",
        description: "SIDs were filtered during authentication. May indicate SID filtering security measures.",
        category: "Authentication",
        criticality: "Medium",
        logSource: "Security",
        investigationTips: [
            "Monitor SID filtering in cross-domain scenarios",
            "Check for bypass attempts",
            "Review trust relationships",
            "Verify filtering policies"
        ],
        relatedEvents: ["4624", "4768"],
        mitreTactics: ["Defense Evasion"],
        commonCauses: ["Cross-domain authentication", "Trust filtering"],
        falsePositives: ["Normal trust filtering", "Security policies"]
    },

    // Ultimate Windows Security - Critical Events
    {
        id: "1100",
        name: "Event Logging Service Shut Down",
        description: "The event logging service has shut down. Critical for detecting audit tampering attempts.",
        category: "Audit Policy", 
        criticality: "High",
        logSource: "System",
        investigationTips: [
            "Check if service shutdown was authorized",
            "Look for signs of attack cleanup",
            "Verify system stability and integrity",
            "Check for correlation with suspicious activity"
        ],
        relatedEvents: ["1102", "4904"],
        mitreTactics: ["Defense Evasion"],
        commonCauses: ["System shutdown", "Service manipulation", "Attack cleanup"],
        falsePositives: ["Normal system maintenance", "Planned shutdowns"]
    },
    {
        id: "1101",
        name: "Audit Events Dropped",
        description: "Audit events have been dropped by the transport. Indicates potential audit system compromise.",
        category: "Audit Policy",
        criticality: "High", 
        logSource: "Security",
        investigationTips: [
            "Check audit system capacity and configuration",
            "Look for signs of deliberate audit overload",
            "Review system performance during the time period",
            "Investigate potential attack activities"
        ],
        relatedEvents: ["4612", "1108"],
        mitreTactics: ["Defense Evasion"],
        commonCauses: ["Resource exhaustion", "System overload", "Attack activities"],
        falsePositives: ["System capacity issues", "High legitimate activity"]
    },
    {
        id: "1104",
        name: "Security Log Full",
        description: "The security log is now full. Critical for audit continuity monitoring.",
        category: "Audit Policy",
        criticality: "High",
        logSource: "System", 
        investigationTips: [
            "Check log retention policies",
            "Look for rapid log filling patterns",
            "Investigate potential log flooding attacks",
            "Verify backup and archiving procedures"
        ],
        relatedEvents: ["1105", "4612"],
        mitreTactics: ["Defense Evasion"],
        commonCauses: ["Log flooding attacks", "High activity periods", "Insufficient log size"],
        falsePositives: ["Normal high-activity periods", "Undersized log files"]
    },
    {
        id: "4610",
        name: "Authentication Package Loaded",
        description: "An authentication package has been loaded by the Local Security Authority. Monitor for malicious authentication modules.",
        category: "System",
        criticality: "Medium",
        logSource: "Security",
        investigationTips: [
            "Verify legitimacy of loaded authentication packages",
            "Check for unsigned or suspicious modules",
            "Monitor for credential harvesting tools",
            "Review LSA security configuration"
        ],
        relatedEvents: ["4622", "4614"],
        mitreTactics: ["Credential Access", "Persistence"],
        commonCauses: ["System initialization", "Security software installation"],
        falsePositives: ["Legitimate security software", "Normal system operations"]
    },
    {
        id: "4612",
        name: "Audit Resources Exhausted",
        description: "Internal resources for queuing audit messages have been exhausted, leading to loss of some audits.",
        category: "Audit Policy",
        criticality: "High",
        logSource: "Security",
        investigationTips: [
            "Check for audit flooding or DoS attacks",
            "Review system performance and capacity",
            "Look for signs of deliberate audit evasion",
            "Investigate high-volume activities"
        ],
        relatedEvents: ["1101", "1104"],
        mitreTactics: ["Defense Evasion"],
        commonCauses: ["System overload", "Audit flooding", "Resource constraints"],
        falsePositives: ["High legitimate activity", "Undersized systems"]
    },
    {
        id: "4615",
        name: "Invalid LPC Port Use",
        description: "Invalid use of LPC port. May indicate process manipulation or exploitation attempts.",
        category: "System",
        criticality: "Medium",
        logSource: "Security",
        investigationTips: [
            "Investigate suspicious process communications",
            "Check for privilege escalation attempts",
            "Review process integrity and behavior",
            "Look for malware or exploitation indicators"
        ],
        relatedEvents: ["4688", "4673"],
        mitreTactics: ["Privilege Escalation", "Defense Evasion"],
        commonCauses: ["Process manipulation", "Exploitation attempts", "Software bugs"],
        falsePositives: ["Application bugs", "Legacy software issues"]
    },
    {
        id: "4657",
        name: "Registry Value Modified",
        description: "A registry value was modified. Critical for monitoring system configuration changes.",
        category: "File & Registry",
        criticality: "Medium", 
        logSource: "Security",
        investigationTips: [
            "Monitor critical registry keys and values",
            "Check for persistence mechanism installation",
            "Review unauthorized configuration changes",
            "Verify business justification for changes"
        ],
        relatedEvents: ["4656", "4663"],
        mitreTactics: ["Persistence", "Defense Evasion"],
        commonCauses: ["Software installation", "Configuration changes", "Malware persistence"],
        falsePositives: ["Normal software operations", "System updates"]
    },
    {
        id: "4660",
        name: "Object Deleted",
        description: "An object was deleted. Important for monitoring unauthorized deletions.",
        category: "File & Registry",
        criticality: "Medium",
        logSource: "Security",
        investigationTips: [
            "Check authorization for object deletion",
            "Monitor critical file and registry deletions", 
            "Look for evidence destruction attempts",
            "Review deletion patterns and timing"
        ],
        relatedEvents: ["4656", "4659"],
        mitreTactics: ["Defense Evasion"],
        commonCauses: ["File cleanup", "Evidence destruction", "Normal operations"],
        falsePositives: ["Routine file management", "Application operations"]
    },
    {
        id: "4674",
        name: "Privileged Object Operation",
        description: "An operation was attempted on a privileged object. Monitor for abuse of sensitive system objects.",
        category: "Security",
        criticality: "Medium",
        logSource: "Security",
        investigationTips: [
            "Monitor operations on sensitive objects",
            "Check for unauthorized privilege usage",
            "Review object access patterns",
            "Verify business justification"
        ],
        relatedEvents: ["4672", "4673"],
        mitreTactics: ["Privilege Escalation"],
        commonCauses: ["Administrative operations", "System maintenance"],
        falsePositives: ["Normal admin operations", "System processes"]
    },
    {
        id: "4778",
        name: "RDP Session Reconnected",
        description: "A session was reconnected to a Window Station. Monitor for RDP session activity.",
        category: "Authentication",
        criticality: "Medium",
        logSource: "Security",
        investigationTips: [
            "Monitor RDP session patterns and timing",
            "Check for unauthorized remote access",
            "Review source IP addresses",
            "Correlate with logon events"
        ],
        relatedEvents: ["4779", "4624", "4647"],
        mitreTactics: ["Lateral Movement", "Initial Access"],
        commonCauses: ["Remote administration", "User remote access"],
        falsePositives: ["Normal remote work", "Administrative access"]
    },
    {
        id: "4779",
        name: "RDP Session Disconnected", 
        description: "A session was disconnected from a Window Station. Monitor for RDP session termination.",
        category: "Authentication",
        criticality: "Medium",
        logSource: "Security",
        investigationTips: [
            "Monitor session disconnect patterns",
            "Check for abrupt disconnections",
            "Review session duration and activity",
            "Look for indicators of compromise"
        ],
        relatedEvents: ["4778", "4634", "4647"],
        mitreTactics: ["Defense Evasion"],
        commonCauses: ["Normal session termination", "Network issues"],
        falsePositives: ["Normal remote work patterns", "Network disconnections"]
    },
    {
        id: "4781",
        name: "Account Name Changed",
        description: "The name of an account was changed. Critical for monitoring account manipulation.",
        category: "Account Management",
        criticality: "High",
        logSource: "Security",
        investigationTips: [
            "Verify authorization for account name changes",
            "Check for account camouflage attempts",
            "Monitor administrative account changes",
            "Review change timing and context"
        ],
        relatedEvents: ["4738", "4720"],
        mitreTactics: ["Defense Evasion", "Persistence"],
        commonCauses: ["Account management", "Organizational changes"],
        falsePositives: ["Normal HR processes", "Account maintenance"]
    },
    {
        id: "4782",
        name: "Password Hash Accessed",
        description: "The password hash of an account was accessed. Critical indicator of credential dumping.",
        category: "Security",
        criticality: "Critical",
        logSource: "Security",
        investigationTips: [
            "Immediate investigation required - potential credential theft",
            "Check for unauthorized access to password stores",
            "Look for credential dumping tools",
            "Review administrative access patterns"
        ],
        relatedEvents: ["4673", "4672"],
        mitreTactics: ["Credential Access"],
        commonCauses: ["Credential dumping attacks", "Unauthorized access"],
        falsePositives: ["Very rare - investigate all occurrences"],
        investigationPlaybook: {
            immediate: {
                title: "Critical Response - Credential Dumping Detection",
                priority: "Critical",
                steps: [
                    {
                        action: "Identify the process accessing password hashes",
                        tool: "Windows Event Viewer, EDR",
                        expected: "Find the specific process and user involved in hash access",
                        query: "Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4782} | Select-Object TimeCreated, ProcessName, SubjectUserName"
                    },
                    {
                        action: "Check for known credential dumping tools",
                        tool: "Antivirus, EDR, Process analysis",
                        expected: "Identify if mimikatz, hashdump, or similar tools were used",
                        query: "Get-Process | Where-Object {$_.ProcessName -match 'mimikatz|procdump|sqldumper'}"
                    },
                    {
                        action: "Examine memory dumps and suspicious processes",
                        tool: "Memory analysis, Process monitor",
                        expected: "Find evidence of LSASS memory access or credential extraction",
                        query: "Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4656} | Where-Object {$_.Message -match 'lsass'}"
                    },
                    {
                        action: "Check for privilege escalation events",
                        tool: "Security logs, SIEM",
                        expected: "Identify how attacker gained access to password hashes",
                        query: "index=security EventCode=4672 earliest=-1h | stats count by SubjectUserName"
                    }
                ]
            },
            shortTerm: {
                title: "Containment and Impact Assessment",
                priority: "High",
                steps: [
                    {
                        action: "Isolate affected system immediately",
                        tool: "Network isolation, EDR containment",
                        expected: "Prevent lateral movement and further credential theft",
                        query: "Disconnect system from network and enable containment mode"
                    },
                    {
                        action: "Identify which accounts were compromised",
                        tool: "Security logs, Active Directory",
                        expected: "Determine scope of credential exposure",
                        query: "Get-ADUser -Filter * -Properties PasswordLastSet | Where-Object {$_.PasswordLastSet -lt (Get-Date).AddDays(-1)}"
                    },
                    {
                        action: "Search for signs of credential reuse",
                        tool: "SIEM, Authentication logs",
                        expected: "Find if stolen credentials were used elsewhere",
                        query: "index=security EventCode=4624 LogonType=3 earliest=-4h | stats count by src_ip, user"
                    },
                    {
                        action: "Check for data exfiltration activities",
                        tool: "Network monitoring, DLP",
                        expected: "Identify if credentials were sent to external systems",
                        query: "Monitor for unusual outbound network traffic and data transfers"
                    }
                ]
            },
            longTerm: {
                title: "Recovery and Hardening",
                priority: "High",
                steps: [
                    {
                        action: "Force password reset for all affected accounts",
                        tool: "Active Directory, Password management",
                        expected: "Invalidate potentially stolen credentials",
                        query: "Set-ADUser -Identity [username] -ChangePasswordAtLogon $true"
                    },
                    {
                        action: "Implement credential guard and protection",
                        tool: "Windows Defender Credential Guard, LAPS",
                        expected: "Prevent future credential dumping attacks",
                        query: "Enable Credential Guard and configure LAPS for admin passwords"
                    },
                    {
                        action: "Enhance monitoring for credential access",
                        tool: "SIEM rules, EDR detection",
                        expected: "Detect future credential dumping attempts",
                        query: "Create detection rules for LSASS access and credential tools"
                    },
                    {
                        action: "Conduct threat hunting across environment",
                        tool: "Threat hunting tools, IOC analysis",
                        expected: "Find any other compromised systems or accounts",
                        query: "Hunt for indicators of credential dumping tools and techniques"
                    }
                ]
            }
        }
    },
    {
        id: "4830",
        name: "SID History Removed",
        description: "SID History was removed from an account. Monitor for unauthorized privilege changes.",
        category: "Account Management", 
        criticality: "High",
        logSource: "Security",
        investigationTips: [
            "Verify authorization for SID history removal",
            "Check impact on account privileges",
            "Monitor for privilege manipulation",
            "Review administrative justification"
        ],
        relatedEvents: ["4765", "4766"],
        mitreTactics: ["Defense Evasion"],
        commonCauses: ["Account cleanup", "Domain migration cleanup"],
        falsePositives: ["Authorized domain administration", "Migration cleanup"]
    },
    {
        id: "5038",
        name: "Code Integrity Violation",
        description: "Code integrity determined that the image hash of a file is not valid. Critical for detecting malware.",
        category: "System",
        criticality: "High",
        logSource: "Security",
        investigationTips: [
            "Investigate unsigned or modified binaries",
            "Check for malware or rootkit installation",
            "Review file integrity and signatures",
            "Monitor for code injection attempts"
        ],
        relatedEvents: ["4688", "4697"],
        mitreTactics: ["Defense Evasion", "Execution"],
        commonCauses: ["Malware installation", "Unsigned software", "File corruption"],
        falsePositives: ["Development tools", "Unsigned legitimate software"]
    },
    {
        id: "5376",
        name: "Credential Manager Backup",
        description: "Credential Manager credentials were backed up. Monitor for credential theft attempts.",
        category: "Security",
        criticality: "Medium",
        logSource: "Security",
        investigationTips: [
            "Monitor credential backup activities",
            "Check for unauthorized credential access",
            "Verify business justification for backup",
            "Review backup timing and context"
        ],
        relatedEvents: ["5377", "5379"],
        mitreTactics: ["Credential Access"],
        commonCauses: ["System backup", "User profile migration"],
        falsePositives: ["Normal backup operations", "Profile transfers"]
    },
    {
        id: "5379",
        name: "Credential Manager Read",
        description: "Credential Manager credentials were read. Monitor for credential harvesting.",
        category: "Security",
        criticality: "Medium",
        logSource: "Security",
        investigationTips: [
            "Monitor credential access patterns",
            "Check for unauthorized credential harvesting",
            "Review application credential usage",
            "Look for malicious credential access"
        ],
        relatedEvents: ["5376", "5381"],
        mitreTactics: ["Credential Access"],
        commonCauses: ["Application authentication", "Credential harvesting"],
        falsePositives: ["Normal application operations", "Single sign-on"]
    },

    // Additional Critical Events
    {
        id: "1102",
        name: "Audit Log Cleared",
        description: "The audit log was cleared. Critical indicator of potential cover-up activity.",
        category: "Audit Policy",
        criticality: "High",
        logSource: "Security",
        investigationTips: [
            "Immediate investigation required",
            "Check who cleared the log",
            "Review timing with other suspicious activity",
            "Examine backup logs if available"
        ],
        relatedEvents: ["4904"],
        mitreTactics: ["Defense Evasion"],
        commonCauses: ["Attack cleanup", "Unauthorized log management"],
        falsePositives: ["Authorized log rotation"],
        investigationPlaybook: {
            immediate: {
                title: "Audit Log Tampering Investigation",
                priority: "High",
                steps: [
                    {
                        action: "Identify who cleared the audit log",
                        tool: "System Event Log, SIEM",
                        expected: "Find the user account and process that cleared the log",
                        query: "Get-WinEvent -FilterHashtable @{LogName='System'; ID=1102} | Select-Object TimeCreated, UserId, ProcessName"
                    },
                    {
                        action: "Check for authorization of log clearing",
                        tool: "Change management, IT operations",
                        expected: "Verify if this was scheduled maintenance or unauthorized activity",
                        query: "Review change tickets and maintenance schedules for authorized log clearing"
                    },
                    {
                        action: "Examine events before log clearing",
                        tool: "Backup logs, SIEM historical data",
                        expected: "Identify suspicious activities that occurred before log clearing",
                        query: "Search backup/forwarded logs for events 2-4 hours before clearing"
                    },
                    {
                        action: "Check for concurrent security events",
                        tool: "Security logs, system logs",
                        expected: "Find other indicators of compromise around the same time",
                        query: "index=security earliest=-4h latest=+1h | stats count by EventCode | sort -count"
                    }
                ]
            },
            shortTerm: {
                title: "Evidence Recovery and Timeline Analysis",
                priority: "High",
                steps: [
                    {
                        action: "Recover audit trail from alternative sources",
                        tool: "Syslog servers, SIEM storage, backup systems",
                        expected: "Reconstruct missing audit events from other log sources",
                        query: "Search all log forwarding destinations and backup systems"
                    },
                    {
                        action: "Analyze user behavior patterns",
                        tool: "User activity monitoring, UEBA",
                        expected: "Identify if the clearing user had unusual activity patterns",
                        query: "Review 30-day activity history for the user who cleared logs"
                    },
                    {
                        action: "Check for signs of privilege escalation",
                        tool: "Security logs, privilege monitoring",
                        expected: "Determine how user gained rights to clear logs",
                        query: "index=security EventCode=4672 user=[clearing_user] earliest=-24h"
                    },
                    {
                        action: "Search for evidence destruction tools",
                        tool: "Process monitoring, file system analysis",
                        expected: "Find tools used for log manipulation or evidence destruction",
                        query: "Search for sdelete, cipher, wevtutil, or similar cleanup tools"
                    }
                ]
            },
            longTerm: {
                title: "Security Hardening and Prevention",
                priority: "Medium",
                steps: [
                    {
                        action: "Implement real-time log forwarding",
                        tool: "Windows Event Forwarding, Syslog",
                        expected: "Ensure logs are immediately sent to secure storage",
                        query: "Configure WEF and syslog forwarding for all critical logs"
                    },
                    {
                        action: "Enhance log clearing detection",
                        tool: "SIEM rules, custom monitoring",
                        expected: "Create alerts for any log clearing activities",
                        query: "Create detection rules for EventID 1102 and related log manipulation"
                    },
                    {
                        action: "Review and restrict log management permissions",
                        tool: "Group Policy, access controls",
                        expected: "Limit who can clear or modify audit logs",
                        query: "Audit and restrict SeAuditPrivilege and log file permissions"
                    },
                    {
                        action: "Implement log integrity monitoring",
                        tool: "File integrity monitoring, tamper detection",
                        expected: "Detect unauthorized modifications to log files",
                        query: "Enable FIM on log directories and implement log signing"
                    }
                ]
            }
        }
    },
    {
        id: "4616",
        name: "System Time Changed",
        description: "The system time was changed. May indicate timestamp manipulation attempts.",
        category: "System",
        criticality: "Medium",
        logSource: "Security",
        investigationTips: [
            "Check who changed the system time",
            "Review time change amount and direction",
            "Monitor for log timestamp manipulation",
            "Correlate with other suspicious activity"
        ],
        relatedEvents: [],
        mitreTactics: ["Defense Evasion"],
        commonCauses: ["Time synchronization", "Administrative changes"],
        falsePositives: ["NTP synchronization", "DST changes"]
    },
    {
        id: "4608",
        name: "Windows Starting Up",
        description: "Windows is starting up. System boot indicator.",
        category: "System",
        criticality: "Low",
        logSource: "Security",
        investigationTips: [
            "Monitor boot frequency patterns",
            "Correlate with shutdown events",
            "Check for unexpected restarts",
            "Review system stability"
        ],
        relatedEvents: ["4609", "6005"],
        mitreTactics: [],
        commonCauses: ["System startup", "Maintenance reboots"],
        falsePositives: ["Normal system operations"]
    },
    {
        id: "4609",
        name: "Windows Shutting Down",
        description: "Windows is shutting down. System shutdown indicator.",
        category: "System",
        criticality: "Low",
        logSource: "Security",
        investigationTips: [
            "Monitor shutdown patterns",
            "Check for unexpected shutdowns",
            "Correlate with user activity",
            "Review system stability"
        ],
        relatedEvents: ["4608", "6006"],
        mitreTactics: [],
        commonCauses: ["System shutdown", "Maintenance"],
        falsePositives: ["Normal operations"]
    }
];

// Export the database
window.eventDatabase = eventDatabase; 