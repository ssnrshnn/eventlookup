# 🛡️ Windows Event ID Dashboard - SOC Analyst Tool

A comprehensive, interactive web-based dashboard for Windows Event ID analysis designed specifically for SOC (Security Operations Center) analysts. Features a cyberpunk/hacker-themed interface with extensive Event ID documentation and investigation guidance.

## 🎯 Features

**Interactive Web Dashboard**
- **Search-driven interface** - Real-time search by Event ID, name, or keywords
- **Advanced filtering** - Filter by category (Authentication, System, Network, etc.) and criticality level
- **Real-time statistics** - Live event count by priority level with visual indicators
- **Detailed event sidebar** - Comprehensive information with investigation guidance
- **Responsive design** - Works on desktop, tablet, and mobile devices

## **Comprehensive Event Database**
- **164 Windows Event IDs** - Comprehensive collection of the most critical security events including complete Sysmon coverage (Events 1-29 + 255) and essential Windows Security events
- **Detailed event information** including:
  - Investigation tips and SOC analyst guidance
  - MITRE ATT&CK tactics and techniques mapping
  - Related events and cross-references
  - Common causes and false positive indicators
  - Criticality levels (Critical, High, Medium, Low)
  - Investigation guidance for SOC analysts

## 📂 Project Structure

```
eventIDs/
├── index.html              # Main dashboard interface
├── styles.css              # Cyberpunk-themed styling with Matrix effects
├── app.js                   # Dashboard functionality and interactions
├── eventData.js             # Comprehensive event database (164 events)
├── generateEventMDs.py      # Python script to generate markdown files
├── events/                  # Individual event documentation (160 files)
│   ├── README.md           # Event index and categories overview
│   ├── 4625.md             # Failed Logon event documentation
│   ├── 4624.md             # Successful Logon event documentation
│   ├── 4688.md             # Process Creation event documentation
│   ├── 4697.md             # Service Installation event documentation
│   └── ... (160 more)      # Complete event documentation library
└── README.md               # Project documentation (this file)
```

## 🎮 Usage Examples

### 🔍 **Search Examples**
- `4625` - Find failed logon events
- `brute force` - Find attack-related events
- `PowerShell` - Find PowerShell-related events
- `Critical` - Show only critical priority events
- `privilege escalation` - Find privilege escalation events

### ⌨️ **Keyboard Shortcuts**
- `Ctrl + K` - Focus search bar
- `Escape` - Close event details sidebar
- `Arrow Keys` - Navigate search results
- `Enter` - Open selected event details


## 🎯 Use Cases

- **SOC Analysts** - Quick reference during incident investigation
- **Security Engineers** - Building detection rules and investigation procedures
- **Threat Hunters** - Understanding Windows event patterns
- **Security Training** - Learning Windows security event analysis
- **Compliance Teams** - Understanding audit requirements

## 🔗 Related Resources

- [Microsoft Security Auditing Events](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/security-auditing-overview)
- [Ultimate Windows Security Encyclopedia](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Windows Event Forwarding](https://docs.microsoft.com/en-us/windows/security/threat-protection/use-windows-event-forwarding-to-assist-in-intrusion-detection)


---

**🛡️ Stay vigilant, SOC analysts! Keep monitoring those event logs! 🛡️**

*Built with 💚 for the cybersecurity community* 