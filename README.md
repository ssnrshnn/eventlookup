# 🛡️ Windows Event ID Dashboard - SOC Analyst Tool

A comprehensive, interactive web-based dashboard for Windows Event ID analysis designed specifically for SOC (Security Operations Center) analysts. Features a cyberpunk/hacker-themed interface with extensive Event ID documentation and investigation playbooks.

## ✨ Live Demo

Simply open `index.html` in your web browser - no installation required!

## 🎯 Features

### 🌟 **Interactive Web Dashboard**
- **Search-driven interface** - Real-time search by Event ID, name, or keywords
- **Advanced filtering** - Filter by category (Authentication, System, Network, etc.) and criticality level
- **Real-time statistics** - Live event count by priority level with visual indicators
- **Detailed event sidebar** - Comprehensive information with investigation playbooks
- **Responsive design** - Works on desktop, tablet, and mobile devices

### 🎨 **Cyberpunk/Hacker Theme**
- **Matrix-style background animation** - Falling green characters effect
- **Neon green color scheme** - Terminal-inspired aesthetics with glowing effects
- **Fira Code monospace font** - Professional coding font for readability
- **Smooth animations** - Pulsing icons, scanning lines, and hover effects
- **Dark theme optimized** - Easy on the eyes during long SOC shifts

### 📚 **Comprehensive Event Database**
- **90+ Windows Event IDs** - Curated collection of the most critical security events
- **Detailed event information** including:
  - Investigation tips and SOC analyst guidance
  - MITRE ATT&CK tactics and techniques mapping
  - Related events and cross-references
  - Common causes and false positive indicators
  - Criticality levels (Critical, High, Medium, Low)
  - Detection queries for Splunk, ELK, and PowerShell

### 📝 **Individual Event Documentation**
- **90+ individual markdown files** - One for each event ID with detailed documentation
- **Structured format** - Consistent documentation structure across all events
- **Investigation playbooks** - Step-by-step SOC response procedures
- **Detection queries** - Ready-to-use search queries for popular SIEM platforms
- **Cross-referenced links** - Easy navigation between related events

## 🚀 Quick Start

### Option 1: Direct Browser Access (Recommended)
1. **Clone or download** this repository
2. **Open `index.html`** directly in your web browser
3. **Start searching** for Windows Event IDs!

### Option 2: Local Web Server
1. **Clone or download** this repository
2. **Start a local web server**:
   ```bash
   # Python 3
   python3 -m http.server 8080
   
   # Python 2
   python -m SimpleHTTPServer 8080
   
   # Node.js (if you have it installed)
   npx serve .
   ```
3. **Open your browser** and navigate to: `http://localhost:8080`
4. **Start investigating** Windows Event IDs!

## 📂 Project Structure

```
eventIDs/
├── index.html              # Main dashboard interface
├── styles.css              # Cyberpunk-themed styling with Matrix effects
├── app.js                  # Dashboard functionality and interactions
├── eventData.json          # Comprehensive event database in JSON format (90+ events)
└── README.md               # Project documentation (this file)
```

## 🔍 Event Categories

### 🔐 **Authentication Events**
- **4624** - Successful Logon
- **4625** - Failed Logon
- **4768** - Kerberos TGT Requested  
- **4771** - Kerberos Pre-auth Failed
- And more...

### 👤 **Account Management**
- **4720** - User Account Created
- **4726** - User Account Deleted
- **4728** - Member Added to Global Group
- **4740** - User Account Locked Out
- And more...

### 🖥️ **System & Boot Events**
- **1074** - System Shutdown/Restart
- **6005** - Event Log Service Started
- **6008** - Unexpected Shutdown
- **7034** - Service Crashed
- And more...

### 🚀 **Process & Application**
- **4688** - Process Created
- **4697** - Service Installed
- **4698** - Scheduled Task Created
- **1000** - Application Error
- And more...

### 🌐 **Network Events**
- **5140** - Network Share Accessed
- **5156** - Windows Filtering Platform Connection
- And more...

### 🔍 **Audit Policy Events**
- **1102** - Security Event Log Cleared (HIGH!)
- **4904** - Security Event Log Cleared (CRITICAL!)
- **4719** - System Audit Policy Changed
- **1100** - Event Logging Service Shut Down
- **1101** - Audit Events Dropped
- **1104** - Security Log Full
- **4612** - Audit Resources Exhausted
- And more...

### 💻 **PowerShell Events**
- **4104** - PowerShell Script Block Logging
- **4103** - PowerShell Module Logging
- And more...

### 🔬 **Sysmon Events**
- **1** - Process Creation
- **3** - Network Connection
- **11** - File Created
- And more...

### 🚨 **Critical Security Events** (Ultimate Windows Security)
- **4782** - Password Hash Accessed (CRITICAL!)
- **4781** - Account Name Changed
- **4830** - SID History Removed
- **5038** - Code Integrity Violation
- **4778/4779** - RDP Session Connect/Disconnect
- **4657** - Registry Value Modified
- **4660** - Object Deleted
- **5376/5379** - Credential Manager Access
- And more...

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

## 🛠️ Technical Details

### **Frontend Stack**
- **Pure HTML/CSS/JavaScript** - No frameworks required
- **Font Awesome** - Icons and symbols
- **Fira Code Font** - Professional monospace font
- **CSS Grid & Flexbox** - Responsive layout

### **Features**
- **Responsive design** - Works on desktop, tablet, and mobile
- **No backend required** - Static files only
- **Fast search** - Client-side filtering and search
- **Sliding sidebar** - Detailed event information without popups
- **Matrix background** - Animated canvas effect
- **Industry compliance** - Based on Microsoft official docs + Ultimate Windows Security expert analysis

### **Browser Support**
- ✅ Chrome/Chromium (recommended)
- ✅ Firefox  
- ✅ Safari
- ✅ Edge

## 📊 Statistics

- **Total Events:** 90+ Windows Event IDs
- **Critical Priority:** High-impact security events
- **High Priority:** Authentication and privilege escalation events  
- **Medium Priority:** System and application events
- **Low Priority:** Informational and diagnostic events
- **Documentation Files:** 90+ detailed markdown files
- **Event Categories:** 10+ categories (Authentication, System, Network, etc.)
- **Data Sources:** Microsoft Official Documentation + Security Community Best Practices

## 🔧 Customization

### **Adding New Events**
1. Edit `eventData.js` to add new event objects
2. Run `python3 generateEventMDs.py` to regenerate markdown files
3. Refresh the dashboard

### **Modifying Themes**
- Edit `styles.css` to change colors and styling
- Modify matrix effect in `app.js` for different background animations

### **Extending Search**
- Add new search fields in the `handleSearch()` method
- Modify event card display in `createEventCard()` method

## 🚨 **Priority Event IDs for SOC**

### **🔴 CRITICAL - Investigate Immediately**
- **4904** - Security Event Log Cleared
- **1102** - Audit Log Cleared

### **🟠 HIGH - Investigate within 1 hour**
- **4625** - Failed Logon (Multiple instances)
- **4720** - User Account Created
- **4697** - Service Installed
- **4698** - Scheduled Task Created
- **4771** - Kerberos Pre-auth Failed

## 🎯 **New Critical Events from Ultimate Windows Security**

### **🔴 CRITICAL - Immediate Investigation Required**
- **4782** - Password Hash Accessed (Credential dumping!)

### **🟠 HIGH - Investigate within 1 hour**
- **4781** - Account Name Changed (Account manipulation)
- **5038** - Code Integrity Violation (Malware detection)
- **4830** - SID History Removed (Privilege manipulation)
- **1100** - Event Logging Service Shut Down (Audit tampering)
- **1101** - Audit Events Dropped (Potential evasion)
- **1104** - Security Log Full (Audit continuity risk)
- **4612** - Audit Resources Exhausted (System overload/attack)

### **🔍 Try These New Event Searches:**
- `4782` - Password hash access (CRITICAL!)
- `4781` - Account name changes
- `5038` - Code integrity violations
- `4657` - Registry modifications
- `4778` - RDP connections
- `5376` - Credential manager access

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. **Add new Event IDs** - Submit PRs with new Windows Event IDs and documentation
2. **Improve documentation** - Enhance existing event descriptions and investigation tips
3. **Report issues** - Found a bug or have a feature request? Open an issue
4. **Share feedback** - Let us know how you're using this tool in your SOC

### Development Setup
1. Fork this repository
2. Make your changes
3. Test the dashboard locally
4. Submit a pull request

## 🎯 Use Cases

- **SOC Analysts** - Quick reference during incident investigation
- **Security Engineers** - Building detection rules and playbooks
- **Threat Hunters** - Understanding Windows event patterns
- **Security Training** - Learning Windows security event analysis
- **Compliance Teams** - Understanding audit requirements

## 🔗 Related Resources

- [Microsoft Security Auditing Events](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/security-auditing-overview)
- [Ultimate Windows Security Encyclopedia](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Windows Event Forwarding](https://docs.microsoft.com/en-us/windows/security/threat-protection/use-windows-event-forwarding-to-assist-in-intrusion-detection)

## 📝 License

This project is open source and available for security professionals and educational purposes.

## 🤝 Contributing

Feel free to contribute by:
- Adding new Windows Event IDs
- Improving investigation tips
- Enhancing the user interface
- Adding new search capabilities
- Expanding documentation

## 📞 Support

For questions or suggestions regarding SOC analysis and Windows Event monitoring, refer to:
- Microsoft Security Documentation
- MITRE ATT&CK Framework
- SANS Digital Forensics and Incident Response

---

**🛡️ Stay vigilant, SOC analysts! Keep monitoring those event logs! 🛡️**

*Built with 💚 for the cybersecurity community* 