// Windows Event ID Dashboard - Main Application Logic

// Matrix Background Effect
class MatrixBackground {
    constructor() {
        this.canvas = document.getElementById('matrix-bg');
        this.ctx = this.canvas.getContext('2d');
        this.chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
        this.fontSize = 14;
        this.columns = 0;
        this.drops = [];
        
        this.init();
        this.animate();
    }
    
    init() {
        this.canvas.width = window.innerWidth;
        this.canvas.height = window.innerHeight;
        this.columns = Math.floor(this.canvas.width / this.fontSize);
        
        // Initialize drops
        for (let i = 0; i < this.columns; i++) {
            this.drops[i] = Math.random() * this.canvas.height;
        }
        
        // Handle resize
        window.addEventListener('resize', () => {
            this.canvas.width = window.innerWidth;
            this.canvas.height = window.innerHeight;
            this.columns = Math.floor(this.canvas.width / this.fontSize);
            this.drops = [];
            for (let i = 0; i < this.columns; i++) {
                this.drops[i] = Math.random() * this.canvas.height;
            }
        });
    }
    
    animate() {
        // Semi-transparent black background
        this.ctx.fillStyle = 'rgba(13, 17, 23, 0.05)';
        this.ctx.fillRect(0, 0, this.canvas.width, this.canvas.height);
        
        // Green text
        this.ctx.fillStyle = '#58a6ff';
        this.ctx.font = `${this.fontSize}px Fira Code, monospace`;
        
        for (let i = 0; i < this.columns; i++) {
            const char = this.chars[Math.floor(Math.random() * this.chars.length)];
            const x = i * this.fontSize;
            const y = this.drops[i] * this.fontSize;
            
            this.ctx.fillText(char, x, y);
            
            // Reset drop position
            if (y > this.canvas.height && Math.random() > 0.975) {
                this.drops[i] = 0;
            }
            
            this.drops[i]++;
        }
        
        requestAnimationFrame(() => this.animate());
    }
}

class EventDashboard {
    constructor() {
        this.events = [];
        this.filteredEvents = [];
        this.currentPage = 1;
        this.eventsPerPage = 20;
        this.hasSearched = false;
        
        this.initializeElements();
        this.bindEvents();
        
        // Fetch the events data from JSON file
        fetch('eventData.json')
            .then(response => response.json())
            .then(data => {
                this.events = data;
                this.filteredEvents = [...this.events];
                this.updateStats();
                this.displayEvents();
                this.updateResultCount();
                console.log(`Loaded ${this.events.length} events from eventData.json`);
            })
            .catch(error => {
                console.error('Error loading event data:', error);
                this.showError('Failed to load event data. Please try refreshing the page.');
            });
    }

    initializeElements() {
        // Search elements
        this.searchInput = document.getElementById('searchInput');
        this.categoryFilter = document.getElementById('categoryFilter');
        this.criticalityFilter = document.getElementById('criticalityFilter');
        this.clearSearchBtn = document.getElementById('clearSearch');
        
        // Results elements
        this.resultsContainer = document.getElementById('resultsContainer');
        this.resultCount = document.getElementById('resultCount');
        this.noResults = document.getElementById('noResults');
        
        // Stats elements
        this.criticalCount = document.getElementById('criticalCount');
        this.highCount = document.getElementById('highCount');
        this.mediumCount = document.getElementById('mediumCount');
        this.totalCount = document.getElementById('totalCount');
        
        // Sidebar elements
        this.sidebar = document.getElementById('eventSidebar');
        this.sidebarTitle = document.getElementById('sidebarTitle');
        this.sidebarBody = document.getElementById('sidebarBody');
        this.closeSidebar = document.getElementById('closeSidebar');
    }

    bindEvents() {
        // Search functionality
        this.searchInput.addEventListener('input', (e) => {
            this.handleSearch();
        });
        
        this.categoryFilter.addEventListener('change', () => {
            this.handleSearch();
        });
        
        this.criticalityFilter.addEventListener('change', () => {
            this.handleSearch();
        });
        
        this.clearSearchBtn.addEventListener('click', () => {
            this.clearSearch();
        });
        
        // Sidebar functionality
        this.closeSidebar.addEventListener('click', () => {
            this.hideSidebar();
        });
        
        // Close sidebar when clicking outside
        document.addEventListener('click', (e) => {
            if (this.sidebar.classList.contains('active') && 
                !this.sidebar.contains(e.target) && 
                !e.target.closest('.event-card')) {
                this.hideSidebar();
            }
        });
        
        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                this.hideSidebar();
            }
            if (e.ctrlKey && e.key === 'k') {
                e.preventDefault();
                this.searchInput.focus();
            }
        });
    }

    handleSearch() {
        const searchTerm = this.searchInput.value.toLowerCase().trim();
        const categoryFilter = this.categoryFilter.value;
        const criticalityFilter = this.criticalityFilter.value;
        
        // If no search term and no filters (or "All" filters), show all events
        if (!searchTerm && (!categoryFilter || categoryFilter === "") && (!criticalityFilter || criticalityFilter === "")) {
            this.filteredEvents = [...this.events];
            this.hasSearched = false;
            this.currentPage = 1;
            this.displayEvents();
            this.updateResultCount();
            return;
        }
        
        this.hasSearched = true;
        
        this.filteredEvents = this.events.filter(event => {
            // Text search (ID, name, description, keywords)
            const matchesSearch = !searchTerm || 
                event.id.toLowerCase().includes(searchTerm) ||
                event.name.toLowerCase().includes(searchTerm) ||
                event.description.toLowerCase().includes(searchTerm) ||
                event.category.toLowerCase().includes(searchTerm) ||
                event.mitreTactics.some(tactic => tactic.toLowerCase().includes(searchTerm)) ||
                event.commonCauses.some(cause => cause.toLowerCase().includes(searchTerm));
            
            // Category filter - treat empty string or no value as "All Categories"
            const matchesCategory = !categoryFilter || categoryFilter === "" || event.category === categoryFilter;
            
            // Criticality filter - treat empty string or no value as "All Criticality"
            const matchesCriticality = !criticalityFilter || criticalityFilter === "" || event.criticality === criticalityFilter;
            
            return matchesSearch && matchesCategory && matchesCriticality;
        });
        
        this.currentPage = 1;
        this.displayEvents();
        this.updateResultCount();
    }

    clearSearch() {
        this.searchInput.value = '';
        this.categoryFilter.value = '';
        this.criticalityFilter.value = '';
        this.filteredEvents = [...this.events];
        this.hasSearched = false;
        this.currentPage = 1;
        this.displayEvents();
        this.updateResultCount();
        this.searchInput.focus();
    }

    showWelcomeMessage() {
        this.hideNoResults();
        this.resultCount.textContent = this.events.length;
        
        this.resultsContainer.innerHTML = `
            <div style="text-align: center; padding: 60px 20px; color: #58a6ff;">
                <div style="font-size: 4rem; margin-bottom: 20px; animation: pulse 2s infinite;">
                    <i class="fas fa-terminal"></i>
                </div>
                <h3 style="font-size: 1.8rem; margin-bottom: 15px; font-family: 'Fira Code', monospace; color: #58a6ff; text-shadow: 0 0 10px rgba(88, 166, 255, 0.5);">
                    > WINDOWS EVENT ANALYZER READY
                </h3>
                <p style="color: rgba(139, 148, 158, 0.9); font-family: 'Fira Code', monospace; margin-bottom: 20px;">
                    Database loaded: ${this.events.length} event signatures
                </p>
                <p style="color: rgba(139, 148, 158, 0.8); font-family: 'Fira Code', monospace; font-size: 0.9rem;">
                    Enter search query to begin threat analysis...
                </p>
                <div style="margin-top: 30px; color: rgba(139, 148, 158, 0.7); font-family: 'Fira Code', monospace; font-size: 0.8rem;">
                    <p>Examples:</p>
                    <p style="margin: 5px 0;">> 4625 (Failed logon)</p>
                    <p style="margin: 5px 0;">> PowerShell (PS events)</p>
                    <p style="margin: 5px 0;">> brute force (Attack patterns)</p>
                </div>
            </div>
        `;
    }

    displayEvents() {
        if (this.filteredEvents.length === 0 && this.hasSearched) {
            this.showNoResults();
            return;
        }
        
        this.hideNoResults();
        
        // If no search/filter is active, show ALL events. Otherwise, use pagination.
        let eventsToShow;
        let startIndex;
        
        if (!this.hasSearched) {
            // Show all events when no search is active
            eventsToShow = this.filteredEvents;
            startIndex = 0;
        } else {
            // Use pagination when search/filter is active
            startIndex = (this.currentPage - 1) * this.eventsPerPage;
            const endIndex = startIndex + this.eventsPerPage;
            eventsToShow = this.filteredEvents.slice(startIndex, endIndex);
        }
        
        this.resultsContainer.innerHTML = eventsToShow.map(event => this.createEventCard(event)).join('');
        
        // Add click listeners to cards
        this.resultsContainer.querySelectorAll('.event-card').forEach((card, index) => {
            card.addEventListener('click', () => {
                const eventIndex = startIndex + index;
                this.showEventDetails(this.filteredEvents[eventIndex]);
            });
        });
    }

    createEventCard(event) {
        const priorityClass = event.criticality.toLowerCase();
        
        return `
            <div class="event-card ${priorityClass}" data-event-id="${event.id}">
                <div class="event-header">
                    <div class="event-id">${event.id}</div>
                    <div class="priority-badge ${priorityClass}">${event.criticality}</div>
                </div>
                <div class="event-name">${event.name}</div>
                <div class="event-description">${this.truncateText(event.description, 120)}</div>
                <div class="event-footer">
                    <div class="event-category">${event.category}</div>
                    <div class="view-details">View Details →</div>
                </div>
            </div>
        `;
    }

    showEventDetails(event) {
        this.sidebarTitle.textContent = `Event ID ${event.id}: ${event.name}`;
        
        const mitreList = event.mitreTactics.length > 0 ? 
            `<ul class="mitre-tactics-list">${event.mitreTactics.map(tactic => {
                const mitreUrl = this.getMitreAttackUrl(tactic);
                return `<li><a href="${mitreUrl}" target="_blank" class="mitre-tactic-link" title="View ${tactic} on MITRE ATT&CK">${tactic} <i class="fas fa-external-link-alt" style="font-size: 0.8em; margin-left: 4px;"></i></a></li>`;
            }).join('')}</ul>` : 
            '<p>None identified</p>';
        
        const investigationList = event.investigationTips.length > 0 ?
            `<ul>${event.investigationTips.map(tip => `<li>${tip}</li>`).join('')}</ul>` :
            '<p>No specific tips available</p>';
        
        const relatedEventsHtml = event.relatedEvents.length > 0 ?
            `<div class="related-events">
                ${event.relatedEvents.map(relatedId => 
                    `<span class="related-event" onclick="dashboard.searchForEvent('${relatedId}')">${relatedId}</span>`
                ).join('')}
            </div>` :
            '<p>No related events</p>';
        
        const commonCausesList = event.commonCauses.length > 0 ?
            `<ul>${event.commonCauses.map(cause => `<li>${cause}</li>`).join('')}</ul>` :
            '<p>None specified</p>';
        
        const falsePositivesList = event.falsePositives.length > 0 ?
            `<ul>${event.falsePositives.map(fp => `<li>${fp}</li>`).join('')}</ul>` :
            '<p>None specified</p>';
        
        // Add fullDescription section if available in JSON (can be added later)
        const fullDescriptionHtml = event.fullDescription ? 
            `<div class="detail-section">
                <h3><i class="fas fa-book"></i> Full Documentation</h3>
                <div class="full-documentation">${event.fullDescription}</div>
            </div>` : '';
        
        this.sidebarBody.innerHTML = `
            <div class="detail-section">
                <h3><i class="fas fa-info-circle"></i> Event Information</h3>
                <p><strong>Event ID:</strong> ${event.id}</p>
                <p><strong>Event Name:</strong> ${event.name}</p>
                <p><strong>Category:</strong> ${event.category}</p>
                <p><strong>Criticality:</strong> <span class="priority-badge ${event.criticality.toLowerCase()}">${event.criticality}</span></p>
                <p><strong>Log Source:</strong> ${event.logSource}</p>
                <p><strong>Microsoft Reference:</strong> <a href="${this.getMicrosoftDocUrl(event.id)}" target="_blank" style="color: #58a6ff; text-decoration: underline;">Event ${event.id} Official Documentation</a></p>
            </div>
            
            <div class="detail-section">
                <h3><i class="fas fa-file-alt"></i> Description</h3>
                <p>${event.description}</p>
            </div>
            
            <div class="detail-section">
                <h3><i class="fas fa-crosshairs"></i> MITRE ATT&CK Tactics</h3>
                ${mitreList}
            </div>
            
            <div class="detail-section investigation-tips">
                <h3><i class="fas fa-search"></i> Investigation Tips</h3>
                ${investigationList}
            </div>
            
            ${this.generatePlaybookSection(event)}
            
            <div class="detail-section">
                <h3><i class="fas fa-link"></i> Related Events</h3>
                ${relatedEventsHtml}
            </div>
            
            <div class="detail-section">
                <h3><i class="fas fa-list-ul"></i> Common Causes</h3>
                ${commonCausesList}
            </div>
            
            <div class="detail-section">
                <h3><i class="fas fa-exclamation-triangle"></i> Potential False Positives</h3>
                ${falsePositivesList}
            </div>
            
            ${fullDescriptionHtml}
        `;
        
        this.showSidebar();
    }

    searchForEvent(eventId) {
        this.hideSidebar();
        this.searchInput.value = eventId;
        this.handleSearch();
        this.searchInput.focus();
    }

    showSidebar() {
        this.sidebar.classList.add('active');
    }

    hideSidebar() {
        this.sidebar.classList.remove('active');
    }

    generatePlaybookSection(event) {
        if (!event.investigationPlaybook) {
            return '';
        }

        const playbook = event.investigationPlaybook;
        
        // Collect all steps from all phases into one list
        let allSteps = [];
        let stepCounter = 1;
        
        ['immediate', 'shortTerm', 'longTerm'].forEach(phase => {
            if (playbook[phase] && playbook[phase].steps) {
                playbook[phase].steps.forEach(step => {
                    allSteps.push({
                        ...step,
                        stepNumber: stepCounter++
                    });
                });
            }
        });

        if (allSteps.length === 0) {
            return '';
        }
        
        let playbookHtml = `
            <div class="detail-section investigation-playbook">
                <div class="playbook-header">
                    <h3><i class="fas fa-book-open"></i> Investigation Playbook</h3>
                    <div class="playbook-info">
                        <span class="step-count">${allSteps.length} Investigation Steps</span>
                    </div>
                </div>
                <div class="playbook-content">
                    <div class="steps-list">
        `;

        allSteps.forEach((step, index) => {
            const stepId = `step-${event.id}-${index}`;
            playbookHtml += `
                <div class="playbook-step">
                    <div class="step-main">
                        <div class="step-checkbox-container">
                            <input type="checkbox" id="${stepId}" class="step-checkbox">
                            <span class="step-number">${step.stepNumber}</span>
                        </div>
                        <div class="step-content">
                            <label for="${stepId}" class="step-title">${step.action}</label>
                            <div class="step-meta">
                                <span class="step-tool">${step.tool}</span>
                            </div>
                        </div>
                        <button class="step-expand" onclick="this.parentElement.parentElement.classList.toggle('expanded')">
                            <i class="fas fa-chevron-down"></i>
                        </button>
                    </div>
                    <div class="step-details">
                        <div class="step-expected">
                            <strong>Expected Result:</strong> ${step.expected}
                        </div>
                        <div class="step-query">
                            <strong>Query/Command:</strong>
                            <div class="query-container">
                                <code>${step.query}</code>
                                <button class="copy-btn" onclick="navigator.clipboard.writeText('${step.query.replace(/'/g, "\\'")}'); this.innerHTML='<i class=\\'fas fa-check\\'></i> Copied'; setTimeout(() => this.innerHTML='<i class=\\'fas fa-copy\\'></i>', 2000);">
                                    <i class="fas fa-copy"></i>
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        });

        playbookHtml += `
                    </div>
                </div>
                <div class="playbook-footer">
                    <button class="playbook-action-btn reset" onclick="dashboard.resetPlaybook('${event.id}')">
                        <i class="fas fa-undo"></i> Reset Progress
                    </button>
                    <button class="playbook-action-btn export" onclick="dashboard.exportPlaybook('${event.id}')">
                        <i class="fas fa-file-export"></i> Export Guide
                    </button>
                </div>
            </div>
        `;

        return playbookHtml;
    }

    resetPlaybook(eventId) {
        const checkboxes = document.querySelectorAll(`input[id*="step-${eventId}"]`);
        checkboxes.forEach(checkbox => {
            checkbox.checked = false;
        });
    }

    exportPlaybook(eventId) {
        const event = this.events.find(e => e.id === eventId);
        if (!event || !event.investigationPlaybook) return;

        const playbook = event.investigationPlaybook;
        
        // Collect all steps from all phases
        let allSteps = [];
        let stepCounter = 1;
        
        ['immediate', 'shortTerm', 'longTerm'].forEach(phase => {
            if (playbook[phase] && playbook[phase].steps) {
                playbook[phase].steps.forEach(step => {
                    allSteps.push({
                        ...step,
                        stepNumber: stepCounter++
                    });
                });
            }
        });

        let exportText = `Investigation Playbook - Event ${event.id}: ${event.name}\n`;
        exportText += `Generated: ${new Date().toLocaleString()}\n`;
        exportText += `Total Steps: ${allSteps.length}\n\n`;
        exportText += '='.repeat(60) + '\n\n';

        allSteps.forEach((step) => {
            exportText += `${step.stepNumber}. ${step.action}\n`;
            exportText += `   Tool: ${step.tool}\n`;
            exportText += `   Expected: ${step.expected}\n`;
            exportText += `   Query: ${step.query}\n`;
            exportText += `   Status: [ ] Not Started\n\n`;
        });

        const blob = new Blob([exportText], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `investigation_playbook_${eventId}.txt`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    showNoResults() {
        this.resultsContainer.style.display = 'none';
        this.noResults.style.display = 'block';
    }

    hideNoResults() {
        this.resultsContainer.style.display = 'grid';
        this.noResults.style.display = 'none';
    }

    updateResultCount() {
        if (!this.hasSearched) {
            this.resultCount.textContent = `${this.events.length} (total in database)`;
        } else {
            this.resultCount.textContent = this.filteredEvents.length;
        }
    }

    updateStats() {
        const stats = this.events.reduce((acc, event) => {
            switch (event.criticality) {
                case 'Critical':
                    acc.critical++;
                    break;
                case 'High':
                    acc.high++;
                    break;
                case 'Medium':
                    acc.medium++;
                    break;
                case 'Low':
                    acc.low++;
                    break;
            }
            acc.total++;
            return acc;
        }, { critical: 0, high: 0, medium: 0, low: 0, total: 0 });
        
        this.criticalCount.textContent = stats.critical;
        this.highCount.textContent = stats.high;
        this.mediumCount.textContent = stats.medium;
        this.totalCount.textContent = stats.total;
    }

    truncateText(text, maxLength) {
        if (text.length <= maxLength) return text;
        return text.substring(0, maxLength) + '...';
    }

    // Utility method for searching by event ID
    findEventById(eventId) {
        return this.events.find(event => event.id === eventId);
    }

    // Get the appropriate Microsoft documentation URL for an event
    getMicrosoftDocUrl(eventId) {
        // Handle different event types with specific documentation patterns
        const id = parseInt(eventId);
        
        // Standard Windows Security Events (4xxx series)
        if (id >= 4608 && id <= 4999) {
            return `https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-${eventId}`;
        }
        
        // System Events (1xxx series)
        if (id >= 1000 && id <= 1999) {
            // These might be in system event documentation
            if (id === 1000 || id === 1001) {
                return `https://learn.microsoft.com/en-us/windows/win32/eventlog/event-logging-elements`;
            }
            if (id === 1100 || id === 1101 || id === 1102 || id === 1104) {
                return `https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-events`;
            }
            return `https://learn.microsoft.com/en-us/windows/win32/eventlog/system-event-log`;
        }
        
        // Sysmon Events (1-50)
        if (id >= 1 && id <= 50 && !isNaN(id)) {
            return `https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#events`;
        }
        
        // Service Events (7xxx series)
        if (id >= 7000 && id <= 7999) {
            return `https://learn.microsoft.com/en-us/windows/win32/services/service-control-manager`;
        }
        
        // Network Events (5xxx series)
        if (id >= 5000 && id <= 5999) {
            return `https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-${eventId}`;
        }
        
        // Boot Events (6xxx series)  
        if (id >= 6000 && id <= 6999) {
            return `https://learn.microsoft.com/en-us/windows/win32/eventlog/eventlog-key`;
        }
        
        // Default to general Windows Security Audit Events documentation
        return `https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-events`;
    }

    // Get the official MITRE ATT&CK URL for a tactic
    getMitreAttackUrl(tacticName) {
        // Mapping of tactic names to their official MITRE ATT&CK IDs and URLs
        const mitreMapping = {
            // Primary Tactics
            'Initial Access': 'TA0001',
            'Execution': 'TA0002', 
            'Persistence': 'TA0003',
            'Privilege Escalation': 'TA0004',
            'Defense Evasion': 'TA0005',
            'Credential Access': 'TA0006',
            'Discovery': 'TA0007',
            'Lateral Movement': 'TA0008',
            'Collection': 'TA0009',
            'Command and Control': 'TA0011',
            'Exfiltration': 'TA0010',
            'Impact': 'TA0040',
            
            // Alternate/Common Variations
            'Reconnaissance': 'TA0043',
            'Resource Development': 'TA0042',
            'C2': 'TA0011', // Command and Control alias
            'Command & Control': 'TA0011', // Alternative format
            'Lateral Movement': 'TA0008',
            'Data Collection': 'TA0009', // Collection alias
            'Data Exfiltration': 'TA0010', // Exfiltration alias
            'System Impact': 'TA0040', // Impact alias
            'Account Manipulation': 'TA0003', // Often under Persistence
            'Valid Accounts': 'TA0001', // Can be Initial Access or Defense Evasion
        };
        
        // Normalize the tactic name (trim and handle variations)
        const normalizedTactic = tacticName.trim();
        const tacticId = mitreMapping[normalizedTactic];
        
        if (tacticId) {
            return `https://attack.mitre.org/tactics/${tacticId}/`;
        }
        
        // If no direct mapping found, try to search for the tactic on MITRE
        // This creates a search URL as fallback
        const searchTerm = encodeURIComponent(normalizedTactic);
        return `https://attack.mitre.org/search/?term=${searchTerm}`;
    }

    // Export functionality
    exportResults() {
        const dataStr = JSON.stringify(this.filteredEvents, null, 2);
        const dataBlob = new Blob([dataStr], { type: 'application/json' });
        const url = URL.createObjectURL(dataBlob);
        const link = document.createElement('a');
        link.href = url;
        link.download = 'windows-event-ids.json';
        link.click();
        URL.revokeObjectURL(url);
    }

    // Search suggestions functionality
    getSearchSuggestions(query) {
        if (!query || query.length < 2) return [];
        
        const suggestions = new Set();
        const lowerQuery = query.toLowerCase();
        
        this.events.forEach(event => {
            // Add event ID if it matches
            if (event.id.toLowerCase().includes(lowerQuery)) {
                suggestions.add(event.id);
            }
            
            // Add event name if it matches
            if (event.name.toLowerCase().includes(lowerQuery)) {
                suggestions.add(event.name);
            }
            
            // Add categories if they match
            if (event.category.toLowerCase().includes(lowerQuery)) {
                suggestions.add(event.category);
            }
        });
        
        return Array.from(suggestions).slice(0, 10);
    }

    // Keyboard navigation for results
    setupKeyboardNavigation() {
        let selectedIndex = -1;
        
        document.addEventListener('keydown', (e) => {
            const cards = this.resultsContainer.querySelectorAll('.event-card');
            
            if (e.key === 'ArrowDown') {
                e.preventDefault();
                selectedIndex = Math.min(selectedIndex + 1, cards.length - 1);
                this.highlightCard(cards, selectedIndex);
            } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                selectedIndex = Math.max(selectedIndex - 1, -1);
                this.highlightCard(cards, selectedIndex);
            } else if (e.key === 'Enter' && selectedIndex >= 0) {
                e.preventDefault();
                cards[selectedIndex].click();
            }
        });
    }

    highlightCard(cards, index) {
        // Remove previous highlights
        cards.forEach(card => card.classList.remove('keyboard-selected'));
        
        // Add highlight to selected card
        if (index >= 0 && index < cards.length) {
            cards[index].classList.add('keyboard-selected');
            cards[index].scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }
    }

    // Add method to show error messages
    showError(message) {
        const errorElement = document.createElement('div');
        errorElement.className = 'error-message';
        errorElement.innerHTML = `
            <div class="error-icon"><i class="fas fa-exclamation-triangle"></i></div>
            <div class="error-text">${message}</div>
        `;
        document.body.appendChild(errorElement);
        
        // Remove the error after 5 seconds
        setTimeout(() => {
            if (errorElement.parentNode) {
                errorElement.parentNode.removeChild(errorElement);
            }
        }, 5000);
    }
}

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    // Start matrix background effect
    new MatrixBackground();
    
    // Initialize dashboard
    window.dashboard = new EventDashboard();
    
    // Add some additional CSS for keyboard navigation
    const style = document.createElement('style');
    style.textContent = `
        .event-card.keyboard-selected {
            outline: 3px solid #667eea;
            outline-offset: 2px;
        }
        
        .event-card:focus {
            outline: 3px solid #667eea;
            outline-offset: 2px;
        }
    `;
    document.head.appendChild(style);
    
    // Add search tips to the search input
    const searchInput = document.getElementById('searchInput');
    searchInput.title = 'Search by Event ID (4625), Event Name (Failed Logon), or Keywords (brute force). Use Ctrl+K to focus.';
    
    // Add welcome message to console
    console.log(`
    🛡️  Windows Event ID Dashboard Loaded
    📊 Total Events: ${window.eventDatabase?.length || 0}
    ⌨️  Keyboard Shortcuts:
       • Ctrl+K: Focus search
       • Escape: Close sidebar
       • Arrow keys: Navigate results
       • Enter: Open selected event
    `);
});

// Global utility functions
window.searchEvent = (eventId) => {
    if (window.dashboard) {
        window.dashboard.searchForEvent(eventId);
    }
};

window.exportData = () => {
    if (window.dashboard) {
        window.dashboard.exportResults();
    }
}; 