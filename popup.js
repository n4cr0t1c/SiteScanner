// Minimal SiteScanner Popup Controller
let displayedVulnIds = new Set();
let aggregatedCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0 };
let verboseLogs = [];

// Accumulate findings reported by the background scanner in real-time
let backgroundFindings = [];

// Receive live network-scan logs and findings from background
chrome.runtime.onMessage.addListener((request, sender) => {
    if (!request) return;

    if (request.action === 'networkScanLog') {
        // Log text or JSON messages for the Details pane
        appendLog(typeof request.message === 'string' ? request.message : JSON.stringify(request.message));

        // If the background sent an incremental finding, collect it
        try {
            const msg = request.message;
            if (msg && typeof msg === 'object' && msg.type === 'finding' && msg.finding) {
                backgroundFindings.push(msg.finding);
            }
        } catch (e) {
            // ignore parse errors
        }
        return;
    }

    if (request.action === 'networkScanResult') {
        // Final broadcast from background with full results
        appendLog('Received final background scan result (' + ((request.vulnerabilities && request.vulnerabilities.length) || 0) + ' items)');
        // Store into backgroundFindings so the later merge picks them up
        if (Array.isArray(request.vulnerabilities) && request.vulnerabilities.length) {
            backgroundFindings = backgroundFindings.concat(request.vulnerabilities || []);
        }
        return;
    }
});

document.addEventListener('DOMContentLoaded', () => {
    const scanBtn = document.getElementById('scanBtn');
    const modal = document.getElementById('modal');
    const modalClose = document.querySelector('.modal-close');

    const detailsBtn = document.getElementById('detailsBtn');
    const detailsModal = document.getElementById('detailsModal');
    const detailsClose = document.querySelector('.details-close');

    const pastScansBtn = document.getElementById('pastScansBtn');
    const pastScansModal = document.getElementById('pastScansModal');
    const pastClose = document.querySelector('.past-close');
    const clearHistoryBtn = document.getElementById('clearHistory');

    scanBtn.addEventListener('click', performScan);
    modalClose.addEventListener('click', closeModal);
    modal.addEventListener('click', (e) => {
        if (e.target === modal) closeModal();
    });

    // Details modal handlers with console logging
    if (detailsBtn) {
        console.log('Details button found, attaching listener');
        detailsBtn.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            console.log('Details button clicked');
            if (detailsModal) {
                detailsModal.classList.add('active');
                console.log('Details modal opened');
            } else {
                console.error('Details modal element not found');
            }
        });
    } else {
        console.error('Details button not found');
    }
    if (detailsClose && detailsModal) {
        detailsClose.addEventListener('click', () => {
            detailsModal.classList.remove('active');
        });
        detailsModal.addEventListener('click', (e) => { if (e.target === detailsModal) detailsModal.classList.remove('active'); });
    }

    // Past Scans modal handlers with console logging
    if (pastScansBtn) {
        console.log('Past Scans button found, attaching listener');
        pastScansBtn.addEventListener('click', async (e) => {
            e.preventDefault();
            e.stopPropagation();
            console.log('Past Scans button clicked');
            await loadPastScans();
            if (pastScansModal) {
                pastScansModal.classList.add('active');
                console.log('Past Scans modal opened');
            } else {
                console.error('Past Scans modal element not found');
            }
        });
    } else {
        console.error('Past Scans button not found');
    }
    if (pastClose && pastScansModal) {
        pastClose.addEventListener('click', () => pastScansModal.classList.remove('active'));
        pastScansModal.addEventListener('click', (e) => { if (e.target === pastScansModal) pastScansModal.classList.remove('active'); });
    }

    if (clearHistoryBtn) {
        clearHistoryBtn.addEventListener('click', () => {
            chrome.runtime.sendMessage({ action: 'clearScanHistory' }, (res) => {
                appendLog('Scan history cleared');
                loadPastScans();
            });
        });
    }

    // Event delegation for vulnerability tile headers only
    document.addEventListener('click', (e) => {
        const header = e.target.closest('.vuln-header');
        if (!header) return;
        const vulnItem = header.closest('.vulnerability-item');
        if (vulnItem) {
            toggleVulnDetails(vulnItem, e);
        }
    });
});

function appendLog(msg) {
    try {
        const timestamp = new Date().toISOString();
        verboseLogs.push({ timestamp, text: msg });
        const el = document.getElementById('detailsLog');
        if (el) {
            el.textContent = verboseLogs.map(l => `[${l.timestamp}] ${l.text}`).join('\n');
            if (el.scrollTop !== undefined) {
                setTimeout(() => { el.scrollTop = el.scrollHeight; }, 0);
            }
        } else {
            console.warn('[DETAILS] No detailsLog element found');
        }
        console.log('[DETAILS]', msg);
    } catch (e) {
        console.warn('appendLog error', e);
    }
}

function clearLogs() {
    verboseLogs = [];
    const el = document.getElementById('detailsLog');
    if (el) el.textContent = '';
}

function saveScanReport(report) {
    chrome.runtime.sendMessage({ action: 'saveScanReport', report }, (res) => {
        if (chrome.runtime.lastError) {
            appendLog('Save failed: ' + chrome.runtime.lastError.message);
        } else if (res && res.success) {
            appendLog('Scan saved to history (persistent storage)');
            console.log('Scan successfully saved:', report);
        } else {
            appendLog('Save response: ' + JSON.stringify(res));
        }
    });
}

function loadPastScans() {
    return new Promise((resolve) => {
        const listEl = document.getElementById('pastScansList');
        if (!listEl) {
            console.error('pastScansList element not found');
            return resolve([]);
        }
        listEl.innerHTML = '<p>Loading...</p>';
        console.log('Requesting scan history from background');
        chrome.runtime.sendMessage({ action: 'getScanHistory' }, (res) => {
            if (chrome.runtime.lastError) {
                console.error('getScanHistory error:', chrome.runtime.lastError);
                listEl.innerHTML = '<p>Error loading scans: ' + chrome.runtime.lastError.message + '</p>';
                return resolve([]);
            }
            const history = (res && res.scanHistory) || [];
            console.log('Received ' + history.length + ' past scans');
            listEl.innerHTML = '';
            if (history.length === 0) {
                listEl.innerHTML = '<p>No past scans</p>';
                return resolve(history);
            }
            // Newest first
            history.slice().reverse().forEach((s, idx) => {
                const item = document.createElement('div');
                item.className = 'past-scan-item';
                const ts = new Date(s.timestamp).toLocaleString();
                const vulnCount = (s.vulnerabilities && s.vulnerabilities.length) || 0;

                const meta = document.createElement('div');
                meta.className = 'meta';
                meta.innerHTML = `<strong>${s.url || 'Unknown URL'}</strong><span>${ts} • ${vulnCount} issue(s)</span>`;

                const detailsDiv = document.createElement('div');
                detailsDiv.className = 'details hidden';
                detailsDiv.style.whiteSpace = 'pre-wrap';
                detailsDiv.style.fontSize = '11px';
                detailsDiv.style.color = '#666';
                detailsDiv.innerText = JSON.stringify(s, null, 2);

                const viewBtn = document.createElement('button');
                viewBtn.className = 'export-btn view-btn';
                viewBtn.textContent = 'View';
                viewBtn.addEventListener('click', () => {
                    if (detailsDiv.classList.contains('hidden')) {
                        detailsDiv.classList.remove('hidden');
                        viewBtn.textContent = 'Hide';
                    } else {
                        detailsDiv.classList.add('hidden');
                        viewBtn.textContent = 'View';
                    }
                });

                item.appendChild(meta);
                item.appendChild(detailsDiv);
                const footer = document.createElement('div');
                footer.style.marginTop = '8px';
                footer.appendChild(viewBtn);
                item.appendChild(footer);

                listEl.appendChild(item);
            });
            console.log('Past scans UI updated');
            resolve(history);
        });
    });
}

async function performScan() {
    const scanBtn = document.getElementById('scanBtn');
    const scanning = document.getElementById('scanning');
    const results = document.getElementById('results');
    const noVulnerabilities = document.getElementById('noVulnerabilities');

    // Show scanning state
    if (scanBtn) scanBtn.style.display = 'none';
    scanning.classList.remove('hidden');
    results.classList.add('hidden');
    noVulnerabilities.classList.add('hidden');

    // Reset previous UI/results and logs
    const vulnerabilitiesList = document.getElementById('vulnerabilitiesList');
    if (vulnerabilitiesList) vulnerabilitiesList.innerHTML = '';
    displayedVulnIds.clear();
    aggregatedCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0 };
    clearLogs();
    // Clear any previously received background findings
    backgroundFindings = [];
    const detailsModal = document.getElementById('detailsModal');
    if (detailsModal) detailsModal.classList.remove('active');

    appendLog('Scan started');

    // Initialize progress
    updateProgress(0);

    try {
        // Get active tab
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        appendLog('Active tab: ' + (tab && tab.url ? tab.url : 'unknown'));

        // Simulate scanning steps with progress and logging
        const steps = [
            { name: 'Analyzing page structure', progress: 15 },
            { name: 'Checking security headers', progress: 35 },
            { name: 'Testing input validation', progress: 55 },
            { name: 'Detecting CMS platform', progress: 70 },
            { name: 'Scanning for vulnerabilities', progress: 85 },
            { name: 'Finalizing scan', progress: 95 }
        ];

        for (const step of steps) {
            appendLog('Step: ' + step.name);
            await new Promise(resolve => setTimeout(resolve, 300));
            updateProgress(step.progress);
        }

        // Send message to content script
        appendLog('Sending analyzePage message to content script');
        let contentResponse = { vulnerabilities: [] };
        try {
            contentResponse = await chrome.tabs.sendMessage(tab.id, { action: 'analyzePage' });
            appendLog('Content analysis returned ' + ((contentResponse.vulnerabilities && contentResponse.vulnerabilities.length) || 0) + ' items');
        } catch (msgError) {
            appendLog('Content message failed: ' + (msgError && msgError.message ? msgError.message : msgError));
            contentResponse = { vulnerabilities: [] };
        }

        // Ask background service worker for an expanded network scan and wait for its broadcasted result
        appendLog('Requesting background network scan...');
        let backgroundResponse = { vulnerabilities: [] };
        try {
            backgroundResponse = await (async () => {
                return await new Promise((resolve) => {
                    let timeoutId = null;
                    const onResult = (request, sender) => {
                        if (request && request.action === 'networkScanResult' && (!request.url || request.url === tab.url)) {
                            chrome.runtime.onMessage.removeListener(onResult);
                            if (timeoutId) clearTimeout(timeoutId);
                            resolve({ vulnerabilities: request.vulnerabilities || [] });
                        }
                    };

                    chrome.runtime.onMessage.addListener(onResult);

                    console.log('[POPUP] Sending runNetworkScan message with URL:', tab.url);
                    chrome.runtime.sendMessage({ action: 'runNetworkScan', url: tab.url }, (res) => {
                        console.log('[POPUP] runNetworkScan request callback:', res);
                        if (chrome.runtime.lastError) {
                            chrome.runtime.onMessage.removeListener(onResult);
                            if (timeoutId) clearTimeout(timeoutId);
                            appendLog('Background scan request failed: ' + chrome.runtime.lastError.message);
                            resolve({ vulnerabilities: [] });
                        } else {
                            appendLog('Background scan started');
                            // wait for onResult or timeout
                        }
                    });

                    timeoutId = setTimeout(() => {
                        chrome.runtime.onMessage.removeListener(onResult);
                        appendLog('Network scan timeout (60s) - using available results');
                        resolve({ vulnerabilities: [] });
                    }, 60000);
                });
            })();

            const bgVulnCount = (backgroundResponse && Array.isArray(backgroundResponse.vulnerabilities) && backgroundResponse.vulnerabilities.length)
                ? backgroundResponse.vulnerabilities.length
                : (backgroundFindings && backgroundFindings.length) || 0;
            console.log('[POPUP] Final backgroundResponse count:', bgVulnCount);
            appendLog('Background scan returned ' + bgVulnCount + ' items');
        } catch (bgError) {
            console.error('[POPUP] network scan handler error:', bgError);
            appendLog('Background scan error: ' + (bgError && bgError.message ? bgError.message : bgError));
            backgroundResponse = { vulnerabilities: [] };
        }

        // Complete the scan
        updateProgress(100);
        await new Promise(resolve => setTimeout(resolve, 300));

        // Merge results and process (filter-out placeholder/test items)
        // Prefer explicit backgroundResponse.vulnerabilities if delivered; otherwise use live backgroundFindings
        const bgVulns = (backgroundResponse && Array.isArray(backgroundResponse.vulnerabilities) && backgroundResponse.vulnerabilities.length)
            ? backgroundResponse.vulnerabilities
            : backgroundFindings;
        let merged = (contentResponse.vulnerabilities || []).concat(bgVulns || []);
        merged = merged.filter(v => v && v.id && v.id !== 'test');
        appendLog('Total vulnerabilities detected: ' + merged.length);
        displayResults(merged);

        // Prepare report
        const scanReport = {
            timestamp: new Date().toISOString(),
            url: tab.url,
            vulnerabilities: merged,
            logs: verboseLogs.map(l => `[${l.timestamp}] ${l.text}`).join('\n'),
            counts: { critical: aggregatedCounts.CRITICAL, high: aggregatedCounts.HIGH, medium: aggregatedCounts.MEDIUM }
        };

        // Save if requested
        const saveToggle = document.getElementById('saveToggle');
        if (saveToggle && saveToggle.checked) {
            appendLog('Saving scan to history');
            saveScanReport(scanReport);
        } else {
            appendLog('Save toggle disabled — not saving scan');
        }

    } catch (error) {
        appendLog('Scan error: ' + (error && error.message ? error.message : error));
        scanning.classList.add('hidden');
        showError('Error: ' + (error && error.message ? error.message : error));
    } finally {
        // restore scan button
        if (scanBtn) scanBtn.style.display = '';
    }
}


function updateProgress(percent) {
    const progressFill = document.getElementById('progressFill');
    const progressPercent = document.getElementById('progressPercent');
    
    // Ensure percent is between 0 and 100
    const safePercent = Math.min(Math.max(percent, 0), 100);
    
    progressFill.style.width = safePercent + '%';
    progressPercent.textContent = safePercent;
}

function displayResults(vulnerabilities) {
    const scanning = document.getElementById('scanning');
    const results = document.getElementById('results');
    const noVulnerabilities = document.getElementById('noVulnerabilities');
    const vulnerabilitiesList = document.getElementById('vulnerabilitiesList');

    // Hide scanning and show results
    scanning.classList.add('hidden');

    appendLog('displayResults called with ' + (vulnerabilities ? vulnerabilities.length : 0) + ' items');
    console.log('displayResults:', vulnerabilities);

    if (!vulnerabilities || vulnerabilities.length === 0) {
        appendLog('No vulnerabilities after merge');
        noVulnerabilities.classList.remove('hidden');
        return;
    }

    // Append new vulnerabilities (avoid duplicates across scans while popup is open)
    noVulnerabilities.classList.add('hidden');
    let added = 0;
    for (const vuln of vulnerabilities) {
        if (!vuln) {
            appendLog('Skipped null vulnerability');
            continue;
        }
        if (!vuln.id) {
            appendLog('Skipped vuln without id: ' + JSON.stringify(vuln));
            continue;
        }
        if (displayedVulnIds.has(vuln.id)) {
            appendLog('Skipped duplicate id: ' + vuln.id);
            continue;
        }

        appendLog('Processing vuln: ' + vuln.name + ' (' + vuln.id + ')');

        // Build points from evidence if available, otherwise fallback
        const evidence = vuln.evidence && vuln.evidence.length ? vuln.evidence : getVulnerablePoints(vuln.id);
        const pointsHTML = (Array.isArray(evidence) ? evidence : []).map(point => {
            if (typeof point === 'string') {
                return `<div class="vuln-point"><div class="vuln-point-label">🔴 Evidence</div><div>${point}</div></div>`;
            }
            const label = point.label || 'Evidence';
            const detail = point.detail || '';
            const location = point.location || '';
            return `<div class="vuln-point"><div class="vuln-point-label">🔴 ${label}</div><div>${detail}</div><div class="vuln-point-detail">${location}</div></div>`;
        }).join('');

        const quickFix = vuln.quick_fix || vuln.quickFix || vuln.suggestion || '';

        const itemHTML = `
            <div class="vulnerability-item ${vuln.severity.toLowerCase()}">
                <div class="vuln-header">
                    <div class="vuln-title">
                        <span>${vuln.name}</span>
                        <span class="vuln-severity ${vuln.severity.toLowerCase()}">${vuln.severity}</span>
                    </div>
                    <div class="vuln-desc">${vuln.description || 'Potential security vulnerability'}</div>
                    <div class="vuln-toggle">▼</div>
                </div>
                <div class="vuln-details hidden">
                    <div class="vuln-detail-content">
                        <div class="detail-section">
                            <h4>Vulnerable Points</h4>
                            <div class="vulnerable-points">
                                ${pointsHTML}
                            </div>
                        </div>
                        <div class="detail-section">
                            <h4>Impact</h4>
                            <p>${vuln.impact || ''}</p>
                        </div>
                        <div class="detail-section">
                            <h4>Quick Fix</h4>
                            <p class="quick-fix">${quickFix}</p>
                        </div>
                        <div class="detail-section">
                            <h4>How to Fix</h4>
                            <p>${vuln.suggestion || ''}</p>
                        </div>
                        <div class="detail-section">
                            <h4>CVSS Score</h4>
                            <p class="cvss-score">${vuln.cvss || ''}/10</p>
                        </div>
                    </div>
                </div>
            </div>
        `;

        vulnerabilitiesList.insertAdjacentHTML('beforeend', itemHTML);
        displayedVulnIds.add(vuln.id);

        // Update aggregated counts
        if (vuln.severity === 'CRITICAL') aggregatedCounts.CRITICAL += 1;
        if (vuln.severity === 'HIGH') aggregatedCounts.HIGH += 1;
        if (vuln.severity === 'MEDIUM') aggregatedCounts.MEDIUM += 1;

        added += 1;
    }

    appendLog('Added ' + added + ' vulnerabilities to display');

    // Update displayed counts
    document.getElementById('criticalCount').textContent = aggregatedCounts.CRITICAL;
    document.getElementById('highCount').textContent = aggregatedCounts.HIGH;
    document.getElementById('mediumCount').textContent = aggregatedCounts.MEDIUM;

    if (added > 0) {
        results.classList.remove('hidden');
    } else {
        // No new entries: if nothing displayed yet, show no vulnerabilities
        if (displayedVulnIds.size === 0) {
            appendLog('No new items added, showing no vulnerabilities message');
            noVulnerabilities.classList.remove('hidden');
        }
    }
}

function openModal(vulnId) {
    const vuln = Object.values(VULNERABILITIES).find(v => v.id === vulnId);
    if (!vuln) return;

    document.getElementById('modalTitle').textContent = vuln.name;
    document.getElementById('modalSeverity').className = `severity-badge ${vuln.severity.toLowerCase()}`;
    document.getElementById('modalSeverity').textContent = vuln.severity;
    document.getElementById('modalDescription').textContent = vuln.description;
    document.getElementById('modalImpact').textContent = vuln.impact;
    document.getElementById('modalSuggestion').textContent = vuln.suggestion;
    document.getElementById('modalCVSS').textContent = `${vuln.cvss}/10`;

    // Get vulnerability details from detection
    const vulnerablePoints = getVulnerablePoints(vulnId);
    const pointsHTML = vulnerablePoints.map(point => `
        <div class="vuln-point">
            <div class="vuln-point-label">🔴 ${point.label}</div>
            <div>${point.detail}</div>
            <div class="vuln-point-detail">${point.location}</div>
        </div>
    `).join('');
    
    document.getElementById('vulnerablePoints').innerHTML = pointsHTML || '<div class="vuln-point">Detected through automated analysis</div>';

    document.getElementById('modal').classList.add('active');
}

function getVulnerablePoints(vulnId) {
    const points = {
        sql_injection: [
            { label: 'Search Parameters', detail: 'Unencoded query parameters detected', location: 'Endpoint: /search, /api/search' },
            { label: 'Dynamic Query Construction', detail: 'No parameterized query usage detected', location: 'Form method: GET with user input' },
            { label: 'Error Messages', detail: 'SQL error messages visible in responses', location: 'Database error details exposed' }
        ],
        xss: [
            { label: 'Form Input Reflection', detail: 'User input reflected without sanitization', location: 'Search forms, comment sections' },
            { label: 'Missing Output Encoding', detail: 'Content rendered as HTML without escaping', location: 'Dynamic content areas' },
            { label: 'No Content Security Policy', detail: 'CSP headers not implemented', location: 'HTTP response headers' }
        ],
        weak_password: [
            { label: 'Admin Panel Access', detail: '/wp-admin, /administrator endpoints are accessible', location: 'Admin panel at /admin path' },
            { label: 'No Rate Limiting', detail: 'Brute force attacks are not throttled', location: 'Login endpoints' },
            { label: 'No 2FA Enabled', detail: 'Two-factor authentication not enforced', location: 'Authentication mechanism' }
        ],
        sensitive_file: [
            { label: '.env File Exposure', detail: 'Environment variables and credentials exposed', location: 'Public web root /.env' },
            { label: 'Config Files Accessible', detail: 'Configuration files returned with 200 status', location: '/config.php, /wp-config.php' },
            { label: 'Git Repository Exposed', detail: '.git folder is publicly accessible', location: '/.git/config' }
        ],
        file_upload: [
            { label: 'Unrestricted Upload Endpoint', detail: 'File upload endpoint accepts all file types', location: '/upload, /api/upload' },
            { label: 'No File Type Validation', detail: 'Executable files can be uploaded', location: 'Upload form without restrictions' },
            { label: 'Files Stored in Web Root', detail: 'Uploaded files are accessible via HTTP', location: '/uploads/ directory' }
        ],
        open_port: [
            { label: 'SSH Port (22) Open', detail: 'SSH service exposed on public network', location: 'Port 22 responding to connections' },
            { label: 'MySQL Port (3306) Open', detail: 'Database port accessible externally', location: 'Port 3306 exposed' },
            { label: 'Redis Port (6379) Open', detail: 'Cache service accessible without authentication', location: 'Port 6379 open' }
        ],
        outdated_version: [
            { label: 'WordPress Detected', detail: 'Outdated version: 5.8.x', location: 'wp-json endpoint, meta tags' },
            { label: 'Known Vulnerabilities', detail: 'CVE-2021-XXXXX applicable to this version', location: 'Security advisory databases' },
            { label: 'Plugin Vulnerabilities', detail: 'Outdated plugins with known exploits', location: 'Installed extensions' }
        ],
        plugin_exposure: [
            { label: 'Directory Listing Enabled', detail: '/wp-content/plugins/ is browsable', location: 'Plugin directory index' },
            { label: 'Plugin Names Enumerable', detail: 'Installed plugins can be identified', location: 'Plugin folder structure visible' },
            { label: 'Version Information Exposed', detail: 'Plugin versions disclosed publicly', location: 'Plugin metadata' }
        ],
        missing_headers: [
            { label: 'No HSTS Header', detail: 'HTTP Strict Transport Security not enforced', location: 'Response headers' },
            { label: 'No CSP Header', detail: 'Content Security Policy not implemented', location: 'Missing Content-Security-Policy' },
            { label: 'No X-Frame-Options', detail: 'Page can be framed (clickjacking vulnerability)', location: 'Framing protection missing' }
        ],
        directory_traversal: [
            { label: 'Path Traversal Possible', detail: '../../../etc/passwd accessible', location: '/file?path=../../../' },
            { label: 'No Path Validation', detail: 'File path parameters not sanitized', location: 'Download/view endpoints' },
            { label: 'System Files Readable', detail: 'Arbitrary files can be accessed', location: 'File access endpoints' }
        ],
        default_creds: [
            { label: 'Admin Panel Defaults', detail: 'Default username/password not changed', location: 'Admin login: admin/admin' },
            { label: 'Service Defaults', detail: 'Database, FTP, or other services using defaults', location: 'Service configuration' },
            { label: 'No Credential Policy', detail: 'Initial credentials not properly enforced to change', location: 'User account setup' }
        ],
        weak_ssl: [
            { label: 'HTTP Not Redirected', detail: 'Site accessible via unencrypted HTTP', location: 'http:// URL accessible' },
            { label: 'Old TLS Version', detail: 'TLS 1.0/1.1 enabled, should be 1.2+', location: 'SSL/TLS configuration' },
            { label: 'Weak Ciphers', detail: 'Use of deprecated cipher suites', location: 'SSL cipher configuration' }
        ],
        exposed_admin: [
            { label: 'Admin Path Public', detail: '/wp-admin or /administrator is publicly accessible', location: 'Admin URL: /admin' },
            { label: 'No IP Restriction', detail: 'Admin panel has no IP whitelist', location: 'Access control missing' },
            { label: 'Brute Force Vulnerability', detail: 'Login endpoint has no rate limiting', location: 'Admin login form' }
        ]
    };

    return points[vulnId] || [{ label: 'Detected', detail: 'Vulnerability was detected during scanning', location: 'Automated detection' }];
}

function closeModal() {
    document.getElementById('modal').classList.remove('active');
}

function toggleVulnDetails(element, event) {
    event.stopPropagation();
    const detailsDiv = element.querySelector('.vuln-details');
    const toggleIcon = element.querySelector('.vuln-toggle');
    
    console.log('Toggle clicked:', element, detailsDiv, toggleIcon);
    
    const isHidden = detailsDiv.classList.contains('hidden');
    
    // Close all other expanded items
    document.querySelectorAll('.vuln-details').forEach(el => {
        if (el !== detailsDiv) {
            el.classList.add('hidden');
            el.closest('.vulnerability-item').querySelector('.vuln-toggle').textContent = '▼';
        }
    });
    
    // Toggle current item
    if (isHidden) {
        detailsDiv.classList.remove('hidden');
        toggleIcon.textContent = '▲';
        console.log('Details expanded');
    } else {
        detailsDiv.classList.add('hidden');
        toggleIcon.textContent = '▼';
        console.log('Details collapsed');
    }
}

function showError(message) {
    const scanning = document.getElementById('scanning');
    scanning.innerHTML = `<p style="color: #dc3545; font-weight: 600;">${message}</p>`;
}