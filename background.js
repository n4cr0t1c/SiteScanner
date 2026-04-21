// Background Service Worker - Handles background tasks and messaging

// Initialize extension
chrome.runtime.onInstalled.addListener(() => {
    console.log('SiteScanner extension installed');
    
    // Set default storage values
    chrome.storage.sync.set({
        scanAutomatically: false,
        notifyOnVulnerabilities: true,
        severityThreshold: 'medium'
    });
});

// Listen for tab updates
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete') {
        // Auto-scan if enabled
        chrome.storage.sync.get(['scanAutomatically'], (result) => {
            if (result.scanAutomatically) {
                // Could trigger auto-scan here
            }
        });
    }
});

// Handle messages from content scripts and popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'logVulnerability') {
        // Only persist when explicitly requested (request.persist === true)
        if (request.persist) {
            // Allow the popup to pass a URL when sender.tab is not available
            const tabInfo = (sender && sender.tab) ? sender.tab : null;
            logVulnerabilityToStorage(request.vulnerability, tabInfo, request.url);
        }
        sendResponse({ success: true });
    }
    
    if (request.action === 'notifyVulnerability') {
        if (shouldNotify(request.severity)) {
            chrome.notifications.create({
                type: 'basic',
                iconUrl: 'icons/icon128.png',
                title: 'Security Vulnerability Detected',
                message: request.message,
                priority: getPriorityForSeverity(request.severity)
            });
        }
        sendResponse({ success: true });
    }

    // Run an optional network-heavy scan from the background service worker.
    if (request.action === 'runNetworkScan') {
        const target = request.url;
        console.log('[MSG_HANDLER] runNetworkScan request for', target);
        
        // Kick off the network scan and return an immediate acknowledgement to the caller.
        // When the scan completes it will broadcast the full results via a separate message
        // so the popup can reliably receive them even if the service worker lifecycle changes.
        runNetworkScan(target).then(vulns => {
            console.log('[MSG_HANDLER] runNetworkScan completed with', vulns.length, 'vulnerabilities');
            try {
                chrome.runtime.sendMessage({ action: 'networkScanResult', url: target, vulnerabilities: vulns });
            } catch (e) {
                console.error('[MSG_HANDLER] Failed to broadcast networkScanResult', e);
            }
        }).catch(err => {
            console.error('[MSG_HANDLER] Network scan error:', err);
            try { chrome.runtime.sendMessage({ action: 'networkScanResult', url: target, vulnerabilities: [] }); } catch (e) {}
        });

        // Respond immediately to the request so the popup isn't blocked waiting for the full scan
        sendResponse({ started: true });
        return false;
    }
    
    // Save a full scan report to persistent history
    if (request.action === 'saveScanReport') {
        const report = request.report;
        console.log('Saving scan report:', report);
        chrome.storage.local.get(['scanHistory'], (result) => {
            let history = result.scanHistory || [];
            history.push(report);
            // Keep last 200 scans
            if (history.length > 200) history = history.slice(-200);
            
            try {
                chrome.storage.local.set({ scanHistory: history }, () => {
                    if (chrome.runtime.lastError) {
                        console.error('Storage save error:', chrome.runtime.lastError);
                        sendResponse({ success: false, error: chrome.runtime.lastError.message });
                    } else {
                        console.log('Scan history saved:', history.length, 'items');
                        sendResponse({ success: true });
                    }
                });
            } catch (e) {
                console.error('Save exception:', e);
                sendResponse({ success: false, error: e.message });
            }
        });
        return true;
    }

    // Retrieve stored scan history
    if (request.action === 'getScanHistory') {
        chrome.storage.local.get(['scanHistory'], (result) => {
            const history = result.scanHistory || [];
            console.log('Retrieved scan history:', history.length, 'items');
            sendResponse({ scanHistory: history });
        });
        return true;
    }

    // Clear stored scan history
    if (request.action === 'clearScanHistory') {
        console.log('Clearing scan history');
        chrome.storage.local.set({ scanHistory: [] }, () => {
            if (chrome.runtime.lastError) {
                console.error('Clear history error:', chrome.runtime.lastError);
                sendResponse({ success: false, error: chrome.runtime.lastError.message });
            } else {
                console.log('Scan history cleared');
                sendResponse({ success: true });
            }
        });
        return true;
    }
});

// Store vulnerability findings
function logVulnerabilityToStorage(vulnerability, tab, url) {
    chrome.storage.local.get(['vulnerabilityLog'], (result) => {
        let log = result.vulnerabilityLog || [];

        log.push({
            vulnerability: vulnerability,
            url: (tab && tab.url) || url || null,
            timestamp: new Date().toISOString(),
            tabId: (tab && tab.id) || null
        });

        // Keep only last 100 entries
        if (log.length > 100) {
            log = log.slice(-100);
        }

        chrome.storage.local.set({ vulnerabilityLog: log });
    });
}

function shouldNotify(severity) {
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    return severityOrder[severity] <= 1; // Notify for critical and high
}

function getPriorityForSeverity(severity) {
    const priorityMap = {
        critical: 2,
        high: 1,
        medium: 0,
        low: -1
    };
    return priorityMap[severity] || 0;
}

// Network scanner ported from plan/cms_scanner.py (heuristic, runs from background)
async function runNetworkScan(targetUrl) {
    const results = [];
    console.log('[BG_SCAN] Starting runNetworkScan for', targetUrl);
    if (!targetUrl) return results;

    let parsed;
    try {
        parsed = new URL(targetUrl);
    } catch (e) {
        return results;
    }

    const origin = parsed.origin;
    const host = parsed.hostname;

    // Allow a longer scan (closer to the Python scanner behavior). Popup will wait longer.
    const scanTimeoutMs = 55000;
    const scanStartTime = Date.now();
    
    function isTimeoutReached() {
        return (Date.now() - scanStartTime) > scanTimeoutMs;
    }

    // Announce scan start to popup (if open)
    try {
        chrome.runtime.sendMessage({ action: 'networkScanLog', message: `Starting network scan for ${targetUrl}` });
    } catch (e) {
        // ignore
    }

    // Vulnerability template database for background scanner
    const VULN_DB = {
        'sql_injection': {
            name: 'SQL Injection',
            severity: 'CRITICAL',
            cvss: 9.8,
            description: 'Application is vulnerable to SQL injection attacks through user input',
            impact: 'Attackers can extract, modify, or delete database contents',
            suggestion: 'Use parameterized queries and input validation. Implement WAF rules.'
        },
        'xss': {
            name: 'Cross-Site Scripting (XSS)',
            severity: 'HIGH',
            cvss: 7.1,
            description: 'User input is not properly sanitized before displaying in page',
            impact: 'Attackers can execute JavaScript in user browsers, steal credentials',
            suggestion: 'Implement input sanitization, output encoding, and CSP headers.'
        },
        'sensitive_file': {
            name: 'Sensitive File Exposure',
            severity: 'CRITICAL',
            cvss: 9.1,
            description: 'Sensitive configuration files are publicly accessible',
            impact: 'Exposure of database credentials, API keys, and system configuration',
            suggestion: 'Remove or restrict access to sensitive files. Use .htaccess or firewall rules.'
        },
        'file_upload': {
            name: 'File Upload Vulnerability',
            severity: 'HIGH',
            cvss: 8.9,
            description: 'File upload endpoints lack proper validation and restrictions',
            impact: 'Arbitrary file upload leading to remote code execution',
            suggestion: 'Validate file types, rename files, store outside root, scan for malware.'
        },
        'missing_headers': {
            name: 'Missing Security Headers',
            severity: 'HIGH',
            cvss: 7.5,
            description: 'Critical security headers are not implemented',
            impact: 'Increased risk of XSS, clickjacking, content-type attacks',
            suggestion: 'Add missing headers: Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options, CSP.'
        },
        'plugin_exposure': {
            name: 'Plugin/Extension Directory Exposure',
            severity: 'MEDIUM',
            cvss: 6.5,
            description: 'Plugin or extension directories are publicly enumerable',
            impact: 'Attackers can identify installed plugins and exploit known vulnerabilities',
            suggestion: 'Disable directory listing. Add Options -Indexes to .htaccess or configure web server.'
        },
        'outdated_version': {
            name: 'Outdated CMS Detected',
            severity: 'MEDIUM',
            cvss: 6.5,
            description: 'CMS is running an outdated version with known vulnerabilities',
            impact: 'Exploitation of known CVEs affecting the installed version',
            suggestion: 'Keep CMS, plugins, and themes updated. Monitor security advisories.'
        },
        'directory_traversal': {
            name: 'Directory Traversal',
            severity: 'CRITICAL',
            cvss: 9.1,
            description: 'Application does not properly validate file paths, allowing access to arbitrary files',
            impact: 'Read/write access to sensitive files outside intended directories',
            suggestion: 'Use Path.GetFullPath() validation, implement input sanitization, use allowlist.'
        },
        'open_port': {
            name: 'Open Port Exposure',
            severity: 'CRITICAL',
            cvss: 9.0,
            description: 'Unnecessary or sensitive services are exposed on open ports',
            impact: 'Direct access to databases, SSH, or other critical services',
            suggestion: 'Close unnecessary ports, use firewall rules, restrict access to trusted IPs.'
        }
    };

    // Helper to push findings and emit live log messages
    function push(id, name, severity, evidence, suggestion) {
        const template = VULN_DB[id] || {};
        const item = {
            id,
            name: name || template.name || 'Unknown Vulnerability',
            severity: severity || template.severity || 'MEDIUM',
            cvss: template.cvss || 0,
            description: template.description || 'Potential security vulnerability detected',
            impact: template.impact || 'Unknown impact',
            suggestion: suggestion || template.suggestion || 'Review and mitigate this finding',
            evidence
        };
        results.push(item);
        console.log('[BG_SCAN] Pushed finding:', id, '| Results array now has', results.length, 'items');
        try {
            chrome.runtime.sendMessage({ action: 'networkScanLog', message: { type: 'finding', finding: item } });
        } catch (e) {
            // ignore
        }
    }

    // Basic page fetch for HTML analysis
    let mainHtml = '';
    try {
        const resp = await fetch(targetUrl, { method: 'GET', redirect: 'follow' });
        mainHtml = await resp.text();
        try { chrome.runtime.sendMessage({ action: 'networkScanLog', message: `Fetched main HTML (${mainHtml.length} bytes)` }); } catch (e) {}
    } catch (e) {
        try { chrome.runtime.sendMessage({ action: 'networkScanLog', message: `Failed to fetch main HTML: ${e && e.message ? e.message : e}` }); } catch (er) {}
        // continue with partial data
    }

    // Check security headers via HEAD
    try {
        const resp = await fetch(targetUrl, { method: 'HEAD' });
        const headers = {};
        resp.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
        const required = ['strict-transport-security', 'x-content-type-options', 'x-frame-options', 'content-security-policy'];
        const missing = required.filter(h => !headers[h]);
        if (missing.length) {
            push('missing_headers', 'Missing Security Headers', 'HIGH', missing.map(m => ({ label: m, detail: 'Header missing', location: targetUrl })), 'Add missing headers: ' + missing.join(', '));
            try { chrome.runtime.sendMessage({ action: 'networkScanLog', message: `Missing headers: ${missing.join(', ')}` }); } catch (e) {}
        }
    } catch (e) {
        try { chrome.runtime.sendMessage({ action: 'networkScanLog', message: `Header fetch failed: ${e && e.message ? e.message : e}` }); } catch (er) {}
        // ignore header errors
    }

    // Sensitive files (expanded list to match Python scanner patterns)
    const sensitiveFiles = ['/.env', '/config.php', '/wp-config.php', '/database.yml', '/.git/config', '/web.config', '/composer.lock', '/package-lock.json', '/robots.txt', '/admin/config', '/secrets'];
    for (const path of sensitiveFiles) {
        if (isTimeoutReached()) {
            try { chrome.runtime.sendMessage({ action: 'networkScanLog', message: `Scan timeout reached - stopping at sensitive file checks` }); } catch (e) {}
            break;
        }
        try {
            const url = origin + path;
            const resp = await fetch(url, { method: 'GET', redirect: 'follow' });
            if (resp.status === 200) {
                push('sensitive_file', 'Sensitive File Exposure', 'CRITICAL', [{ label: path, detail: `Accessible: ${url}`, location: url }], 'Remove or restrict access to sensitive files.');
                try { chrome.runtime.sendMessage({ action: 'networkScanLog', message: `Sensitive file accessible: ${url}` }); } catch (e) {}
            }
        } catch (e) {
            // ignore
        }
    }

    // File upload endpoints
    const uploadEndpoints = ['/upload', '/api/upload', '/media/upload', '/file/upload', '/files/upload'];
    for (const endpoint of uploadEndpoints) {
        if (isTimeoutReached()) {
            try { chrome.runtime.sendMessage({ action: 'networkScanLog', message: `Scan timeout reached - stopping at upload endpoint checks` }); } catch (e) {}
            break;
        }
        try {
            const url = origin + endpoint;
            const resp = await fetch(url, { method: 'POST', redirect: 'follow' });
            if (resp.status !== 404 && resp.status < 500) {
                push('file_upload', 'File Upload Vulnerability', 'HIGH', [{ label: endpoint, detail: `Endpoint responded: ${resp.status}`, location: url }], 'Validate file types and store uploads outside web root.');
                try { chrome.runtime.sendMessage({ action: 'networkScanLog', message: `Upload endpoint responsive: ${url} (${resp.status})` }); } catch (e) {}
            }
        } catch (e) {
            // ignore
        }
    }

    // Plugin/extension directories
    const pluginPaths = ['/wp-content/plugins', '/modules', '/extensions', '/components', '/plugins', '/wp-content/themes'];
    for (const p of pluginPaths) {
        if (isTimeoutReached()) {
            try { chrome.runtime.sendMessage({ action: 'networkScanLog', message: `Scan timeout reached - stopping plugin path checks` }); } catch (e) {}
            break;
        }
        try {
            const url = origin + p;
            const resp = await fetch(url, { method: 'GET', redirect: 'follow' });
            if (resp.status === 200) {
                push('plugin_exposure', 'Plugin/Extension Directory Exposure', 'MEDIUM', [{ label: p, detail: `Accessible: ${url}`, location: url }], 'Disable directory listing and hide plugin folders.');
                try { chrome.runtime.sendMessage({ action: 'networkScanLog', message: `Plugin path accessible: ${url}` }); } catch (e) {}
            }
        } catch (e) {
            // ignore
        }
    }

    // Outdated CMS detection
    if (mainHtml) {
        const lower = mainHtml.toLowerCase();
        if (lower.includes('wp-content') || lower.includes('wp-json')) {
            push('outdated_version', 'Outdated CMS Detected', 'MEDIUM', [{ label: 'WordPress', detail: 'Signatures found in HTML', location: targetUrl }], 'Keep CMS and plugins up to date.');
        } else if (lower.includes('drupal') || lower.includes('sites/default')) {
            push('outdated_version', 'Outdated CMS Detected', 'MEDIUM', [{ label: 'Drupal', detail: 'Signatures found in HTML', location: targetUrl }], 'Keep CMS and modules up to date.');
        }
    }

    // SQL Injection & XSS checks (heuristic: reflect/pattern detection)
    const sqlPayloads = ["' OR '1'='1", "' OR 1=1--", "1' UNION SELECT NULL--", "admin' --"];
    const xssPayloads = ['<script>alert("xss")</script>', '"><script>alert("xss")</script>', '<img src=x onerror="alert(\'xss\')">', '<svg onload=alert("xss")>'];
    const endpoints = ['/search', '/api/search', '/posts', '/products', '/?id=1', '/comment', '/search.php', '/index.php'];

    for (const endpoint of endpoints) {
        if (isTimeoutReached()) {
            try { chrome.runtime.sendMessage({ action: 'networkScanLog', message: `Scan timeout reached - stopping SQL/XSS checks` }); } catch (e) {}
            break;
        }
        for (const payload of sqlPayloads) {
            try {
                const sep = endpoint.includes('?') ? '&' : '?';
                const url = origin + endpoint + sep + 'q=' + encodeURIComponent(payload);
                const resp = await fetch(url, { method: 'GET', redirect: 'follow' });
                const text = await resp.text();
                const sqlErrors = ['sql syntax', 'mysql_fetch', 'sqlstate', 'syntax error', 'ora-', 'postgresql', 'you have an error in your sql syntax', 'unexpected end of statement'];
                if (sqlErrors.some(p => text.toLowerCase().includes(p))) {
                    push('sql_injection', 'SQL Injection', 'CRITICAL', [{ label: 'SQL error', detail: `Error text found at ${url}`, location: url }], 'Use parameterized queries and input validation.');
                    try { chrome.runtime.sendMessage({ action: 'networkScanLog', message: `SQL error text detected at ${url}` }); } catch (e) {}
                    break;
                }
            } catch (e) {
                // ignore
            }
        }
    }

    for (const endpoint of endpoints) {
        if (isTimeoutReached()) {
            try { chrome.runtime.sendMessage({ action: 'networkScanLog', message: `Scan timeout reached - stopping XSS checks` }); } catch (e) {}
            break;
        }
        for (const payload of xssPayloads) {
            try {
                const sep = endpoint.includes('?') ? '&' : '?';
                const url = origin + endpoint + sep + 'q=' + encodeURIComponent(payload);
                const resp = await fetch(url, { method: 'GET', redirect: 'follow' });
                const text = await resp.text();
                if (text.includes(payload)) {
                    push('xss', 'Cross-Site Scripting (XSS)', 'HIGH', [{ label: 'Reflected input', detail: `Payload reflected at ${url}`, location: url }], 'Implement input sanitization and CSP.');
                    try { chrome.runtime.sendMessage({ action: 'networkScanLog', message: `Reflected XSS payload at ${url}` }); } catch (e) {}
                    break;
                }
            } catch (e) {
                // ignore
            }
        }
    }

    // Directory traversal
    const traversalPayloads = ['../../../etc/passwd', '..\\..\\..\\windows\\win.ini', '....//....//....//etc/passwd'];
    const traversalEndpoints = ['/file', '/download', '/api/file'];
    for (const endpoint of traversalEndpoints) {
        if (isTimeoutReached()) {
            try { chrome.runtime.sendMessage({ action: 'networkScanLog', message: `Scan timeout reached - stopping directory traversal checks` }); } catch (e) {}
            break;
        }
        for (const payload of traversalPayloads) {
            try {
                const sep = endpoint.includes('?') ? '&' : '?';
                const url = origin + endpoint + sep + 'path=' + encodeURIComponent(payload);
                const resp = await fetch(url, { method: 'GET', redirect: 'follow' });
                const text = await resp.text();
                if (text.includes('root:') || text.includes('[drivers]')) {
                    push('directory_traversal', 'Directory Traversal', 'CRITICAL', [{ label: 'Traversal', detail: `Sensitive file content at ${url}`, location: url }], 'Validate and canonicalize file paths.');
                    try { chrome.runtime.sendMessage({ action: 'networkScanLog', message: `Directory traversal content detected at ${url}` }); } catch (e) {}
                    break;
                }
            } catch (e) {
                // ignore
            }
        }
    }

    // Lightweight open port heuristic: try a few common HTTP ports (HTTP-based heuristic only)
    if (!isTimeoutReached()) {
        const portCandidates = [8080, 8443, 3000, 8000, 5000];
        for (const port of portCandidates) {
            if (isTimeoutReached()) {
                try { chrome.runtime.sendMessage({ action: 'networkScanLog', message: `Scan timeout reached - stopping port checks` }); } catch (e) {}
                break;
            }
            try {
                const portUrl = `${parsed.protocol}//${host}:${port}/`;
                // Use no-cors HEAD to attempt to detect a listening HTTP service; treat a resolved fetch as evidence
                await fetch(portUrl, { method: 'HEAD', mode: 'no-cors', redirect: 'follow' });
                push('open_port', 'Open Port Exposure', [8080, 8443].includes(port) ? 'MEDIUM' : 'MEDIUM', [{ label: `Port ${port}`, detail: `HTTP service responded on port ${port}`, location: portUrl }], 'Close unnecessary ports or restrict access.');
            } catch (e) {
                // ignore network errors (port closed/unreachable)
            }
        }
    }

    // Deduplicate by id
    const unique = [];
    const seen = new Set();
    for (const r of results) {
        if (r && r.id && !seen.has(r.id)) {
            unique.push(r);
            seen.add(r.id);
        }
    }

    console.log('[BG_SCAN] FINAL RESULTS: results array has', results.length, 'items | unique has', unique.length, 'items');
    console.log('[BG_SCAN] Unique items:', unique.map(u => u.id));

    try {
        chrome.runtime.sendMessage({ action: 'networkScanLog', message: `Network scan complete: ${unique.length} unique findings` });
    } catch (e) {}

    // Broadcast final scan results so the popup can receive them reliably
    try {
        chrome.runtime.sendMessage({ action: 'networkScanResult', url: targetUrl, vulnerabilities: unique });
    } catch (e) {}

    return unique;
}

// Handle extension icon click
chrome.action.onClicked.addListener((tab) => {
    chrome.tabs.sendMessage(tab.id, {
        action: 'showResults'
    }).catch(() => {
        // Content script not loaded yet
        console.log('Content script not ready');
    });
});
