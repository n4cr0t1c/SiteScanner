// Content Script - CMS Security Scanner based on plan/cms_scanner.py logic

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'analyzePage') {
        analyzeCurrentPage().then(vulnerabilities => sendResponse({ vulnerabilities }));
        return true;
    }
});

async function analyzeCurrentPage() {
    const results = [];
    const html = document.documentElement.outerHTML || '';
    const lowerHtml = html.toLowerCase();
    const meta = document.head.innerHTML || '';
    const lowerMeta = meta.toLowerCase();
    const url = window.location.href || '';
    const lowerUrl = url.toLowerCase();
    const params = new URLSearchParams(window.location.search);
    const forms = Array.from(document.querySelectorAll('form'));
    const inputs = Array.from(document.querySelectorAll('input'));
    const headers = {};

    try {
        const response = await fetch(window.location.href, { method: 'HEAD', credentials: 'same-origin' });
        for (const [key, value] of response.headers.entries()) {
            headers[key.toLowerCase()] = value;
        }
    } catch (error) {
        // HEAD may fail on some sites, continue with page HTML analysis only
        console.warn('Header fetch failed:', error);
    }

    function push(id, evidence) {
        const base = window.VULNERABILITIES && window.VULNERABILITIES[id];
        if (!base) return;
        const item = Object.assign({}, base);
        item.evidence = evidence || [];
        results.push(item);
    }

    // SQL Injection patterns
    const sqlErrors = ['sql syntax', 'mysql_fetch', 'sqlstate', 'syntax error', 'ora-', 'postgresql', 'you have an error in your sql syntax', 'unexpected end of statement'];
    const sqlPayloads = ['union select', "or 1=1", "or '1'='1", 'information_schema', 'sleep(', 'benchmark('];
    const hasSqlError = sqlErrors.some(p => lowerHtml.includes(p));
    const hasSqlPayload = sqlPayloads.some(p => lowerHtml.includes(p));
    if (hasSqlError || hasSqlPayload) {
        push('SQL_INJECTION', [
            {
                label: hasSqlError ? 'SQL Error Message' : 'SQL Payload Pattern',
                detail: hasSqlError ? 'SQL error text found in page content' : 'Potential SQL payload found in HTML',
                location: url
            }
        ]);
    }

    // XSS vectors
    const xssVectors = ['<script>', 'onerror=', 'onload=', 'onclick=', 'onmouseover=', 'javascript:'];
    const reflectedParams = [];
    for (const [key, value] of params.entries()) {
        if (!value || value.length < 2) continue;
        if (lowerHtml.includes(value.toLowerCase())) {
            reflectedParams.push({
                label: `Parameter: ${key}`,
                detail: `Value "${value}" reflected in page`,
                location: url
            });
        }
    }
    const hasXssVectors = xssVectors.some(v => lowerHtml.includes(v));
    if (reflectedParams.length > 0 && hasXssVectors) {
        push('XSS', reflectedParams);
    }

    // Weak Password Policy / Admin Panel - IMPROVED DETECTION
    const adminPaths = ['/wp-admin', '/wp-login.php', '/administrator', '/admin', '/login', '/user/login', '/admin/login', '/adminlogin', '/control', '/backend'];
    const hasAdminInUrl = adminPaths.some(p => lowerUrl.includes(p));
    const hasLoginForm = forms.some(f => f.querySelector('input[type="password"]'));
    // Also check for common password input patterns
    const hasPasswordInput = inputs.some(i => i.type === 'password' || lowerHtml.includes('password'));
    if (hasAdminInUrl || hasLoginForm || hasPasswordInput) {
        push('WEAK_PASSWORD', [
            {
                label: 'Weak Authentication Detected',
                detail: hasAdminInUrl ? 'Admin or login path detected' : (hasPasswordInput ? 'Password input field detected' : 'Login form detected'),
                location: url
            }
        ]);
    }

    // Sensitive File Exposure - EXPANDED PATTERNS
    const sensitiveFiles = ['/.env', '/config.php', '/wp-config.php', '/database.yml', '/.git/config', '/web.config', '/.git', '/composer.lock', '/package-lock.json', '/secrets'];
    const detectedSensitiveFiles = sensitiveFiles.filter(path => lowerHtml.includes(path));
    if (detectedSensitiveFiles.length > 0) {
        push('SENSITIVE_FILE_EXPOSURE', [
            {
                label: 'Sensitive File Reference',
                detail: detectedSensitiveFiles.join(', '),
                location: 'HTML content'
            }
        ]);
    }

    // File Upload Vulnerabilities
    const hasFileUpload = inputs.some(i => i.type === 'file');
    const hasMultipartForm = forms.some(f => f.enctype && f.enctype.includes('multipart'));
    if (hasFileUpload || hasMultipartForm) {
        push('FILE_UPLOAD', [
            {
                label: 'File Upload Point',
                detail: hasMultipartForm ? 'Multipart form data found' : 'File input field found',
                location: url
            }
        ]);
    }

    // Outdated CMS Detection
    if (lowerHtml.includes('wp-content') || lowerHtml.includes('wp-json')) {
        push('OUTDATED_VERSION', [
            {
                label: 'WordPress Detected',
                detail: 'WordPress signatures found in the page',
                location: 'HTML analysis'
            }
        ]);
    } else if (lowerHtml.includes('drupal') || lowerHtml.includes('sites/default')) {
        push('OUTDATED_VERSION', [
            {
                label: 'Drupal Detected',
                detail: 'Drupal signatures found in the page',
                location: 'HTML analysis'
            }
        ]);
    } else if (lowerHtml.includes('joomla')) {
        push('OUTDATED_VERSION', [
            {
                label: 'Joomla Detected',
                detail: 'Joomla signatures found in the page',
                location: 'HTML analysis'
            }
        ]);
    }

    // Plugin/Extension Exposure
    const pluginPaths = ['/wp-content/plugins', '/modules', '/extensions', '/components'];
    const detectedPluginPaths = pluginPaths.filter(p => lowerHtml.includes(p));
    if (detectedPluginPaths.length > 0) {
        push('PLUGIN_EXPOSURE', [
            {
                label: 'Plugin Paths Found',
                detail: detectedPluginPaths.join(', '),
                location: 'HTML analysis'
            }
        ]);
    }

    // Missing Security Headers - use actual response headers when possible
    const requiredHeaders = [
        { key: 'strict-transport-security', label: 'Strict-Transport-Security' },
        { key: 'x-content-type-options', label: 'X-Content-Type-Options' },
        { key: 'x-frame-options', label: 'X-Frame-Options' },
        { key: 'content-security-policy', label: 'Content-Security-Policy' }
    ];
    const missingHeaders = requiredHeaders
        .filter(header => !headers[header.key] && !lowerMeta.includes(header.key))
        .map(header => header.label);
    if (missingHeaders.length > 0) {
        push('MISSING_HEADERS', [
            {
                label: 'Missing Security Headers',
                detail: missingHeaders.join(', '),
                location: 'Response headers / meta tags'
            }
        ]);
    }

    // Directory Traversal
    const traversalPatterns = ['/../', '..\\', 'path=..', 'file=..', 'dir=..'];
    const hasTraversalPattern = traversalPatterns.some(pattern => lowerUrl.includes(pattern));
    if (hasTraversalPattern) {
        push('DIRECTORY_TRAVERSAL', [
            {
                label: 'Traversal Pattern',
                detail: 'Path traversal pattern detected in URL',
                location: url
            }
        ]);
    }

    // Open Port Exposure heuristic
    const portPatterns = ['ssh://', 'mysql://', 'postgres://', 'mongodb://', 'redis://'];
    const portUrlsFound = portPatterns.filter(p => lowerHtml.includes(p));
    const commonPortRegex = /https?:\/\/[^\s'"<>]+:(22|23|3306|5432|27017|6379|8080|8443)\b/g;
    const portMatches = [...lowerHtml.matchAll(commonPortRegex)].map(match => match[1]);
    if (portUrlsFound.length > 0 || portMatches.length > 0) {
        const evidenceList = [];
        portUrlsFound.forEach(p => evidenceList.push({ label: 'Service URL', detail: `Found protocol ${p}`, location: 'HTML content' }));
        portMatches.forEach(port => evidenceList.push({ label: 'Port Reference', detail: `Port ${port} referenced in URL`, location: 'HTML content' }));
        push('OPEN_PORT', evidenceList);
    }

    // Weak SSL / HTTP
    if (window.location.protocol === 'http:') {
        push('WEAK_SSL', [
            {
                label: 'Unencrypted Connection',
                detail: 'Page is served over HTTP instead of HTTPS',
                location: url
            }
        ]);
    }

    // Deduplicate results by id
    const unique = [];
    const seen = new Set();
    for (const vuln of results) {
        if (vuln && vuln.id && !seen.has(vuln.id)) {
            unique.push(vuln);
            seen.add(vuln.id);
        }
    }

    return unique;
}
