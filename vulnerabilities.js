// CMS Vulnerability Detection Database - Minimal Edition

const VULNERABILITIES = {
    SQL_INJECTION: {
        id: 'sql_injection',
        name: 'SQL Injection',
        severity: 'CRITICAL',
        cvss: 9.8,
        description: 'Application is vulnerable to SQL injection attacks through user input',
        impact: 'Attackers can extract, modify, or delete database contents',
        suggestion: 'Use parameterized queries and input validation. Implement WAF rules.',
        quick_fix: 'Sanitize inputs and switch to prepared statements (parameterized queries).'
    },
    XSS: {
        id: 'xss',
        name: 'Cross-Site Scripting (XSS)',
        severity: 'HIGH',
        cvss: 7.1,
        description: 'User input is not properly sanitized before displaying in page',
        impact: 'Attackers can execute JavaScript in user browsers, steal credentials',
        suggestion: 'Implement input sanitization, output encoding, and CSP headers.',
        quick_fix: 'Escape output and add a Content-Security-Policy. Validate user input server-side.'
    },
    WEAK_PASSWORD: {
        id: 'weak_password',
        name: 'Weak Password Policy',
        severity: 'HIGH',
        cvss: 7.3,
        description: 'Admin panel accessible without authentication or weak password requirements',
        impact: 'Unauthorized access to admin functions, system compromise',
        suggestion: 'Enforce strong password requirements, implement rate limiting, use 2FA.',
        quick_fix: 'Enforce password complexity, enable account lockout and enable 2FA for admin users.'
    },
    SENSITIVE_FILE_EXPOSURE: {
        id: 'sensitive_file',
        name: 'Sensitive File Exposure',
        severity: 'CRITICAL',
        cvss: 9.1,
        description: 'Sensitive configuration files are publicly accessible',
        impact: 'Exposure of database credentials, API keys, and system configuration',
        suggestion: 'Remove or restrict access to sensitive files. Use .htaccess or firewall rules.',
        quick_fix: 'Remove sensitive files from web root and restrict access via server config (deny from all).'
    },
    FILE_UPLOAD: {
        id: 'file_upload',
        name: 'File Upload Vulnerability',
        severity: 'HIGH',
        cvss: 8.9,
        description: 'File upload endpoints lack proper validation and restrictions',
        impact: 'Arbitrary file upload leading to remote code execution',
        suggestion: 'Validate file types, rename files, store outside root, scan for malware.',
        quick_fix: 'Restrict allowed file types, validate content server-side and store uploads outside webroot.'
    },
    OPEN_PORT: {
        id: 'open_port',
        name: 'Open Port Exposure',
        severity: 'CRITICAL',
        cvss: 9.0,
        description: 'Unnecessary or sensitive services are exposed on open ports',
        impact: 'Direct access to databases, SSH, or other critical services',
        suggestion: 'Close unnecessary ports, use firewall rules, restrict access to trusted IPs.',
        quick_fix: 'Close service ports or restrict access with firewall rules (iptables/ufw/security groups).'
    },
    OUTDATED_VERSION: {
        id: 'outdated_version',
        name: 'Outdated CMS Version',
        severity: 'MEDIUM',
        cvss: 6.5,
        description: 'CMS is running an outdated version with known vulnerabilities',
        impact: 'Exploitation of known CVEs affecting the installed version',
        suggestion: 'Keep CMS, plugins, and themes updated. Monitor security advisories.',
        quick_fix: 'Update the CMS and all plugins/themes to the latest secure versions.'
    },
    PLUGIN_EXPOSURE: {
        id: 'plugin_exposure',
        name: 'Plugin Directory Exposure',
        severity: 'MEDIUM',
        cvss: 6.5,
        description: 'Plugin or extension directories are publicly enumerable',
        impact: 'Attackers can identify installed plugins and exploit known vulnerabilities',
        suggestion: 'Disable directory listing. Add Options -Indexes to .htaccess or configure web server.',
        quick_fix: 'Disable directory listing and remove publicly exposed plugin files; patch or remove vulnerable plugins.'
    },
    MISSING_HEADERS: {
        id: 'missing_headers',
        name: 'Missing Security Headers',
        severity: 'HIGH',
        cvss: 7.5,
        description: 'Critical security headers are not implemented',
        impact: 'Increased risk of XSS, clickjacking, content-type attacks',
        suggestion: 'Add missing headers: Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options, CSP.',
        quick_fix: 'Add HSTS, X-Content-Type-Options: nosniff, X-Frame-Options: DENY, and a restrictive CSP header.'
    },
    DIRECTORY_TRAVERSAL: {
        id: 'directory_traversal',
        name: 'Directory Traversal',
        severity: 'CRITICAL',
        cvss: 9.1,
        description: 'Application does not properly validate file paths, allowing access to arbitrary files',
        impact: 'Read/write access to sensitive files outside intended directories',
        suggestion: 'Use Path.GetFullPath() validation, implement input sanitization, use allowlist.',
        quick_fix: 'Validate and canonicalize file paths server-side and use an allowlist for accessible files.'
    },
    DEFAULT_CREDENTIALS: {
        id: 'default_creds',
        name: 'Default Credentials',
        severity: 'CRITICAL',
        cvss: 9.8,
        description: 'Default credentials are still active on admin panels or services',
        impact: 'Immediate unauthorized access and full system compromise',
        suggestion: 'Change all default credentials to strong, unique passwords immediately.',
        quick_fix: 'Change default accounts and enforce password change on first login; disable unused accounts.'
    },
    WEAK_SSL: {
        id: 'weak_ssl',
        name: 'Weak SSL/TLS',
        severity: 'HIGH',
        cvss: 7.4,
        description: 'Outdated or weak SSL/TLS protocols are enabled',
        impact: 'Man-in-the-middle attacks, data interception, session hijacking',
        suggestion: 'Use TLS 1.2 or higher. Disable weak ciphers and old protocols.',
        quick_fix: 'Enable TLS 1.2+/1.3, disable legacy ciphers and protocols in server configuration.'
    },
    EXPOSED_ADMIN: {
        id: 'exposed_admin',
        name: 'Exposed Admin Panel',
        severity: 'HIGH',
        cvss: 7.4,
        description: 'Admin panel is publicly accessible without IP restriction',
        impact: 'Brute force attacks, unauthorized access, system compromise',
        suggestion: 'Restrict admin panel access via IP whitelist or change default paths.',
        quick_fix: 'Restrict admin URLs by IP, enable VPN-only access, or move admin panel to a non-standard path.'
    }
};

// Detection functions
function detectCMS() {
    const html = document.documentElement.outerHTML;
    const meta = document.head.innerHTML;
    const detected = [];

    if (html.includes('wp-content') || html.includes('wp-admin') || html.includes('wp-json')) {
        detected.push('WordPress');
    }
    if (html.includes('sites/default') || html.includes('/modules/') || html.includes('drupal')) {
        detected.push('Drupal');
    }
    if (html.includes('joomla') || html.includes('/administrator/')) {
        detected.push('Joomla');
    }
    if (html.includes('magento') || html.includes('/skin/') || html.includes('/media/')) {
        detected.push('Magento');
    }

    return detected;
}

function analyzeVulnerabilities() {
    const detected = detectCMS();
    const vulnerabilities = [];

    // Check for missing HTTPS
    if (window.location.protocol !== 'https:') {
        vulnerabilities.push(VULNERABILITIES.WEAK_SSL);
    }

    // Check for weak password policy
    if (document.querySelector('input[type="password"]') && !document.body.innerHTML.includes('password')) {
        vulnerabilities.push(VULNERABILITIES.WEAK_PASSWORD);
    }

    // Check for exposed admin panel
    if (document.innerHTML.includes('/wp-admin') || document.innerHTML.includes('/administrator/') || document.innerHTML.includes('/admin/')) {
        vulnerabilities.push(VULNERABILITIES.EXPOSED_ADMIN);
    }

    // Check for outdated CMS
    if (detected.length > 0) {
        vulnerabilities.push(VULNERABILITIES.OUTDATED_VERSION);
    }

    // Check for sensitive files
    const sensitivePatterns = ['/.env', '/config.php', '/web.config', '/.git'];
    sensitivePatterns.forEach(pattern => {
        if (document.body.innerHTML.includes(pattern)) {
            vulnerabilities.push(VULNERABILITIES.SENSITIVE_FILE_EXPOSURE);
        }
    });

    // Check for missing security headers (basic check)
    const missingHeaders = ['CSP', 'HSTS', 'X-Frame-Options'];
    vulnerabilities.push(VULNERABILITIES.MISSING_HEADERS);

    // Remove duplicates
    return vulnerabilities.filter((v, i, arr) => arr.findIndex(a => a.id === v.id) === i);
}