const fetch = require('node-fetch');
const { generateAiResponse } = require('./ollamaService');

// Helper: make HTTP requests with timeout
async function httpGet(url, options = {}) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);
    try {
        const res = await fetch(url, {
            signal: controller.signal,
            headers: {
                'User-Agent': 'SecurityScanner/1.0',
                ...options.headers,
            },
            redirect: 'follow',
            ...options,
        });
        const text = await res.text();
        return { status: res.status, headers: res.headers, body: text, ok: res.ok, url: res.url };
    } catch (err) {
        return { error: err.message, status: 0, headers: {}, body: '', ok: false };
    } finally {
        clearTimeout(timeout);
    }
}

// ── 1. Injection & AI Payload Mutation (WAF Bypass) ────────────────────────────
async function checkInjection(targetUrl) {
    const initialPayloads = ["'", '"', '1=1--', '<script>', '${7*7}', '{{7*7}}'];
    const issues = [];
    const errorPatterns = [
        /sql syntax/i, /mysql_fetch/i, /ora-\d{5}/i, /sqlite/i,
        /syntax error/i, /unclosed quotation/i, /ODBC Driver/i,
    ];

    for (let payload of initialPayloads.slice(0, 3)) {
        let testUrl = `${targetUrl}?id=${encodeURIComponent(payload)}&q=${encodeURIComponent(payload)}`;
        let res = await httpGet(testUrl);

        // AI Zero-Day Payload Mutator: If WAF blocks (403/406), mutate the payload
        if (res.status === 403 || res.status === 406) {
            console.log(`[WAF Blocked] Injection payload: ${payload}. Requesting AI mutation...`);
            const mutated = await generateAiResponse(`
        You are a red team payload generator. The target Web Application Firewall (WAF) blocked the SQL injection payload: "${payload}".
        Provide ONE highly obfuscated, encoding-mutated SQL injection payload that bypasses common regex WAFs (e.g., using URL encoding, hex encoding, SQL comment obfuscation like /*!50000UniOn*/, or whitespace bypasses).
        RESPOND ONLY WITH THE RAW MUTATED PAYLOAD. Do not include quotes, markdown, or explanations.
      `);
            if (mutated && mutated.length < 100) {
                payload = mutated.trim();
                console.log(`[WAF Bypass Attempt] New AI mutated payload: ${payload}`);
                testUrl = `${targetUrl}?id=${encodeURIComponent(payload)}&q=${encodeURIComponent(payload)}`;
                res = await httpGet(testUrl);
            }
        }

        if (res.body && errorPatterns.some((p) => p.test(res.body))) {
            issues.push(`SQL/Command injection indicator with payload: ${payload}`);
        }
    }

    return {
        owaspId: 'A03:2021',
        name: 'Injection',
        vulnerable: issues.length > 0,
        severity: issues.length > 0 ? 'Critical' : 'Low',
        issues,
        description: issues.length > 0
            ? 'Application may be vulnerable to injection attacks. Error messages leaked on malformed input.'
            : 'No obvious injection error leakage detected.',
        recommendation: 'Use parameterized queries, prepared statements, and input validation. Never concatenate user input into queries.',
        evidence: issues.join('; ') || 'No injection errors detected',
    };
}

// ── 2. Broken Authentication ───────────────────────────────────────────────────
async function checkBrokenAuth(targetUrl) {
    const issues = [];
    const res = await httpGet(targetUrl);

    if (res.headers) {
        const setCookie = res.headers.get ? res.headers.get('set-cookie') : res.headers['set-cookie'];
        if (setCookie) {
            if (!/HttpOnly/i.test(setCookie)) issues.push('Session cookie missing HttpOnly flag');
            if (!/Secure/i.test(setCookie)) issues.push('Session cookie missing Secure flag');
            if (!/SameSite/i.test(setCookie)) issues.push('Session cookie missing SameSite attribute');
        }
    }

    const loginPaths = ['/login', '/signin', '/admin'];
    for (const path of loginPaths) {
        const loginRes = await httpGet(new URL(path, targetUrl).href);
        if (!loginRes.error && loginRes.status !== 404) {
            if (!loginRes.headers.get || !loginRes.headers.get('x-frame-options')) {
                issues.push(`Login page ${path} missing X-Frame-Options header (Clickjacking risk)`);
            }
        }
    }

    return {
        owaspId: 'A07:2021',
        name: 'Broken Authentication',
        vulnerable: issues.length > 0,
        severity: issues.length > 1 ? 'High' : issues.length > 0 ? 'Medium' : 'Low',
        issues,
        description: issues.length > 0
            ? 'Authentication weaknesses detected in session management configuration.'
            : 'Session cookies appear to be configured with appropriate security flags.',
        recommendation: 'Implement HttpOnly, Secure, and SameSite cookie attributes. Enforce MFA and account lockout policies.',
        evidence: issues.join('; ') || 'Cookie security flags appear properly configured',
    };
}

// ── 3. Sensitive Data Exposure ─────────────────────────────────────────────────
async function checkSensitiveDataExposure(targetUrl) {
    const issues = [];
    const parsedUrl = new URL(targetUrl);

    if (parsedUrl.protocol !== 'https:') {
        issues.push('Site does not enforce HTTPS — data transmitted in plaintext');
    }

    const res = await httpGet(targetUrl);
    if (res.headers) {
        const hsts = res.headers.get ? res.headers.get('strict-transport-security') : res.headers['strict-transport-security'];
        if (!hsts) issues.push('Missing Strict-Transport-Security (HSTS) header');

        const csp = res.headers.get ? res.headers.get('content-security-policy') : res.headers['content-security-policy'];
        if (!csp) issues.push('Missing Content-Security-Policy header');
    }

    const sensitivePatterns = [
        /password\s*[:=]\s*["'][^"']{3,}/i,
        /api[_-]?key\s*[:=]\s*["'][^"']{10,}/i,
        /secret\s*[:=]\s*["'][^"']{5,}/i,
        /BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY/i,
        /token\s*[:=]\s*["'][A-Za-z0-9_\-]{20,}/i,
    ];

    if (res.body) {
        sensitivePatterns.forEach((p) => {
            if (p.test(res.body)) issues.push(`Potential sensitive data in response body: ${p.source.slice(0, 40)}`);
        });
    }

    return {
        owaspId: 'A02:2021',
        name: 'Sensitive Data Exposure',
        vulnerable: issues.length > 0,
        severity: issues.length > 2 ? 'High' : issues.length > 0 ? 'Medium' : 'Low',
        issues,
        description: issues.length > 0
            ? 'Potential sensitive data exposure identified through insecure transport or leaked secrets.'
            : 'No obvious sensitive data exposure found.',
        recommendation: 'Enforce HTTPS everywhere, implement HSTS, avoid exposing secrets in HTML/JS, use CSP headers.',
        evidence: issues.join('; ') || 'HTTPS and security headers appear configured',
    };
}

// ── 4. XXE ─────────────────────────────────────────────────────────────────────
async function checkXXE(targetUrl) {
    const issues = [];
    const xxePayload = `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`;

    const res = await httpGet(targetUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/xml' },
        body: xxePayload,
    });

    if (res.body) {
        if (/root:x:/i.test(res.body)) {
            issues.push('CRITICAL: XXE successful — /etc/passwd content returned in response');
        } else if (/DOCTYPE/.test(res.body) || /ENTITY/.test(res.body)) {
            issues.push('Server may reflect XML entity declarations — potential XXE');
        } else if (res.status === 500) {
            issues.push('Server returned 500 on XML input — possible XXE processing error');
        }
    }

    return {
        owaspId: 'A05:2021',
        name: 'XML External Entities (XXE)',
        vulnerable: issues.length > 0,
        severity: issues.some((i) => i.includes('CRITICAL')) ? 'Critical' : issues.length > 0 ? 'Medium' : 'Low',
        issues,
        description: issues.length > 0
            ? 'XML parser may process external entity references, enabling file disclosure or SSRF.'
            : 'No obvious XXE vulnerability detected.',
        recommendation: 'Disable external entity processing in XML parsers. Use a secure XML library configuration.',
        evidence: issues.join('; ') || 'No XXE response indicators',
    };
}

// ── 5. Broken Access Control ────────────────────────────────────────────────────
async function checkBrokenAccessControl(targetUrl) {
    const issues = [];
    const sensitivePaths = [
        '/admin', '/admin/dashboard', '/.env', '/config', '/api/users',
        '/backup', '/phpmyadmin', '/wp-admin', '/actuator', '/api/admin',
    ];

    for (const path of sensitivePaths) {
        const res = await httpGet(new URL(path, targetUrl).href);
        if (!res.error && res.status !== 404 && res.status !== 0) {
            if (res.status === 200) {
                issues.push(`Accessible sensitive path without auth: ${path} (HTTP ${res.status})`);
            } else if (res.status < 400) {
                issues.push(`Redirect or accessible path: ${path} (HTTP ${res.status})`);
            }
        }
    }

    // IDOR test — try incrementing IDs
    const idorPaths = ['/api/user/1', '/api/users/1', '/user/1', '/account/1'];
    for (const path of idorPaths) {
        const res = await httpGet(new URL(path, targetUrl).href);
        if (res.status === 200 && res.body.length > 50) {
            issues.push(`Potential IDOR: ${path} returned data without auth`);
        }
    }

    return {
        owaspId: 'A01:2021',
        name: 'Broken Access Control',
        vulnerable: issues.length > 0,
        severity: issues.some((i) => i.includes('.env') || i.includes('admin')) ? 'Critical' : issues.length > 0 ? 'High' : 'Low',
        issues,
        description: issues.length > 0
            ? 'Sensitive paths or resources accessible without proper authentication.'
            : 'No obvious access control bypass detected.',
        recommendation: 'Implement deny-by-default access control. Validate authorization on every request. Use indirect object references.',
        evidence: issues.join('; ') || 'Sensitive paths return expected 403/404 responses',
    };
}

// ── 6. Security Misconfiguration ───────────────────────────────────────────────
async function checkSecurityMisconfiguration(targetUrl) {
    const issues = [];
    const res = await httpGet(targetUrl);

    if (res.headers) {
        const get = (h) => res.headers.get ? res.headers.get(h) : res.headers[h];
        const server = get('server');
        const xPowered = get('x-powered-by');
        const xContentType = get('x-content-type-options');
        const xFrame = get('x-frame-options');
        const referrer = get('referrer-policy');

        if (server) issues.push(`Server header reveals version info: ${server}`);
        if (xPowered) issues.push(`X-Powered-By header exposes tech stack: ${xPowered}`);
        if (!xContentType) issues.push('Missing X-Content-Type-Options: nosniff header');
        if (!xFrame) issues.push('Missing X-Frame-Options header (clickjacking risk)');
        if (!referrer) issues.push('Missing Referrer-Policy header');
    }

    const debugPaths = ['/.git/HEAD', '/phpinfo.php', '/info.php', '/server-status', '/api/debug'];
    for (const path of debugPaths) {
        const res2 = await httpGet(new URL(path, targetUrl).href);
        if (res2.status === 200) {
            issues.push(`Debug/config file accessible: ${path}`);
        }
    }

    return {
        owaspId: 'A05:2021',
        name: 'Security Misconfiguration',
        vulnerable: issues.length > 0,
        severity: issues.length > 3 ? 'High' : issues.length > 0 ? 'Medium' : 'Low',
        issues,
        description: issues.length > 0
            ? 'Security misconfiguration detected via exposed headers, version info, or debug endpoints.'
            : 'No obvious security misconfiguration found.',
        recommendation: 'Remove server version headers, add security headers, disable debug endpoints in production.',
        evidence: issues.join('; ') || 'Security headers properly configured',
    };
}

// ── 7. XSS & AI Payload Mutation (WAF Bypass) ──────────────────────────────────────────────
async function checkXSS(targetUrl) {
    const issues = [];
    const xssPayloads = [
        '<script>alert(1)</script>',
        '"><script>alert(1)</script>',
        "';alert(1)//",
        '<img src=x onerror=alert(1)>',
    ];

    for (let payload of xssPayloads.slice(0, 2)) {
        let testUrl = `${targetUrl}?q=${encodeURIComponent(payload)}&search=${encodeURIComponent(payload)}&name=${encodeURIComponent(payload)}`;
        let res = await httpGet(testUrl);

        // AI Zero-Day Payload Mutator: If WAF blocks (403/406), mutate the payload
        if (res.status === 403 || res.status === 406) {
            console.log(`[WAF Blocked] XSS payload: ${payload}. Requesting AI mutation...`);
            const mutated = await generateAiResponse(`
        You are a red team payload generator. The target WAF blocked the XSS payload: "${payload}".
        Provide ONE highly obfuscated XSS payload that bypasses filters (e.g., using SVG/Math tags, unicode encoding, JSFuck variants, or mixed case).
        RESPOND ONLY WITH THE RAW MUTATED HTML/JS PAYLOAD. Do not include markdown, explanations, or quotes.
      `);
            if (mutated && mutated.length < 150) {
                payload = mutated.trim();
                console.log(`[WAF Bypass Attempt] New AI mutated XSS payload: ${payload}`);
                testUrl = `${targetUrl}?q=${encodeURIComponent(payload)}&search=${encodeURIComponent(payload)}&name=${encodeURIComponent(payload)}`;
                res = await httpGet(testUrl);
            }
        }

        if (res.body && res.body.includes(payload)) {
            issues.push(`Reflected XSS: payload returned unencoded in response for: ${payload.slice(0, 40)}`);
        }
    }

    const res = await httpGet(targetUrl);
    if (res.headers) {
        const csp = res.headers.get ? res.headers.get('content-security-policy') : res.headers['content-security-policy'];
        if (!csp) {
            issues.push('No Content-Security-Policy header — XSS payloads can execute without restriction');
        } else if (/unsafe-inline/i.test(csp)) {
            issues.push("CSP contains 'unsafe-inline' — reduces XSS protection");
        }
    }

    return {
        owaspId: 'A03:2021',
        name: 'Cross-Site Scripting (XSS)',
        vulnerable: issues.length > 0,
        severity: issues.some((i) => i.includes('Reflected XSS')) ? 'High' : issues.length > 0 ? 'Medium' : 'Low',
        issues,
        description: issues.length > 0
            ? 'XSS vulnerability indicators found — unencoded output or missing CSP.'
            : 'No reflected XSS detected. CSP appears configured.',
        recommendation: 'Encode all output, implement strict CSP, use modern frameworks with auto-escaping.',
        evidence: issues.join('; ') || 'No reflected XSS detected',
    };
}

// ── 8. Insecure Deserialization ────────────────────────────────────────────────
async function checkInsecureDeserialization(targetUrl) {
    const issues = [];

    const javaSerialProbe = Buffer.from('aced0005', 'hex').toString('base64');
    const phpSerialProbe = 'O:8:"stdClass":0:{}';

    const res1 = await httpGet(targetUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/octet-stream' },
        body: javaSerialProbe,
    });
    if (res1.status === 500) {
        issues.push('Server returned 500 on Java serialization magic bytes — potential deserialization endpoint');
    }

    const userAgent = res1.headers && res1.headers.get ? res1.headers.get('server') : '';
    if (userAgent && /(java|tomcat|spring|jboss|weblogic)/i.test(userAgent)) {
        issues.push(`Java application server detected (${userAgent}) — assess deserialization risks`);
    }

    const res2 = await httpGet(`${targetUrl}?data=${encodeURIComponent(phpSerialProbe)}`);
    if (res2.body && /unserialize|__wakeup|__destruct/i.test(res2.body)) {
        issues.push('PHP serialization artifacts detected in response');
    }

    return {
        owaspId: 'A08:2021',
        name: 'Insecure Deserialization',
        vulnerable: issues.length > 0,
        severity: issues.length > 0 ? 'High' : 'Low',
        issues,
        description: issues.length > 0
            ? 'Potential insecure deserialization indicators detected.'
            : 'No obvious insecure deserialization indicators found.',
        recommendation: 'Avoid deserializing user-controlled data. Use integrity checks and allowlists for deserialized types.',
        evidence: issues.join('; ') || 'No deserialization indicators',
    };
}

// ── 9. Known Vulnerable Components ────────────────────────────────────────────
async function checkKnownVulnerableComponents(targetUrl) {
    const issues = [];
    const res = await httpGet(targetUrl);

    const headerChecks = {
        server: [
            { pattern: /Apache\/2\.[0-3]\./i, msg: 'Potentially outdated Apache version' },
            { pattern: /nginx\/1\.(1[0-8]|[0-9])\./i, msg: 'Potentially outdated nginx version' },
            { pattern: /Microsoft-IIS\/[0-7]\./i, msg: 'Outdated IIS version detected' },
        ],
        'x-powered-by': [
            { pattern: /PHP\/[0-6]\./i, msg: 'End-of-life PHP version detected' },
            { pattern: /ASP\.NET\s+[1-3]\./i, msg: 'Outdated ASP.NET version' },
        ],
    };

    if (res.headers) {
        for (const [header, checks] of Object.entries(headerChecks)) {
            const val = res.headers.get ? res.headers.get(header) : res.headers[header];
            if (val) {
                checks.forEach(({ pattern, msg }) => {
                    if (pattern.test(val)) issues.push(`${msg}: ${val}`);
                });
            }
        }
    }

    // Check for jQuery version in body
    if (res.body) {
        const jqMatch = res.body.match(/jquery[^"']*["']([0-9]+\.[0-9]+\.[0-9]+)/i);
        if (jqMatch) {
            const [major, minor] = jqMatch[1].split('.').map(Number);
            if (major < 3 || (major === 3 && minor < 6)) {
                issues.push(`Outdated jQuery version detected: ${jqMatch[1]} — known XSS vulnerabilities`);
            }
        }

        const boostrapMatch = res.body.match(/bootstrap[^"']*["']([0-9]+\.[0-9]+\.[0-9]+)/i);
        if (boostrapMatch) {
            const [major] = boostrapMatch[1].split('.').map(Number);
            if (major < 4) {
                issues.push(`Outdated Bootstrap version: ${boostrapMatch[1]}`);
            }
        }
    }

    return {
        owaspId: 'A06:2021',
        name: 'Vulnerable & Outdated Components',
        vulnerable: issues.length > 0,
        severity: issues.some((i) => i.includes('End-of-life') || i.includes('XSS')) ? 'High' : issues.length > 0 ? 'Medium' : 'Low',
        issues,
        description: issues.length > 0
            ? 'Outdated or potentially vulnerable components detected via server headers or client-side libraries.'
            : 'No obviously outdated components detected.',
        recommendation: 'Regularly update all dependencies. Use tools like npm audit, Dependabot, or OWASP Dependency-Check.',
        evidence: issues.join('; ') || 'No outdated component signatures detected',
    };
}

// ── 10. Insufficient Logging & Monitoring ──────────────────────────────────────
async function checkInsufficientLogging(targetUrl) {
    const issues = [];
    const res = await httpGet(targetUrl);

    if (res.headers) {
        const get = (h) => res.headers.get ? res.headers.get(h) : res.headers[h];
        if (!get('report-to') && !get('nel')) {
            issues.push('No Network Error Logging (NEL) or Report-To headers — network errors not being monitored');
        }
        if (!get('content-security-policy') || !/report-uri|report-to/i.test(get('content-security-policy') || '')) {
            issues.push('CSP has no report-uri/report-to — CSP violations not being logged');
        }
    }

    // Try 404 to see if errors are verbose
    const errRes = await httpGet(`${targetUrl}/this-page-definitely-does-not-exist-12345`);
    if (errRes.body) {
        const debugPatterns = [/stack trace/i, /at Object\./i, /Error:/i, /Exception/i, /line \d+/i];
        if (debugPatterns.some((p) => p.test(errRes.body))) {
            issues.push('Stack traces or exception details exposed in error responses');
        }
    }

    return {
        owaspId: 'A09:2021',
        name: 'Insufficient Logging & Monitoring',
        vulnerable: issues.length > 0,
        severity: issues.some((i) => i.includes('Stack trace')) ? 'High' : issues.length > 0 ? 'Medium' : 'Informational',
        issues,
        description: issues.length > 0
            ? 'Insufficient logging, monitoring, or error handling configuration detected.'
            : 'Basic logging indicators appear present.',
        recommendation: 'Implement centralized logging, set up alerts for anomalies, configure CSP reporting, and sanitize error messages.',
        evidence: issues.join('; ') || 'No excessive error disclosure detected',
    };
}

// ── 11. Semantic Business Logic & Stealth Leak Detection (AI-Powered) ────────
async function checkSemanticLeakage(targetUrl) {
    const issues = [];
    const res = await httpGet(targetUrl);

    if (!res.body) {
        return {
            owaspId: 'A04:2021', // Insecure Design / Business Logic
            name: 'Semantic Information Disclosure',
            vulnerable: false,
            severity: 'Low',
            issues: [],
            description: 'AI Semantic scanner skipped due to empty response.',
            recommendation: 'N/A',
            evidence: 'No response body',
        };
    }

    // Extract a chunk of the HTML/JS for Ollama to analyze (to avoid token limits)
    // We prioritize <head>, inline <script> tags, and HTML comments
    const headMatch = res.body.match(/<head>[\s\S]*?<\/head>/i);
    const scriptsMatch = [...res.body.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/gi)].map(m => m[1]).join('\n').slice(0, 2000);
    const commentsMatch = [...res.body.matchAll(/<!--([\s\S]*?)-->/g)].map(m => m[1]).join('\n').slice(0, 1000);

    const contextChunk = `
HTML Comments:
${commentsMatch}

Scripts snippet:
${scriptsMatch}
  `.trim();

    if (contextChunk.length > 50) {
        console.log(`[Semantic Analysis] Forwarding DOM chunk to AI for context analysis...`);
        const aiReview = await generateAiResponse(`
      You are an elite penetration tester looking for semantic information leaks and business logic clues in raw web source code.
      Analyze the following HTML comments and inline JavaScript snippets from a web application.
      Identify any of the following:
      1. Developer comments mentioning "TODO", "FIXME", "hack", or internal complaints/bugs.
      2. Mentions of internal dev/staging URLs, private IP addresses, or network names.
      3. Hardcoded authorization logic (e.g., "if (role === 'admin')").
      
      Respond directly with ONLY a bulleted list of any critical findings. If you find absolutely nothing suspicious, reply with the exact phrase "NO_LEAKS_FOUND".
      
      Input Data:
      ${contextChunk}
    `);

        if (aiReview && !aiReview.includes('NO_LEAKS_FOUND') && aiReview.length > 15) {
            issues.push(`AI Semantic Analyzer detected in-code leaks:\n${aiReview}`);
        }
    }

    return {
        owaspId: 'A04:2021',
        name: 'Semantic Info Disclosure (AI)',
        vulnerable: issues.length > 0,
        severity: issues.length > 0 ? 'Medium' : 'Low',
        issues,
        description: issues.length > 0
            ? 'The AI detected semantic information disclosure in page source (e.g. developer comments, inner logic).'
            : 'No obvious semantic leaks detected by AI.',
        recommendation: 'Remove developer comments from production builds. Obfuscate or remove client-side enforcement of authorization logic.',
        evidence: issues.join('\n') || 'No semantic leaks detected',
    };
}

// ── Helper: Infer Tech Stack for Auto-Patching ──────────────────────────────────
function inferTechStack(resHeaders, body) {
    let stack = ['Generic Web App'];
    if (!resHeaders) return stack;

    const get = (h) => resHeaders.get ? resHeaders.get(h) : resHeaders[h];
    const server = get('server') || '';
    const xPowered = get('x-powered-by') || '';

    if (/Express/i.test(xPowered)) stack.push('Node.js / Express');
    else if (/PHP/i.test(xPowered) || /PHP/.test(server)) stack.push('PHP');
    else if (/ASP\.NET/.test(xPowered)) stack.push('.NET / C#');

    if (/nginx/i.test(server)) stack.push('Nginx');
    else if (/apache/i.test(server)) stack.push('Apache');

    return stack;
}

// ── Main orchestrator ──────────────────────────────────────────────────────────
async function runOWASPScan(targetUrl, onProgress) {
    const checks = [
        checkInjection,
        checkBrokenAuth,
        checkSensitiveDataExposure,
        checkXXE,
        checkBrokenAccessControl,
        checkSecurityMisconfiguration,
        checkXSS,
        checkInsecureDeserialization,
        checkKnownVulnerableComponents,
        checkInsufficientLogging,
        checkSemanticLeakage,
    ];

    const results = [];

    // Hit root URL once to identify stack for auto-patching
    const rootRes = await httpGet(targetUrl);
    const techStack = inferTechStack(rootRes.headers, rootRes.body);
    console.log(`[Scan Initialized] Inferred Tech Stack: ${techStack.join(', ')}`);

    for (let i = 0; i < checks.length; i++) {
        const progress = Math.round(((i + 1) / checks.length) * 90); // 0–90%, AI uses 90–100%
        if (onProgress) onProgress(progress);
        try {
            const result = await checks[i](targetUrl);
            results.push(result);
        } catch (err) {
            console.error(`Check ${i + 1} failed:`, err.message);
            results.push({
                owaspId: 'N/A',
                name: `Check ${i + 1} (${checks[i].name})`,
                vulnerable: false,
                severity: 'Informational',
                issues: [`Check failed: ${err.message}`],
                description: 'Unable to complete this check.',
                recommendation: 'Manual review recommended.',
                evidence: err.message,
            });
        }
    }

    return { results, techStack };
}

module.exports = { runOWASPScan };
