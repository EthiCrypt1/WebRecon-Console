(function() {
  const STORAGE_KEY = '__recon_data_' + location.hostname;

  // Load existing data if this site already has some (persists across page loads)
  let existing = [];
  try {
    const saved = sessionStorage.getItem(STORAGE_KEY);
    if (saved) existing = JSON.parse(saved);
  } catch (e) {}

  window.__recon = {
    requests: existing,
    origin: location.origin
  };

  function persist() {
    try {
      sessionStorage.setItem(STORAGE_KEY, JSON.stringify(window.__recon.requests));
    } catch (e) {
      // sessionStorage full — trim oldest entries
      window.__recon.requests = window.__recon.requests.slice(-200);
    }
  }

  function safeBody(body) {
    if (body === null || body === undefined) return null;
    if (typeof body === 'string') return body;
    if (body instanceof URLSearchParams) return body.toString();
    if (body instanceof FormData) {
      const obj = {};
      for (const [k, v] of body.entries()) obj[k] = (v instanceof File ? `[File: ${v.name}]` : v);
      return obj;
    }
    if (body instanceof Blob) return `[Blob: ${body.size} bytes]`;
    if (body instanceof ArrayBuffer || ArrayBuffer.isView(body)) return `[Binary: ${body.byteLength || body.length} bytes]`;
    if (typeof body === 'object') return body;
    return String(body);
  }

  // ---- Hook fetch ----
  const _fetch = window.fetch;
  window.fetch = function(...args) {
    try {
      const url = typeof args[0] === 'string' ? args[0] : args[0]?.url;
      const options = args[1] || {};
      window.__recon.requests.push({
        page: location.pathname,
        type: 'fetch',
        method: options.method || 'GET',
        url: url,
        body: safeBody(options.body),
        time: new Date().toISOString()
      });
      persist();
    } catch (e) {}
    return _fetch.apply(this, args);
  };

  // ---- Hook XHR ----
  const _open = XMLHttpRequest.prototype.open;
  const _send = XMLHttpRequest.prototype.send;

  XMLHttpRequest.prototype.open = function(method, url) {
    this.__method = method;
    this.__url = url;
    return _open.apply(this, arguments);
  };

  XMLHttpRequest.prototype.send = function(body) {
    try {
      window.__recon.requests.push({
        page: location.pathname,
        type: 'xhr',
        method: this.__method,
        url: this.__url,
        body: safeBody(body),
        time: new Date().toISOString()
      });
      persist();
    } catch (e) {}
    return _send.apply(this, arguments);
  };

  console.log(`%c[+] Recon active on ${location.pathname}. Total captured so far: ${window.__recon.requests.length}`, 'color: lime; font-weight: bold;');
  console.log('%c[!] Re-paste this script after every login/navigation to keep capturing.', 'color: orange;');
})();

// ---- Auto-scroll to trigger lazy-loaded requests ----
async function autoScroll() {
  console.log('[+] Auto-scrolling...');
  let lastHeight = 0;
  for (let i = 0; i < 30; i++) {
    window.scrollBy(0, 400);
    await new Promise(r => setTimeout(r, 300));
    if (document.body.scrollHeight === lastHeight) break;
    lastHeight = document.body.scrollHeight;
  }
  window.scrollTo(0, 0);
  console.log('[+] Done scrolling.');
}

// ---- Security checks ----
function checkStorageAndCookies() {
  const findings = {};
  findings.jsReadableCookies = document.cookie ? document.cookie.split(';').map(c => c.trim().split('=')[0]) : [];
  findings.localStorage = { ...localStorage };
  findings.sessionStorage = { ...sessionStorage };

  const sensitivePattern = /token|key|secret|auth|session|jwt|password|api/i;
  findings.suspiciousStorageKeys = [
    ...Object.keys(localStorage).filter(k => sensitivePattern.test(k)),
    ...Object.keys(sessionStorage).filter(k => sensitivePattern.test(k))
  ];

  findings.mixedContent = [];
  if (location.protocol === 'https:') {
    document.querySelectorAll('script[src], link[href], img[src], iframe[src]').forEach(el => {
      const src = el.src || el.href;
      if (src && src.startsWith('http://')) findings.mixedContent.push(src);
    });
  }
  return findings;
}

// ---- Summarize endpoints + params ----
function summarizeEndpoints() {
  const summary = {};
  window.__recon.requests.forEach(entry => {
    try {
      const u = new URL(entry.url, location.origin);
      const key = `${entry.method} ${u.origin}${u.pathname}`;
      if (!summary[key]) summary[key] = { queryParams: new Set(), bodyParams: new Set(), seenOnPages: new Set() };

      u.searchParams.forEach((_, k) => summary[key].queryParams.add(k));
      summary[key].seenOnPages.add(entry.page || '?');

      if (entry.body && typeof entry.body === 'object' && !Array.isArray(entry.body)) {
        Object.keys(entry.body).forEach(k => summary[key].bodyParams.add(k));
      } else if (typeof entry.body === 'string') {
        try {
          const parsed = JSON.parse(entry.body);
          if (parsed && typeof parsed === 'object') Object.keys(parsed).forEach(k => summary[key].bodyParams.add(k));
        } catch {
          new URLSearchParams(entry.body).forEach((_, k) => summary[key].bodyParams.add(k));
        }
      }
    } catch (e) {}
  });

  const output = {};
  for (const key in summary) {
    output[key] = {
      queryParams: [...summary[key].queryParams],
      bodyParams: [...summary[key].bodyParams],
      seenOnPages: [...summary[key].seenOnPages]
    };
  }
  return output;
}

function filterNoise(requests) {
  const noisePatterns = /clarity\.ms|google-analytics|doubleclick|hubspot|hs-analytics|facebook\.com\/tr|gtm\.js|googletagmanager|bing|linkedin\.com\/px|snapchat|reddit\.com\/api|twitter\.com\/i\/adsct|sentry\.io|segment\.(io|com)/i;
  return requests.filter(r => !noisePatterns.test(r.url));
}

// ---- Generate + download report ----
function reconReport() {
  const cleanRequests = filterNoise(window.__recon.requests);

  const report = {
    target: location.origin,
    generatedAt: new Date().toISOString(),
    totalRequestsCaptured: window.__recon.requests.length,
    applicationRequests: cleanRequests.length,
    endpoints: summarizeEndpoints(),
    likelyApplicationRequests: cleanRequests,
    rawRequests: window.__recon.requests,
    securityChecks: checkStorageAndCookies(),
    notes: [
      "jsReadableCookies = cookies visible to JS (i.e. NOT HttpOnly). Verify actual HttpOnly cookies in Application tab.",
      "Security headers (CSP, X-Frame-Options, HSTS) are NOT visible to JS — check Network tab/HAR.",
      "Data persists across page reloads via sessionStorage for this hostname, but hooks must be re-pasted on each new page load.",
      "Run clearReconData() to start fresh for a new testing session."
    ]
  };

  console.log(report);

  const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `recon_${location.hostname}_${Date.now()}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);

  console.log(`%c[+] Report downloaded: ${report.totalRequestsCaptured} total, ${report.applicationRequests} likely app requests across ${new Set(window.__recon.requests.map(r => r.page)).size} pages.`, 'color: lime; font-weight: bold;');
}

// ---- Reset for a new target/session ----
function clearReconData() {
  sessionStorage.removeItem('__recon_data_' + location.hostname);
  window.__recon.requests = [];
  console.log('[+] Recon data cleared for this session.');
}