/**
 * CSP Analyzer — pure JS implementation of the core analysis logic.
 * Runs in the browser extension context (no Python dependency).
 */

const KEYWORDS = new Set([
  "'self'", "'none'", "'unsafe-inline'", "'unsafe-eval'",
  "'strict-dynamic'", "'unsafe-hashes'", "'unsafe-allow-redirects'",
  "'report-sample'", "'wasm-unsafe-eval'", "'inline-speculation-rules'",
]);

const SCHEMES = new Set(["https:", "http:", "data:", "blob:", "mediastream:", "filesystem:"]);

const FETCH_DIRECTIVES = new Set([
  "script-src", "script-src-elem", "script-src-attr",
  "style-src", "style-src-elem", "style-src-attr",
  "img-src", "font-src", "connect-src", "media-src",
  "object-src", "prefetch-src", "child-src", "frame-src",
  "worker-src", "manifest-src",
]);

const BROAD_DOMAINS = new Set([
  "*.googleapis.com", "*.gstatic.com", "*.google.com",
  "*.cloudflare.com", "*.amazonaws.com", "*.azurewebsites.net",
  "*.herokuapp.com", "*.firebaseapp.com", "*.cloudfront.net", "*.akamaihd.net",
]);

const ARBITRARY_HOSTING = new Set([
  "raw.githubusercontent.com", "cdn.rawgit.com", "rawgit.com",
  "gist.githubusercontent.com", "pastebin.com", "codepen.io",
  "jsfiddle.net", "plnkr.co", "surge.sh", "netlify.app",
  "vercel.app", "pages.dev", "workers.dev", "web.app", "firebaseapp.com",
]);

const SEVERITY_WEIGHT = { critical: 30, high: 15, medium: 5, low: 2, info: 0 };

function parseCSP(header) {
  const directives = {};
  if (!header || !header.trim()) return directives;

  for (const raw of header.split(";")) {
    const trimmed = raw.trim();
    if (!trimmed) continue;
    const tokens = trimmed.split(/\s+/);
    const name = tokens[0].toLowerCase();
    if (!(name in directives)) {
      directives[name] = tokens.slice(1);
    }
  }
  return directives;
}

function effectiveSources(directives, name) {
  if (directives[name]) return directives[name];
  if (FETCH_DIRECTIVES.has(name) && directives["default-src"]) return directives["default-src"];
  return [];
}

function hasSrc(sources, value) {
  return sources.some(s => s.toLowerCase() === value.toLowerCase());
}

function analyzeCSP(header, reportOnly = false) {
  const directives = parseCSP(header);
  const findings = [];

  if (Object.keys(directives).length === 0) return { findings, grade: "-", score: 0, directives };

  const scriptSrcs = effectiveSources(directives, "script-src");

  // No script-src or default-src
  if (!directives["script-src"] && !directives["default-src"]) {
    findings.push({ severity: "critical", title: "No script-src or default-src", directive: null });
  }

  // unsafe-inline in script-src
  if (hasSrc(scriptSrcs, "'unsafe-inline'")) {
    const hasNonce = scriptSrcs.some(s => s.match(/^'nonce-/i));
    const hasHash = scriptSrcs.some(s => s.match(/^'sha(256|384|512)-/i));
    if (hasNonce || hasHash) {
      findings.push({ severity: "medium", title: "'unsafe-inline' + nonce/hash (CSP2 downgrade)", directive: "script-src" });
    } else {
      findings.push({ severity: "critical", title: "'unsafe-inline' allows inline scripts", directive: "script-src" });
    }
  }

  // data: in script-src
  if (hasSrc(scriptSrcs, "data:")) {
    findings.push({ severity: "critical", title: "data: URI in script-src", directive: "script-src" });
  }

  // unsafe-eval
  if (hasSrc(scriptSrcs, "'unsafe-eval'")) {
    findings.push({ severity: "high", title: "'unsafe-eval' allows eval()", directive: "script-src" });
  }

  // https: scheme
  if (hasSrc(scriptSrcs, "https:")) {
    findings.push({ severity: "high", title: "https: allows any HTTPS origin", directive: "script-src" });
  }

  // Wildcard
  if (hasSrc(scriptSrcs, "*")) {
    findings.push({ severity: "high", title: "Wildcard * in script-src", directive: "script-src" });
  }

  // blob:
  if (hasSrc(scriptSrcs, "blob:")) {
    findings.push({ severity: "high", title: "blob: URI in script-src", directive: "script-src" });
  }

  // Missing object-src
  const objSrcs = effectiveSources(directives, "object-src");
  if (objSrcs.length === 0 && !directives["object-src"]) {
    findings.push({ severity: "high", title: "Missing object-src", directive: null });
  } else if (!hasSrc(objSrcs, "'none'")) {
    findings.push({ severity: "medium", title: "object-src not 'none'", directive: "object-src" });
  }

  // strict-dynamic without nonce/hash
  if (hasSrc(scriptSrcs, "'strict-dynamic'")) {
    const hasNonce = scriptSrcs.some(s => s.match(/^'nonce-/i));
    const hasHash = scriptSrcs.some(s => s.match(/^'sha(256|384|512)-/i));
    if (!hasNonce && !hasHash) {
      findings.push({ severity: "high", title: "'strict-dynamic' without nonce/hash", directive: "script-src" });
    }
  }

  // Missing directives
  if (!directives["base-uri"]) {
    findings.push({ severity: "medium", title: "Missing base-uri", directive: null });
  }
  if (!directives["form-action"]) {
    findings.push({ severity: "medium", title: "Missing form-action", directive: null });
  }
  if (!directives["frame-ancestors"]) {
    findings.push({ severity: "medium", title: "Missing frame-ancestors", directive: null });
  }

  // Broad domains
  for (const src of scriptSrcs) {
    if (BROAD_DOMAINS.has(src.toLowerCase())) {
      findings.push({ severity: "medium", title: `Broad domain: ${src}`, directive: "script-src" });
    }
  }

  // Arbitrary hosting
  for (const src of scriptSrcs) {
    const host = src.toLowerCase().replace(/^https?:\/\//, "").split(":")[0];
    if (ARBITRARY_HOSTING.has(host)) {
      findings.push({ severity: "critical", title: `Arbitrary hosting: ${host}`, directive: "script-src" });
    }
  }

  // Report-only
  if (reportOnly) {
    findings.push({ severity: "info", title: "Report-Only (not enforced)", directive: null });
  }

  // Score
  const penalty = findings.reduce((sum, f) => sum + (SEVERITY_WEIGHT[f.severity] || 0), 0);
  const score = Math.max(0, 100 - penalty);
  let grade;
  if (score >= 95) grade = "A+";
  else if (score >= 90) grade = "A";
  else if (score >= 80) grade = "B";
  else if (score >= 70) grade = "C";
  else if (score >= 50) grade = "D";
  else grade = "F";

  // Sort by severity
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  findings.sort((a, b) => order[a.severity] - order[b.severity]);

  return { findings, grade, score, directives };
}

// Export for use in other extension scripts
if (typeof globalThis !== "undefined") {
  globalThis.cspAnalyzer = { parseCSP, analyzeCSP };
}
