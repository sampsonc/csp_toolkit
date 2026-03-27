/**
 * Popup script — renders CSP analysis results when the user clicks the badge.
 */

const GRADE_CLASS = {
  "A+": "grade-A-plus",
  "A": "grade-A",
  "B": "grade-B",
  "C": "grade-C",
  "D": "grade-D",
  "F": "grade-F",
  "-": "grade-none",
};

const SEV_CLASS = {
  critical: "sev-critical",
  high: "sev-high",
  medium: "sev-medium",
  low: "sev-low",
  info: "sev-info",
};

const SEV_LABEL = {
  critical: "CRIT",
  high: "HIGH",
  medium: "MED",
  low: "LOW",
  info: "INFO",
};

function render(data) {
  const el = document.getElementById("content");

  if (!data) {
    el.innerHTML = `
      <div class="no-csp">
        <div class="emoji">&#128270;</div>
        <div>Navigate to a page to analyze its CSP.</div>
      </div>`;
    return;
  }

  const { url, cspHeader, cspRoHeader, analysis } = data;
  const { grade, score, findings, directives } = analysis;

  if (!cspHeader && !cspRoHeader) {
    el.innerHTML = `
      <div class="header">
        <div class="grade-badge grade-none">-</div>
        <div class="header-info">
          <div class="score">No CSP</div>
          <div class="url">${escapeHtml(url)}</div>
        </div>
      </div>
      <div class="no-csp">
        This page has no Content-Security-Policy header.
      </div>`;
    return;
  }

  const gradeClass = GRADE_CLASS[grade] || "grade-none";
  const mode = cspHeader ? "Enforced" : "Report-Only";

  // Count severities
  const counts = {};
  for (const f of findings) {
    counts[f.severity] = (counts[f.severity] || 0) + 1;
  }

  let html = `
    <div class="header">
      <div class="grade-badge ${gradeClass}">${grade}</div>
      <div class="header-info">
        <div class="score">${score}/100 &middot; ${mode} &middot; ${findings.length} findings</div>
        <div class="url">${escapeHtml(url)}</div>
      </div>
    </div>`;

  // Severity counts
  if (findings.length > 0) {
    html += `<div class="section"><div class="counts">`;
    for (const sev of ["critical", "high", "medium", "low", "info"]) {
      if (counts[sev]) {
        html += `<span class="count-chip"><span class="sev ${SEV_CLASS[sev]}">${SEV_LABEL[sev]}</span> ${counts[sev]}</span>`;
      }
    }
    html += `</div></div>`;
  }

  // Findings list
  if (findings.length > 0) {
    html += `<div class="section"><div class="section-title">Findings</div>`;
    for (const f of findings) {
      const dirTag = f.directive ? `<span class="directive-tag">${escapeHtml(f.directive)}</span>` : "";
      html += `
        <div class="finding">
          <span class="sev ${SEV_CLASS[f.severity]}">${SEV_LABEL[f.severity]}</span>
          <span class="finding-title">${escapeHtml(f.title)}${dirTag}</span>
        </div>`;
    }
    html += `</div>`;
  }

  // Raw CSP
  const rawCsp = cspHeader || cspRoHeader;
  html += `
    <div class="section">
      <div class="section-title">Raw CSP</div>
      <div class="raw-csp">${escapeHtml(rawCsp)}</div>
    </div>`;

  el.innerHTML = html;
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

// Request data from background
chrome.runtime.sendMessage({ type: "getTabData" }, render);
