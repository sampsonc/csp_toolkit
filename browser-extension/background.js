/**
 * Background service worker — captures CSP headers from responses
 * and updates the extension badge with the policy grade.
 */

importScripts("csp-analyzer.js");

// Store CSP data per tab
const tabData = {};

const GRADE_COLORS = {
  "A+": "#22c55e",
  "A":  "#22c55e",
  "B":  "#eab308",
  "C":  "#f97316",
  "D":  "#ef4444",
  "F":  "#dc2626",
  "-":  "#6b7280",
};

const GRADE_BG = {
  "A+": [34, 197, 94, 255],
  "A":  [34, 197, 94, 255],
  "B":  [234, 179, 8, 255],
  "C":  [249, 115, 22, 255],
  "D":  [239, 68, 68, 255],
  "F":  [220, 38, 38, 255],
  "-":  [107, 114, 128, 255],
};

// Listen for response headers on main frame navigation
chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (details.type !== "main_frame") return;

    const tabId = details.tabId;
    if (tabId < 0) return;

    let cspHeader = null;
    let cspRoHeader = null;

    for (const header of details.responseHeaders || []) {
      const name = header.name.toLowerCase();
      if (name === "content-security-policy") {
        cspHeader = header.value;
      } else if (name === "content-security-policy-report-only") {
        cspRoHeader = header.value;
      }
    }

    // Analyze the enforced policy (preferred) or report-only
    const headerToAnalyze = cspHeader || cspRoHeader;
    const isReportOnly = !cspHeader && !!cspRoHeader;

    let result;
    if (headerToAnalyze) {
      result = cspAnalyzer.analyzeCSP(headerToAnalyze, isReportOnly);
    } else {
      result = { findings: [], grade: "-", score: 0, directives: {} };
    }

    tabData[tabId] = {
      url: details.url,
      cspHeader,
      cspRoHeader,
      analysis: result,
      timestamp: Date.now(),
    };

    // Update badge
    const grade = result.grade;
    const bg = GRADE_BG[grade] || GRADE_BG["-"];
    chrome.action.setBadgeText({ tabId, text: grade });
    chrome.action.setBadgeBackgroundColor({ tabId, color: bg });
    chrome.action.setTitle({
      tabId,
      title: `CSP: ${grade} (${result.score}/100) — ${result.findings.length} findings`,
    });
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);

// Clean up when tabs close
chrome.tabs.onRemoved.addListener((tabId) => {
  delete tabData[tabId];
});

// Provide data to popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "getTabData") {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]) {
        sendResponse(tabData[tabs[0].id] || null);
      } else {
        sendResponse(null);
      }
    });
    return true; // async response
  }
});
