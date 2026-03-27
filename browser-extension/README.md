# CSP Toolkit Browser Extension

Chrome extension that shows a CSP grade badge on every page you visit.

## Features

- Captures CSP headers from every page navigation
- Grades policies A+ to F with a colored badge in the toolbar
- Click the badge to see:
  - Score (0-100) and grade
  - Severity-sorted findings list
  - Raw CSP header
- Distinguishes enforced vs report-only policies
- Zero network requests — all analysis runs locally in the browser

## Install (Developer Mode)

1. Open `chrome://extensions/` in Chrome
2. Enable "Developer mode" (top right toggle)
3. Click "Load unpacked"
4. Select this `browser-extension/` directory
5. Navigate to any page — the badge shows the CSP grade

## Icons

Placeholder icons are included. To generate nicer ones, open `icons/generate-icons.html` in a browser and save the canvases as PNGs.

## How It Works

- `background.js` — Service worker that listens to `webRequest.onHeadersReceived`, captures CSP headers, runs analysis, and sets the badge text/color
- `csp-analyzer.js` — Pure JS port of the core analysis logic (no Python dependency)
- `popup.html` / `popup.js` — Renders the analysis results when the badge is clicked
