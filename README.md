# SiteScanner

SiteScanner is a simple browser extension that scans the currently open webpage for common security issues and surface-level vulnerabilities. It provides a popup UI and uses a content script to inspect page content and a background script for orchestration.

**Features**
- Quick scan for known patterns and insecure constructs (implemented in `vulnerabilities.js`).
- Popup UI for starting scans and viewing results (`popup.html`, `popup.js`, `popup.css`).
- Content script injection to inspect DOM and page resources (`content.js`).
- Background script for handling extension lifecycle and messaging (`background.js`).

**Files**
- `manifest.json` — extension manifest and permissions.
- `background.js` — background/service worker script.
- `content.js` — content script that runs on pages.
- `popup.html`, `popup.js`, `popup.css` — extension popup UI.
- `vulnerabilities.js` — vulnerability detection rules and helpers.
- `icons/` — extension icons.

**Installation (developer / local testing)**
1. Open your browser's extensions page (e.g., `chrome://extensions/` or `edge://extensions/`).
2. Enable Developer mode.
3. Click "Load unpacked" and select the repository folder containing this extension.
4. The extension will appear in the toolbar; click the icon to open the popup and run scans.

**Usage**
- Open any webpage you want to inspect.
- Click the extension icon to open the popup.
- Use the popup controls to start a scan. Results will display in the popup UI.

**Development**
- Make code changes in the corresponding files listed above.
- Use the browser extension console (background and content script consoles) for debugging.
- Keep `manifest.json` permissions minimal while developing; add only what the extension requires.

**Contributing**
- Open issues or pull requests with clear descriptions and tests/examples when possible.

**License**
This project is provided under the MIT License. See the LICENSE file if provided.
