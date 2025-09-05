# Triad: The Ultimate Recon & Mapping Tool for Bug Bounty Hunters

![Triad Banner](https://img.shields.io/badge/Bug%20Bounty-Ultimate%20Recon%20Tool-green?style=for-the-badge)

Triad is a powerful, modular, and extensible toolkit for bug bounty hunters and security researchers. It automates reconnaissance, JavaScript analysis, DOM mapping, reflection, sink, vulnerability, sanitization, and special character checks—giving you a comprehensive edge in your web security assessments.

---

## 🚀 Features

- **Automated Reconnaissance**: Passive & active recon with subdomain and JS link discovery.
- **Advanced JavaScript Extraction**: Regex-based sensitive data hunting in JS files.
- **DOM & Functionality Mapping**: Deep enumeration of forms, inputs, endpoints, and more.
- **Reflection & Sink Analysis**: Automated checks for reflected input and XSS sinks.
- **Vulnerability & Sanitization Testing**: Detects XSS, SQLi, CSRF, and input sanitization issues.
- **Special Character Fuzzing**: Finds bypasses and weak input filters.
- **WAF & Proxy Support**: Detects WAFs and supports proxying and authenticated sessions.
- **Robust Error Handling**: Retries, logging, and schema validation for reliability.
- **Extensible Patterns**: Easily add new sensitive data patterns and DOM features.

---

## 🛠️ Installation

1. **Clone the repo:**

   ```bash
   git clone https://github.com/LifeJiggy/Script-Combo.git
   cd Script-Combo
   ```

2. **Install Python dependencies:**

   ```bash
   pip install -r requirements.txt
   ```

3. **Install Node.js dependencies:**

   ```bash
   npm install puppeteer puppeteer-extra puppeteer-extra-plugin-stealth node-fetch abort-controller
   ```

---

## ⚡ Usage

```bash
python Triad.py
```

- Interactive CLI guides you through target selection, phase selection, and configuration.
- Supports recon, regex, and mapping phases.
- Output is saved in structured JSON files for each phase.

---

## 📸 Example Workflow

1. **Recon**:  
   Discover subdomains and JS links.
2. **Regex**:  
   Extract sensitive data from selected JS files.
3. **Mapping**:  
   Enumerate forms, inputs, endpoints, and test for reflection, sinks, vulnerabilities, sanitization, and special character handling.

---

## 📝 Output

- All results are saved in the `output/` directory, organized by target and timestamp.
- Each phase (recon, regex, enumerate, reflection, sinks, vulnerable, sanitization, characters) has its own JSON file.

---

## 📖 JavaScript Extraction & Mapping (`js_extract.js`)

`js_extract.js` is a Node.js script for advanced JavaScript and DOM analysis. It supports multiple modes for extracting sensitive data, mapping user-facing functionality, and testing for common web vulnerabilities.

### Modes

- **enumerate**: Deeply maps forms, inputs, endpoints, and user functionality in the DOM. Crawls links and outputs a comprehensive JSON map.
- **regex**: Downloads and scans JavaScript files for sensitive data using advanced regex patterns. Outputs all findings to JSON.
- **reflection**: Tests if user input is reflected in the DOM (potential XSS vectors).
- **sinks**: Checks for the presence of dangerous JavaScript sinks (e.g., `eval`, `innerHTML`).
- **vulnerable**: Attempts to detect XSS, SQLi, CSRF, and open redirect vulnerabilities by injecting payloads.
- **sanitization**: Tests input fields for sanitization/encoding of special characters.
- **characters**: Fuzzes input fields with special characters to find weak filters or bypasses.

### Usage

```bash
node js_extract.js <url> <outputDir> <mode> [jsLinks] [headers] [userAgents] [crawlDepth] [threads] [delay] [loginCreds] [selections]
```

- `<url>`: Target URL to analyze
- `<outputDir>`: Directory to save output JSON files
- `<mode>`: One of `enumerate`, `regex`, `reflection`, `sinks`, `vulnerable`, `sanitization`, `characters`
- `[jsLinks]`: (regex mode) Comma-separated JS URLs to scan
- `[headers]`: JSON array of HTTP headers
- `[userAgents]`: JSON array of user-agent strings
- `[crawlDepth]`: Max number of links to crawl (default: 10)
- `[threads]`: Number of concurrent fetches (default: 10)
- `[delay]`: Delay between requests in seconds (default: 5)
- `[loginCreds]`: JSON object with login credentials and/or proxy
- `[selections]`: JSON array of selected functionalities (for advanced modes)

#### Example: Enumerate DOM Functionality

```bash
node js_extract.js https://target.com ./output enumerate
```

#### Example: Extract Sensitive Data from JS Files

```bash
node js_extract.js https://target.com ./output regex "https://target.com/app.js,https://target.com/main.js"
```

#### Example: Reflection Testing

```bash
node js_extract.js https://target.com ./output reflection
```

### Output

- **enumerate.json**: Map of all detected forms, inputs, endpoints, and user features.
- **js_data.json**: All sensitive data findings from JS files (regex mode).
- **reflection.json**: Reflected input findings.
- **sinks.json**: Detected dangerous JS sinks.
- **vulnerable.json**: Vulnerability findings (XSS, SQLi, CSRF, redirects).
- **sanitization.json**: Input sanitization test results.
- **characters.json**: Special character fuzzing results.
- **error.log**: All errors and context for troubleshooting.

### Extending Patterns

- To add new sensitive data patterns, edit the `sensitivePatterns` array in `js_extract.js`.
- To add new user functionality mappings, update the `userFunctionalities` array and DOM extraction logic.

### Notes

- Requires Node.js 14+ and Chrome/Chromium (handled by Puppeteer).
- Supports proxies and authenticated sessions via `loginCreds`.
- Robust error handling and logging for reliability.

---

## 🛡️ Disclaimer

This tool is for educational and authorized security testing only.  
**Do not use against systems without permission.**

---

## 👤 Author

- **ArkhAngelLifeJiggy**  
  [X (Twitter)](https://x.com/ArkhLifeJiggy) | [GitHub](https://github.com/LifeJiggy)

---

## ⭐ Star this repo if you find it useful!
