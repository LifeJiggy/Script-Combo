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

4. **(Windows only)**:  
   Install [Git Bash](https://gitforwindows.org/) for bash-based recon scripts.

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
## 🛡️ Disclaimer

This tool is for educational and authorized security testing only.  
**Do not use against systems without permission.**

---

## 👤 Author

- **ArkhAngelLifeJiggy**  
  [X (Twitter)](https://x.com/ArkhLifeJiggy) | [GitHub](https://github.com/LifeJiggy)

---

## ⭐ Star this repo if you find it useful!
