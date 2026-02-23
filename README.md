# SAYARI VAPT Scanner
## Project Introduction
================================================================================
   ███████╗ █████╗ ██╗   ██╗ █████╗ ██████╗ ██╗
   ██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗██╔══██╗██║
   ███████╗███████║ ╚████╔╝ ███████║██████╔╝██║
   ╚════██║██╔══██║  ╚██╔╝  ██╔══██║██╔══██╗██║
   ███████║██║  ██║   ██║   ██║  ██║██║  ██║██║
   ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝
================================================================================
  Vulnerability Assesment and Penetration Testing (VAPT) Scanner
  Created by Dr3amy | For Authorized Use Only
================================================================================

A comprehensive, all-in-one Vulnerability Assessment and Penetration Testing (VAPT) scanner written in Python. This tool automates the detection of security misconfigurations and common web vulnerabilities, generating professional reports with risk scores and interactive charts.

---

## Disclaimer

**This tool is intended for authorized security testing only.**

Unauthorized use against systems you do not own or have explicit permission to test is illegal. The author assumes no liability and is not responsible for any misuse or damage caused by this program. By using this tool, you agree to use it responsibly and ethically.

---

## Features

The scanner performs a wide range of checks to identify security weaknesses:

### Vulnerability Detection
* **SQL Injection (SQLi):** Detects error-based and basic SQL injection vulnerabilities via URL parameters and forms.
* **Cross-Site Scripting (XSS):** Checks for reflected XSS in parameters and form inputs.
* **Directory Traversal (LFI):** Tests for Local File Inclusion using various encoding bypass techniques.
* **Open Redirect:** Identifies URL redirection vulnerabilities that could facilitate phishing.
* **Sensitive File Exposure:** Scans for exposed configuration files (`.env`, `.git`, `web.config`), backups, and logs.

### Configuration & Headers
* **Security Headers Analysis:** Checks for missing headers (`CSP`, `X-Frame-Options`, `HSTS`, etc.).
* **SSL/TLS Analysis:** Validates certificate expiration, weak protocols (TLS 1.0/1.1), and weak signature algorithms.
* **CORS Misconfiguration:** Tests for overly permissive Cross-Origin Resource Sharing policies.
* **Clickjacking:** Checks if the site can be framed by external domains.
* **Cookie Security:** Analyzes cookies for missing `Secure`, `HttpOnly`, and `SameSite` attributes.

### Reporting
* **Interactive HTML Reports:** Generates a modern, dark-themed dashboard with :contentReference[oaicite:0]{index=0} visualizations.
* **JSON Reports:** Structured data output for integration with other tools.
* **Risk Scoring:** Calculates a risk score based on the severity of findings.

---

## Installation

### Prerequisites
* Python 3.6 or higher
* pip (Python package installer)

### Setup

1. **Clone the repository**
   ```bash
  git clone https://github.com/ecsanga/SAYARI.git
   cd SAYARI
````

2. **Install dependencies**

   ```bash
   pip3 install -r requirements.txt
   ```

---

## Usage

### Basic Scan

To run a scan against a target URL:

```bash
python3 sayari_scanner.py https://example.com
```

### Advanced Options

| Argument       | Description                                                    |
| -------------- | -------------------------------------------------------------- |
| `url`          | The target URL to scan (required).                             |
| `--timeout`    | Request timeout in seconds (default: 10).                      |
| `--proxy`      | Proxy URL for routing traffic (e.g., `http://127.0.0.1:8080`). |
| `--user-agent` | Custom User-Agent string for requests.                         |

### Examples

**Using a Proxy (Burp Suite / ZAP):**

Burp Suite is developed by PortSwigger and ZAP is maintained by OWASP.

```bash
python3 sayari_scanner.py https://example.com --proxy http://127.0.0.1:8080
```

**Custom Timeout and User-Agent:**

```bash
python3 sayari_scanner.py https://example.com --timeout 15 --user-agent "Googlebot"
```

---

## Output

Upon completion, the scanner saves the results in the current directory with filenames based on the target domain and timestamp.

1. **HTML Report (`*_sayari_*.html`)**

   * A visually appealing, responsive dashboard.
   * Includes severity distribution pie charts and category breakdown bar charts.
   * Expandable rows for detailed vulnerability descriptions and remediation advice.

2. **JSON Report (`*_sayari_*.json`)**

   * Structured raw data suitable for CI/CD pipelines or further programmatic analysis.

---

## Dependencies

Create a `requirements.txt` file with the following content:

```text
requests>=2.25.0
urllib3>=1.26.0
```

---

## How It Works

1. **Reconnaissance** – Extracts forms and parses URL parameters from the target page.
2. **Payload Injection** – Iterates through extensive payload lists for SQLi, XSS, and traversal testing.
3. **Analysis** – Analyzes HTTP responses for error patterns, reflection, and security misconfigurations.
4. **Multithreading** – Uses `ThreadPoolExecutor` for efficient sensitive file detection.
5. **Reporting** – Aggregates findings, calculates a risk score, and generates dual-format reports.

---
`
