# Multi-Vendor Vulnerability Analyzer (CVSS-Based Severity)

[![Python](https://img.shields.io/badge/python-3.11-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Multi-Vendor Vulnerability Analyzer** is a desktop application for analyzing vulnerability scan results from multiple vendors (Nessus, Qualys, Rapid7) with CVSS-based severity, SLA/aging calculations, and advanced metrics. It provides both single-scan analysis and scan comparison in a native GUI, no browser required.



---

## Features

- **Multi-Vendor Support:** Automatically detects scan source (Nessus, Qualys, Rapid7) with override option.
- **CVSS-Based Severity:** Standardized FedRAMP-aligned severity mapping:
  - Critical: 9.0–10.0
  - High: 7.0–8.9
  - Medium: 4.0–6.9
  - Low: 0.1–3.9
- **Compliance Profiles:** SLA/aging rules based on severity (FedRAMP Moderate/High or Custom).
- **Single Scan Analysis:**
  - Metrics summary: Critical, High, Medium, Low counts
  - Expired vulnerabilities based on SLA
  - CVSS ≥9 count and oldest vulnerability
  - Risk Score calculation
  - Enriched table including Plugin ID, Name, Host, CVSS, Age, Days Left, Expired status, and Solution
- **Scan Comparison (New vs Old):**
  - Highlights new, resolved, and unchanged vulnerabilities
  - Comparison table with status per entry
  - Downloadable CSV of comparison results
- **Visualizations (Plotly):**
  - Severity Pie Chart
  - Top 5 Hosts by Critical Vulnerabilities
  - Aging Buckets Pie Chart (0–30, 31–60, 61–90, 90+ days)
- **Cleaned CSV Export:** Save enriched report for further analysis.
- **Native Desktop GUI:** Fully interactive with tables, dropdowns, and buttons; no browser required.

---

## Installation

Clone the repository:


- git clone https://github.com/yourusername/multi-vendor-vuln-analyzer.git
- cd multi-vendor-vuln-analyzer
- python -m venv venv
- venv\Scripts\activate
- pip install -r requirements.txt
- python app.py

### Running the Executable (Windows)

Windows Executable: You can also download the pre-built .exe release from the GitHub [Releases](https://github.com/aeonstwilight/multi-vendor-vuln-analyzer/releases) page. No Python installation is required.
Extract the folder anywhere.  
Run `app.exe` from the extracted folder.

## Usage
- Upload a CSV file from Nessus, Qualys, or Rapid7.
- Optionally select a vendor override.
- Choose a compliance profile.
- Click Analyze to view metrics and risk score.
- View enriched table and visualizations.
- Click Download Cleaned CSV to save the processed report.

Scan Comparison

- Upload an old scan CSV and a new scan CSV.
- Click Compare Scans to view:
  - New vulnerabilities
  - Resolved vulnerabilities
  - Unchanged vulnerabilities
- Download comparison results via CSV.

## License

This project is licensed under the MIT License. See the LICENSE file for details.
