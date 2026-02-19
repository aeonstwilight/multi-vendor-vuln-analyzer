# Nessus Vuln Report

[![Python](https://img.shields.io/badge/python-3.11-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Nessus Vuln Report is a **lightweight desktop tool** for analyzing Nessus CSV vulnerability reports. It provides metrics, risk scoring, and visualizations for quick vulnerability triage — all in a **native desktop GUI** using PySimpleGUI.

---

## Features

- **Metrics Summary**: Critical, High, Medium, Low counts
- **Risk Score**: Automatically calculated based on severity
- **Exploitable Findings**: Count of vulnerabilities with exploits available
- **Visualizations**:
  - Severity Pie Chart
  - Top 5 Hosts by Critical Vulnerabilities
  - Aging Buckets (0-30, 31-60, 61-90, 90+ days)
- **Cleaned CSV Download**: Save processed report for further analysis
- **Native GUI**: No browser required

---

## Installation

### Running the Executable (Windows)

1. Download `NessusVulnReport.zip` from the [Releases](https://github.com/YOUR_USERNAME/nessus-vuln-report/releases) page.  
2. Extract the folder anywhere.  
3. Run `app.exe` from the extracted folder.



## Usage

###

Upload your Nessus CSV file.

Click Analyze to see metrics and risk score.

Use the buttons to view Severity Pie Chart, Top 5 Hosts, and Aging Buckets.

Click Download Cleaned CSV to save the processed report.
