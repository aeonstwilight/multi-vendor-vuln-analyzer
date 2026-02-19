# nessus-vuln-report


nessus-vuln-report is a **lightweight desktop tool** for analyzing Nessus CSV vulnerability reports. It provides metrics, risk scoring, and visualizations for quick vulnerability triage.

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

---

## Installation

1. Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/nessus-vuln-report.git
cd nessus-vuln-report
```
python -m venv venv
venv\Scripts\activate       # Windows
pip install -r requirements.txt

Usage

Run the desktop application:

python app.py


Upload your Nessus CSV file.

Click Analyze to see metrics and risk score.

Use the buttons to view Severity Pie Chart, Top 5 Hosts, and Aging Buckets.

Click Download Cleaned CSV to save the processed report.
