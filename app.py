import PySimpleGUI as sg
import pandas as pd
from datetime import datetime
import plotly.express as px

# ----------------------------
# Data Cleaning & Metrics
# ----------------------------
def load_and_clean(file):
    df = pd.read_csv(file)
    df.columns = df.columns.str.strip()

    required_columns = [
        "Plugin ID", "Plugin Name", "Severity",
        "CVSS", "Host", "Exploit Available",
        "First Discovered", "Last Observed",
        "Solution"
    ]

    # Fill missing columns safely
    for col in required_columns:
        if col not in df.columns:
            if col == "CVSS":
                df[col] = 0
            elif col in ["First Discovered", "Last Observed"]:
                df[col] = pd.NaT
            else:
                df[col] = ""

    # Normalize
    df["Severity"] = df["Severity"].astype(str).str.strip().str.title()
    df["Exploit Available"] = df["Exploit Available"].astype(str).str.strip().str.lower()
    df["CVSS"] = pd.to_numeric(df["CVSS"], errors="coerce").fillna(0)

    # Dates
    df["First Discovered"] = pd.to_datetime(
        df["First Discovered"], errors="coerce"
    ).dt.tz_localize(None)

    df["Last Observed"] = pd.to_datetime(
        df["Last Observed"], errors="coerce"
    ).dt.tz_localize(None)

    # Remove duplicates
    df = df.drop_duplicates(subset=["Host", "Plugin ID"])

    # Compute age
    today = pd.Timestamp(datetime.today())
    df["Age_Days"] = (today - df["First Discovered"]).dt.days

    # Expiration logic
    def get_remediation_days(severity):
        if severity == "Low":
            return 180
        elif severity == "Medium":
            return 90
        elif severity in ["High", "Critical"]:
            return 30
        return None

    df["Remediation_Days"] = df["Severity"].apply(get_remediation_days)

    df["Days_Left"] = df["Remediation_Days"] - df["Age_Days"]

    df["Expired"] = df["Days_Left"] < 0

    return df


def generate_metrics(df):
    metrics = {}
    metrics["total"] = len(df)
    metrics["critical"] = len(df[df["Severity"] == "Critical"])
    metrics["high"] = len(df[df["Severity"] == "High"])
    metrics["medium"] = len(df[df["Severity"] == "Medium"])
    metrics["low"] = len(df[df["Severity"] == "Low"])
    metrics["exploitable"] = len(df[df["Exploit Available"].isin(["yes", "true", "1"])])
    metrics["cvss_9_plus"] = len(df[df["CVSS"] >= 9])
    metrics["oldest"] = df["First Discovered"].min()
    return metrics


def calculate_risk(metrics):
    score = metrics["critical"] * 5 + metrics["high"] * 3 + metrics["medium"] * 1
    if score <= 20:
        rating = "Low"
    elif score <= 50:
        rating = "Moderate"
    elif score <= 100:
        rating = "High"
    else:
        rating = "Severe"
    return score, rating


# ----------------------------
# Table Filtering
# ----------------------------
def get_filtered_table(df, values):
    filtered = df.copy()

    # Expired filter
    if values["-FILTER_EXPIRED-"]:
        filtered = filtered[filtered["Expired"] == True]

    # Severity filters
    severities = []
    if values["-FILTER_CRIT-"]: severities.append("Critical")
    if values["-FILTER_HIGH-"]: severities.append("High")
    if values["-FILTER_MED-"]: severities.append("Medium")
    if values["-FILTER_LOW-"]: severities.append("Low")

    if severities:
        filtered = filtered[filtered["Severity"].isin(severities)]

    table_data = []

    for _, row in filtered.iterrows():
        prefix = "⚠️ " if row["Expired"] else ""

        # Truncate solution for readability
        solution_text = str(row["Solution"])
        if len(solution_text) > 120:
            solution_text = solution_text[:120] + "..."

        table_data.append([
            row["Plugin ID"],
            prefix + str(row["Plugin Name"]),
            row["Severity"],
            row["Host"],
            row["CVSS"],
            row["Exploit Available"],
            row["Age_Days"],
            row["Days_Left"],
            row["Expired"],
            solution_text
        ])

    return table_data


# ----------------------------
# GUI Layout
# ----------------------------
sg.theme("LightBlue2")

layout = [
    [sg.Text("Nessus Vuln Report - Desktop Analyzer", font=("Any", 16))],
    [sg.Text("Upload Nessus CSV:"), sg.Input(key="-FILE-"),
     sg.FileBrowse(file_types=(("CSV Files", "*.csv"),))],
    [sg.Button("Analyze")],
    [sg.HorizontalSeparator()],
    [sg.Text("Metrics Summary:", font=("Any", 14))],
    [sg.Text("Critical: 0", key="-CRIT-"),
     sg.Text("High: 0", key="-HIGH-"),
     sg.Text("Medium: 0", key="-MED-"),
     sg.Text("Low: 0", key="-LOW-")],
    [sg.Text("Risk Score: 0", key="-SCORE-"),
     sg.Text("Rating: N/A", key="-RATING-")],
    [sg.Text("Exploitable Findings: 0", key="-EXPLOIT-"),
     sg.Text("CVSS >= 9: 0", key="-CVSS9-"),
     sg.Text("Oldest Vulnerability: N/A", key="-OLDEST-")],
    [sg.Text("Filters:")],
    [sg.Checkbox("Show Only Expired", key="-FILTER_EXPIRED-"),
     sg.Checkbox("Critical", key="-FILTER_CRIT-"),
     sg.Checkbox("High", key="-FILTER_HIGH-"),
     sg.Checkbox("Medium", key="-FILTER_MED-"),
     sg.Checkbox("Low", key="-FILTER_LOW-"),
     sg.Button("Apply Filters")],
    [sg.Text("Vulnerabilities Table:")],
    [sg.Table(
        values=[],
        headings=[
            "Plugin ID", "Plugin Name", "Severity",
            "Host", "CVSS", "Exploit",
            "Age Days", "Days Left",
            "Expired", "Solution"
        ],
        key="-TABLE-",
        auto_size_columns=False,
        col_widths=[8, 28, 10, 15, 5, 8, 8, 8, 8, 35],
        justification='left',
        row_height=22,
        enable_events=True,
        num_rows=15
    )],
    [sg.Button("Show Severity Pie Chart"),
     sg.Button("Show Top 5 Hosts"),
     sg.Button("Show Aging Buckets")],
    [sg.Button("Download Cleaned CSV"), sg.Button("Exit")]
]

window = sg.Window("Nessus Vuln Report", layout, size=(1300, 650))

# ----------------------------
# Event Loop
# ----------------------------
df_cleaned = None

while True:
    event, values = window.read()
    if event == sg.WINDOW_CLOSED or event == "Exit":
        break

    if event == "Analyze":
        try:
            file = values["-FILE-"]
            if not file:
                sg.popup_error("Please select a CSV file.")
                continue

            df_cleaned = load_and_clean(file)
            metrics = generate_metrics(df_cleaned)
            score, rating = calculate_risk(metrics)

            window["-CRIT-"].update(f"Critical: {metrics['critical']}")
            window["-HIGH-"].update(f"High: {metrics['high']}")
            window["-MED-"].update(f"Medium: {metrics['medium']}")
            window["-LOW-"].update(f"Low: {metrics['low']}")
            window["-SCORE-"].update(f"Risk Score: {score}")
            window["-RATING-"].update(f"Rating: {rating}")
            window["-EXPLOIT-"].update(f"Exploitable Findings: {metrics['exploitable']}")
            window["-CVSS9-"].update(f"CVSS >= 9: {metrics['cvss_9_plus']}")
            window["-OLDEST-"].update(f"Oldest Vulnerability: {metrics['oldest']}")

            table_values = get_filtered_table(df_cleaned, values)
            window["-TABLE-"].update(values=table_values)

            sg.popup("Analysis Complete!", title="Success")

        except Exception as e:
            sg.popup_error(f"Error processing file:\n{e}")

    if event == "Apply Filters" and df_cleaned is not None:
        table_values = get_filtered_table(df_cleaned, values)
        window["-TABLE-"].update(values=table_values)

window.close()
