import PySimpleGUI as sg
import pandas as pd
from datetime import datetime
import plotly.express as px

# ----------------------------
# Compliance Profiles
# ----------------------------
COMPLIANCE_PROFILES = {
    "FedRAMP Moderate/High": {"Critical":30, "High":30, "Medium":90, "Low":180},
    "Custom": {"Critical":30, "High":30, "Medium":90, "Low":180}  # editable later
}

# ----------------------------
# CVSS-Based Severity Mapping
# ----------------------------
def severity_from_cvss(cvss):
    try:
        cvss = float(cvss)
    except:
        return "Low"
    if cvss >= 9.0:
        return "Critical"
    elif cvss >= 7.0:
        return "High"
    elif cvss >= 4.0:
        return "Medium"
    elif cvss > 0.0:
        return "Low"
    else:
        return "Low"

# ----------------------------
# Vendor Detection & Normalization
# ----------------------------
def detect_vendor(df):
    cols = [c.lower() for c in df.columns]
    if "plugin id" in cols:
        return "Nessus"
    elif "qid" in cols:
        return "Qualys"
    elif "vulnerability id" in cols or "vuln id" in cols:
        return "Rapid7"
    else:
        return "Unknown"

def normalize_data(df, vendor):
    df.columns = df.columns.str.strip()
    normalized = pd.DataFrame()
    if vendor == "Nessus":
        normalized["Plugin ID"] = df.get("Plugin ID")
        normalized["Plugin Name"] = df.get("Plugin Name")
        normalized["Host"] = df.get("Host")
        normalized["CVSS"] = df.get("CVSS")
        normalized["Exploit Available"] = df.get("Exploit Available","")
        normalized["First Discovered"] = df.get("First Discovered")
        normalized["Last Observed"] = df.get("Last Observed")
        normalized["Solution"] = df.get("Solution","")
    elif vendor == "Qualys":
        normalized["Plugin ID"] = df.get("QID")
        normalized["Plugin Name"] = df.get("Title")
        normalized["Host"] = df.get("IP")
        normalized["CVSS"] = df.get("CVSS Base")
        normalized["Exploit Available"] = ""
        normalized["First Discovered"] = df.get("First Found")
        normalized["Last Observed"] = df.get("Last Found")
        normalized["Solution"] = df.get("Solution","")
    elif vendor == "Rapid7":
        normalized["Plugin ID"] = df.get("Vulnerability ID")
        normalized["Plugin Name"] = df.get("Title")
        normalized["Host"] = df.get("Asset IP Address")
        normalized["CVSS"] = df.get("CVSS Score")
        normalized["Exploit Available"] = df.get("Exploits","")
        normalized["First Discovered"] = df.get("Date Discovered")
        normalized["Last Observed"] = df.get("Date Observed")
        normalized["Solution"] = df.get("Solution","")
    else:
        raise ValueError("Unsupported or unknown scan format.")
    return normalized

# ----------------------------
# Cleaning + SLA Logic
# ----------------------------
def clean_and_enrich(df, profile):
    df["CVSS"] = pd.to_numeric(df["CVSS"], errors="coerce").fillna(0)
    df["Severity"] = df["CVSS"].apply(severity_from_cvss)
    df["First Discovered"] = pd.to_datetime(df["First Discovered"], errors="coerce").dt.tz_localize(None)
    df["Last Observed"] = pd.to_datetime(df["Last Observed"], errors="coerce").dt.tz_localize(None)
    df = df.drop_duplicates(subset=["Host","Plugin ID"])
    today = pd.Timestamp(datetime.today())
    df["Age_Days"] = (today - df["First Discovered"]).dt.days
    df["Remediation_Days"] = df["Severity"].apply(lambda sev: profile.get(sev,90))
    df["Days_Left"] = df["Remediation_Days"] - df["Age_Days"]
    df["Expired"] = df["Days_Left"] < 0
    return df

# ----------------------------
# Metrics & Risk
# ----------------------------
def generate_metrics(df):
    metrics = {}
    metrics["total"] = len(df)
    metrics["critical"] = len(df[df["Severity"]=="Critical"])
    metrics["high"] = len(df[df["Severity"]=="High"])
    metrics["medium"] = len(df[df["Severity"]=="Medium"])
    metrics["low"] = len(df[df["Severity"]=="Low"])
    metrics["cvss_9_plus"] = len(df[df["CVSS"]>=9])
    metrics["oldest"] = df["First Discovered"].min()
    metrics["expired"] = len(df[df["Expired"]==True])
    return metrics

def calculate_risk(metrics):
    score = metrics["critical"]*5 + metrics["high"]*3 + metrics["medium"]
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
# Scan Comparison
# ----------------------------
def compare_scans(df_new, df_old):
    df_new_set = df_new.set_index(["Host","Plugin ID"])
    df_old_set = df_old.set_index(["Host","Plugin ID"])
    new_only = df_new_set[~df_new_set.index.isin(df_old_set.index)].reset_index()
    resolved = df_old_set[~df_old_set.index.isin(df_new_set.index)].reset_index()
    unchanged = df_new_set[df_new_set.index.isin(df_old_set.index)].reset_index()
    return new_only, resolved, unchanged

# ----------------------------
# GUI Layout
# ----------------------------
sg.theme("LightBlue2")

single_scan_layout = [
    [sg.Text("Upload CSV:"), sg.Input(key="-FILE-"), sg.FileBrowse(file_types=(("CSV Files","*.csv"),))],
    [sg.Text("Vendor Override:"), sg.Combo(["Auto Detect","Nessus","Qualys","Rapid7"], default_value="Auto Detect", key="-VENDOR-")],
    [sg.Text("Compliance Profile:"), sg.Combo(list(COMPLIANCE_PROFILES.keys()), default_value="FedRAMP Moderate/High", key="-PROFILE-")],
    [sg.Button("Analyze")],
    [sg.HorizontalSeparator()],
    [sg.Text("Metrics Summary:", font=("Any",14))],
    [sg.Text("Critical: 0", key="-CRIT-"), sg.Text("High: 0", key="-HIGH-"),
     sg.Text("Medium: 0", key="-MED-"), sg.Text("Low: 0", key="-LOW-")],
    [sg.Text("Expired: 0", key="-EXPIRED-")],
    [sg.Text("Risk Score: 0", key="-SCORE-"), sg.Text("Rating: N/A", key="-RATING-")],
    [sg.Text("Vulnerabilities Table:")],
    [sg.Table(values=[], headings=["Plugin ID","Plugin Name","Severity","Host","CVSS","Age","Days Left","Expired","Solution"],
              key="-TABLE-", auto_size_columns=False, col_widths=[10,25,10,15,6,6,8,8,30], num_rows=15)],
    [sg.Button("Show Severity Pie Chart"), sg.Button("Show Top 5 Hosts"), sg.Button("Show Aging Buckets")],
    [sg.Button("Download Cleaned CSV")]
]

scan_comparison_layout = [
    [sg.Text("Upload Old Scan CSV:"), sg.Input(key="-OLD-"), sg.FileBrowse(file_types=(("CSV Files","*.csv"),))],
    [sg.Text("Upload New Scan CSV:"), sg.Input(key="-NEW-"), sg.FileBrowse(file_types=(("CSV Files","*.csv"),))],
    [sg.Button("Compare Scans")],
    [sg.HorizontalSeparator()],
    [sg.Text("Comparison Metrics:", font=("Any",14))],
    [sg.Text("New Vulnerabilities: 0", key="-NEWV-"), sg.Text("Resolved Vulnerabilities: 0", key="-RESOLVED-")],
    [sg.Text("Unchanged Vulnerabilities: 0", key="-UNCH-")],
    [sg.Text("Comparison Table:")],
    [sg.Table(values=[], headings=["Plugin ID","Plugin Name","Severity","Host","Status"],
              key="-COMP_TABLE-", auto_size_columns=False, col_widths=[10,25,10,15,10], num_rows=15)],
    [sg.Button("Download Comparison CSV")]
]

layout = [
    [sg.TabGroup([[sg.Tab("Single Scan Analysis", single_scan_layout),
                   sg.Tab("Scan Comparison", scan_comparison_layout)]])]
]

window = sg.Window("Multi-Vendor Vulnerability Analyzer (CVSS-Based Severity)", layout, size=(1200,700))

df_cleaned = None
df_old_cleaned = None
df_new_cleaned = None

# ----------------------------
# Event Loop
# ----------------------------
while True:
    event, values = window.read()
    if event in (sg.WINDOW_CLOSED,"Exit"):
        break

    # ----------------------------
    # Single Scan Analysis
    # ----------------------------
    if event == "Analyze":
        try:
            file = values["-FILE-"]
            if not file:
                sg.popup_error("Please select a CSV file.")
                continue
            df_raw = pd.read_csv(file)
            vendor = detect_vendor(df_raw)
            override = values["-VENDOR-"]
            if override != "Auto Detect":
                vendor = override
            if vendor=="Unknown":
                sg.popup_error("Unsupported CSV format.")
                continue
            profile_name = values["-PROFILE-"]
            profile = COMPLIANCE_PROFILES[profile_name]

            df_normalized = normalize_data(df_raw, vendor)
            df_cleaned = clean_and_enrich(df_normalized, profile)

            metrics = generate_metrics(df_cleaned)
            score, rating = calculate_risk(metrics)

            window["-CRIT-"].update(f"Critical: {metrics['critical']}")
            window["-HIGH-"].update(f"High: {metrics['high']}")
            window["-MED-"].update(f"Medium: {metrics['medium']}")
            window["-LOW-"].update(f"Low: {metrics['low']}")
            window["-EXPIRED-"].update(f"Expired: {metrics['expired']}")
            window["-SCORE-"].update(f"Risk Score: {score}")
            window["-RATING-"].update(f"Rating: {rating}")

            table_data = df_cleaned[["Plugin ID","Plugin Name","Severity","Host","CVSS","Age_Days","Days_Left","Expired","Solution"]].fillna("").values.tolist()
            window["-TABLE-"].update(values=table_data)
            sg.popup(f"Analysis Complete! Detected Vendor: {vendor}", title="Success")
        except Exception as e:
            sg.popup_error(f"Error processing file:\n{e}")

    # ----------------------------
    # Scan Comparison
    # ----------------------------
    if event == "Compare Scans":
        try:
            old_file = values["-OLD-"]
            new_file = values["-NEW-"]
            if not old_file or not new_file:
                sg.popup_error("Please select both Old and New scan CSVs.")
                continue

            profile = COMPLIANCE_PROFILES["FedRAMP Moderate/High"]

            df_old_raw = pd.read_csv(old_file)
            df_new_raw = pd.read_csv(new_file)

            vendor_old = detect_vendor(df_old_raw)
            vendor_new = detect_vendor(df_new_raw)

            df_old_cleaned = clean_and_enrich(normalize_data(df_old_raw,vendor_old), profile)
            df_new_cleaned = clean_and_enrich(normalize_data(df_new_raw,vendor_new), profile)

            new_only, resolved, unchanged = compare_scans(df_new_cleaned, df_old_cleaned)

            window["-NEWV-"].update(f"New Vulnerabilities: {len(new_only)}")
            window["-RESOLVED-"].update(f"Resolved Vulnerabilities: {len(resolved)}")
            window["-UNCH-"].update(f"Unchanged Vulnerabilities: {len(unchanged)}")

            comp_table_data = []
            for df_tmp, status in [(new_only,"New"),(resolved,"Resolved"),(unchanged,"Unchanged")]:
                tmp = df_tmp.copy()
                tmp["Status"] = status
                comp_table_data.extend(tmp[["Plugin ID","Plugin Name","Severity","Host","Status"]].fillna("").values.tolist())
            window["-COMP_TABLE-"].update(values=comp_table_data)
            sg.popup("Scan Comparison Complete!")

        except Exception as e:
            sg.popup_error(f"Error comparing scans:\n{e}")

    # ----------------------------
    # Download buttons
    # ----------------------------
    if event == "Download Cleaned CSV" and df_cleaned is not None:
        save_path = sg.popup_get_file("Save Cleaned CSV", save_as=True, no_window=True, file_types=(("CSV Files","*.csv"),))
        if save_path:
            if not save_path.endswith(".csv"):
                save_path += ".csv"
            df_cleaned.to_csv(save_path,index=False)
            sg.popup(f"Saved cleaned CSV to:\n{save_path}")

    if event == "Download Comparison CSV" and df_new_cleaned is not None and df_old_cleaned is not None:
        save_path = sg.popup_get_file("Save Comparison CSV", save_as=True, no_window=True, file_types=(("CSV Files","*.csv"),))
        if save_path:
            if not save_path.endswith(".csv"):
                save_path += ".csv"
            all_comp = []
            for df_tmp, status in [(df_new_cleaned, "New"),(df_old_cleaned, "Resolved")]:
                tmp = df_tmp.copy()
                tmp["Status"] = status
                all_comp.append(tmp)
            pd.concat(all_comp, ignore_index=True).to_csv(save_path,index=False)
            sg.popup(f"Saved comparison CSV to:\n{save_path}")

window.close()
