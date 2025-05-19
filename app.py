import subprocess
import os
import re
import json
from urllib.parse import urlparse
from flask import Flask, render_template, request, send_file, jsonify
import pdfkit
import threading
import time
from collections import Counter
import matplotlib
matplotlib.use('Agg')  # Important for headless environments (like PDF export)
import matplotlib.pyplot as plt
import requests
import nvdlib

app = Flask(__name__)
OUTPUT_DIR = "output"
os.makedirs(OUTPUT_DIR, exist_ok=True)

progress = {
    "status": "Idle",
    "steps": [],
    "scan_type": "full",
    "timestamp": time.strftime("%Y%m%d_%H%M%S")
}

def update_progress(message):
    progress["status"] = message
    progress["steps"].append({"timestamp": time.strftime("%H:%M:%S"), "message": message})

def clear_output_dir():
    for filename in os.listdir(OUTPUT_DIR):
        file_path = os.path.join(OUTPUT_DIR, filename)
        if os.path.isfile(file_path):
            open(file_path, 'w').close()

def extract_domain(url_or_domain):
    parsed = urlparse(url_or_domain)
    return parsed.netloc if parsed.netloc else parsed.path

def get_ip_from_nslookup(domain):
    try:
        result = subprocess.run(["nslookup", domain], capture_output=True, text=True, timeout=10)
        output = result.stdout
        matches = re.findall(r"Address:\s*([\d\.]+)", output)
        return (matches[-1], output) if matches else (None, output)
    except Exception as e:
        return None, f"Error resolving IP: {e}"

ANSI_ESCAPE_RE = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')

def strip_ansi(text):
    return ANSI_ESCAPE_RE.sub('', text)

def run_command(cmd, output_file, step_name, strip_ansi_output=False, timeout=180):
    try:
        update_progress(f"Running {step_name}...")
        with open(output_file, "w") as out:
            out.write(f"Running command: {' '.join(cmd)}\n\n")
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
            stdout = result.stdout.decode(errors="ignore")
            stderr = result.stderr.decode(errors="ignore")
            if strip_ansi_output:
                stdout = strip_ansi(stdout)
                stderr = strip_ansi(stderr)
            out.write(stdout)
            if stderr:
                out.write("\n--- STDERR ---\n" + stderr)
        update_progress(f"{step_name} completed.")
    except subprocess.TimeoutExpired:
        update_progress(f"{step_name} timed out.")
        with open(output_file, "w") as out:
            out.write(f"ERROR: Command timed out: {' '.join(cmd)}\n")
    except Exception as e:
        update_progress(f"{step_name} failed.")
        with open(output_file, "w") as out:
            out.write(f"ERROR: {e}\n")

def run_recon(target):
    domain = extract_domain(target)
    timestamp = progress["timestamp"]
    run_command(["whois", domain], f"{OUTPUT_DIR}/whois_{timestamp}.txt", "Whois")
    ip, nslookup_output = get_ip_from_nslookup(domain)
    with open(f"{OUTPUT_DIR}/nslookup_{timestamp}.txt", "w") as f:
        f.write(nslookup_output)
    if ip:
        run_command(["sudo", "masscan", ip, "-p1-1000"], f"{OUTPUT_DIR}/masscan_{timestamp}.txt", "Masscan")
    else:
        update_progress("IP resolution failed. Skipping Masscan.")
    run_command(["dnsrecon", "-d", domain, "-a"], f"{OUTPUT_DIR}/dnsrecon_{timestamp}.txt", "DNSRecon")
    url = f"https://{domain}" if not target.startswith("http") else target
    run_command(["wappalyzer", "-i", url], f"{OUTPUT_DIR}/wappalyzer_{timestamp}.txt", "Wappalyzer", strip_ansi_output=True)

def run_scanning(target):
    timestamp = progress["timestamp"]
    url = f"https://{target}" if not target.startswith("http") else target
    run_command(["xsstrike", "-u", url, "--crawl"], f"{OUTPUT_DIR}/xsstrike_{timestamp}.txt", "XSStrike", strip_ansi_output=True, timeout=120)
    run_command(["sqlmap", "-u", url, "--technique=BEUSTQ", "--crawl", "3", "--batch", "--threads", "8"], f"{OUTPUT_DIR}/sqlmap_{timestamp}.txt", "SQLMap")

def quick_scan(target):
    domain = extract_domain(target)
    timestamp = progress["timestamp"]
    run_command(["whois", domain], f"{OUTPUT_DIR}/whois_{timestamp}.txt", "Whois")
    ip, nslookup_output = get_ip_from_nslookup(domain)
    with open(f"{OUTPUT_DIR}/nslookup_{timestamp}.txt", "w") as f:
        f.write(nslookup_output)
    if ip:
        run_command(["sudo", "masscan", ip, "-p1-1000", "--rate", "1000"], f"{OUTPUT_DIR}/masscan_{timestamp}.txt", "Masscan")
    else:
        update_progress("IP resolution failed. Skipping Masscan.")
    url = f"https://{domain}" if not target.startswith("http") else target
    run_command(["wappalyzer", "-i", url], f"{OUTPUT_DIR}/wappalyzer_{timestamp}.txt", "Wappalyzer", strip_ansi_output=True)
    run_command(["dnsrecon", "-d", domain, "-a"], f"{OUTPUT_DIR}/dnsrecon_{timestamp}.txt", "DNSRecon")

def get_cvss_score_from_nvd(cve_id):
    try:
        results = nvdlib.searchCVE(cveId=cve_id, key='98b53deb-a7ab-4397-a914-0334b30c04f6')
        if results:
            cve = results[0]
            if hasattr(cve, 'v31score') and cve.v31score:
                return float(cve.v31score), cve.v31vector
            elif hasattr(cve, 'v3score') and cve.v3score:
                return float(cve.v3score), cve.v3vector
            elif hasattr(cve, 'v2score') and cve.v2score:
                return float(cve.v2score), cve.v2vector
    except Exception as e:
        print(f"Error fetching CVSS data for {cve_id}: {e}")
    return 0.0, ""

def parse_xsstrike_output(filepath):
    with open(filepath, 'r', encoding='utf-8') as file:
        lines = file.readlines()
    cves = []
    seen = set()
    current_component = current_version = current_location = None
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if line.startswith('[+] Vulnerable component:'):
            match = re.match(r'\[\+\] Vulnerable component: (.+?) v([0-9\.]+)', line)
            if match:
                current_component = match.group(1).strip()
                current_version = match.group(2).strip()
        elif line.startswith('[!] Component location:'):
            current_location = line.split(":", 1)[1].strip()
        elif line.startswith('[!] Summary:'):
            summary = line.split(":", 1)[1].strip()
            i += 1
            severity = lines[i].strip().split(":", 1)[1].strip().lower()
            i += 1
            cve_line = lines[i].strip()
            cve_match = re.match(r'\[\!\] CVE: (CVE-\d{4}-\d+)', cve_line)
            if cve_match:
                cve_id = cve_match.group(1)
                if cve_id in seen:
                    i += 1
                    continue
                seen.add(cve_id)
                score, vector = get_cvss_score_from_nvd(cve_id)
                cves.append({
                    "component": current_component,
                    "version": current_version,
                    "location": current_location,
                    "severity": severity,
                    "cve": cve_id,
                    "description": summary,
                    "cvss": score,
                    "vector": vector
                })
        i += 1
    return cves

def plot_cve_severity_distribution(cves):
    severity_counts = Counter(cve["severity"] for cve in cves)
    labels = ["low", "medium", "high"]
    values = [severity_counts.get(label, 0) for label in labels]
    colors = ['#87ceeb', '#ffa500', '#ff073a']
    plt.figure(figsize=(4, 3))  # Smaller size
    plt.bar(labels, values, color=colors)
    plt.title("CVE Severity Distribution")
    plt.xlabel("Severity")
    plt.ylabel("Count")
    plt.tight_layout()
    chart_path = os.path.join(OUTPUT_DIR, "xsstrike_cve_chart.png")
    plt.savefig(chart_path)
    plt.close()
    return chart_path

def load_output(tool):
    filename = f"{tool}_{progress.get('timestamp', 'latest')}.txt"
    try:
        with open(os.path.join(OUTPUT_DIR, filename)) as f:
            return f.read()
    except FileNotFoundError:
        return f"[!] {tool} output not found."

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        target = request.form.get("target")
        scan_type = request.form.get("scan_type")
        if not target or not scan_type:
            return "Target and Scan Type are required", 400
        clear_output_dir()
        progress.update({
            "status": "Scanning...",
            "steps": [],
            "scan_type": scan_type,
            "timestamp": time.strftime("%Y%m%d_%H%M%S")
        })
        def run_selected_scan():
            if scan_type == "quick":
                quick_scan(target)
            else:
                run_recon(target)
                run_scanning(target)
            progress["status"] = "Completed"
        threading.Thread(target=run_selected_scan).start()
        return render_template("loading.html", target=target)
    return render_template("form.html")

@app.route("/progress")
def progress_status():
    return jsonify(progress)

@app.route("/report")
def report():
    timestamp = progress["timestamp"]
    xsstrike_path = os.path.join(OUTPUT_DIR, f"xsstrike_{timestamp}.txt")
    xsstrike_cves = parse_xsstrike_output(xsstrike_path) if os.path.exists(xsstrike_path) else []
    xsstrike_cves.sort(key=lambda x: x.get("cvss", 0), reverse=True)
    severity_counts = Counter(cve["severity"] for cve in xsstrike_cves)
    xsstrike_summary = {
        "low": severity_counts.get("low", 0),
        "medium": severity_counts.get("medium", 0),
        "high": severity_counts.get("high", 0)
    }
    chart_path = plot_cve_severity_distribution(xsstrike_cves) if xsstrike_cves else None
    return render_template("report.html",
        target="Last scanned",
        scan_type=progress.get("scan_type", "full"),
        whois=load_output("whois"),
        nslookup=load_output("nslookup"),
        masscan=load_output("masscan"),
        dnsrecon=load_output("dnsrecon"),
        whatweb=load_output("wappalyzer"),
        sqlmap=load_output("sqlmap"),
        xsstrike=load_output("xsstrike"),
        xsstrike_cves=xsstrike_cves,
        xsstrike_chart=chart_path,
        xsstrike_summary=xsstrike_summary
    )
@app.route("/download/pdf")
def download_pdf():
    timestamp = progress["timestamp"]
    chart_path = os.path.join(OUTPUT_DIR, "xsstrike_cve_chart.png")
    report_html = report()
    pdf_path = os.path.join(OUTPUT_DIR, f"report_{timestamp}.pdf")
    pdfkit.from_string(report_html, pdf_path, options={"enable-local-file-access": ""})
    return send_file(pdf_path, as_attachment=True, download_name="recon_report.pdf")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)

