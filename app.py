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
        if matches:
            ip_address = matches[-1]
            return ip_address, output
        return None, output
    except Exception as e:
        return None, f"Error resolving IP: {e}"

ANSI_ESCAPE_RE = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')

def strip_ansi(text):
    return ANSI_ESCAPE_RE.sub('', text)

def run_command(cmd, output_file, step_name, strip_ansi_output=False):
    try:
        update_progress(f"Running {step_name}...")
        with open(output_file, "w") as out:
            out.write(f"Running command: {' '.join(cmd)}\n\n")
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180)
            stdout = result.stdout.decode(errors="ignore")
            stderr = result.stderr.decode(errors="ignore")

            if strip_ansi_output:
                stdout = strip_ansi(stdout)
                stderr = strip_ansi(stderr)

            out.write(stdout)
            if stderr:
                out.write("\n--- STDERR ---\n")
                out.write(stderr)

        update_progress(f"{step_name} completed.")
    except subprocess.TimeoutExpired:
        update_progress(f"{step_name} timed out.")
        with open(output_file, "w") as out:
            out.write(f"ERROR: Command timed out: {' '.join(cmd)}\n")
    except Exception as e:
        update_progress(f"{step_name} failed.")
        with open(output_file, "w") as out:
            out.write(f"ERROR: Failed to run command: {e}\n")

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
        with open(f"{OUTPUT_DIR}/masscan_{timestamp}.txt", "w") as f:
            f.write("[!] Failed to resolve IP for masscan.\n")

    run_command(["dnsrecon", "-d", domain, "-a"], f"{OUTPUT_DIR}/dnsrecon_{timestamp}.txt", "DNSRecon")

    url = f"https://{domain}" if not target.startswith("http") else target
    run_command(["wappalyzer", "-i", url], f"{OUTPUT_DIR}/wappalyzer_{timestamp}.txt", "Wappalyzer", strip_ansi_output=True)

def run_cve_scan(target):
    timestamp = progress["timestamp"]
    url = f"https://{target}" if not target.startswith("http") else target
    run_command([
        "nuclei", "-u", url,
        "-severity", "low,medium,high,critical",
        "-json", "-o", f"{OUTPUT_DIR}/nuclei_{timestamp}.json"
    ], f"{OUTPUT_DIR}/nuclei_{timestamp}.txt", "Nuclei CVE Scan")

def run_scanning(target):
    timestamp = progress["timestamp"]
    url = f"https://{target}" if not target.startswith("http") else target

    sqlmap_cmd = [
        "sqlmap", "-u", url,
        "--technique=BEUSTQ", "--crawl", "3",
        "--batch", "--threads", "8"
    ]
    run_command(sqlmap_cmd, f"{OUTPUT_DIR}/sqlmap_{timestamp}.txt", "SQLMap")

    xsstrike_cmd = ["xsstrike", "-u", url, "--crawl"]
    run_command(xsstrike_cmd, f"{OUTPUT_DIR}/xsstrike_{timestamp}.txt", "XSStrike")

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
        with open(f"{OUTPUT_DIR}/masscan_{timestamp}.txt", "w") as f:
            f.write("[!] Failed to resolve IP for masscan.\n")

    url = f"https://{domain}" if not target.startswith("http") else target
    run_command(["wappalyzer", "-i", url], f"{OUTPUT_DIR}/wappalyzer_{timestamp}.txt", "Wappalyzer", strip_ansi_output=True)

    run_command(["dnsrecon", "-d", domain, "-a"], f"{OUTPUT_DIR}/dnsrecon_{timestamp}.txt", "DNSRecon")

    for fname in ["sqlmap", "xsstrike", "nuclei", "nuclei.json"]:
        open(os.path.join(OUTPUT_DIR, f"{fname}_{timestamp}.txt"), 'w').close()

def count_cve_severities():
    timestamp = progress["timestamp"]
    counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    try:
        with open(os.path.join(OUTPUT_DIR, f"nuclei_{timestamp}.json")) as f:
            data = [json.loads(line) for line in f if line.strip()]
            severities = [entry.get("info", {}).get("severity", "").lower() for entry in data]
            counts.update(Counter(severities))
    except FileNotFoundError:
        pass
    return counts

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
        progress["status"] = "Scanning..."
        progress["steps"] = []
        progress["scan_type"] = scan_type
        progress["timestamp"] = time.strftime("%Y%m%d_%H%M%S")

        def run_selected_scan():
            if scan_type == "quick":
                quick_scan(target)
            else:
                run_recon(target)
                run_cve_scan(target)
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
    context = {
        "target": "Last scanned",
        "scan_type": progress.get("scan_type", "full"),
        "whois": load_output("whois"),
        "nslookup": load_output("nslookup"),
        "masscan": load_output("masscan"),
        "dnsrecon": load_output("dnsrecon"),
        "whatweb": load_output("wappalyzer"),
        "sqlmap": load_output("sqlmap"),
        "xsstrike": load_output("xsstrike"),
        "cve_counts": count_cve_severities()
    }
    return render_template("report.html", **context)

@app.route("/download/html")
def download_html():
    rendered = render_template("report.html",
        target="YourTarget",
        scan_type=progress.get("scan_type", "full"),
        whois=load_output("whois"),
        nslookup=load_output("nslookup"),
        masscan=load_output("masscan"),
        dnsrecon=load_output("dnsrecon"),
        whatweb=load_output("wappalyzer"),
        sqlmap=load_output("sqlmap"),
        xsstrike=load_output("xsstrike"),
        cve_counts=count_cve_severities()
    )
    html_path = os.path.join(OUTPUT_DIR, f"report_{progress['timestamp']}.html")
    with open(html_path, "w") as f:
        f.write(rendered)
    return send_file(html_path, as_attachment=True, download_name="recon_report.html")

@app.route("/download/pdf")
def download_pdf():
    rendered = render_template("report.html",
        target="YourTarget",
        scan_type=progress.get("scan_type", "full"),
        whois=load_output("whois"),
        nslookup=load_output("nslookup"),
        masscan=load_output("masscan"),
        dnsrecon=load_output("dnsrecon"),
        whatweb=load_output("wappalyzer"),
        sqlmap=load_output("sqlmap"),
        xsstrike=load_output("xsstrike"),
        cve_counts=count_cve_severities()
    )
    pdf_path = os.path.join(OUTPUT_DIR, f"report_{progress['timestamp']}.pdf")
    pdfkit.from_string(rendered, pdf_path)
    return send_file(pdf_path, as_attachment=True, download_name="recon_report.pdf")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)

