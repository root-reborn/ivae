import subprocess
import os
from flask import Flask, render_template, request, send_file, jsonify
import pdfkit
import threading
import time

app = Flask(__name__)
OUTPUT_DIR = "output"
os.makedirs(OUTPUT_DIR, exist_ok=True)

progress = {
    "status": "Idle",
    "steps": []
}

def update_progress(message):
    progress["status"] = message
    progress["steps"].append({"timestamp": time.strftime("%H:%M:%S"), "message": message})

def clear_output_dir():
    for filename in os.listdir(OUTPUT_DIR):
        file_path = os.path.join(OUTPUT_DIR, filename)
        if os.path.isfile(file_path):
            open(file_path, 'w').close()

def run_command(cmd, output_file, step_name):
    try:
        update_progress(f"Running {step_name}...")
        with open(output_file, "w") as out:
            out.write(f"Running command: {' '.join(cmd)}\n\n")
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180)
            out.write(result.stdout.decode(errors="ignore"))
            if result.stderr:
                out.write("\n--- STDERR ---\n")
                out.write(result.stderr.decode(errors="ignore"))
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
    run_command(["whois", target], f"{OUTPUT_DIR}/whois.txt", "Whois")
    run_command(["nslookup", target], f"{OUTPUT_DIR}/nslookup.txt", "NSLookup")
    run_command(["masscan", target, "-p1-1000", "--rate", "1000"], f"{OUTPUT_DIR}/masscan.txt", "Masscan")
    run_command(["nmap", "-sV", target], f"{OUTPUT_DIR}/nmap.txt", "Nmap")
    run_command(["whatweb", target], f"{OUTPUT_DIR}/whatweb.txt", "WhatWeb")

def run_scanning(target):
    url = f"https://{target}" if not target.startswith("http") else target

    sqlmap_cmd = [
        "sqlmap",
        "-u", url,
        "--technique=BEUSTQ",
        "--crawl", "3",
        "--batch",
        "--threads", "8"
    ]
    run_command(sqlmap_cmd, f"{OUTPUT_DIR}/sqlmap.txt", "SQLMap")

    xsstrike_cmd = [
        "xsstrike",
        "-u", url,
        "--crawl"
    ]
    run_command(xsstrike_cmd, f"{OUTPUT_DIR}/xsstrike.txt", "XSStrike")

def load_output(filename):
    try:
        with open(os.path.join(OUTPUT_DIR, filename)) as f:
            return f.read()
    except FileNotFoundError:
        return f"[!] {filename} not found or failed to generate."

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        target = request.form.get("target")
        if not target:
            return "Target is required", 400

        clear_output_dir()
        progress["status"] = "Scanning..."
        progress["steps"] = []

        def full_scan():
            run_recon(target)
            run_scanning(target)
            progress["status"] = "Completed"

        scan_thread = threading.Thread(target=full_scan)
        scan_thread.start()

        return render_template("loading.html", target=target)

    return render_template("form.html")

@app.route("/progress")
def progress_status():
    return jsonify(progress)

@app.route("/report")
def report():
    context = {
        "target": "Last scanned",
        "whois": load_output("whois.txt"),
        "nslookup": load_output("nslookup.txt"),
        "masscan": load_output("masscan.txt"),
        "nmap": load_output("nmap.txt"),
        "whatweb": load_output("whatweb.txt"),
        "sqlmap": load_output("sqlmap.txt"),
        "xsstrike": load_output("xsstrike.txt"),
    }
    return render_template("report.html", **context)

@app.route("/download/html")
def download_html():
    return send_file("templates/report.html", as_attachment=True, download_name="recon_report.html")

@app.route("/download/pdf")
def download_pdf():
    rendered = render_template("report.html",
        target="YourTarget",
        whois=load_output("whois.txt"),
        nslookup=load_output("nslookup.txt"),
        masscan=load_output("masscan.txt"),
        nmap=load_output("nmap.txt"),
        whatweb=load_output("whatweb.txt"),
        sqlmap=load_output("sqlmap.txt"),
        xsstrike=load_output("xsstrike.txt"),
    )
    pdfkit.from_string(rendered, "output/report.pdf")
    return send_file("output/report.pdf", as_attachment=True, download_name="recon_report.pdf")

if __name__ == "__main__":
    app.run(debug=False)

