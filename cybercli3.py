#!/usr/bin/env python3

import click
import subprocess
import json
from pathlib import Path
import ollama  # Using Ollama for Mistral LLM

# Define paths for manually installed tools (Modify these paths as needed)
TOOL_PATHS = {
    "sublist3r": "/Users/ASL-User/Desktop/CyberCli/Sublist3r/sublist3r.py",
    "dirsearch": "/Users/ASL-User/Desktop/CyberCli/dirsearch/dirsearch.py",
    "theHarvester": "/Users/ASL-User/Desktop/CyberCli/theHarvester/theHarvester.py",
    "sqlmap": "/Users/ASL-User/Desktop/CyberCli/sqlmap/sqlmap.py",
}

# Function to check if a tool is installed
def check_tool_installed(tool):
    if tool in TOOL_PATHS:
        return Path(TOOL_PATHS[tool]).exists()
    return subprocess.getoutput(f"which {tool}").strip() != ""

# Function to run a shell command safely
def run_command(command, tool_name):
    if not check_tool_installed(tool_name):
        return f"⚠️ {tool_name} is not installed or found in the expected path."
    try:
        return subprocess.getoutput(command)
    except Exception as e:
        return f"Error executing {tool_name}: {str(e)}"

# Step 1: Generate subdomains.txt
def generate_subdomains(target):
    click.echo("🔎 Gathering subdomains using Sublist3r...")
    subdomains_file = "subdomains.txt"
    subprocess.run(f"python3 {TOOL_PATHS['sublist3r']} -d {target} -o {subdomains_file}", shell=True)
    subprocess.run("sort -u subdomains.txt -o subdomains.txt", shell=True)
    return subdomains_file

# Function to run ZAP with detailed output
def run_zap_scan(target):
    click.echo("🚨 Running ZAP scan...")
    # Run quick-scan with all alert levels
    quick_scan_cmd = f"zap-cli --port 8080 quick-scan --alert-level Informational -s all {target}"
    quick_scan_output = run_command(quick_scan_cmd, "zap")

    # Generate a detailed HTML report
    report_file = f"zap_report_{target}.html"
    report_cmd = f"zap-cli --port 8080 report -o {report_file} -f html"
    run_command(report_cmd, "zap")

    # Read the detailed report file content
    report_content = ""
    report_path = Path(report_file)
    if report_path.exists():
        with report_path.open("r", encoding="utf-8") as f:
            report_content = f.read()

    return {
        "quick_scan": quick_scan_output,
        "detailed_report": report_content
    }

# Reconnaissance Phase
def run_recon(target, scanner="dirsearch"):
    click.echo("🔍 Running reconnaissance modules...")

    dir_enum_output = ""
    if scanner == "dirsearch":
        dir_enum_output = run_command(
            f"python3 {TOOL_PATHS['dirsearch']} -u https://{target} -e php,asp,html,js,txt,xml,json,sql,zip,env,pdf",
            "dirsearch"
        )
    elif scanner == "gobuster":
        wordlist = "/Users/ASL-User/Desktop/CyberCli/small.txt"
        dir_enum_output = run_command(
            f"gobuster dir -u https://{target} -w {wordlist} -x php,asp,html,js,txt,xml,json,sql,zip,env,pdf -t 50 -b 403",
            "gobuster"
        )

    recon_data = {
        "nmap": run_command(f"nmap -sV {target}", "nmap"),
        "nslookup": run_command(f"nslookup {target}", "nslookup"),
        "dig": run_command(f"dig {target}", "dig"),
        "theHarvester": run_command(f"python3 {TOOL_PATHS['theHarvester']} -d {target} -b all", "theHarvester"),
        "amass": run_command(f"amass enum -d {target}", "amass"),
        "directory_enum": dir_enum_output
    }
    return recon_data

# Vulnerability Assessment Phase
def run_vulnerability(target):
    click.echo("🚨 Running vulnerability scanning modules...")
    vulnerability_data = {
        "nikto": run_command(f"nikto -h {target}", "nikto"),
        "zap": run_zap_scan(target),  # Now includes both quick-scan and full report
        "wfuzz": run_command(f"wfuzz -c -z file,/usr/share/seclists/Fuzzing/parameter-names.txt --hc 404 {target}/FUZZ", "wfuzz"),
        "sqlmap": run_command(f"python3 {TOOL_PATHS['sqlmap']} -u {target} --batch  --level=5 --risk=3 --crawl=1 --random-agent --tamper=space2comment", "sqlmap")
    }
    return vulnerability_data

# Subdomain Takeover Detection
def run_subjack():
    click.echo("🔗 Checking for subdomain takeovers using Subjack...")
    subdomains_file = "subdomains.txt"
    takeover_results = "takeover_results.txt"
    fingerprints_file = "fingerprints.json"
    cmd = f"subjack -w {subdomains_file} -t 100 -timeout 30 -ssl -c {fingerprints_file} -o {takeover_results}"
    subprocess.run(cmd, shell=True)
    if Path(takeover_results).exists():
        with open(takeover_results, "r") as f:
            return f.read()
    return "No subdomain takeovers detected."

# LLM Summarization (Mistral via Ollama)
def run_llm(raw_outputs):
    click.echo("🤖 Interpreting raw outputs using Mistral via Ollama...")
    input_text = f"Summarize the following cybersecurity assessment data:\n{json.dumps(raw_outputs, indent=2)}"
    response = ollama.chat(model="mistral", messages=[
                           {"role": "user", "content": input_text}])
    return response["message"]["content"] if "message" in response else "Error generating summary."

@click.command()
@click.argument("target")
def main(target):
    click.echo(f"🚀 Starting cybersecurity assessment for {target}...\n")
    generate_subdomains(target)
    recon_data = run_recon(target)
    vulnerability_data = run_vulnerability(target)
    subjack_results = run_subjack()

    raw_outputs = {
        "recon": recon_data,
        "vulnerability": vulnerability_data,
        "subjack": subjack_results,
    }

    # Step 6: LLM-based Interpretation
    summary = run_llm(raw_outputs)
    report_path = Path(f"{target}_report.json")
    with report_path.open("w") as f:
        json.dump(raw_outputs, f, indent=2)

    click.echo("\n===== 📜 Final Report =====")
    click.echo(summary)
    click.echo(f"\n✅ Assessment complete. Report saved as {report_path}")

if __name__ == "__main__":
    main()