#!/usr/bin/env python3

import click
import subprocess
import json
from pathlib import Path
import ollama  # Using Ollama for Mistral LLM

# Define paths for manually installed tools (Modify these paths as needed)
TOOL_PATHS = {
    "recon-ng": "/path/to/recon-ng/recon-ng",
    "spiderfoot": "/Users/ASL-User/Desktop/CyberCli/spiderfoot/sf.py",
    "sublist3r": "/Users/ASL-User/Desktop/CyberCli/Sublist3r/sublist3r.py",
    "dirsearch": "/Users/ASL-User/Desktop/CyberCli/dirsearch/dirsearch.py",
    "theHarvester": "/Users/ASL-User/Desktop/CyberCli/theHarvester/theHarvester.py",
    "sqlmap": "/Users/ASL-User/Desktop/CyberCli/sqlmap/sqlmap.py",
}

# Function to check if a tool is installed (either system-wide or from GitHub)
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
    click.echo("🔎 Gathering subdomains using Amass & Sublist3r...")
    subdomains_file = "subdomains.txt"

    # Run Amass
    subprocess.run(f"amass enum -d {target} -o {subdomains_file}", shell=True)

    # Run Sublist3r
    subprocess.run(f"python3 {TOOL_PATHS['sublist3r']} -d {target} -o {subdomains_file}", shell=True)

    # Deduplicate results
    subprocess.run("sort -u subdomains.txt -o subdomains.txt", shell=True)

    return subdomains_file

# Reconnaissance Phase
def run_recon(target):
    click.echo("🔍 Running reconnaissance modules...")

    recon_data = {
        "nmap": run_command(f"nmap -sV {target}", "nmap"),
        "theHarvester": run_command(f"python3 {TOOL_PATHS['theHarvester']} -d {target} -b all", "theHarvester"),
        "recon-ng": run_command(f"python3 {TOOL_PATHS['recon-ng']} -r scripts/recon_script -d {target}", "recon-ng"),
        "spiderfoot": run_command(f"python3 {TOOL_PATHS['spiderfoot']} -s {target}", "spiderfoot"),
        "amass": run_command(f"amass enum -d {target}", "amass"),
        "sublist3r": run_command(f"python3 {TOOL_PATHS['sublist3r']} -d {target}", "sublist3r"),
        "dirsearch": run_command(f"python3 {TOOL_PATHS['dirsearch']} -u {target} -e php,asp,txt,html", "dirsearch"),
    }
    return recon_data

# Vulnerability Assessment Phase
def run_vulnerability(target):
    click.echo("🚨 Running vulnerability scanning modules...")

    vulnerability_data = {
        "nikto": run_command(f"nikto -h {target}", "nikto"),
        "zap": run_command(f"zap-cli quick-scan {target}", "zap"),
        "wfuzz": run_command(f"wfuzz -c -z file,/usr/share/seclists/Fuzzing/parameter-names.txt --hc 404 {target}/FUZZ", "wfuzz"),
    }
    return vulnerability_data

# Subdomain Takeover Detection (Subjack)
def run_subjack():
    click.echo("🔗 Checking for subdomain takeovers using Subjack...")
    subdomains_file = "subdomains.txt"
    takeover_results = "takeover_results.txt"
    fingerprint = "fingerprints.json"

    # Run Subjack
    subprocess.run(f"subjack -w {subdomains_file} -t 100 -timeout 30 -c {fingerprint} -ssl -o {takeover_results}", shell=True)

    # Read results
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

    # Step 1: Generate Subdomains
    generate_subdomains(target)

    # Step 2: Run Reconnaissance
    recon_data = run_recon(target)

    # Step 3: Run Vulnerability Scanning
    vulnerability_data = run_vulnerability(target)

    # Step 4: Check for Subdomain Takeovers
    subjack_results = run_subjack()

    # Aggregate raw outputs from all stages
    raw_outputs = {
        "recon": recon_data,
        "vulnerability": vulnerability_data,
        "subjack": subjack_results
    }

    # Step 5: LLM-based Interpretation
    summary = run_llm(raw_outputs)

    # Save report
    report_path = Path(f"{target}_report.json")
    with report_path.open("w") as f:
        json.dump(raw_outputs, f, indent=2)

    # Display final report
    click.echo("\n===== 📜 Final Report =====")
    click.echo(summary)
    click.echo(f"\n✅ Assessment complete. Report saved as {report_path}")

if __name__ == "__main__":
    main()