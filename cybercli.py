#!/usr/bin/env python3

import click
import subprocess
import json
from pathlib import Path
import ollama  # Use Ollama instead of llama_cpp

# Ensure required tools are installed


def check_tool_installed(tool):
    return subprocess.getoutput(f"which {tool}").strip() != ""

# Function to run a shell command and return output


def run_command(command):
    try:
        return subprocess.getoutput(command)
    except Exception as e:
        return f"Error executing {command}: {str(e)}"

# Reconnaissance Phase


def run_recon(target):
    click.echo("Running reconnaissance modules...")

    recon_data = {
        "nmap": run_command(f"nmap -sV {target}"),
        "theHarvester": run_command(f"theHarvester -d {target} -b all"),
        "recon-ng": run_command(f"recon-ng -r scripts/recon_script -d {target}"),
        "spiderfoot": run_command(f"sfcli.py -s {target}"),
        "amass": run_command(f"amass enum -d {target}"),
        "sublist3r": run_command(f"sublist3r -d {target}"),
        "subjack": run_command(f"subjack -w subdomains.txt -t 100 -timeout 30 -ssl"),
        "dirsearch": run_command(f"dirsearch -u {target} -e php,asp,txt,html"),
    }
    return recon_data

# Vulnerability Assessment Phase


def run_vulnerability(target):
    click.echo("Running vulnerability scanning modules...")

    vulnerability_data = {
        "nikto": run_command(f"nikto -h {target}"),
        "zap": run_command(f"zap-cli quick-scan {target}"),
        "wfuzz": run_command(f"wfuzz -c -z file,/usr/share/seclists/Fuzzing/parameter-names.txt --hc 404 {target}/FUZZ"),
    }
    return vulnerability_data

# LLM Summarization (Mistral 7B via Ollama)


def run_llm(raw_outputs):
    click.echo("Interpreting raw outputs using Mistral via Ollama...")

    input_text = f"Summarize the following cybersecurity assessment data:\n{json.dumps(raw_outputs, indent=2)}"

    response = ollama.chat(model="mistral", messages=[
                           {"role": "user", "content": input_text}])

    return response["message"]["content"] if "message" in response else "Error generating summary."


@click.command()
@click.argument("target")
def main(target):
    click.echo(f"Starting cybersecurity assessment for {target}...\n")

    # Stage 1: Reconnaissance
    recon_data = run_recon(target)

    # Stage 2: Vulnerability Scanning
    vulnerability_data = run_vulnerability(target)

    # Aggregate raw outputs from all stages
    raw_outputs = {
        "recon": recon_data,
        "vulnerability": vulnerability_data,
    }

    # Stage 3: LLM-based Interpretation
    summary = run_llm(raw_outputs)

    # Save report
    report_path = Path(f"{target}_report.json")
    with report_path.open("w") as f:
        json.dump(raw_outputs, f, indent=2)

    # Display final report
    click.echo("\n===== Final Report =====")
    click.echo(summary)
    click.echo(f"\nAssessment complete. Report saved as {report_path}")


if __name__ == "__main__":
    main()
