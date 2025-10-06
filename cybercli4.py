#!/usr/bin/env python3

import time
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
        click.secho(
            f"⚠️ {tool_name} is not installed or found in the expected path.", fg="red"
        )
        return f"{tool_name} is missing."
    try:
        return subprocess.getoutput(command)
    except Exception as e:
        return f"Error executing {tool_name}: {str(e)}"

# Step 1: Generate subdomains.txt using Sublist3r


def generate_subdomains(target):
    click.secho("🔎 Gathering subdomains using Sublist3r...", fg="green")
    subdomains_file = "subdomains.txt"
    subprocess.run(
        f"python3 {TOOL_PATHS['sublist3r']} -d {target} -o {subdomains_file}",
        shell=True
    )
    subprocess.run("sort -u subdomains.txt -o subdomains.txt", shell=True)
    return subdomains_file

# ZAP helper functions remain unchanged...


def is_zapcli_installed():
    return subprocess.getoutput("which zap-cli").strip() != ""


def is_zap_running(port=8080, timeout=60):
    try:
        result = subprocess.run(
            ["zap-cli", "--port", str(port), "status", "-t", str(timeout)],
            capture_output=True, text=True,
        )
        return result.returncode == 0
    except FileNotFoundError:
        return False


def start_zap_daemon(port=8080):
    if not is_zapcli_installed():
        click.secho(
            "⚠️ zap-cli is not installed. Please install via `pip install zapcli`.", fg="red"
        )
        return False
    if is_zap_running(port):
        click.secho(f"✅ ZAP already running on port {port}.", fg="green")
        return True
    click.secho(
        f"⚠️ ZAP not running. Launching daemon on port {port}…", fg="yellow"
    )
    subprocess.Popen([
        "/Applications/ZAP.app/Contents/Java/zap.sh",
        "-daemon", "-port", str(port), "-config", "api.disablekey=true"
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    click.secho("🔄 Waiting up to 30s for ZAP to initialize…", fg="yellow")
    for _ in range(30):
        if is_zap_running(port, timeout=1):
            click.secho("✅ ZAP is up and running.", fg="green")
            return True
        time.sleep(1)
    click.secho("❌ ZAP failed to start within 30s.", fg="red")
    return False


def run_zap_scan(target, port=8080):
    click.secho("🚨 Running ZAP scan…", fg="red")
    if not start_zap_daemon(port):
        return {"quick_scan": "Failed to start ZAP daemon.", "detailed_report": ""}
    quick_cmd = [
        "zap-cli", "--port", str(port),
        "quick-scan", "--alert-level", "Informational", "-s", "all", f"https://{target}"
    ]
    quick_out = subprocess.getoutput(" ".join(quick_cmd))
    report_file = f"zap_report_{target}.html"
    report_cmd = [
        "zap-cli", "--port", str(port),
        "report", "-o", report_file, "-f", "html"
    ]
    subprocess.getoutput(" ".join(report_cmd))
    report_content = ""
    if Path(report_file).exists():
        report_content = Path(report_file).read_text(encoding="utf-8")
    return {"quick_scan": quick_out, "detailed_report": report_content}

# Reconnaissance Phase with improved Subjack handling


def run_recon(
    target,
    scanner="dirsearch",
    nm=False, am=False, ns=False, dg=False,
    th=False, sl=False, sj=False
):
    recon_data = {}
    if nm:
        click.secho("📡 Running Nmap scan...", fg="blue")
        recon_data["nmap"] = run_command(f"nmap -sV {target}", "nmap")
    if ns:
        click.secho("🧠 Running nslookup...", fg="blue")
        recon_data["nslookup"] = run_command(f"nslookup {target}", "nslookup")
    if dg:
        click.secho("🔬 Running dig...", fg="blue")
        recon_data["dig"] = run_command(f"dig {target}", "dig")
    if am:
        click.secho("📈 Running Amass...", fg="blue")
        recon_data["amass"] = run_command(f"amass enum -d {target}", "amass")
    if th:
        click.secho("🔍 Running theHarvester...", fg="blue")
        recon_data["theHarvester"] = run_command(
            f"python3 {TOOL_PATHS['theHarvester']} -d {target} -b all",
            "theHarvester"
        )

    # Prepare subdomains: reuse existing, else --sl, else empty list
    subdomains_file = None
    if Path("subdomains.txt").exists():
        subdomains_file = "subdomains.txt"
        with open(subdomains_file) as f:
            recon_data["subdomains"] = f.read().splitlines()
    elif sl:
        subdomains_file = generate_subdomains(target)
        with open(subdomains_file) as f:
            recon_data["subdomains"] = f.read().splitlines()
    else:
        recon_data.setdefault("subdomains", [])

    if sj:
        # If still no subdomains, generate now
        if not subdomains_file:
            click.secho(
                "ℹ️  No subdomains.txt found—running Sublist3r under the hood.", fg="yellow"
            )
            subdomains_file = generate_subdomains(target)
        click.secho("🔗 Running Subjack takeover check…", fg="yellow")
        recon_data["subdomain_takeovers"] = run_subjack(
            subdomains=subdomains_file)

    if not any([nm, ns, dg, am, th, sl, sj]):
        click.secho("📂 Running default directory enumeration...", fg="green")
        if scanner == "dirsearch":
            recon_data["directory_enum"] = run_command(
                f"python3 {TOOL_PATHS['dirsearch']} -u https://{target} -e php,asp,html,js,txt,xml,json,sql,zip,env,pdf",
                "dirsearch"
            )
        else:
            wordlist = "/Users/ASL-User/Desktop/CyberCli/small.txt"
            recon_data["directory_enum"] = run_command(
                f"gobuster dir -u https://{target} -w {wordlist} -x php,asp,html,js,txt,xml,json,sql,zip,env,pdf -t 50 -b 403",
                "gobuster"
            )

    return recon_data

# Vulnerability Assessment Phase remains unchanged


def run_vulnerability(target, nk=False, zp=False, sm=False):
    vulns = {}
    if nk:
        click.secho("🛡️  Running Nikto...", fg="red")
        vulns["nikto"] = run_command(f"nikto -h {target}", "nikto")
    if zp:
        vulns["zap"] = run_zap_scan(target)
    if sm:
        click.secho("💉 Running SQLMap...", fg="red")
        vulns["sqlmap"] = run_command(
            f"python3 {TOOL_PATHS['sqlmap']} -u {target} --batch --level=5 --risk=3 --crawl=1 --random-agent --tamper=space2comment",
            "sqlmap"
        )
    return vulns

# Subjack helper now captures errors and prints stdout/stderr


def run_subjack(subdomains=None):
    subdomains_file = subdomains or "subdomains.txt"
    takeover_results = "takeover_results.txt"
    fingerprints_file = "/Users/ASL-User/Desktop/CyberCli/fingerprints.json"

    # 1) Remove stale results
    if Path(takeover_results).exists():
        Path(takeover_results).unlink()

    cmd = [
        "subjack",
        "-w", subdomains_file,
        "-t", "100",
        "-timeout", "30",
        "-ssl",
        "-c", fingerprints_file,
        "-o", takeover_results,
        "-v",          # keep verbose if you want detailed status
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)

    # 2) If file created, read + dedupe
    if Path(takeover_results).exists():
        lines = Path(takeover_results).read_text().splitlines()
        unique = sorted(set(lines))
        return "\n".join(unique) or "No subdomain takeovers detected."

    # 3) Clean exit but no file → no takeovers
    if proc.returncode == 0:
        return "No subdomain takeovers detected."

    # 4) Real error
    return (
        f"Subjack error (rc={proc.returncode}).\n"
        f"STDOUT:\n{proc.stdout}\n"
        f"STDERR:\n{proc.stderr}"
    )

# LLM Summarization (Mistral via Ollama stays the same)


def run_llm(raw_outputs):
    click.secho(
        "🤖 Interpreting raw outputs using Mistral via Ollama...", fg="bright_magenta"
    )
    input_text = (
        f"Summarize the following cybersecurity assessment data:\n{json.dumps(raw_outputs, indent=2)}"
    )
    response = ollama.chat(model="mistral", messages=[
        {"role": "user", "content": input_text}
    ])
    return response.get("message", {}).get("content", "Error generating summary.")


@click.command()
@click.argument("target")
@click.option("--scanner", type=click.Choice(["dirsearch", "gobuster"]), default=None,
              help="If used alone, run only directory enumeration; omit for full-stack.")
@click.option("--nm", is_flag=True, help="Run Nmap")
@click.option("--am", is_flag=True, help="Run Amass")
@click.option("--ns", is_flag=True, help="Run nslookup")
@click.option("--dg", is_flag=True, help="Run dig")
@click.option("--sl", is_flag=True, help="Run Sublist3r")
@click.option("--nk", is_flag=True, help="Run Nikto")
@click.option("--zp", is_flag=True, help="Run ZAP")
@click.option("--sm", is_flag=True, help="Run SQLMap")
@click.option("--sj", is_flag=True, help="Include Subjack in Recon phase")
@click.option("--th", is_flag=True, help="Run theHarvester")
@click.option("--recon", is_flag=True, help="Run only Reconnaissance tools")
@click.option("--vuln", is_flag=True, help="Run only Vulnerability tools")
def main(target, scanner, nm, am, ns, dg, sl, nk, zp, sm, sj, th, recon, vuln):
    click.secho(
        f"🚀 Starting cybersecurity assessment for {target}...\n", fg="bright_cyan", bold=True)
    raw_outputs = {}

    non_scanner_flags = any(
        [recon, vuln, sj, nm, am, ns, dg, sl, nk, zp, sm, th])

    # Scanner-only mode
    if scanner and not non_scanner_flags:
        click.secho(
            f"📂 Running only directory enumeration with {scanner}...", fg="green", bold=True)
        recon_data = run_recon(target, scanner)
        raw_outputs["recon"] = recon_data
        raw_outputs["vulnerability"] = "Skipped."
        summary = run_llm(raw_outputs)
        click.secho("\n===== 📜 Report =====", fg="bright_magenta", bold=True)
        click.echo(summary)
        return

    full_stack = not non_scanner_flags

    # Recon phase
    if full_stack or recon or any([nm, am, ns, dg, th, sl, sj]):
        phase = "FULL" if full_stack else "SELECTED"
        click.secho(
            f"🔍 Running {phase} Reconnaissance phase...", fg="green", bold=True)
        recon_data = run_recon(target, scanner or "dirsearch",
                               nm=nm, am=am, ns=ns, dg=dg, th=th, sl=sl, sj=sj)
        raw_outputs["recon"] = recon_data
    else:
        raw_outputs["recon"] = "Skipped."

    # Vulnerability phase
    if full_stack or vuln or any([nk, zp, sm]):
        phase = "FULL" if full_stack else "SELECTED"
        click.secho(
            f"🚨 Running {phase} Vulnerability scanning phase...", fg="red", bold=True)
        vulnerability_data = run_vulnerability(target, nk=nk, zp=zp, sm=sm)
        raw_outputs["vulnerability"] = vulnerability_data
    else:
        raw_outputs["vulnerability"] = "Skipped."

    # Summarize and save
    summary = run_llm(raw_outputs)
    report_path = Path(f"{target}_report.json")
    with report_path.open("w") as f:
        json.dump(raw_outputs, f, indent=2)

    click.secho("\n===== 📜 Final Report =====", fg="bright_magenta", bold=True)
    click.echo(summary)
    click.secho(
        f"\n✅ Assessment complete. Report saved as {report_path}", fg="bright_green")


if __name__ == "__main__":
    main()
