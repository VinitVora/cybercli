#!/usr/bin/env python3

import time
import click
import subprocess
import json
from pathlib import Path
import ollama  # Using Ollama for Mistral LLM

# ─── 1. Preprocess raw outputs ──────────────────────────────────────────────────
def preprocess_outputs(raw_outputs):
    cleaned = {}
    for phase, data in raw_outputs.items():
        if isinstance(data, dict):
            cleaned[phase] = {}
            for tool, output in data.items():
                if isinstance(output, str):
                    lines = output.strip().splitlines()
                    useful_lines = [
                        line for line in lines
                        if any(kw in line.lower() for kw in [
                            "/", "open", "found", "sql", "vulnerable",
                            "subdomain", "takeover", "port"
                        ])
                        and not line.strip().startswith(("[*]", "[+]", "[-]", "[!]"))
                        and "403" not in line and "200" not in line
                    ]
                    cleaned[phase][tool] = "\n".join(
                        sorted(set(useful_lines))) or "No actionable data."
                else:
                    cleaned[phase][tool] = output
        else:
            cleaned[phase] = data
    return cleaned


# ─── 2. Tool paths & helpers ────────────────────────────────────────────────────
TOOL_PATHS = {
    "sublist3r": "/Users/ASL-User/Desktop/CyberCli/Sublist3r/sublist3r.py",
    "dirsearch": "/Users/ASL-User/Desktop/CyberCli/dirsearch/dirsearch.py",
    "theHarvester": "/Users/ASL-User/Desktop/CyberCli/theHarvester/theHarvester.py",
    "sqlmap": "/Users/ASL-User/Desktop/CyberCli/sqlmap/sqlmap.py",
}


def check_tool_installed(tool):
    if tool in TOOL_PATHS:
        return Path(TOOL_PATHS[tool]).exists()
    return subprocess.getoutput(f"which {tool}").strip() != ""


def run_command(command, tool_name):
    if not check_tool_installed(tool_name):
        click.secho(f"⚠️ {tool_name} not found.", fg="red")
        return f"{tool_name} is missing."
    try:
        return subprocess.getoutput(command)
    except Exception as e:
        return f"Error executing {tool_name}: {e}"


def generate_subdomains(target):
    click.secho("🔎 Gathering subdomains...", fg="green")
    subdomains_file = "subdomains.txt"
    subprocess.run(
        f"python3 {TOOL_PATHS['sublist3r']} -d {target} -o {subdomains_file}", shell=True)
    subprocess.run("sort -u subdomains.txt -o subdomains.txt", shell=True)
    return subdomains_file

# ─── 3. ZAP helpers ─────────────────────────────────────────────────────────────
def is_zapcli_installed():
    return subprocess.getoutput("which zap-cli").strip() != ""


def is_zap_running(port=8080, timeout=60):
    try:
        res = subprocess.run(["zap-cli", "--port", str(port), "status",
                             "-t", str(timeout)], capture_output=True, text=True)
        return res.returncode == 0
    except FileNotFoundError:
        return False


def start_zap_daemon(port=8080):
    if not is_zapcli_installed():
        click.secho("⚠️ zap-cli not installed.", fg="red")
        return False
    if is_zap_running(port):
        click.secho(f"✅ ZAP already running on port {port}.", fg="green")
        return True
    click.secho("⚠️ Launching ZAP daemon…", fg="yellow")
    subprocess.Popen([
        "/Applications/ZAP.app/Contents/Java/zap.sh", "-daemon",
        "-port", str(port), "-config", "api.disablekey=true"
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(30):
        if is_zap_running(port, timeout=1):
            click.secho("✅ ZAP is up.", fg="green")
            return True
        time.sleep(1)
    click.secho("❌ ZAP failed to start.", fg="red")
    return False


def run_zap_scan(target, port=8080):
    click.secho("🚨 Running ZAP quick-scan…", fg="red")
    if not start_zap_daemon(port):
        return {"quick_scan": "Failed to start ZAP", "detailed_report": ""}
    quick_out = subprocess.getoutput(
        f"zap-cli --port {port} quick-scan --alert-level Informational -s all https://{target}")
    report_file = f"zap_report_{target}.html"
    subprocess.getoutput(
        f"zap-cli --port {port} report -o {report_file} -f html")
    content = Path(report_file).read_text(
        encoding="utf-8") if Path(report_file).exists() else ""
    return {"quick_scan": quick_out, "detailed_report": content}

# ─── 4. Recon & Vuln phases ─────────────────────────────────────────────────────
def run_recon(target, scanner="dirsearch", nm=False, am=False, ns=False, dg=False, th=False, sl=False, sj=False):
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
            f"python3 {TOOL_PATHS['theHarvester']} -d {target} -b all", "theHarvester")

    # Subdomains logic
    subdomains_file = None
    if Path("subdomains.txt").exists():
        subdomains_file = "subdomains.txt"
    elif sl:
        subdomains_file = generate_subdomains(target)
    recon_data["subdomains"] = Path(subdomains_file).read_text(
    ).splitlines() if subdomains_file else []

    if sj:
        click.secho("🔗 Running Subjack takeover check…", fg="yellow")
        recon_data["subdomain_takeovers"] = run_subjack(
            subdomains_file or "subdomains.txt")

    if not any([nm, ns, dg, am, th, sl, sj]):
        click.secho("📂 Running default directory enumeration...", fg="green")
        recon_data["directory_enum"] = run_command(
            f"python3 {TOOL_PATHS['dirsearch']} -u https://{target} -e php,asp,html,js,txt,xml,json,sql,zip,env,pdf",
            "dirsearch"
        )
    return recon_data


def run_vulnerability(target, nk=False, zp=False, sm=False):
    vulns = {}
    if nk:
        click.secho("🛡️ Running Nikto...", fg="red")
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

# ─── 5. Subjack helper ──────────────────────────────────────────────────────────
def run_subjack(subdomains):
    takeover_results = "takeover_results.txt"
    fingerprints_file = "/Users/ASL-User/Desktop/CyberCli/fingerprints.json"

    # Remove stale
    if Path(takeover_results).exists():
        Path(takeover_results).unlink()

    cmd = [
        "subjack",
        "-w", subdomains,
        "-t", "100",
        "-timeout", "30",
        "-ssl",
        "-c", fingerprints_file,
        "-o", takeover_results,
        "-v",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)

    if Path(takeover_results).exists():
        lines = Path(takeover_results).read_text().splitlines()
        return "\n".join(sorted(set(lines))) or "No subdomain takeovers detected."
    if proc.returncode == 0:
        return "No subdomain takeovers detected."
    return f"Subjack error (rc={proc.returncode}):\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"

# ─── 6. Enhanced LLM summarization ────────────────────────────────────────────
def run_llm(raw_outputs, target="target"):
    click.secho("🤖 Summarizing with Mistral…", fg="bright_magenta")
    pre = preprocess_outputs(raw_outputs)

    base_prompt = (
        "You are a cybersecurity analyst. A CLI tool ran reconnaissance and vulnerability assessment tools "
        "against the target below. Summarize findings, list vulnerabilities, highlight any and everything that you find interesting or concerning,"
        "and recommend next steps.\n\n"
        f"{json.dumps(pre, indent=2)}"
    )
    resp = ollama.chat(model="mistral", messages=[
                       {"role": "user", "content": base_prompt}])
    summary = resp.get("message", {}).get("content", "").strip()

    if not summary or "no significant" in summary.lower() or len(summary) < 30:
        click.secho("🔁 Weak LLM response—retrying…", fg="yellow")
        retry_prompt = (
            "As a cybersecurity expert, extract every single actionable takeaway from this data—even minimal ones. Be concise and specific.\n\n"
            f"{json.dumps(pre, indent=2)}"
        )
        resp = ollama.chat(model="mistral", messages=[
                           {"role": "user", "content": retry_prompt}])
        summary = resp.get("message", {}).get(
            "content", "Error generating summary.").strip()

    Path(f"{target}_summary.txt").write_text(summary, encoding="utf-8")
    return summary

# ─── 7. CLI Entry Point ────────────────────────────────────────────────────────
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
        f"🚀 Starting cybersecurity assessment for {target}…\n", fg="bright_cyan", bold=True)
    raw_outputs = {}
    flags_used = any([recon, vuln, sj, nm, am, ns, dg, sl, nk, zp, sm, th])

    if scanner and not flags_used:
        click.secho(
            f"📂 Directory enum only ({scanner})…", fg="green", bold=True)
        raw_outputs["recon"] = run_recon(target, scanner)
        raw_outputs["vulnerability"] = "Skipped."
        summary = run_llm(raw_outputs, target)
        click.secho("\n===== 📜 Report =====", fg="bright_magenta", bold=True)
        click.echo(summary)
        return

    full_stack = not flags_used
    # Recon
    if full_stack or recon or any([nm, am, ns, dg, th, sl, sj]):
        mode = "FULL" if full_stack else "SELECTED"
        click.secho(f"🔍 Running {mode} Recon phase…", fg="green", bold=True)
        raw_outputs["recon"] = run_recon(target, scanner or "dirsearch",
                                         nm=nm, am=am, ns=ns, dg=dg, th=th, sl=sl, sj=sj)
    else:
        raw_outputs["recon"] = "Skipped."
    # Vulnerability
    if full_stack or vuln or any([nk, zp, sm]):
        mode = "FULL" if full_stack else "SELECTED"
        click.secho(
            f"🚨 Running {mode} Vulnerability phase…", fg="red", bold=True)
        raw_outputs["vulnerability"] = run_vulnerability(
            target, nk=nk, zp=zp, sm=sm)
    else:
        raw_outputs["vulnerability"] = "Skipped."

    # Summarize & persist
    summary = run_llm(raw_outputs, target)
    Path(f"{target}_report.json").write_text(json.dumps(raw_outputs, indent=2))
    click.secho("\n===== 📜 Final Report =====", fg="bright_magenta", bold=True)
    click.echo(summary)
    click.secho(
        f"\n✅ Done. Raw JSON → {target}_report.json; Summary → {target}_summary.txt", fg="bright_green")


if __name__ == "__main__":
    main()
