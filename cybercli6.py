#!/usr/bin/env python3
import time
import click
import subprocess
import json
from pathlib import Path
import yaml
import os
import ollama  # Using Ollama for Mistral LLM

# ─── Global flags ─────────────────────────────────────────────────────────────
use_sudo_flag = False

# ─── Load Scan Profiles from YAML ──────────────────────────────────────────────
CONFIG_PATH = Path("CyberCLIScanProfiles.yaml")

def load_profiles():
    with CONFIG_PATH.open() as f:
        data = yaml.safe_load(f)
    return data.get("profiles", {})

PROFILES = load_profiles()

# ─── Tool paths (make these configurable via env if you like) ─────────────────
TOOL_PATHS = {
    "sublist3r":    os.getenv("CYBERCLI_SUBLIST3R_PATH",    "/Users/ASL-User/Desktop/CyberCli/Sublist3r/sublist3r.py"),
    "dirsearch":    os.getenv("CYBERCLI_DIRSEARCH_PATH",    "/Users/ASL-User/Desktop/CyberCli/dirsearch/dirsearch.py"),
    "theHarvester": os.getenv("CYBERCLI_HARVESTER_PATH",    "/Users/ASL-User/Desktop/CyberCli/theHarvester/theHarvester.py"),
    "sqlmap":       os.getenv("CYBERCLI_SQLMAP_PATH",       "/Users/ASL-User/Desktop/CyberCli/sqlmap/sqlmap.py"),
}

# ─── Helpers ──────────────────────────────────────────────────────────────────

def check_tool_installed(tool):
    # if we have a custom path, check that; otherwise fall back to `which`
    if tool in TOOL_PATHS and TOOL_PATHS[tool]:
        return Path(TOOL_PATHS[tool]).exists()
    return bool(subprocess.getoutput(f"which {tool}").strip())

def run_command(cmd, tool):
    full_cmd = f"sudo {cmd}" if use_sudo_flag else cmd
    if not check_tool_installed(tool):
        click.secho(f"⚠️ {tool} not found.", fg="red")
        return f"{tool} missing."
    click.secho(f"▶️  {full_cmd}", fg="blue")
    try:
        return subprocess.getoutput(full_cmd)
    except Exception as e:
        return f"Error executing {tool}: {e}"

def start_zap_daemon(port=8080, timeout=60):
    if subprocess.getoutput("which zap-cli").strip() == "":
        click.secho("⚠️ zap-cli not installed.", fg="red")
        return False
    # try status first
    for _ in range(timeout):
        if subprocess.run(
            ["zap-cli", "--port", str(port), "status", "-t", "1"],
            capture_output=True
        ).returncode == 0:
            return True
        time.sleep(1)
    # then start if not running
    subprocess.Popen([
        "/Applications/ZAP.app/Contents/Java/zap.sh", "-daemon",
        "-port", str(port), "-config", "api.disablekey=true"
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(timeout):
        if subprocess.run(
            ["zap-cli", "--port", str(port), "status", "-t", "1"],
            capture_output=True
        ).returncode == 0:
            return True
        time.sleep(1)
    click.secho("❌ ZAP failed to start.", fg="red")
    return False

def run_zap_scan(target, extra_flags=""):
    port = 8080
    click.secho("🚨 Running ZAP scan…", fg="red")
    if not start_zap_daemon(port):
        return {"quick_scan": "ZAP start failed", "detailed_report": ""}
    quick_cmd = f"zap-cli --port {port} quick-scan {extra_flags}"
    quick_out = run_command(quick_cmd, "zap-cli")
    report_file = f"zap_report_{target}.html"
    run_command(
        f"zap-cli --port {port} report -o {report_file} -f html", "zap-cli")
    report_text = (
        Path(report_file).read_text(encoding="utf-8")
        if Path(report_file).exists() else ""
    )
    return {"quick_scan": quick_out, "detailed_report": report_text}

def preprocess_outputs(raw):
    cleaned = {}
    for phase, data in raw.items():
        if isinstance(data, dict):
            cleaned[phase] = {}
            for tool, out in data.items():
                if isinstance(out, str):
                    lines = [
                        l for l in out.splitlines()
                        if any(k in l.lower() for k in [
                            "/", "open", "found", "sql", "vulnerable",
                            "subdomain", "takeover", "port"
                        ])
                        and not l.strip().startswith(("[*]", "+", "-", "!"))
                        and "403" not in l and "200" not in l
                    ]
                    cleaned[phase][tool] = "\n".join(sorted(set(lines))) \
                                           or "No actionable data."
                else:
                    cleaned[phase][tool] = out
        else:
            cleaned[phase] = data
    return cleaned

def run_llm(raw, target):
    click.secho("🤖 Summarizing…", fg="bright_magenta")
    total_tools = sum(len(v) for v in raw.values() if isinstance(v, dict))
    data = raw if total_tools == 1 else preprocess_outputs(raw)
    prompt = (
        "You are a cybersec analyst. Summarize findings, list vulns, "
        "highlight concerns, and recommend next steps.\n\n"
        + json.dumps(data, indent=2)
    )
    resp = ollama.chat(model="mistral", messages=[
                       {"role": "user", "content": prompt}])
    summary = resp.get("message", {}).get("content", "").strip()
    if not summary or len(summary) < 30:
        retry = (
            "Extract every actionable takeaway—be concise.\n\n"
            + json.dumps(data, indent=2)
        )
        resp = ollama.chat(model="mistral", messages=[
                           {"role": "user", "content": retry}])
        summary = resp.get("message", {}).get(
            "content", "Error generating").strip()
    Path(f"{target}_summary.txt").write_text(summary, encoding="utf-8")
    return summary

# ─── Command Builder ──────────────────────────────────────────────────────────
# Each mapping now just injects the fully-formed flags string
TOOL_CMD_MAP = {
    "nmap":       lambda flags: f"nmap {flags}",
    "nikto":      lambda flags: f"nikto {flags}",
    "sqlmap":     lambda flags: f"python3 {TOOL_PATHS['sqlmap']} {flags}",
    "dirsearch":  lambda flags: f"python3 {TOOL_PATHS['dirsearch']} {flags}",
    "gobuster":   lambda flags: f"gobuster {flags}",
    "theharvester": lambda flags: f"python3 {TOOL_PATHS['theHarvester']} {flags}",
    "amass":      lambda flags: f"amass {flags}",
    "dig":        lambda flags: f"dig {flags}",
    "nslookup":   lambda flags: f"nslookup {flags}",
}

def build_command(tool, flags, target):
    # interpolate target into flags
    real_flags = flags.replace("{{target}}", target)
    key = tool.replace("-", "").lower()
    if key in TOOL_CMD_MAP:
        return TOOL_CMD_MAP[key](real_flags)
    # fallback
    return f"{tool} {real_flags}"

# ─── CLI Entry Point ──────────────────────────────────────────────────────────

@click.command()
@click.option("--sudo", "use_sudo", is_flag=True, help="Prefix all tools with sudo")
@click.argument("target")
@click.option("--profile", type=click.Choice(list(PROFILES.keys())), default=None,
              help="Pick a prebuilt scan profile")
@click.option("--mode",    type=str, default=None,
              help="Mode within the profile (light/medium/aggressive/etc.)")
@click.option("--nm", metavar="FLAGS", default=None, help="Run nmap with FLAGS")
@click.option("--am", metavar="FLAGS", default=None, help="Run amass with FLAGS")
@click.option("--ns", metavar="FLAGS", default=None, help="Run nslookup with FLAGS")
@click.option("--dg", metavar="FLAGS", default=None, help="Run dig with FLAGS")
@click.option("--sl", metavar="FLAGS", default=None, help="Run sublist3r with FLAGS")
@click.option("--sj", metavar="FLAGS", default=None, help="Run subjack with FLAGS")
@click.option("--th", metavar="FLAGS", default=None, help="Run theHarvester with FLAGS")
@click.option("--nk", metavar="FLAGS", default=None, help="Run nikto with FLAGS")
@click.option("--zp", metavar="FLAGS", default=None, help="Run zap-cli with FLAGS")
@click.option("--sm", metavar="FLAGS", default=None, help="Run sqlmap with FLAGS")
def main(use_sudo, target, profile, mode,
         nm, am, ns, dg, sl, sj, th, nk, zp, sm):
    global use_sudo_flag
    use_sudo_flag = use_sudo

    click.secho(f"🚀 Starting assessment for {target}\n", fg="bright_cyan", bold=True)
    raw = {"recon": {}, "vulnerability": {}}

    single_flags = any(v is not None for v in [nm, am, ns, dg, sl, sj, th, nk, zp, sm])
    if not profile and not single_flags:
        profile, mode = "web-vuln-scan", "aggressive"
        click.secho("🧠 No flags/profile given – defaulting to web-vuln-scan:aggressive", fg="yellow")

    if profile:
        if mode not in PROFILES[profile]["modes"]:
            raise click.BadParameter(f"--mode must be one of {list(PROFILES[profile]['modes'])}")
        tools_cfg = PROFILES[profile]["modes"][mode]["tools"]
        overrides = {"nmap": nm, "amass": am, "nslookup": ns, "dig": dg,
                     "sublist3r": sl, "subjack": sj, "theharvester": th,
                     "nikto": nk, "zap-cli": zp, "sqlmap": sm}
        for tool, flags in tools_cfg.items():
            if overrides.get(tool) is not None:
                click.secho(f"⚠️ Overriding {tool} flags via CLI", fg="yellow")
                flags = overrides[tool]
            if tool == "zap-cli":
                raw["vulnerability"]["zap"] = run_zap_scan(target, flags.replace("{{target}}", target))
            elif tool == "subjack":
                click.secho("🔗 Running Subjack takeover check…", fg="yellow")
                cmd = flags.replace("{{target}}", target)
                raw["recon"]["subjack"] = run_command(f"subjack {cmd}", "subjack")
            else:
                cmd = build_command(tool, flags, target)
                section = "recon" if tool in TOOL_CMD_MAP else "vulnerability"
                raw[section][tool] = run_command(cmd, tool)
    else:
        # single-tool mode
        requested = {"nmap": nm, "amass": am, "nslookup": ns, "dig": dg,
                     "sublist3r": sl, "subjack": sj, "theharvester": th,
                     "nikto": nk, "zap-cli": zp, "sqlmap": sm}
        if not single_flags:
            requested = {k: "" for k in requested}
        for tool, flags in requested.items():
            if flags is None:
                continue
            if tool == "zap-cli":
                raw["vulnerability"]["zap"] = run_zap_scan(target, flags.replace("{{target}}", target))
            elif tool == "subjack":
                click.secho("🔗 Running Subjack takeover check…", fg="yellow")
                raw["recon"]["subjack"] = run_command(f"subjack {flags}", "subjack")
            else:
                cmd = build_command(tool, flags, target)
                section = "recon" if tool in TOOL_CMD_MAP else "vulnerability"
                raw[section][tool] = run_command(cmd, tool)

    # Summarize & persist
    summary = run_llm(raw, target)
    Path(f"{target}_report.json").write_text(json.dumps(raw, indent=2))
    click.secho("\n===== 📜 Final Report =====", fg="bright_magenta", bold=True)
    click.echo(summary)
    click.secho(f"\n✅ Done. JSON → {target}_report.json; Summary → {target}_summary.txt", fg="bright_green")

if __name__ == "__main__":
    main()