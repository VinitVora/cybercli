#!/usr/bin/env python3
import requests
import time
import click
import subprocess
import json
from pathlib import Path
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import yaml
import os
import ollama

use_sudo_flag = False
CONFIG_PATH = Path("CyberCLIScanProfiles.yaml")

def load_profiles():
    with CONFIG_PATH.open() as f:
        data = yaml.safe_load(f)
    return data.get("profiles", {})


PROFILES = load_profiles()

TOOL_PATHS = {
    "dirsearch":    os.getenv("CYBERCLI_DIRSEARCH_PATH", "/Users/ASL-User/Desktop/CyberCli/dirsearch/dirsearch.py"),
    "theHarvester": os.getenv("CYBERCLI_HARVESTER_PATH", "/Users/ASL-User/Desktop/CyberCli/theHarvester/theHarvester.py"),
    "sqlmap":       os.getenv("CYBERCLI_SQLMAP_PATH",    "/Users/ASL-User/Desktop/CyberCli/sqlmap/sqlmap.py"),
}

TOOL_CMD_MAP = {
    "nmap": lambda flags: f"nmap {flags}",
    "nikto": lambda flags: f"nikto {flags}",
    "sqlmap": lambda flags: f"python3 {TOOL_PATHS['sqlmap']} {flags}",
    "dirsearch": lambda flags: f"python3 {TOOL_PATHS['dirsearch']} {flags}",
    "gobuster": lambda flags: f"gobuster {flags}",
    "theharvester": lambda flags: f"python3 {TOOL_PATHS['theHarvester']} {flags}",
    "amass": lambda flags: f"amass {flags}",
    "dig": lambda flags: f"dig {flags}",
    "nslookup": lambda flags: f"nslookup {flags}",
    "subfinder": lambda flags: f"subfinder {flags}",
}

TOOL_SECTIONS = {
    "nmap": "recon", "amass": "recon", "nslookup": "recon", "dig": "recon",
    "subfinder": "recon", "subjack": "recon", "theharvester": "recon",
    "gobuster": "recon", "dirsearch": "recon", "nikto": "vulnerability",
    "sqlmap": "vulnerability", "zap-cli": "vulnerability"
}


def sanitize_target(target):
    return target.replace("https://", "").replace("http://", "").replace("/", "_")


def check_tool_installed(tool):
    if tool in TOOL_PATHS and TOOL_PATHS[tool]:
        return Path(TOOL_PATHS[tool]).exists()
    return bool(subprocess.getoutput(f"which {tool}").strip())


def run_command(full_cmd, tool):
    click.secho(f"🚀 Running {tool} with:\n{full_cmd}\n", fg="blue")
    try:
        result = subprocess.run(
            full_cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.stdout.decode()
    except subprocess.CalledProcessError as e:
        click.secho(f"❌ Error running {tool}: {e.stderr.decode()}", fg="red")
        if e.stdout:
            click.secho(f"📤 STDOUT:\n{e.stdout.decode()}", fg="yellow")
        return ""


def start_zap_daemon(port=8080, timeout=60):
    if subprocess.run(
        ["zap-cli", "--port", str(port), "status", "-t", "1"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    ).returncode == 0:
        click.secho("⚡️ Found existing ZAP daemon", fg="yellow")
        return None

    proc = subprocess.Popen(
        ["/Applications/ZAP.app/Contents/Java/zap.sh",
         "-daemon", "-port", str(port), "-config", "api.disablekey=true"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True
    )
    line = proc.stderr.readline()
    if "home directory is already in use" in line:
        click.secho("⚡️ ZAP home in use; assuming existing daemon", fg="yellow")
        proc.stderr.close()
        return None

    end = time.time() + timeout
    while time.time() < end:
        if subprocess.run(
            ["zap-cli", "--port", str(port), "status", "-t", "1"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        ).returncode == 0:
            return proc
        time.sleep(1)

    proc.kill()
    raise RuntimeError(f"ZAP failed to start after {timeout} seconds.")


def ensure_valid_url(target):
    if target.startswith(("http://", "https://")):
        return target
    https_url = f"https://{target}"
    try:
        resp = requests.head(https_url, timeout=5, allow_redirects=True)
        if resp.status_code < 400:
            return https_url
    except requests.RequestException:
        pass
    return f"http://{target}"


def parse_zap_html_report(html_content):
    soup = BeautifulSoup(html_content, "html.parser")
    summary = soup.find("table", class_="alerts")
    if not summary:
        return {"alerts": []}

    alerts = []
    for row in summary.find_all("tr")[1:]:
        cols = row.find_all("td")
        if len(cols) != 3:
            continue
        alerts.append({
            "type": cols[0].get_text(strip=True),
            "risk": cols[1].get_text(strip=True),
            "instances": int(cols[2].get_text(strip=True) or 0),
            "description": "", "url": [], "solution": "",
            "reference": [], "cwe_id": "", "wasc_id": "", "plugin_id": ""
        })

    for detail in soup.find_all("table", {"class": "results"}):
        header = detail.find(
            "th", {"class": lambda c: c and c.startswith("risk-")})
        name = header.find_next_sibling("th").get_text(strip=True)
        entry = next((a for a in alerts if a["type"] == name), None)
        if not entry:
            continue
        for tr in detail.find_all("tr"):
            cols = tr.find_all("td")
            if len(cols) != 2:
                continue
            key = cols[0].get_text(strip=True)
            val = cols[1].get_text(strip=True, separator=" ").strip()
            if key == "Description":
                entry["description"] = val
            elif key == "URL":
                entry["url"].append(cols[1].find("a")["href"])
            elif key == "Instances":
                entry["instances"] = int(val or entry["instances"])
            elif key == "Solution":
                entry["solution"] = val
            elif key == "Reference":
                entry["reference"] = [a["href"]
                                      for a in cols[1].find_all("a", href=True)]
            elif key == "CWE Id":
                entry["cwe_id"] = val
            elif key == "WASC Id":
                entry["wasc_id"] = val
            elif key == "Plugin Id":
                entry["plugin_id"] = val

    return {"alerts": alerts}


def extract_spidered_urls():
    result = subprocess.run(["zap-cli", "urls"],
                            capture_output=True, text=True)
    return set(result.stdout.splitlines())


def zap_scan_url_with_timeout(url, timeout=60):
    try:
        subprocess.run(["zap-cli", "active-scan", url],
                       timeout=timeout, check=True)
        return {"url": url, "status": "scanned"}
    except subprocess.TimeoutExpired:
        return {"url": url, "status": "timed_out"}
    except subprocess.CalledProcessError:
        return {"url": url, "status": "error"}


def run_zap_scan(target, zap_mode="quick-scan", timeout=60, fast_mode=False, port=8080):
    zap_proc = start_zap_daemon(port)
    try:
        safe_url = ensure_valid_url(target)
        subprocess.run(["zap-cli", "--port", str(port),
                       "open-url", safe_url], check=True)
        if zap_mode in ("quick-scan", "medium"):
            subprocess.run(["zap-cli", "--port", str(port),
                           "spider", safe_url], check=True)
        if zap_mode == "aggressive":
            subprocess.run(["zap-cli", "--port", str(port),
                           "ajax-spider", safe_url], check=True)
        subprocess.run(["zap-cli", "--port", str(port),
                       "status", "-t", str(timeout)], check=True)
        if zap_mode != "quick-scan":
            subprocess.run(["zap-cli", "--port", str(port),
                           "active-scan", safe_url], check=True)
        subprocess.run(["zap-cli", "--port", str(port), "report",
                       "-o", "zap_output.html", "-f", "html"], check=True)
        html = Path("zap_output.html").read_text()
        return {"raw_json": parse_zap_html_report(html)["alerts"]}
    finally:
        if zap_proc:
            try:
                zap_proc.kill()
                click.secho("🛑 Killed ZAP daemon", fg="red")
            except Exception as e:
                click.secho(f"⚠️ Failed to kill ZAP daemon: {e}", fg="yellow")


def preprocess_outputs(raw):
    cleaned = {}
    for phase, data in raw.items():
        if isinstance(data, dict):
            cleaned[phase] = {}
            for tool, out in data.items():
                if isinstance(out, str):
                    lines = [
                        l for l in out.splitlines()
                        if any(k in l.lower() for k in ["/", "open", "found", "sql", "vulnerable", "subdomain", "takeover", "port"])
                        and not l.strip().startswith(("[*]", "+", "-", "!")) and "403" not in l and "200" not in l
                    ]
                    cleaned[phase][tool] = "\n".join(
                        sorted(set(lines))) or "No actionable data."
                else:
                    cleaned[phase][tool] = out
        else:
            cleaned[phase] = data
    return cleaned


def run_llm(raw, target):
    click.secho("🤖 Summarizing…", fg="bright_magenta")
    if "vulnerability" in raw and "zap" in raw["vulnerability"]:
        zap_data = raw["vulnerability"]["zap"]
        if isinstance(zap_data, dict) and zap_data.get("raw_json"):
            prompt = (
                "You are a cybersec analyst. Analyze the following ZAP scan results (in JSON), summarize findings by risk level, "
                "list each vulnerability found, affected endpoints, and recommend next steps.\n\n"
                + json.dumps(zap_data["raw_json"], indent=2)
            )
            response = ollama.chat(model="mistral", messages=[
                                   {"role": "user", "content": prompt}])
            return response.get("message", {}).get("content", "").strip() or "Error: Summary failed."

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
        retry = "Extract every actionable takeaway—be concise.\n\n" + \
            json.dumps(data, indent=2)
        resp = ollama.chat(model="mistral", messages=[
                           {"role": "user", "content": retry}])
        summary = resp.get("message", {}).get(
            "content", "Error generating").strip()

    Path(f"{sanitize_target(target)}_summary.txt").write_text(
        summary, encoding="utf-8")
    return summary


def extract_root_domain(target):
    hostname = urlparse(target).hostname or target
    parts = hostname.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else hostname


def build_command(tool, flags, target):
    real_target = extract_root_domain(
        target) if tool == "subfinder" else target
    real_flags = flags.replace("{{target}}", real_target)
    key = tool.replace("-", "").lower()
    return TOOL_CMD_MAP.get(key, lambda f: f"{tool} {f}")(real_flags)


@click.command()
@click.option("--sudo", "use_sudo", is_flag=True, help="Prefix all tools with sudo")
@click.option("--profile", type=click.Choice(list(PROFILES.keys())), default=None, help="Pick a prebuilt scan profile")
@click.option("--mode", default=None, help="Mode within the profile (light/medium/aggressive/etc.)")
@click.option("--list-profiles", is_flag=True, help="List available profiles and exit")
@click.option("--out-dir", type=click.Path(), default=".", help="Directory to save output files")
@click.option("--nm", default=None, help="Run nmap with FLAGS")
@click.option("--am", default=None, help="Run amass with FLAGS")
@click.option("--ns", default=None, help="Run nslookup with FLAGS")
@click.option("--dg", default=None, help="Run dig with FLAGS")
@click.option("--sf", default=None, help="Run subfinder with FLAGS")
@click.option("--sj", default=None, help="Run subjack with FLAGS")
@click.option("--th", default=None, help="Run theHarvester with FLAGS")
@click.option("--nk", default=None, help="Run nikto with FLAGS")
@click.option("--zp", default=None, help="Run zap-cli with FLAGS")
@click.option("--sm", default=None, help="Run sqlmap with FLAGS")
@click.option("--zap-timeout", default=60, help="Timeout per URL for ZAP active scan (in seconds)")
@click.option("--fast", is_flag=True, help="Enable fast scan (skips ajax spider)")
@click.argument("target", required=False)
def main(use_sudo, profile, mode, list_profiles, out_dir,
         nm, am, ns, dg, sf, sj, th, nk, zp, sm, zap_timeout, fast, target):
    global use_sudo_flag
    use_sudo_flag = use_sudo

    if list_profiles:
        click.secho("Available Profiles & Modes:\n", fg="cyan", bold=True)
        for prof, data in PROFILES.items():
            click.echo(f"{prof}: {data['description']}")
            for m, d in data['modes'].items():
                click.echo(f"  - {m}: {d['description']}")
        return

    raw = {"recon": {}, "vulnerability": {}}

    # ─── TARGET RESOLUTION ───────────────────────────────────────────────
    # a) If positional given → use it
    if target:
        resolved = target

    # b) Else if a single tool-flag is set → extract from that
    elif any([nm, am, ns, dg, sf, sj, th, nk, zp, sm]):
        for flag in (nm, am, ns, dg, sf, sj, th, nk, zp, sm):
            if flag:
                for p in flag.split():
                    if p.startswith(("http://", "https://")) or p.count(".") >= 1:
                        resolved = p
                        break
            if 'resolved' in locals():
                break

    # c) Else if profile+mode without target → error
    elif profile and mode:
        raise click.BadParameter(
            "You must supply a target with --profile/--mode. "
            "e.g. `cybercli --profile web-vuln-scan --mode light example.com`"
        )

    # d) Nothing → error
    else:
        raise click.BadParameter(
            "Target is required. Pass it positionally or in your tool flags "
            "like `--nk \"-h https://example.com\"`."
        )

    # Now that we have one, stick it back and sanitize
    target = resolved
    safe_target = sanitize_target(target)
    # ────────────────────────────────────────────────────────────────────

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    click.secho(
        f"🚀 Starting assessment for {target}\n", fg="bright_cyan", bold=True)

    single_flags = any(v is not None for v in [
                       nm, am, ns, dg, sf, sj, th, nk, zp, sm])
    if not profile and not single_flags:
        profile, mode = "web-vuln-scan", "aggressive"
        click.secho(
            "🧠 No flags/profile given – defaulting to web-vuln-scan:aggressive", fg="yellow")

    overrides = {"nmap": nm, "amass": am, "nslookup": ns, "dig": dg,
                 "subfinder": sf, "subjack": sj, "theharvester": th,
                 "nikto": nk, "zap-cli": zp, "sqlmap": sm}

    if profile:
        if mode not in PROFILES[profile]["modes"]:
            raise click.BadParameter(
                f"--mode must be one of {list(PROFILES[profile]['modes'])}")
        for tool, flags in PROFILES[profile]["modes"][mode]["tools"].items():
            if overrides.get(tool) is not None:
                click.secho(f"⚠️ Overriding {tool} flags via CLI", fg="yellow")
                flags = overrides[tool]
            flags = flags.replace("{{out_dir}}", str(out_dir))

            if tool == "zap-cli":
                raw["vulnerability"]["zap"] = run_zap_scan(
                    target, mode, zap_timeout, fast)
            elif tool == "subjack":
                click.secho("🔗 Running Subjack takeover check…", fg="yellow")
                root = extract_root_domain(target)
                sub_file = out_dir / "subdomains.txt"
                with open(sub_file, "w") as f:
                    proc = subprocess.run(["subfinder", "-d", root, "-silent"],
                                          stdout=f, stderr=subprocess.PIPE, check=False)
                if proc.stderr:
                    click.secho(
                        f"❌ subfinder stderr: {proc.stderr.decode()}", fg="red")
                cmd = f"subjack -w {sub_file} " + flags
                raw["recon"]["subjack"] = run_command(cmd, "subjack")
            else:
                cmd = build_command(tool, flags, target)
                section = TOOL_SECTIONS.get(tool, "recon")
                raw[section][tool] = run_command(cmd, tool)
    else:
        for tool, flags in overrides.items():
            if flags is None:
                continue
            flags = flags.replace("{{out_dir}}", str(out_dir))
            if tool == "zap-cli":
                raw["vulnerability"]["zap"] = run_zap_scan(
                    target, flags.strip().lower(), zap_timeout, fast)
            elif tool == "subjack":
                click.secho("🔗 Running Subjack takeover check…", fg="yellow")
                raw["recon"]["subjack"] = run_command(
                    f"subjack {flags}", "subjack")
            else:
                cmd = build_command(tool, flags, target)
                section = TOOL_SECTIONS.get(tool, "recon")
                raw[section][tool] = run_command(cmd, tool)
                if tool == "subfinder" and raw[section][tool].strip():
                    (out_dir / "subdomains.txt").write_text(
                        raw[section][tool], encoding="utf-8")

    summary = run_llm(raw, target)
    (out_dir / f"{safe_target}_report.json").write_text(json.dumps(raw, indent=2))
    (out_dir / f"{safe_target}_summary.txt").write_text(summary,
                                                        encoding="utf-8")

    click.secho("\n===== 📜 Final Report =====", fg="bright_magenta", bold=True)
    click.echo(summary)
    click.secho(f"\n✅ Done. Output saved to {out_dir}", fg="bright_green")


if __name__ == "__main__":
    main()