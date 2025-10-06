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

ZAP_API = "http://localhost:8080"
API_KEY = ""  # blank since we already start ZAP with `-config api.disablekey=true`

# === NEW: Skip paid tools ===
SKIPPED_TOOLS = ["shodan", "censys", "binaryedge", "zoomeye"]


def load_profiles():
    with CONFIG_PATH.open() as f:
        data = yaml.safe_load(f)
    return data.get("profiles", {})


PROFILES = load_profiles()

TOOL_PATHS = {
    "dirsearch":    os.getenv("CYBERCLI_DIRSEARCH_PATH", "/Users/ASL-User/Desktop/CyberCli/dirsearch/dirsearch.py"),
    "theHarvester": os.getenv("CYBERCLI_HARVESTER_PATH", ""),
    "sqlmap":       os.getenv("CYBERCLI_SQLMAP_PATH",    "/Users/ASL-User/Desktop/CyberCli/sqlmap/sqlmap.py"),
}

TOOL_CMD_MAP = {
    "nmap": lambda flags: f"nmap {flags}",
    "nikto": lambda flags: f"nikto {flags}",
    "sqlmap": lambda flags: f"python3 {TOOL_PATHS['sqlmap']} {flags}",
    "dirsearch": lambda flags: f"python3 {TOOL_PATHS['dirsearch']} {flags}",
    "gobuster": lambda flags: f"gobuster {flags}",
    "theharvester": lambda flags: f"theHarvester {flags}",
    "amass": lambda flags: f"amass {flags}",
    "dig": lambda flags: f"dig {flags}",
    "nslookup": lambda flags: f"nslookup {flags}",
    "subfinder": lambda flags: f"subfinder {flags}",
}

TOOL_SECTIONS = {
    "nmap": "recon", "amass": "recon", "nslookup": "recon", "dig": "recon",
    "subfinder": "recon", "subjack": "recon", "theharvester": "recon",
    "gobuster": "recon", "dirsearch": "recon", "nikto": "vulnerability",
    "sqlmap": "vulnerability"
}


def sanitize_target(target):
    return target.replace("https://", "").replace("http://", "").replace("/", "_")


def check_tool_installed(tool):
    if tool in TOOL_PATHS and TOOL_PATHS[tool]:
        return Path(TOOL_PATHS[tool]).exists()
    return bool(subprocess.getoutput(f"which {tool}").strip())


def run_command(full_cmd, tool):
    click.secho(f"🚀 Running {tool} with:\n{full_cmd}\n", fg="blue")
    proc = subprocess.Popen(full_cmd, shell=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out_bytes, _ = proc.communicate()
    output = out_bytes.decode(errors="ignore")
    filtered = "\n".join(
        line for line in output.splitlines()
        if "coroutine" not in line.lower()
           and "was never awaited" not in line.lower()
    )
    if proc.returncode != 0:
        return f"[ERROR] {tool} exited with code {proc.returncode}\n{filtered}"
    return filtered


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


def zap_wait_for_completion(url, scan_type, timeout, scan_id=None):
    """
    Wait until a Spider/Ajax/Active scan finishes, or timeout seconds elapse.
    Handles missing 'status' keys by retrying until valid JSON is returned.
    """
    start = time.time()
    while True:
        elapsed = time.time() - start
        if elapsed > timeout:
            click.secho(
                f"⚠️ {scan_type} did not complete within {timeout}s, proceeding anyway.", fg="yellow")
            break

        try:
            if scan_type == "spider":
                resp = requests.get(
                    f"{ZAP_API}/JSON/spider/view/status/",
                    params={"apikey": API_KEY},
                    timeout=5
                ).json()
                raw_status = resp.get("status") or resp.get("value")

            elif scan_type == "ajax":
                resp = requests.get(
                    f"{ZAP_API}/JSON/ajaxSpider/view/status/",
                    params={"apikey": API_KEY},
                    timeout=5
                ).json()
                raw_status = resp.get("status") or resp.get("value")

            elif scan_type == "active":
                resp = requests.get(
                    f"{ZAP_API}/JSON/ascan/view/status/",
                    params={"apikey": API_KEY, "scanId": scan_id},
                    timeout=5
                ).json()
                raw_status = resp.get("status") or resp.get("value")

            else:
                break

            # If we got a string or int, parse it
            if raw_status is not None:
                try:
                    status = int(raw_status)
                except (ValueError, TypeError):
                    # Some endpoints return strings like "running"
                    status = None

                # Break when we reach 100% (or non‑running for Ajax)
                if scan_type == "ajax":
                    if raw_status != "running":
                        break
                elif status is not None and status >= 100:
                    break

        except requests.RequestException as e:
            # Network glitch → retry
            click.secho(f"Retrying {scan_type} status check: {e}", fg="yellow")

        time.sleep(2)


def zap_spider(url, timeout):
    requests.get(f"{ZAP_API}/JSON/spider/action/scan/",
                 params={"apikey": API_KEY, "url": url})
    zap_wait_for_completion(url, "spider", timeout=timeout)


def zap_ajax_spider(url, timeout):
    requests.get(f"{ZAP_API}/JSON/ajaxSpider/action/scan/",
                 params={"apikey": API_KEY, "url": url})
    zap_wait_for_completion(url, "ajax", timeout=timeout)


def zap_active_scan(url, timeout):
    resp = requests.get(f"{ZAP_API}/JSON/ascan/action/scan/",
                        params={"apikey": API_KEY, "url": url}).json()
    scan_id = resp.get("scan")
    zap_wait_for_completion(url, "active", scan_id=scan_id, timeout=timeout)


def zap_get_alerts():
    return requests.get(f"{ZAP_API}/JSON/core/view/alerts/", params={"apikey": API_KEY}).json()


def zap_get_html_report():
    return requests.get(f"{ZAP_API}/OTHER/core/other/htmlreport/", params={"apikey": API_KEY}).text


def run_zap_scan(target, zap_mode="quick-scan", timeout=60, fast_mode=False, port=8080):
    """
    Runs ZAP scan using API instead of zap-cli.
    Auto‑starts the ZAP daemon if it isn’t already running, and kills it when done.
    Modes:
      - quick-scan   → Spider only (passive scanning happens automatically)
      - medium       → Spider + Active Scan
      - aggressive   → Spider + Ajax Spider + Active Scan
    """
    # ── Auto‑start ZAP if needed ─────────────────────────────────────────
    zap_proc = None
    try:
        # see if ZAP is already up
        requests.get(f"{ZAP_API}/JSON/core/view/version/", timeout=2)
    except requests.exceptions.RequestException:
        click.secho("ZAP not running - launching daemon…", fg="yellow")
        zap_proc = subprocess.Popen(
            ["/Applications/ZAP.app/Contents/Java/zap.sh",
             "-daemon", "-port", str(port), "-config", "api.disablekey=true"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        # wait for ZAP to be ready
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                requests.get(f"{ZAP_API}/JSON/core/view/version/", timeout=1)
                click.secho("ZAP daemon is up", fg="green")
                break
            except requests.exceptions.RequestException:
                time.sleep(1)
        else:
            zap_proc.kill()
            raise RuntimeError("ZAP failed to start within timeout.")

    click.secho(f"⚡ Using ZAP API mode: {zap_mode}", fg="cyan")

    # ── Perform the scan ─────────────────────────────────────────────────
    target_url = ensure_valid_url(target)
    click.secho(f"  • Creating new ZAP session", fg="blue")
    requests.get(
        f"{ZAP_API}/JSON/core/action/newSession/",
        params={"apikey": API_KEY, "name": sanitize_target(target_url)},
        timeout=5
    )

    # ── Open the URL ─────────────────────────────────────────────────────
    click.secho(f"  • Opening URL in ZAP: {target_url}", fg="blue")
    requests.get(
        f"{ZAP_API}/JSON/core/action/accessUrl/",
        params={"apikey": API_KEY, "url": target_url},
        timeout=10
    )

    # ── Spider ───────────────────────────────────────────────────────────
    zap_spider(target_url, timeout=timeout)

    # ── Ajax Spider for aggressive ──────────────────────────────────────
    if zap_mode == "aggressive":
        zap_ajax_spider(target_url, timeout=timeout)

    # ── Active Scan ─────────────────────────────────────────────────────
    if zap_mode in ("medium", "aggressive"):
        zap_active_scan(target_url, timeout=timeout)

    # ── Export Reports ───────────────────────────────────────────────────
    html_report = zap_get_html_report()
    Path("zap_output.html").write_text(html_report, encoding="utf-8")
    alerts_json = zap_get_alerts()
    alerts = alerts_json.get("alerts", [])
    # ── Print passive vs active alert counts ────────────────────────────
    passive = [a for a in alerts if a.get("method") == "Passive"]
    active = [a for a in alerts if a.get("method") == "Active"]
    click.secho(
        f"📝 ZAP found {len(passive)} passive alerts and {len(active)} active alerts",
        fg="yellow"
    )
    result = {"raw_json": alerts}

    # ── Teardown ─────────────────────────────────────────────────────────
    if zap_proc:
        zap_proc.kill()
        click.secho("🛑 Killed ZAP daemon", fg="red")

    return result


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

# This was an experiment to see if our separate LLM summarization function could handle different tools outputs effectively. (In the next version that is cybercli9.py adding separate functions for each tool, we will use the same approach but with more specialized prompts for each tool's output


def build_theharvester_prompt(output, target):
    return f"""
You are a cybersecurity analyst specializing in OSINT.
Analyze the following theHarvester scan output for the target {target}.

### Task:
1. List all identified assets and intelligence clearly, grouped by category:
   - Emails
   - Phone numbers
   - IP addresses
   - Domains & subdomains
   - Hostnames
   - Cloud or CDN endpoints (e.g., AWS, Azure, Cloudflare, load balancers)
   - ASN and network ownership details
   - People names, organizations, or any sensitive identifiers
2. For each finding:
   - Provide a short contextual one-line description explaining what it represents
     (e.g., if an IP belongs to Cloudflare, note it; if an email is corporate, note 
     its potential relevance, etc.)
3. Identify patterns or anomalies such as:
   - Multiple emails from the same domain → mention it as a pattern.
   - Potential takeover risks (e.g., dangling DNS, misconfigured LB) → note them.
   - Gaps in data (e.g., "no emails found") → mention explicitly.

### Deliverables:
- A clear, well-structured summary grouped by category.
- Bullet-point format preferred.
- Concise, professional language.

Here is the raw theHarvester output:
{output}
"""


def run_llm(raw, target):
    click.secho("🤖 Summarizing…", fg="bright_magenta")
    summaries = []
    # Specialized: theHarvester
    harv = raw.get("recon", {}).get("theharvester")
    click.secho(f"DEBUG: harv is {repr(harv)[:100]}", fg="red")
    if harv:
        prompt = build_theharvester_prompt(harv, target)
        resp = ollama.chat(model="mistral", messages=[
                           {"role": "user", "content": prompt}])
        text = resp.get("message", {}).get("content", "").strip()
        summaries.append(text or "[Error summarizing theHarvester output]")
    # Specialized: ZAP
    zap = raw.get("vulnerability", {}).get("zap")
    if zap and isinstance(zap, dict) and zap.get("raw_json"):
        prompt = (
            "You are a cybersec analyst. Analyze the following ZAP scan results (in JSON), "
            "summarize findings by risk level, list each vulnerability found, affected endpoints, "
            "and recommend next steps.\n\n" +
            json.dumps(zap["raw_json"], indent=2)
        )
        resp = ollama.chat(model="mistral", messages=[
                           {"role": "user", "content": prompt}])
        summaries.append(resp.get("message", {}).get("content", "").strip()
                         or "[Error summarizing ZAP output]")
    # Fallback: generic for any remaining data
    # Check if any other outputs exist besides those handled above
    remaining = {}
    for phase, tools in raw.items():
        for tool, out in tools.items():
            if (phase == "recon" and tool == "theharvester") or (phase == "vulnerability" and tool == "zap"):
                continue
            remaining.setdefault(phase, {})[tool] = out
    if any(remaining.values()):
        data = remaining if sum(
            len(v) for v in remaining.values()) == 1 else preprocess_outputs(remaining)
        prompt = (
            "You are a cybersec analyst. Summarize findings, list vulnerabilities if any, "
            "highlight concerns, and recommend next steps.\n\n" +
            json.dumps(data, indent=2)
        )
        resp = ollama.chat(model="mistral", messages=[
                           {"role": "user", "content": prompt}])
        summaries.append(resp.get("message", {}).get("content", "").strip()
                         or "[Error in generic summary]")
    # Combine
    final = "\n\n---\n\n".join(summaries)
    Path(f"{sanitize_target(target)}_summary.txt").write_text(
        final, encoding="utf-8")
    return final


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
@click.option("--out-dir", type=click.Path(), default="/Users/ASL-User_1/Desktop/CyberCli/", help="Directory to save output files")
@click.option("--nm", default=None, help="Run nmap with FLAGS")
@click.option("--am", default=None, help="Run amass with FLAGS")
@click.option("--ns", default=None, help="Run nslookup with FLAGS")
@click.option("--dg", default=None, help="Run dig with FLAGS")
@click.option("--sf", default=None, help="Run subfinder with FLAGS")
@click.option("--sj", default=None, help="Run subjack with FLAGS")
@click.option("--th", default=None, help="Run theHarvester with FLAGS")
@click.option("--nk", default=None, help="Run nikto with FLAGS")
@click.option("--zap-mode", type=click.Choice(["quick-scan", "medium", "aggressive"]),
              default=None, help="Run ZAP scan in specified mode")
@click.option("--sm", default=None, help="Run sqlmap with FLAGS")
@click.option("--zap-timeout", default=60, help="Timeout per URL for ZAP active scan (in seconds)")
@click.option("--fast", is_flag=True, help="Enable fast scan (skips ajax spider)")
@click.argument("target", required=False)
def main(use_sudo, profile, mode, list_profiles, out_dir,
         nm, am, ns, dg, sf, sj, th, nk, zap_mode, sm, zap_timeout, fast, target):
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
    if target:
        resolved = target
    elif any([nm, am, ns, dg, sf, sj, th, nk, zap_mode, sm]):
        for flag in (nm, am, ns, dg, sf, sj, th, nk, sm):
            if not flag:
                continue
            for token in flag.split():
                # skip flags themselves
                if token.startswith("-"):
                    continue
                # absolute URLs
                if token.startswith(("http://", "https://")):
                    resolved = token
                    break
                # domain‐looking tokens: must contain a dot, but not be a known data file
                suffix = Path(token).suffix.lower()
                if token.count(".") >= 1 and suffix not in {".txt", ".json", ".yaml", ".yml"}:
                    resolved = token
                    break
            if 'resolved' in locals():
                break
    elif profile and mode:
        raise click.BadParameter(
            "You must supply a target with --profile/--mode. "
            "e.g. `cybercli --profile web-vuln-scan --mode light example.com`"
        )
    else:
        raise click.BadParameter(
            "Target is required. Pass it positionally or in your tool flags "
            "like `--nk \"-h https://example.com\"`."
        )

    target = resolved
    safe_target = sanitize_target(target)

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    click.secho(
        f"Starting assessment for {target}\n", fg="bright_cyan", bold=True)

    single_flags = any(v is not None for v in [
        nm, am, ns, dg, sf, sj, th, nk, zap_mode, sm
    ])
    if not profile and not single_flags:
        profile, mode = "web-vuln-scan", "aggressive"
        click.secho(
            "No flags/profile given - defaulting to web-vuln-scan:aggressive", fg="yellow"
        )

    overrides = {"nmap": nm, "amass": am, "nslookup": ns, "dig": dg,
                 "subfinder": sf, "subjack": sj, "theharvester": th,
                 "nikto": nk, "zap": zap_mode, "sqlmap": sm}

    if profile:
        if mode not in PROFILES[profile]["modes"]:
            raise click.BadParameter(
                f"--mode must be one of {list(PROFILES[profile]['modes'])}")
        for tool, flags in PROFILES[profile]["modes"][mode]["tools"].items():
            if tool in SKIPPED_TOOLS:
                click.secho(f"Skipping {tool} (paid tool)", fg="yellow")
                continue
            if overrides.get(tool) is not None:
                click.secho(f"⚠️ Overriding {tool} flags via CLI", fg="yellow")
                flags = overrides[tool]
            flags = flags.replace("{{out_dir}}", str(out_dir))

            if tool == "zap":
                raw["vulnerability"]["zap"] = run_zap_scan(
                    target, flags or mode, zap_timeout, fast)
            elif tool == "subjack":
                click.secho("🔗 Running Subjack takeover check…", fg="yellow")
                root = extract_root_domain(target)
                sub_file = out_dir / "subdomains.txt"
                with open(sub_file, "w") as f:
                    proc = subprocess.run(
                        ["subfinder", "-d", root, "-silent"], stdout=f, stderr=subprocess.PIPE, check=False)
                if proc.stderr:
                    click.secho(
                        f"subfinder stderr: {proc.stderr.decode()}", fg="red")
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
            if tool == "zap":
                raw["vulnerability"]["zap"] = run_zap_scan(
                    target, flags.strip().lower() if flags else "quick-scan", zap_timeout, fast)
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
    click.secho(f"\nDone. Output saved to {out_dir}", fg="bright_green")


if __name__ == "__main__":
    main()
