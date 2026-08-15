#!/usr/bin/env python3
"""
sbbt.py

Small single-domain bug-hunting / recon orchestration script.

This script invokes a set of external recon tools (when available) to
collect subdomains, probe HTTP hosts, perform port scans, and run
basic content discovery. It writes outputs to outputs/<domain>/<timestamp>/
and creates a "latest" symlink for convenience.

Tools are invoked only if present on PATH. Potentially intrusive tools
(masscan, sqlmap) require explicit consent via --yes.

Usage examples:
  python3 sbbt.py --domain example.com
  python3 sbbt.py --domain example.com --tools=subfinder,amass,httpx

Note: Review commands before running on targets. Use only on domains you are
authorized to test.
"""

from __future__ import annotations
import argparse
import datetime
import os
import shutil
import subprocess
import sys
import logging
from typing import Dict, List, Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("sbbt")

# Tool command templates. Many tools have slightly differing args across versions ---
# these templates use conservative, widely-supported flags. Adjust as needed.
TOOL_COMMANDS = {
    "assetfinder": lambda domain, out: ["assetfinder", "--subs-only", domain],
    "amass": lambda domain, out: ["amass", "enum", "-d", domain, "-o", out],
    "subfinder": lambda domain, out: ["subfinder", "-d", domain, "-silent", "-o", out],
    "findomain": lambda domain, out: ["findomain", "-t", domain, "-u", out],
    "shuffledns": lambda infile, out: ["shuffledns", "-list", infile, "-r", "/etc/resolv.conf", "-o", out],
    "sublist3r": lambda domain, out: ["sublist3r", "-d", domain, "-o", out],
    "waybackurls": lambda domain, out: ["waybackurls", domain],
    "gau": lambda domain, out: ["gau", domain],
    "gauplus": lambda domain, out: ["gauplus", "--input", domain],
    "hakrawler": lambda domain, out: ["hakrawler", "-domain", domain, "-depth", "2"],
    "httpx": lambda infile, out: ["httpx", "-list", infile, "-silent", "-o", out],
    "dnsx": lambda infile, out: ["dnsx", "-l", infile, "-a", "-resp", "-o", out],
    "naabu": lambda infile, out: ["naabu", "-list", infile, "-o", out],
    "masscan": lambda infile, out: ["masscan", "-iL", infile, "-p0-65535", "--rate", "1000", "-oL", out],
    "nmap": lambda infile, out_prefix: ["nmap", "-iL", infile, "-Pn", "-sV", "-oA", out_prefix],
    "ffuf": lambda url_template, out: ["ffuf", "-u", url_template, "-w", "/usr/share/wordlists/dirb/common.txt", "-o", out],
    "gobuster": lambda url, out: ["gobuster", "dir", "-u", url, "-w", "/usr/share/wordlists/dirb/common.txt", "-o", out],
    "dirsearch": lambda url, out: ["python3", "-m", "dirsearch", "-u", url, "-e", "php,html,asp,aspx,js", "-o", out],
    "sqlmap": lambda target, out: ["sqlmap", "-u", target, "--batch", "-o", out],
}

# List of tool keys in TOOL_COMMANDS (order used for defaults)
ALL_TOOLS = [
    "assetfinder",
    "amass",
    "subfinder",
    "findomain",
    "shuffledns",
    "sublist3r",
    "waybackurls",
    "gau",
    "gauplus",
    "hakrawler",
    "dnsx",
    "httpx",
    "naabu",
    "masscan",
    "nmap",
    "ffuf",
    "gobuster",
    "dirsearch",
    "sqlmap",
]


def detect_tools() -> Dict[str, Optional[str]]:
    found = {}
    for t in ALL_TOOLS:
        found[t] = shutil.which(t)
    return found


def ensure_domain_outdir(base_out: str, domain: str) -> str:
    timestamp = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    domain_dir = os.path.join(base_out, domain)
    out_dir = os.path.join(domain_dir, timestamp)
    os.makedirs(out_dir, exist_ok=True)
    latest_link = os.path.join(domain_dir, "latest")
    try:
        if os.path.islink(latest_link) or os.path.exists(latest_link):
            try:
                os.remove(latest_link)
            except Exception:
                pass
        os.symlink(out_dir, latest_link)
    except Exception:
        logger.debug("Could not create symlink %s -> %s (platform may not support symlinks)", latest_link, out_dir)
    return out_dir


def run_command(cmd: List[str], cwd: Optional[str] = None, out_file: Optional[str] = None, shell: bool = False) -> int:
    logger.info("Running: %s", " ".join(cmd) if isinstance(cmd, list) else str(cmd))
    try:
        if shell:
            proc = subprocess.run(" ".join(cmd) if isinstance(cmd, list) else cmd, shell=True, check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            if out_file:
                with open(out_file, "w", encoding="utf-8") as fh:
                    fh.write(proc.stdout or "")
            print(proc.stdout or "")
            return proc.returncode
        else:
            with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=cwd, text=True) as p:
                with (open(out_file, "w", encoding="utf-8") if out_file else open(os.devnull, "w")) as fh:
                    for line in p.stdout:
                        print(line, end="")
                        fh.write(line)
                p.wait()
                return p.returncode
    except FileNotFoundError:
        logger.warning("Command not found: %s", cmd[0] if isinstance(cmd, list) else cmd)
        return 127
    except Exception as e:
        logger.exception("Error running command: %s", e)
        return 1


def read_lines_strip(path: str) -> List[str]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return [l.strip() for l in fh if l.strip()]
    except Exception:
        return []


def gather_ct(domain: str, outpath: str) -> None:
    """Query crt.sh (JSON) for CT entries (simple, widely-available passive source)."""
    out = outpath
    try:
        import urllib.request, urllib.parse, json
        q = urllib.parse.quote_plus(f"%.{domain}")
        url = f"https://crt.sh/?q={q}&output=json"
        logger.info("Querying crt.sh for %s", domain)
        with urllib.request.urlopen(url, timeout=30) as r:
            raw = r.read().decode("utf-8", errors="ignore")
        # crude JSON parse; crt.sh sometimes returns non-JSON; catch exceptions
        try:
            obj = json.loads(raw)
            names = set()
            for e in obj:
                nv = e.get("name_value") or ""
                for n in nv.splitlines():
                    n = n.strip().lstrip("*.").lower()
                    if n:
                        names.add(n)
            with open(out, "w", encoding="utf-8") as fh:
                fh.write("\n".join(sorted(names)) + ("\n" if names else ""))
        except Exception:
            # fallback: extract host-like tokens
            lines = {tok.strip().lstrip("*.").lower() for tok in raw.replace('"', " ").split() if domain in tok}
            with open(out, "w", encoding="utf-8") as fh:
                fh.write("\n".join(sorted(lines)) + ("\n" if lines else ""))
    except Exception as e:
        logger.warning("crt.sh query failed: %s", e)


def main() -> int:
    p = argparse.ArgumentParser(description="sbbt: small bug-hunting / recon runner (expanded tools)")
    p.add_argument("--domain", help="Target domain")
    p.add_argument("--outdir", default="outputs", help="Base outputs directory")
    p.add_argument("--targets-file", help="Optional file with targets (one per line)")
    p.add_argument("--tools", help=f"Comma-separated tools to run (default: all). Options: {', '.join(ALL_TOOLS)}")
    p.add_argument("--yes", action="store_true", help="Allow intrusive tools (masscan, sqlmap, etc.)")
    p.add_argument("--dry-run", action="store_true", help="Show commands but do not execute")
    args, _ = p.parse_known_args()

    if not args.domain and not args.targets_file:
        logger.error("Either --domain or --targets-file is required")
        p.print_help()
        return 2

    selected = ALL_TOOLS if not args.tools else [t.strip() for t in args.tools.split(",") if t.strip()]
    tools_on_path = detect_tools()

    primary = args.domain if args.domain else os.path.basename(args.targets_file)
    outdir = ensure_domain_outdir(args.outdir, primary)
    logger.info("Outputs to %s", outdir)

    subdomains_file = os.path.join(outdir, "subdomains.txt")

    # copy targets-file if provided
    if args.targets_file:
        targets = read_lines_strip(args.targets_file)
        if targets:
            with open(subdomains_file, "w", encoding="utf-8") as fh:
                fh.write("\n".join(targets) + "\n")
            logger.info("Copied %d targets to %s", len(targets), subdomains_file)

    # 0) Certificate Transparency
    crt_out = os.path.join(outdir, "crtsh_subdomains.txt")
    if args.domain:
        if args.dry_run:
            logger.info("DRY RUN: crt.sh lookup for %s -> %s", args.domain, crt_out)
        else:
            gather_ct(args.domain, crt_out)
            if os.path.exists(crt_out):
                with open(subdomains_file, "a", encoding="utf-8") as fh:
                    fh.write("\n")
                    fh.write(open(crt_out, "r", encoding="utf-8").read())

    # Passive tools: assetfinder, findomain, subfinder, amass, shuffledns, sublist3r
    passive_tools = ["assetfinder", "findomain", "subfinder", "amass", "shuffledns", "sublist3r"]
    for t in passive_tools:
        if t not in selected:
            continue
        if not tools_on_path.get(t):
            logger.debug("%s not present; skipping", t)
            continue
        out = os.path.join(outdir, f"{t}.txt")
        # protect against missing command templates
        if t not in TOOL_COMMANDS:
            logger.debug("No command template for %s; skipping", t)
            continue
        cmd = TOOL_COMMANDS[t](args.domain, out)
        if args.dry_run:
            logger.info("DRY RUN: %s", " ".join(cmd))
        else:
            rc = run_command(cmd, out_file=out)
            if rc == 0 and os.path.exists(out):
                with open(subdomains_file, "a", encoding="utf-8") as fh:
                    fh.write("\n")
                    with open(out, "r", encoding="utf-8") as rf:
                        fh.write(rf.read())

    # Archives/Endpoints: waybackurls, gau, gauplus, hakrawler
    archive_tools = ["waybackurls", "gau", "gauplus", "hakrawler"]
    for t in archive_tools:
        if t not in selected:
            continue
        if not tools_on_path.get(t):
            logger.debug("%s not present; skipping", t)
            continue
        out = os.path.join(outdir, f"{t}.txt")
        if t not in TOOL_COMMANDS:
            logger.debug("No command template for %s; skipping", t)
            continue
        cmd = TOOL_COMMANDS[t](args.domain, out)
        if args.dry_run:
            logger.info("DRY RUN: %s", " ".join(cmd))
        else:
            run_command(cmd, out_file=out)
            # try to extract hosts to subdomains_file
            if os.path.exists(out):
                with open(out, "r", encoding="utf-8", errors="ignore") as fh, open(subdomains_file, "a", encoding="utf-8") as sfh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            from urllib.parse import urlparse
                            h = urlparse(line).hostname or line
                        except Exception:
                            h = line
                        sfh.write(h + "\n")

    # Deduplicate subdomains
    if os.path.exists(subdomains_file):
        items = sorted(set(read_lines_strip(subdomains_file)))
        with open(subdomains_file, "w", encoding="utf-8") as fh:
            fh.write("\n".join(items) + ("\n" if items else ""))
        logger.info("Consolidated subdomains: %d", len(items))

    # DNS resolution / enrichment with dnsx
    if "dnsx" in selected and tools_on_path.get("dnsx") and os.path.exists(subdomains_file):
        dnsx_out = os.path.join(outdir, "dnsx.txt")
        if args.dry_run:
            logger.info("DRY RUN: dnsx -l %s", subdomains_file)
        else:
            run_command(TOOL_COMMANDS["dnsx"](subdomains_file, dnsx_out), out_file=dnsx_out)

    # HTTP probing with httpx (rate-limited)
    if "httpx" in selected and tools_on_path.get("httpx") and os.path.exists(subdomains_file):
        httpx_out = os.path.join(outdir, "httpx.json")
        if args.dry_run:
            logger.info("DRY RUN: httpx -list %s", subdomains_file)
        else:
            run_command(TOOL_COMMANDS["httpx"](subdomains_file, httpx_out), out_file=httpx_out)

    # Port scanning: naabu (non-intrusive), masscan (intrusive), nmap
    if "naabu" in selected and tools_on_path.get("naabu") and os.path.exists(subdomains_file):
        naabu_out = os.path.join(outdir, "naabu.txt")
        if args.dry_run:
            logger.info("DRY RUN: naabu -list %s", subdomains_file)
        else:
            run_command(TOOL_COMMANDS["naabu"](subdomains_file, naabu_out), out_file=naabu_out)

    if "masscan" in selected:
        if tools_on_path.get("masscan") and os.path.exists(subdomains_file):
            if not args.yes:
                logger.warning("masscan is intrusive and requires --yes to run; skipping")
            else:
                masscan_out = os.path.join(outdir, "masscan.txt")
                if args.dry_run:
                    logger.info("DRY RUN: masscan -iL %s", subdomains_file)
                else:
                    run_command(TOOL_COMMANDS["masscan"](subdomains_file, masscan_out), out_file=masscan_out)
        else:
            logger.debug("masscan not found or no subdomains; skipping")

    if "nmap" in selected and tools_on_path.get("nmap"):
        nmap_in = os.path.join(outdir, "naabu.txt") if os.path.exists(os.path.join(outdir, "naabu.txt")) else subdomains_file
        if os.path.exists(nmap_in):
            prefix = os.path.join(outdir, "nmap")
            if args.dry_run:
                logger.info("DRY RUN: nmap -iL %s", nmap_in)
            else:
                run_command(TOOL_COMMANDS["nmap"](nmap_in, prefix))
        else:
            logger.debug("No input for nmap; skipping")

    # Content discovery: ffuf/gobuster/dirsearch
    if "ffuf" in selected and tools_on_path.get("ffuf") and args.domain:
        ffuf_out = os.path.join(outdir, "ffuf.txt")
        url_template = f"https://FUZZ.{args.domain}/"
        if args.dry_run:
            logger.info("DRY RUN: ffuf %s", url_template)
        else:
            run_command(TOOL_COMMANDS["ffuf"](url_template, ffuf_out), out_file=ffuf_out)

    if "gobuster" in selected and tools_on_path.get("gobuster") and args.domain:
        gob_out = os.path.join(outdir, "gobuster.txt")
        url = f"https://{args.domain}/"
        if args.dry_run:
            logger.info("DRY RUN: gobuster dir %s", url)
        else:
            run_command(TOOL_COMMANDS["gobuster"](url, gob_out), out_file=gob_out)

    if "dirsearch" in selected and tools_on_path.get("dirsearch") and args.domain:
        dir_out = os.path.join(outdir, "dirsearch.txt")
        url = f"https://{args.domain}/"
        if args.dry_run:
            logger.info("DRY RUN: dirsearch %s", url)
        else:
            run_command(TOOL_COMMANDS["dirsearch"](url, dir_out), out_file=dir_out)

    # sqlmap (intrusive) - require explicit consent via --yes
    if "sqlmap" in selected and tools_on_path.get("sqlmap"):
        if not args.yes:
            logger.warning("sqlmap is intrusive; re-run with --yes to enable or omit sqlmap from --tools")
        else:
            target = None
            httpx_json = os.path.join(outdir, "httpx.json")
            # simple heuristic: pick first discovered URL
            if os.path.exists(httpx_json):
                for line in read_lines_strip(httpx_json):
                    if line.startswith("http"):
                        target = line
                        break
            if not target and args.domain:
                target = f"http://{args.domain}/"
            if target:
                sql_out = os.path.join(outdir, "sqlmap.log")
                if args.dry_run:
                    logger.info("DRY RUN: sqlmap -u %s", target)
                else:
                    run_command(TOOL_COMMANDS["sqlmap"](target, sql_out), out_file=sql_out)
            else:
                logger.debug("No target found for sqlmap; skipping")

    logger.info("sbbt run complete. Check %s for outputs", outdir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
