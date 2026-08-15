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
                    fh.write(proc.stdout)
            print(proc.stdout)
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


def main() -> int:
    p = argparse.ArgumentParser(description="sbbt: small bug-hunting / recon runner (expanded tools)")
    p.add_argument("--domain", help="Domain to target")
    p.add_argument("--outdir", default="outputs", help="Base outputs directory (default: outputs)")
    p.add_argument("--targets-file", help="Optional file with targets (one per line)")
    p.add_argument("--tools", help=f"Comma-separated list of tools to run (default: all). Options: {', '.join(ALL_TOOLS)}")
    p.add_argument("--yes", action="store_true", help="Assume yes for any prompts (required for intrusive tools like masscan/sqlmap)")
    p.add_argument("--dry-run", action="store_true", help="Show what would run but do not execute")
    args, extra = p.parse_known_args()

    if not args.domain and not args.targets_file:
        logger.error("Either --domain or --targets-file is required")
        p.print_help()
        return 2

    selected = ALL_TOOLS
    if args.tools:
        selected = [t.strip() for t in args.tools.split(",") if t.strip()]

    tools_on_path = detect_tools()

    # Prepare outdir
    primary_target = args.domain if args.domain else os.path.basename(args.targets_file)
    outdir = ensure_domain_outdir(args.outdir, primary_target)
    logger.info("Outputs will be written to %s", outdir)

    # Shared files
    subdomains_file = os.path.join(outdir, "subdomains.txt")

    # If a targets file was provided, copy it to outdir and use it
    if args.targets_file:
        targets = read_lines_strip(args.targets_file)
        if targets:
            with open(subdomains_file, "w", encoding="utf-8") as fh:
                fh.write("\n".join(targets) + "\n")
            logger.info("Copied %d targets from %s to %s", len(targets), args.targets_file, subdomains_file)

    # 1) Assetfinder
    if "assetfinder" in selected:
        if tools_on_path.get("assetfinder"):
            out = os.path.join(outdir, "assetfinder.txt")
            cmd = TOOL_COMMANDS["assetfinder"](args.domain, out)
            if args.dry_run:
                logger.info("DRY RUN: %s", " ".join(cmd))
            else:
                rc = run_command(cmd, out_file=out)
                if rc == 0:
                    with open(subdomains_file, "a", encoding="utf-8") as fh:
                        fh.write("\n")
                        fh.write(open(out, "r", encoding="utf-8").read())
        else:
            logger.debug("assetfinder not found; skipping")

    # 2) subfinder
    if "subfinder" in selected:
        if tools_on_path.get("subfinder"):
            out = os.path.join(outdir, "subfinder.txt")
            cmd = TOOL_COMMANDS["subfinder"](args.domain, out)
            if args.dry_run:
                logger.info("DRY RUN: %s", " ".join(cmd))
            else:
                rc = run_command(cmd, out_file=out)
                if rc == 0 and os.path.exists(out):
                    with open(subdomains_file, "a", encoding="utf-8") as fh:
                        fh.write("\n")
                        fh.write(open(out, "r", encoding="utf-8").read())
        else:
            logger.warning("subfinder not found on PATH; skipping")

    # 3) amass
    if "amass" in selected:
        if tools_on_path.get("amass"):
            out = os.path.join(outdir, "amass.txt")
            cmd = TOOL_COMMANDS["amass"](args.domain, out)
            if args.dry_run:
                logger.info("DRY RUN: %s", " ".join(cmd))
            else:
                run_command(cmd, out_file=out)
                if os.path.exists(out):
                    with open(subdomains_file, "a", encoding="utf-8") as fh:
                        fh.write("\n")
                        fh.write(open(out, "r", encoding="utf-8").read())
        else:
            logger.debug("amass not found; skipping")

    # 4) sublist3r (if installed)
    if "sublist3r" in selected:
        if tools_on_path.get("sublist3r"):
            out = os.path.join(outdir, "sublist3r.txt")
            cmd = TOOL_COMMANDS["sublist3r"](args.domain, out)
            if args.dry_run:
                logger.info("DRY RUN: %s", " ".join(cmd))
            else:
                run_command(cmd, out_file=out)
                if os.path.exists(out):
                    with open(subdomains_file, "a", encoding="utf-8") as fh:
                        fh.write("\n")
                        fh.write(open(out, "r", encoding="utf-8").read())
        else:
            logger.debug("sublist3r not found; skipping")

    # 5) Certificate transparency & archive tools (waybackurls, gau, gauplus)
    wayback_out = os.path.join(outdir, "wayback_urls.txt")
    if "waybackurls" in selected and tools_on_path.get("waybackurls"):
        if args.dry_run:
            logger.info("DRY RUN: waybackurls %s", args.domain)
        else:
            rc = run_command(TOOL_COMMANDS["waybackurls"](args.domain, wayback_out), out_file=wayback_out)
    else:
        logger.debug("waybackurls not found; skipping")

    if "gau" in selected and tools_on_path.get("gau"):
        gau_out = os.path.join(outdir, "gau.txt")
        if args.dry_run:
            logger.info("DRY RUN: gau %s", args.domain)
        else:
            run_command(TOOL_COMMANDS["gau"](args.domain, gau_out), out_file=gau_out)
    else:
        logger.debug("gau not found; skipping")

    if "gauplus" in selected and tools_on_path.get("gauplus"):
        gauplus_out = os.path.join(outdir, "gauplus.txt")
        if args.dry_run:
            logger.info("DRY RUN: gauplus %s", args.domain)
        else:
            run_command(TOOL_COMMANDS["gauplus"](args.domain, gauplus_out), out_file=gauplus_out)
    else:
        logger.debug("gauplus not found; skipping")

    # 6) Hakrawler (lightweight crawler for endpoints)
    if "hakrawler" in selected and tools_on_path.get("hakrawler"):
        hak_out = os.path.join(outdir, "hakrawler.txt")
        if args.dry_run:
            logger.info("DRY RUN: hakrawler -domain %s", args.domain)
        else:
            run_command(TOOL_COMMANDS["hakrawler"](args.domain, hak_out), out_file=hak_out)
    else:
        logger.debug("hakrawler not found; skipping")

    # Consolidate subdomains from generated files
    candidates = []
    for fname in ("assetfinder.txt", "subfinder.txt", "amass.txt", "sublist3r.txt"):
        path = os.path.join(outdir, fname)
        if os.path.exists(path):
            candidates.append(path)

    # If wayback/gau outputs exist, extract hosts and append
    for fname in ("wayback_urls.txt", "gau.txt", "gauplus.txt", "hakrawler.txt"):
        path = os.path.join(outdir, fname)
        if os.path.exists(path):
            # attempt to extract hostnames
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    # naive extraction of hostname
                    try:
                        from urllib.parse import urlparse
                        u = urlparse(line)
                        host = u.hostname or line
                    except Exception:
                        host = line
                    with open(subdomains_file, "a", encoding="utf-8") as sfh:
                        sfh.write(host + "\n")

    # Also include any pre-existing subdomains_file content (targets-file case handled earlier)

    # Deduplicate subdomains file
    if os.path.exists(subdomains_file):
        lines = sorted(set(read_lines_strip(subdomains_file)))
        with open(subdomains_file, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + ("\n" if lines else ""))
        logger.info("Consolidated subdomains: %d entries", len(lines))

    # DNS resolution / probing with dnsx
    if "dnsx" in selected:
        if tools_on_path.get("dnsx") and os.path.exists(subdomains_file):
            dnsx_out = os.path.join(outdir, "dnsx.txt")
            if args.dry_run:
                logger.info("DRY RUN: dnsx -l %s", subdomains_file)
            else:
                run_command(TOOL_COMMANDS["dnsx"](subdomains_file, dnsx_out), out_file=dnsx_out)
        else:
            logger.debug("dnsx not found or no subdomains to resolve; skipping")

    # Probe HTTP/HTTPS using httpx
    if "httpx" in selected:
        if tools_on_path.get("httpx") and os.path.exists(subdomains_file):
            httpx_out = os.path.join(outdir, "httpx.json")
            if args.dry_run:
                logger.info("DRY RUN: httpx -list %s", subdomains_file)
            else:
                run_command(TOOL_COMMANDS["httpx"](subdomains_file, httpx_out), out_file=httpx_out)
        else:
            logger.debug("httpx not found or no subdomains; skipping")

    # Port discovery: naabu (non-intrusive) and masscan (fast, intrusive) and nmap
    if "naabu" in selected:
        if tools_on_path.get("naabu") and os.path.exists(subdomains_file):
            naabu_out = os.path.join(outdir, "naabu.txt")
            if args.dry_run:
                logger.info("DRY RUN: naabu -list %s", subdomains_file)
            else:
                run_command(TOOL_COMMANDS["naabu"](subdomains_file, naabu_out), out_file=naabu_out)
        else:
            logger.debug("naabu not found or no subdomains; skipping")

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

    if "nmap" in selected:
        if tools_on_path.get("nmap"):
            nmap_in = os.path.join(outdir, "naabu.txt") if os.path.exists(os.path.join(outdir, "naabu.txt")) else subdomains_file
            if os.path.exists(nmap_in):
                prefix = os.path.join(outdir, "nmap")
                if args.dry_run:
                    logger.info("DRY RUN: nmap -iL %s", nmap_in)
                else:
                    run_command(TOOL_COMMANDS["nmap"](nmap_in, prefix))
            else:
                logger.debug("No input for nmap; skipping")
        else:
            logger.debug("nmap not found; skipping")

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
