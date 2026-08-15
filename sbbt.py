#!/usr/bin/env python3
"""
sbbt.py

Simple single-domain bug-hunting / recon orchestration script.

This script invokes a set of external recon tools (when available) to
collect subdomains, probe HTTP hosts, perform port scans, and run
basic content discovery. It writes outputs to outputs/<domain>/<timestamp>/
and creates a "latest" symlink for convenience.

This is intentionally conservative: tools are invoked only if present on
PATH, and for potentially intrusive tools (like sqlmap) the script
requires explicit consent via --yes and/or tool selection.

Usage examples:
  python3 sbbt.py --domain example.com
  python3 sbbt.py --domain example.com --outdir outputs --tools=subfinder,amass,httpx

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

# Minimal tool command templates. These are conservative and may be modified
# per your environment or preferred flags.
TOOL_COMMANDS = {
    "subfinder": lambda domain, out: ["subfinder", "-d", domain, "-silent", "-o", out],
    "amass": lambda domain, out: ["amass", "enum", "-d", domain, "-o", out],
    "httpx": lambda infile, out: ["httpx", "-list", infile, "-silent", "-o", out],
    "naabu": lambda infile, out: ["naabu", "-list", infile, "-o", out],
    "nmap": lambda infile, out_prefix: ["nmap", "-iL", infile, "-Pn", "-sV", "-oA", out_prefix],
    "ffuf": lambda url_template, out: ["ffuf", "-u", url_template, "-w", "/usr/share/wordlists/dirb/common.txt", "-o", out],
    "gobuster": lambda url, out: ["gobuster", "dir", "-u", url, "-w", "/usr/share/wordlists/dirb/common.txt", "-o", out],
    "sqlmap": lambda target, out: ["sqlmap", "-u", target, "--batch", "-o", out],
}

ALL_TOOLS = list(TOOL_COMMANDS.keys())


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


def run_command(cmd: List[str], cwd: Optional[str] = None, out_file: Optional[str] = None) -> int:
    logger.info("Running: %s", " ".join(cmd))
    try:
        with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=cwd, text=True) as p:
            # Stream output to console and optionally save to file
            with (open(out_file, "w", encoding="utf-8") if out_file else open(os.devnull, "w")) as fh:
                for line in p.stdout:
                    print(line, end="")
                    fh.write(line)
            p.wait()
            return p.returncode
    except FileNotFoundError:
        logger.warning("Command not found: %s", cmd[0])
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
    p = argparse.ArgumentParser(description="sbbt: small bug-hunting / recon runner")
    p.add_argument("--domain", help="Domain to target")
    p.add_argument("--outdir", default="outputs", help="Base outputs directory (default: outputs)")
    p.add_argument("--targets-file", help="Optional file with targets (one per line)")
    p.add_argument("--tools", help=f"Comma-separated list of tools to run (default: all). Options: {', '.join(ALL_TOOLS)}")
    p.add_argument("--yes", action="store_true", help="Assume yes for any prompts (required for some intrusive tools)")
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

    # Make a simple hosts/subdomains file to share between steps
    subdomains_file = os.path.join(outdir, "subdomains.txt")

    # If a targets file was provided, copy it to outdir and use it
    if args.targets_file:
        targets = read_lines_strip(args.targets_file)
        if targets:
            # write a copy
            with open(subdomains_file, "w", encoding="utf-8") as fh:
                fh.write("\n".join(targets) + "\n")
            logger.info("Copied %d targets from %s to %s", len(targets), args.targets_file, subdomains_file)

    # 1) subfinder
    if "subfinder" in selected:
        if tools_on_path.get("subfinder"):
            out = os.path.join(outdir, "subfinder.txt")
            cmd = TOOL_COMMANDS["subfinder"](args.domain, out)
            if args.dry_run:
                logger.info("DRY RUN: %s", " ".join(cmd))
            else:
                rc = run_command(cmd, out_file=out)
                if rc == 0 and os.path.exists(out):
                    # append to common subdomains file
                    with open(subdomains_file, "a", encoding="utf-8") as fh:
                        fh.write("\n")
                        fh.write(open(out, "r", encoding="utf-8").read())
        else:
            logger.warning("subfinder not found on PATH; skipping")

    # 2) amass
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
            logger.warning("amass not found on PATH; skipping")

    # Deduplicate subdomains file
    if os.path.exists(subdomains_file):
        lines = sorted(set(read_lines_strip(subdomains_file)))
        with open(subdomains_file, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + ("\n" if lines else ""))
        logger.info("Consolidated subdomains: %d entries", len(lines))

    # 3) httpx to probe alive hosts (if httpx installed)
    if "httpx" in selected:
        if tools_on_path.get("httpx"):
            if os.path.exists(subdomains_file):
                out = os.path.join(outdir, "httpx.json")
                cmd = TOOL_COMMANDS["httpx"](subdomains_file, out)
                if args.dry_run:
                    logger.info("DRY RUN: %s", " ".join(cmd))
                else:
                    run_command(cmd, out_file=out)
            else:
                logger.warning("No subdomains file available for httpx; skipping")
        else:
            logger.warning("httpx not found on PATH; skipping")

    # 4) naabu (port discovery)
    if "naabu" in selected:
        if tools_on_path.get("naabu"):
            if os.path.exists(subdomains_file):
                out = os.path.join(outdir, "naabu.txt")
                cmd = TOOL_COMMANDS["naabu"](subdomains_file, out)
                if args.dry_run:
                    logger.info("DRY RUN: %s", " ".join(cmd))
                else:
                    run_command(cmd, out_file=out)
            else:
                logger.warning("No subdomains file available for naabu; skipping")
        else:
            logger.warning("naabu not found on PATH; skipping")

    # 5) nmap (use naabu output or subdomains)
    if "nmap" in selected:
        if tools_on_path.get("nmap"):
            # Attempt to use naabu results first
            nmap_in = os.path.join(outdir, "naabu.txt") if os.path.exists(os.path.join(outdir, "naabu.txt")) else subdomains_file
            if os.path.exists(nmap_in):
                prefix = os.path.join(outdir, "nmap")
                cmd = TOOL_COMMANDS["nmap"](nmap_in, prefix)
                if args.dry_run:
                    logger.info("DRY RUN: %s", " ".join(cmd))
                else:
                    run_command(cmd)
            else:
                logger.warning("No input for nmap; skipping")
        else:
            logger.warning("nmap not found on PATH; skipping")

    # 6) ffuf (content discovery) - run only if domain is provided (construct template)
    if "ffuf" in selected:
        if tools_on_path.get("ffuf"):
            if args.domain:
                out = os.path.join(outdir, "ffuf.txt")
                url_template = f"https://FUZZ.{args.domain}/"
                cmd = TOOL_COMMANDS["ffuf"](url_template, out)
                if args.dry_run:
                    logger.info("DRY RUN: %s", " ".join(cmd))
                else:
                    run_command(cmd, out_file=out)
            else:
                logger.warning("ffuf requires --domain; skipping")
        else:
            logger.warning("ffuf not found on PATH; skipping")

    # 7) gobuster
    if "gobuster" in selected:
        if tools_on_path.get("gobuster"):
            if args.domain:
                out = os.path.join(outdir, "gobuster.txt")
                url = f"https://{args.domain}/"
                cmd = TOOL_COMMANDS["gobuster"](url, out)
                if args.dry_run:
                    logger.info("DRY RUN: %s", " ".join(cmd))
                else:
                    run_command(cmd, out_file=out)
            else:
                logger.warning("gobuster requires --domain; skipping")
        else:
            logger.warning("gobuster not found on PATH; skipping")

    # 8) sqlmap - intrusive; require explicit consent (and target URL)
    if "sqlmap" in selected:
        if tools_on_path.get("sqlmap"):
            if not args.yes:
                logger.warning("sqlmap is potentially intrusive. Re-run with --yes to allow it or omit sqlmap from --tools")
            else:
                # Attempt to get a target URL from httpx results or take http://domain/
                target = None
                httpx_json = os.path.join(outdir, "httpx.json")
                if os.path.exists(httpx_json):
                    # try simple heuristic: read first line that contains http
                    for line in read_lines_strip(httpx_json):
                        if line.startswith("http"):
                            target = line
                            break
                if not target and args.domain:
                    target = f"http://{args.domain}/"
                if target:
                    out = os.path.join(outdir, "sqlmap.log")
                    cmd = TOOL_COMMANDS["sqlmap"](target, out)
                    if args.dry_run:
                        logger.info("DRY RUN: %s", " ".join(cmd))
                    else:
                        run_command(cmd, out_file=out)
                else:
                    logger.warning("No target URL for sqlmap; skipping")
        else:
            logger.warning("sqlmap not found on PATH; skipping")

    logger.info("sbbt run complete. Check %s for outputs", outdir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
