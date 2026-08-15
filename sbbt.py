#!/usr/bin/env python3
"""
sbbt.py

Small single-domain bug-hunting / recon orchestration script.

This script invokes a set of external recon tools (when available) to
collect subdomains, probe HTTP hosts, perform port scans, and run
basic content discovery. It writes outputs to outputs/<domain>/<timestamp>/
and creates a "latest" symlink for convenience.

Tools are invoked only if present on PATH. Potentially intrusive tools
(masscan, sqlmap, etc.) require explicit consent via --yes.

Usage examples:
  python3 sbbt.py --domain example.com
  python3 sbbt.py --domain example.com --tools=subfinder,amass,httpx
  python3 sbbt.py --domain example.com --stages=passive,archive,dns,http,ports,content,vuln

Notes:
- Review commands before running on targets. Use only on domains you are
  authorized to test.
- This script supports staged (stepwise) execution and runs tools in
  background worker threads per stage. It prints simple progress
  (percentage complete) while a stage runs.
"""

from __future__ import annotations
import argparse
import datetime
import os
import shutil
import subprocess
import sys
import logging
import time
import concurrent.futures
from typing import Dict, List, Optional, Tuple

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
    "nuclei": lambda infile, out: ["nuclei", "-l", infile, "-o", out],
}

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
    "nuclei",
]

STAGE_TOOLS = {
    "passive": ["assetfinder", "findomain", "subfinder", "amass", "shuffledns", "sublist3r"],
    "archive": ["waybackurls", "gau", "gauplus", "hakrawler"],
    "dns": ["dnsx"],
    "http": ["httpx"],
    "ports": ["naabu", "masscan", "nmap"],
    "content": ["ffuf", "gobuster", "dirsearch"],
    "intrusive": ["sqlmap", "masscan"],
    "vuln": ["nuclei"],
}


def detect_tools() -> Dict[str, Optional[str]]:
    """Detect available tools on PATH."""
    found = {}
    for t in ALL_TOOLS:
        found[t] = shutil.which(t)
    return found


def ensure_domain_outdir(base_out: str, domain: str) -> str:
    """Ensure domain output directory exists and create latest symlink."""
    timestamp = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    domain_dir = os.path.join(base_out, domain)
    out_dir = os.path.join(domain_dir, timestamp)
    os.makedirs(out_dir, exist_ok=True)
    latest_link = os.path.join(domain_dir, "latest")
    try:
        if os.path.islink(latest_link) or os.path.exists(latest_link):
            try:
                os.remove(latest_link)
            except (OSError, FileNotFoundError):
                pass
        os.symlink(out_dir, latest_link)
    except (OSError, FileExistsError, NotImplementedError):
        logger.debug("Could not create symlink %s -> %s (platform may not support symlinks)", latest_link, out_dir)
    return out_dir


def run_tool(cmd: List[str], out_file: Optional[str] = None, cwd: Optional[str] = None) -> Tuple[int, str]:
    """Run a tool command and write output to out_file if provided.

    If the tool itself declares the same output file in its args, we avoid
    opening/truncating that path so the tool can write to it safely.

    Returns (returncode, out_file_path_used_or_empty).
    """
    logger.debug("Starting tool: %s", " ".join(cmd))
    # Decide whether we should open the out_file or let the tool manage it
    write_output_here = False
    if out_file:
        try:
            # If out_file string appears verbatim in args, assume tool writes it
            if not any(out_file == str(a) or out_file in str(a) for a in cmd):
                write_output_here = True
        except Exception:
            write_output_here = True

    try:
        if write_output_here and out_file:
            with open(out_file, "w", encoding="utf-8") as fh:
                p = subprocess.Popen(cmd, stdout=fh, stderr=subprocess.STDOUT, cwd=cwd, text=True)
                rc = p.wait()
            return rc, out_file
        else:
            # let tool write its own file (or discard output)
            # We still attach stdout/stderr to devnull to avoid flooding the runner
            with open(os.devnull, "w", encoding="utf-8") as devnull:
                p = subprocess.Popen(cmd, stdout=devnull, stderr=subprocess.STDOUT, cwd=cwd, text=True)
                rc = p.wait()
            return rc, out_file or ""
    except FileNotFoundError:
        logger.warning("Command not found: %s", cmd[0] if isinstance(cmd, list) else cmd)
        return 127, out_file or ""
    except Exception as e:
        logger.exception("Error running command %s: %s", cmd, e)
        return 1, out_file or ""


def run_tasks_concurrent(tasks: List[Tuple[str, List[str], str]], workers: int = 4, stage_name: str = "") -> Dict[str, Dict]:
    """Run a list of tasks concurrently and show simple progress.

    tasks: list of tuples (tool_name, cmd_list, out_file_path)
    Returns a mapping tool_name -> {rc, out}
    """
    results: Dict[str, Dict] = {}
    total = len(tasks)
    if total == 0:
        return results

    logger.info("Running stage '%s' with %d worker(s): %d task(s)", stage_name, workers, total)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        future_to_task = {ex.submit(run_tool, cmd, out): (tool, cmd, out) for (tool, cmd, out) in tasks}

        completed = 0
        # Polling loop to display progress percentage
        while future_to_task:
            done, _ = concurrent.futures.wait(future_to_task.keys(), timeout=0.5, return_when=concurrent.futures.FIRST_COMPLETED)
            for fut in list(done):
                task_info = future_to_task.pop(fut)
                tool, cmd, out = task_info
                try:
                    rc, outpath = fut.result()
                except Exception as e:
                    rc, outpath = 1, out
                    logger.exception("Task %s failed: %s", tool, e)
                results[tool] = {"rc": rc, "out": outpath}
                completed += 1
            percent = int((completed / total) * 100)
            sys.stdout.write(f"\r[Stage {stage_name}] Completed {completed}/{total} ({percent}%)")
            sys.stdout.flush()
        # final newline
        sys.stdout.write("\n")
    return results


def read_lines_strip(path: str) -> List[str]:
    """Read lines from file, strip whitespace, and return non-empty lines."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return [l.strip() for l in fh if l.strip()]
    except Exception:
        return []


def gather_ct(domain: str, outpath: str) -> None:
    """Query crt.sh (JSON) for CT entries (simple, widely-available passive source)."""
    out = outpath
    try:
        import urllib.request
        import urllib.parse
        import json
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
    """Main entry point for sbbt recon orchestration."""
    p = argparse.ArgumentParser(
        description="sbbt: small, professional-looking single-domain recon runner (staged)",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p.add_argument("--domain", help="Target domain (e.g. example.com)")
    p.add_argument("--outdir", default="outputs", help="Base outputs directory")
    p.add_argument("--targets-file", help="Optional file with targets (one per line)")
    p.add_argument("--tools", help=f"Comma-separated tools to run (default: all). Options: {', '.join(ALL_TOOLS)}")
    p.add_argument("--stages", help=(
        "Comma-separated stages to run (stepwise):\n"
        "  passive  - passive subdomain enumeration (amass, subfinder, etc.)\n"
        "  archive  - archives/endpoints (waybackurls, gau, hakrawler)\n"
        "  dns      - DNS enrichment with dnsx\n"
        "  http     - HTTP probing with httpx\n"
        "  ports    - port scanning (naabu, masscan, nmap)\n"
        "  content  - content discovery (ffuf/gobuster/dirsearch)\n"
        "  vuln     - vulnerability scanning (nuclei)\n"
        "  intrusive- intrusive tools (sqlmap, masscan)\n"
        "  all      - run all stages (default)\n"
    ))
    p.add_argument("--yes", action="store_true", help="Allow intrusive tools (masscan, sqlmap, etc.)")
    p.add_argument("--dry-run", action="store_true", help="Show commands but do not execute")
    p.add_argument("--workers", type=int, default=4, help="Number of concurrent worker threads per stage")
    args, _ = p.parse_known_args()

    if not args.domain and not args.targets_file:
        logger.error("Either --domain or --targets-file is required")
        p.print_help()
        return 2

    tools_on_path = detect_tools()
    # Auto-select only tools that are actually on PATH when --tools is not provided.
    installed_tools = [t for t, path in tools_on_path.items() if path]
    if not args.tools:
        selected = [t for t in ALL_TOOLS if t in installed_tools]
        logger.info("No --tools specified; auto-selecting %d tool(s) detected on PATH: %s", len(selected), ", ".join(selected) if selected else "none")
    else:
        requested = [t.strip() for t in args.tools.split(",") if t.strip()]
        missing = [t for t in requested if t not in installed_tools]
        selected = [t for t in requested if t in installed_tools]
        if missing:
            logger.warning("Requested tools not found on PATH and will be skipped: %s", ", ".join(missing))

    primary = args.domain if args.domain else os.path.basename(args.targets_file)
    outdir = ensure_domain_outdir(args.outdir, primary)
    logger.info("Outputs to %s", outdir)

    stages = {"all"}
    if args.stages:
        stages = {s.strip() for s in args.stages.split(",") if s.strip()}
    def stage_enabled(name: str) -> bool:
        return "all" in stages or name in stages

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
    if args.domain and stage_enabled("passive"):
        if args.dry_run:
            logger.info("DRY RUN: crt.sh lookup for %s -> %s", args.domain, crt_out)
        else:
            gather_ct(args.domain, crt_out)
            if os.path.exists(crt_out):
                with open(subdomains_file, "a", encoding="utf-8") as fh:
                    fh.write("\n")
                    with open(crt_out, "r", encoding="utf-8") as crt_fh:
                        fh.write(crt_fh.read())

    # Passive stage: run passive tools concurrently
    if stage_enabled("passive"):
        passive_tools = [t for t in STAGE_TOOLS["passive"] if t in selected and tools_on_path.get(t)]
        tasks = []
        for t in passive_tools:
            out = os.path.join(outdir, f"{t}.txt")
            if t not in TOOL_COMMANDS:
                logger.debug("No command template for %s; skipping", t)
                continue
            cmd = TOOL_COMMANDS[t](args.domain, out)
            if args.dry_run:
                logger.info("DRY RUN: %s", " ".join(cmd))
            else:
                tasks.append((t, cmd, out))
        if tasks and not args.dry_run:
            run_tasks_concurrent(tasks, workers=args.workers, stage_name="passive")
            # merge outputs into subdomains.txt
            for _, _, out in tasks:
                if os.path.exists(out):
                    with open(subdomains_file, "a", encoding="utf-8") as fh, open(out, "r", encoding="utf-8", errors="ignore") as rf:
                        fh.write("\n")
                        fh.write(rf.read())

    # Archive stage
    if stage_enabled("archive"):
        archive_tools = [t for t in STAGE_TOOLS["archive"] if t in selected and tools_on_path.get(t)]
        tasks = []
        for t in archive_tools:
            out = os.path.join(outdir, f"{t}.txt")
            if t not in TOOL_COMMANDS:
                logger.debug("No command template for %s; skipping", t)
                continue
            cmd = TOOL_COMMANDS[t](args.domain, out)
            if args.dry_run:
                logger.info("DRY RUN: %s", " ".join(cmd))
            else:
                tasks.append((t, cmd, out))
        if tasks and not args.dry_run:
            run_tasks_concurrent(tasks, workers=args.workers, stage_name="archive")
            # try to extract hosts to subdomains_file
            for _, _, out in tasks:
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

    # DNS stage
    if stage_enabled("dns") and "dnsx" in selected and tools_on_path.get("dnsx") and os.path.exists(subdomains_file):
        dnsx_out = os.path.join(outdir, "dnsx.txt")
        cmd = TOOL_COMMANDS["dnsx"](subdomains_file, dnsx_out)
        if args.dry_run:
            logger.info("DRY RUN: %s", " ".join(cmd))
        else:
            run_tasks_concurrent([("dnsx", cmd, dnsx_out)], workers=1, stage_name="dns")

    # HTTP probing stage
    httpx_out = os.path.join(outdir, "httpx.json")
    if stage_enabled("http") and "httpx" in selected and tools_on_path.get("httpx") and os.path.exists(subdomains_file):
        cmd = TOOL_COMMANDS["httpx"](subdomains_file, httpx_out)
        if args.dry_run:
            logger.info("DRY RUN: %s", " ".join(cmd))
        else:
            run_tasks_concurrent([("httpx", cmd, httpx_out)], workers=max(1, args.workers), stage_name="http")

    # Ports stage
    if stage_enabled("ports"):
        port_tasks = []
        if "naabu" in selected and tools_on_path.get("naabu") and os.path.exists(subdomains_file):
            naabu_out = os.path.join(outdir, "naabu.txt")
            naabu_cmd = TOOL_COMMANDS["naabu"](subdomains_file, naabu_out)
            port_tasks.append(("naabu", naabu_cmd, naabu_out))
        # masscan is intrusive; respect --yes and intrusive stage
        if "masscan" in selected and tools_on_path.get("masscan") and os.path.exists(subdomains_file):
            if not args.yes:
                logger.warning("masscan is intrusive and requires --yes to run; skipping")
            else:
                masscan_out = os.path.join(outdir, "masscan.txt")
                masscan_cmd = TOOL_COMMANDS["masscan"](subdomains_file, masscan_out)
                port_tasks.append(("masscan", masscan_cmd, masscan_out))
        if port_tasks and not args.dry_run:
            run_tasks_concurrent(port_tasks, workers=args.workers, stage_name="ports")

    # Nmap (may consume naabu results)
    if stage_enabled("ports") and "nmap" in selected and tools_on_path.get("nmap"):
        nmap_exists = os.path.exists(os.path.join(outdir, "naabu.txt"))
        nmap_in = os.path.join(outdir, "naabu.txt") if nmap_exists else subdomains_file
        if os.path.exists(nmap_in):
            prefix = os.path.join(outdir, "nmap")
            cmd = TOOL_COMMANDS["nmap"](nmap_in, prefix)
            if args.dry_run:
                logger.info("DRY RUN: %s", " ".join(cmd))
            else:
                run_tasks_concurrent([("nmap", cmd, prefix)], workers=1, stage_name="nmap")

    # Content stage
    if stage_enabled("content"):
        content_tasks = []
        if "ffuf" in selected and tools_on_path.get("ffuf") and args.domain:
            ffuf_out = os.path.join(outdir, "ffuf.txt")
            url_template = f"https://FUZZ.{args.domain}/"
            ffuf_cmd = TOOL_COMMANDS["ffuf"](url_template, ffuf_out)
            content_tasks.append(("ffuf", ffuf_cmd, ffuf_out))
        if "gobuster" in selected and tools_on_path.get("gobuster") and args.domain:
            gob_out = os.path.join(outdir, "gobuster.txt")
            url = f"https://{args.domain}/"
            gob_cmd = TOOL_COMMANDS["gobuster"](url, gob_out)
            content_tasks.append(("gobuster", gob_cmd, gob_out))
        if "dirsearch" in selected and tools_on_path.get("dirsearch") and args.domain:
            dir_out = os.path.join(outdir, "dirsearch.txt")
            url = f"https://{args.domain}/"
            dir_cmd = TOOL_COMMANDS["dirsearch"](url, dir_out)
            content_tasks.append(("dirsearch", dir_cmd, dir_out))
        if content_tasks and not args.dry_run:
            run_tasks_concurrent(content_tasks, workers=args.workers, stage_name="content")

    # sqlmap (intrusive) stage
    if "sqlmap" in selected and tools_on_path.get("sqlmap"):
        if not args.yes:
            logger.warning(
                "sqlmap is intrusive; re-run with --yes to enable or omit sqlmap from --tools"
            )
        else:
            target = None
            if os.path.exists(httpx_out):
                for line in read_lines_strip(httpx_out):
                    if line.startswith("http"):
                        target = line
                        break
            if not target and args.domain:
                target = f"http://{args.domain}/"
            if target:
                sql_out = os.path.join(outdir, "sqlmap.log")
                cmd = TOOL_COMMANDS["sqlmap"](target, sql_out)
                if args.dry_run:
                    logger.info("DRY RUN: %s", " ".join(cmd))
                else:
                    run_tasks_concurrent([("sqlmap", cmd, sql_out)], workers=1, stage_name="sqlmap")

    # Vulnerability stage (nuclei)
    if stage_enabled("vuln") and "nuclei" in selected and tools_on_path.get("nuclei"):
        nuclei_out = os.path.join(outdir, "nuclei.txt")
        nuclei_input = httpx_out if os.path.exists(httpx_out) else subdomains_file
        cmd = TOOL_COMMANDS["nuclei"](nuclei_input, nuclei_out)
        if args.dry_run:
            logger.info("DRY RUN: %s", " ".join(cmd))
        else:
            run_tasks_concurrent(
                [("nuclei", cmd, nuclei_out)], workers=args.workers, stage_name="vuln"
            )

    logger.info("sbbt run complete. Check %s for outputs", outdir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
