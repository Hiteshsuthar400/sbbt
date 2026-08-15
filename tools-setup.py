#!/usr/bin/env python3
"""
tools-setup.py

Checks for required external tools and offers automated installation where possible.
After successful setup it can invoke sbbt.py for a target domain and place outputs
in outputs/<domain>/<timestamp>/ and create a 'latest' symlink for the domain so
subsequent tools can easily reuse outputs.

Usage examples:
  python3 tools-setup.py --check                 # only check and report missing tools
  python3 tools-setup.py --install --yes         # attempt to install missing tools without prompt
  python3 tools-setup.py --install --domain example.com --run-sbbt --yes

IMPORTANT: This script will run platform package managers and `go install` when
asked to --install. Review the printed commands before confirming. Use only on
systems where you have permission and only scan targets you are authorized to test.
"""

from __future__ import annotations
import argparse
import os
import shutil
import subprocess
import sys
import datetime
import logging
from typing import Dict, List, Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("tools-setup")

# Tools we expect (matching sbbt.py)
REQUIRED_BINARIES = {
    "subfinder": {
        "install_go": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "notes": "Go-based: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    },
    "amass": {
        "apt": "amass",
        "notes": "amass (OWASP) - apt or binary releases",
    },
    "httpx": {
        "install_go": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "notes": "Go-based: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
    },
    "naabu": {
        "install_go": "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
        "notes": "Go-based: go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
    },
    "nmap": {
        "apt": "nmap",
        "brew": "nmap",
        "notes": "nmap - use system package manager",
    },
    "ffuf": {
        "install_go": "github.com/ffuf/ffuf@latest",
        "notes": "Go-based: go install -v github.com/ffuf/ffuf@latest",
    },
    "gobuster": {
        "apt": "gobuster",
        "brew": "gobuster",
        "notes": "gobuster - apt/brew",
    },
    "sqlmap": {
        "git": "https://github.com/sqlmapproject/sqlmap.git",
        "notes": "sqlmap - clone repository or run as python script",
    },
}

# Python packages that sbbt.py expects (we only ensure pip availability)
REQUIRED_PY_PACKAGES = ["requests", "beautifulsoup4", "tqdm", "dnspython"]

# Helper functions

def is_executable_in_path(name: str) -> Optional[str]:
    return shutil.which(name)


def detect_platform() -> Dict[str, bool]:
    plat = {
        "linux": sys.platform.startswith("linux"),
        "darwin": sys.platform == "darwin",
        "windows": sys.platform.startswith("win"),
    }
    return plat


def run_shell(cmd: List[str], check: bool = False) -> subprocess.CompletedProcess:
    logger.debug("Running shell: %s", " ".join(cmd))
    return subprocess.run(cmd, check=check)


def ensure_go_bin_in_path() -> bool:
    # quick check for 'go' tool and GOBIN or GOPATH/bin presence
    go = shutil.which("go")
    if not go:
        return False
    # check that $GOBIN or $GOPATH/bin is in PATH (best-effort)
    gobin = os.environ.get("GOBIN")
    gopath = os.environ.get("GOPATH")
    if gobin and os.path.isdir(gobin) and gobin in os.environ.get("PATH", ""):
        return True
    if gopath:
        gpbin = os.path.join(gopath, "bin")
        if os.path.isdir(gpbin) and gpbin in os.environ.get("PATH", ""):
            return True
    # try default GOPATH
    default_gp = os.path.expanduser("~/go/bin")
    if os.path.isdir(default_gp) and default_gp in os.environ.get("PATH", ""):
        return True
    return False


def install_python_packages(packages: List[str]) -> bool:
    cmd = [sys.executable, "-m", "pip", "install"] + packages
    logger.info("Installing python packages: %s", ", ".join(packages))
    proc = run_shell(cmd)
    return proc.returncode == 0


def try_install_tool(tool: str, info: Dict, platform: Dict[str, bool], auto_yes: bool) -> bool:
    """Attempt automated installation using heuristic methods. Returns True if installed."""
    logger.info("Attempting installation for: %s", tool)
    # 1) Go install if available in metadata
    if info.get("install_go"):
        if shutil.which("go"):
            cmd = [shutil.which("go"), "install", info["install_go"]]
            logger.info("Running go install for %s: %s", tool, " ".join(cmd))
            try:
                run_shell(cmd, check=True)
            except subprocess.CalledProcessError as e:
                logger.warning("go install failed for %s: %s", tool, e)
            else:
                if shutil.which(tool):
                    logger.info("Installed %s via go install", tool)
                    return True
        else:
            logger.warning("Go not found; cannot go install %s", tool)
    # 2) platform package manager
    # Linux: apt
    if platform.get("linux"):
        if info.get("apt"):
            apt_pkg = info["apt"]
            cmd = ["sudo", "apt-get", "update"]
            logger.info("Running: %s", " ".join(cmd))
            try:
                run_shell(cmd, check=True)
            except subprocess.CalledProcessError:
                logger.warning("apt-get update failed; skipping apt install for %s", tool)
            else:
                install_cmd = ["sudo", "apt-get", "install", "-y", apt_pkg]
                logger.info("Running: %s", " ".join(install_cmd))
                try:
                    run_shell(install_cmd, check=True)
                except subprocess.CalledProcessError:
                    logger.warning("apt install failed for %s", tool)
                else:
                    if shutil.which(tool):
                        return True
    # macOS: brew
    if platform.get("darwin") and info.get("brew"):
        if shutil.which("brew"):
            install_cmd = ["brew", "install", info["brew"]]
            logger.info("Running: %s", " ".join(install_cmd))
            try:
                run_shell(install_cmd, check=True)
            except subprocess.CalledProcessError:
                logger.warning("brew install failed for %s", tool)
            else:
                if shutil.which(tool):
                    return True
    # 3) git clone for sqlmap
    if info.get("git"):
        repo = info["git"]
        target_dir = os.path.expanduser(os.path.join("~", ".local", tool))
        if os.path.exists(target_dir):
            logger.info("%s clone target already exists: %s", tool, target_dir)
        else:
            cmd = ["git", "clone", "--depth", "1", repo, target_dir]
            logger.info("Cloning %s -> %s", repo, target_dir)
            try:
                run_shell(cmd, check=True)
            except subprocess.CalledProcessError:
                logger.warning("git clone failed for %s", tool)
            else:
                # for sqlmap, add wrapper to ~/.local/bin
                bin_dir = os.path.expanduser("~/.local/bin")
                os.makedirs(bin_dir, exist_ok=True)
                wrapper = os.path.join(bin_dir, tool)
                main_py = os.path.join(target_dir, "sqlmap.py")
                if os.path.exists(main_py):
                    with open(wrapper, "w", encoding="utf-8") as fh:
                        fh.write(f"#!/usr/bin/env python3\nimport sys\nimport runpy\nrunpy.run_path(\"{main_py}\", run_name=\"__main__\")\n")
                    try:
                        os.chmod(wrapper, 0o755)
                        logger.info("Created wrapper %s -> %s", wrapper, main_py)
                    except Exception:
                        logger.warning("Could not make wrapper executable: %s", wrapper)
                if shutil.which(tool) or os.path.exists(wrapper):
                    return True
    # If we reach here, automated install failed
    logger.info("Automated install attempts finished for %s; tool may still be missing. See notes: %s", tool, info.get("notes"))
    return False


def check_requirements(auto_install: bool = False, auto_yes: bool = False) -> Dict[str, bool]:
    platform = detect_platform()
    status = {}
    for tool, info in REQUIRED_BINARIES.items():
        path = shutil.which(tool)
        found = path is not None
        status[tool] = found
        logger.info("%s -> %s", tool, path if found else "MISSING")
    # Python packages check
    missing_py = []
    for p in REQUIRED_PY_PACKAGES:
        try:
            __import__(p)
            logger.info("Python package %s -> OK", p)
        except Exception:
            logger.warning("Python package %s -> MISSING", p)
            missing_py.append(p)
    if missing_py and auto_install:
        if auto_yes:
            install_python_packages(missing_py)
        else:
            resp = input(f"Install missing python packages {missing_py}? [Y/n]: ")
            if resp.strip().lower() in ("", "y", "yes"):
                install_python_packages(missing_py)

    # Try installing missing external binaries if requested
    if auto_install:
        for tool, info in REQUIRED_BINARIES.items():
            if not status.get(tool):
                ok = try_install_tool(tool, info, platform, auto_yes)
                status[tool] = ok or status.get(tool)
    return status


def ensure_domain_outdir(base_out: str, domain: str) -> str:
    # Create outputs/<domain>/<timestamp>/ and a 'latest' symlink
    timestamp = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    domain_dir = os.path.join(base_out, domain)
    out_dir = os.path.join(domain_dir, timestamp)
    os.makedirs(out_dir, exist_ok=True)
    # create or update latest symlink
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


def run_sbbt_with_domain(domain: str, outdir_base: str, extra_args: List[str]) -> int:
    # Ensure sbbt.py exists in cwd
    if not os.path.exists("sbbt.py"):
        logger.error("sbbt.py not found in current directory. Please place sbbt.py next to tools-setup.py")
        return 2
    outdir = ensure_domain_outdir(outdir_base, domain)
    cmd = [sys.executable, "sbbt.py", "--domain", domain, "--outdir", outdir] + extra_args
    logger.info("Running sbbt pipeline: %s", " ".join(cmd))
    proc = subprocess.run(cmd)
    return proc.returncode


def parse_args():
    p = argparse.ArgumentParser(description="tools-setup: check + install external tools used by sbbt.py")
    p.add_argument("--check", action="store_true", help="Only check and report missing tools")
    p.add_argument("--install", action="store_true", help="Attempt to automatically install missing tools")
    p.add_argument("--yes", action="store_true", help="Assume yes for prompts during install")
    p.add_argument("--domain", help="Domain to run sbbt on after setup (optional)")
    p.add_argument("--run-sbbt", action="store_true", help="Invoke sbbt.py after successful setup")
    p.add_argument("--outdir", default="outputs", help="Base outputs directory (default: outputs)")
    p.add_argument("--sbbt-args", nargs=argparse.REMAINDER, help="Extra args passed to sbbt.py (e.g. --targets-file targets.txt)")
    return p.parse_args()


def main():
    args = parse_args()
    logger.info("tools-setup starting")
    status = check_requirements(auto_install=args.install, auto_yes=args.yes)
    missing = [k for k, v in status.items() if not v]
    if missing:
        logger.warning("Missing tools after checks: %s", ", ".join(missing))
    else:
        logger.info("All required tools present")

    if args.check and not args.install:
        logger.info("Check-only requested; exiting")
        return 0

    if args.install:
        # Re-check after attempted install
        status = check_requirements(auto_install=False)
        missing = [k for k, v in status.items() if not v]
        if missing:
            logger.warning("After install attempts the following tools are still missing: %s", ", ".join(missing))
            logger.info("You may need to install them manually following the notes in REQUIRED_BINARIES in this script.")

    # If requested, run sbbt.py for domain
    if args.run_sbbt:
        if not args.domain:
            logger.error("--run-sbbt requires --domain to be specified")
            return 3
        extra = args.sbbt_args or []
        # If user passed --yes we forward to sbbt.py to allow non-interactive pip install
        if args.yes:
            extra = ["--yes"] + extra
        rc = run_sbbt_with_domain(args.domain, args.outdir, extra)
        logger.info("sbbt.py exited with code %s", rc)
        return rc

    logger.info("tools-setup finished")
    return 0

if __name__ == "__main__":
    sys.exit(main())
