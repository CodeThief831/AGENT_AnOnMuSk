"""
Agent AnonMusk — Tool Installer (Windows)
=========================================
Automated downloader and installer for Windows security binaries.
"""

import os
import shutil
import zipfile
import requests
import subprocess
from pathlib import Path
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, DownloadColumn, TransferSpeedColumn

console = Console()

# ── Configuration ────────────────────────────────────────────

TOOLS_DIR = Path("./tools")
GITHUB_REPOS = {
    "subfinder": "projectdiscovery/subfinder",
    "httpx": "projectdiscovery/httpx",
    "nuclei": "projectdiscovery/nuclei",
    "katana": "projectdiscovery/katana",
    "amass": "owasp-amass/amass",
    "assetfinder": "tomnomnom/assetfinder",
    "waybackurls": "tomnomnom/waybackurls",
    "gau": "lc/gau",
}

# ── Implementation ───────────────────────────────────────────

def install_all_tools():
    """Download and install all core tools for Windows."""
    TOOLS_DIR.mkdir(exist_ok=True)
    
    console.print(f"\n[bold red]🚀 Agent AnonMusk — Tool Installer (Windows)[/]")
    console.print(f"[dim]Installation directory: {TOOLS_DIR.absolute()}[/]\n")

    # Check if 'go' is present (fallback for tools without easy binaries)
    go_present = shutil.which("go") is not None

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        DownloadColumn(),
        TransferSpeedColumn(),
    ) as progress:
        for tool, repo in GITHUB_REPOS.items():
            task_id = progress.add_task(f"Installing {tool}...", total=None)
            
            try:
                if go_present:
                    # Prefer 'go install' if available as it's cleaner
                    progress.update(task_id, description=f"Go installing {tool}...")
                    cmd = f"go install -v github.com/{repo}/cmd/{tool}@latest" if "projectdiscovery" in repo else f"go install -v github.com/{repo}@latest"
                    if tool == "amass":
                        cmd = "go install -v github.com/owasp-amass/amass/v4/...@master"
                    
                    subprocess.run(cmd, shell=True, check=False, capture_output=True)
                    # If go install worked, we're done for this tool
                    if shutil.which(tool):
                        progress.update(task_id, description=f"[green]✓ {tool} installed (via go)", completed=100)
                        continue

                # Binary download fallback (or primary for specific ones)
                progress.update(task_id, description=f"Downloading {tool} binary...")
                success = _download_github_release(tool, repo, progress, task_id)
                
                if success:
                    progress.update(task_id, description=f"[green]✓ {tool} installed", completed=100)
                else:
                    progress.update(task_id, description=f"[red]✗ {tool} failed", completed=100)

            except Exception as e:
                progress.update(task_id, description=f"[red]✗ {tool} error: {str(e)}", completed=100)

    console.print(f"\n[bold green]✅ Tool installation process complete![/]")
    console.print(f"[yellow]💡 Ensure {TOOLS_DIR.absolute()} is in your PATH, or rely on internal wrappers.[/]\n")

def _download_github_release(tool: str, repo: str, progress, task_id) -> bool:
    """Helper to download and extract GitHub release binaries."""
    try:
        api_url = f"https://api.github.com/repos/{repo}/releases/latest"
        response = requests.get(api_url, timeout=10)
        if response.status_code != 200:
            return False
        
        data = response.json()
        assets = data.get("assets", [])
        
        # Look for windows amd64 zip
        download_url = None
        for asset in assets:
            name = asset["name"].lower()
            if "windows" in name and ("amd64" in name or "64-bit" in name) and name.endswith(".zip"):
                download_url = asset["browser_download_url"]
                break
        
        if not download_url:
            # Try tar.gz as backup
            for asset in assets:
                name = asset["name"].lower()
                if "windows" in name and ".zip" in name:
                    download_url = asset["browser_download_url"]
                    break
        
        if not download_url:
            return False

        # Download zip
        zip_path = TOOLS_DIR / f"{tool}.zip"
        r = requests.get(download_url, stream=True, timeout=30)
        total_size = int(r.headers.get('content-length', 0))
        progress.update(task_id, total=total_size)
        
        with open(zip_path, 'wb') as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)
                progress.advance(task_id, advance=len(chunk))

        # Extract
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            # We want to extract just the .exe to tools/
            for member in zip_ref.namelist():
                if member.endswith(".exe"):
                    filename = os.path.basename(member)
                    source = zip_ref.open(member)
                    target = open(TOOLS_DIR / filename, "wb")
                    with source, target:
                        shutil.copyfileobj(source, target)
        
        # Cleanup
        os.remove(zip_path)
        return True

    except Exception:
        return False

if __name__ == "__main__":
    install_all_tools()
