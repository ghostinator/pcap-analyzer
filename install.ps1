# One-liner installer for PCAP Analyzer on Windows:
#   irm https://raw.githubusercontent.com/ghostinator/pcap-analyzer/main/install.ps1 | iex
#
# Clones the repo (or updates an existing clone), then hands off to setup.ps1
# to install Python/tkinter/git if needed, create a venv, and launch the GUI.
$ErrorActionPreference = 'Stop'

$RepoUrl = 'https://github.com/ghostinator/pcap-analyzer.git'
$InstallDir = if ($env:PCAP_ANALYZER_DIR) { $env:PCAP_ANALYZER_DIR } else { Join-Path $env:USERPROFILE 'pcap-analyzer' }

function Test-Command($name) {
    return [bool](Get-Command $name -ErrorAction SilentlyContinue)
}

if (-not (Test-Command 'git')) {
    Write-Host "git not found. Installing via winget..."
    if (-not (Test-Command 'winget')) {
        Write-Host "winget not found. Install git from https://git-scm.com/download/win, then re-run this script."
        exit 1
    }
    winget install --id Git.Git -e --source winget --accept-source-agreements --accept-package-agreements
    if ($LASTEXITCODE -ne 0) {
        Write-Host "winget install failed. Install git manually from https://git-scm.com/download/win, then re-run this script."
        exit 1
    }
    $env:Path = [System.Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [System.Environment]::GetEnvironmentVariable('Path', 'User')
    if (-not (Test-Command 'git')) {
        Write-Host "git was installed but isn't on PATH yet. Open a new terminal and re-run this script."
        exit 1
    }
}

if (Test-Path (Join-Path $InstallDir '.git')) {
    Write-Host "Found existing install at $InstallDir, updating..."
    git -C $InstallDir pull --ff-only
} else {
    Write-Host "Cloning into $InstallDir..."
    git clone $RepoUrl $InstallDir
}

Set-Location $InstallDir
& .\setup.ps1 -Run
