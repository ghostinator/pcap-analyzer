# Sets up the venv and dependencies for PCAP Analyzer on Windows.
# Run from inside a clone of this repo:
#   .\setup.ps1          # set up only
#   .\setup.ps1 -Run     # set up and launch the GUI
param(
    [switch]$Run
)
$ErrorActionPreference = 'Stop'
Set-Location -Path $PSScriptRoot

function Test-Command($name) {
    return [bool](Get-Command $name -ErrorAction SilentlyContinue)
}

function Test-Tkinter($pythonExe) {
    & $pythonExe -c "import tkinter" 2>$null
    return $LASTEXITCODE -eq 0
}

function Find-PythonWithTkinter {
    # Prefer the `py` launcher (what python.org's installer registers) over a
    # bare `python`, which on stock Windows is often the Microsoft Store's
    # app-execution-alias stub that doesn't actually have Python installed.
    $candidates = @()
    if (Test-Command 'py') { $candidates += @('py -3', 'py') }
    if (Test-Command 'python') { $candidates += 'python' }
    if (Test-Command 'python3') { $candidates += 'python3' }

    foreach ($cmd in $candidates) {
        $parts = $cmd -split ' '
        $exe = $parts[0]
        $exeArgs = $parts | Select-Object -Skip 1
        try {
            & $exe @exeArgs -c "import tkinter" 2>$null
            if ($LASTEXITCODE -eq 0) {
                return $cmd
            }
        } catch {
            continue
        }
    }
    return $null
}

function Install-Python {
    Write-Host "Python 3 (with tkinter) not found. Installing via winget..."
    if (-not (Test-Command 'winget')) {
        Write-Host "winget not found. Install Python 3.9+ yourself from https://www.python.org/downloads/"
        Write-Host "(the 'tcl/tk and IDLE' option is checked by default and provides tkinter), then re-run this script."
        exit 1
    }
    # Python.org's official build via winget - NOT the Microsoft Store package,
    # which has had a spotty tkinter track record.
    winget install --id Python.Python.3.13 -e --source winget --accept-source-agreements --accept-package-agreements
    if ($LASTEXITCODE -ne 0) {
        Write-Host "winget install failed. Install Python 3.9+ manually from https://www.python.org/downloads/, then re-run this script."
        exit 1
    }
    Write-Host "Python installed. You may need to open a new terminal for PATH changes to take effect."
}

$pythonCmd = Find-PythonWithTkinter
if (-not $pythonCmd) {
    Install-Python
    # Refresh PATH in this session so a newly-installed python/py is visible
    # without requiring the user to reopen their terminal.
    $env:Path = [System.Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [System.Environment]::GetEnvironmentVariable('Path', 'User')
    $pythonCmd = Find-PythonWithTkinter
    if (-not $pythonCmd) {
        Write-Host "Still can't find a Python with tkinter after install. Open a new terminal and re-run this script, or install manually from https://www.python.org/downloads/"
        exit 1
    }
}

$pyParts = $pythonCmd -split ' '
$pyExe = $pyParts[0]
$pyArgs = $pyParts | Select-Object -Skip 1
$resolvedPath = (Get-Command $pyExe -ErrorAction SilentlyContinue).Source
$versionOutput = & $pyExe @pyArgs --version 2>&1
Write-Host "Using: $pythonCmd -> $resolvedPath ($versionOutput)"

if (-not (Test-Path 'venv\Scripts\python.exe')) {
    Write-Host "Creating virtual environment in $(Get-Location)\venv ..."
    $venvOutput = & $pyExe @pyArgs -m venv venv --clear 2>&1
    Write-Host "exit code: $LASTEXITCODE"
    if ($venvOutput) { Write-Host "output: $venvOutput" }
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path 'venv\Scripts\python.exe')) {
        Write-Host "Virtual environment creation failed (venv\Scripts\python.exe not found afterward)."
        if (Test-Path 'venv') {
            Write-Host "venv\ contents:"
            Get-ChildItem -Recurse venv | ForEach-Object { Write-Host "  $($_.FullName)" }
        } else {
            Write-Host "venv\ was not created at all."
        }
        exit 1
    }
}

Write-Host "Installing dependencies..."
& .\venv\Scripts\python.exe -m pip install --quiet --upgrade pip
if ($LASTEXITCODE -ne 0) { Write-Host "pip upgrade failed (exit $LASTEXITCODE)"; exit 1 }
& .\venv\Scripts\pip.exe install --quiet -r requirements.txt
if ($LASTEXITCODE -ne 0) { Write-Host "dependency install failed (exit $LASTEXITCODE)"; exit 1 }

Write-Host ""
Write-Host "Setup complete."
Write-Host "  GUI:       venv\Scripts\python.exe pcap_analyzer_gui.py"
Write-Host "  CLI tools: venv\Scripts\python.exe tools\pcap_info.py <capture.pcap>   (see README for the full list)"

if ($Run) {
    & .\venv\Scripts\python.exe pcap_analyzer_gui.py
}
