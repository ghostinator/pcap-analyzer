#!/usr/bin/env bash
# Sets up the venv and dependencies for PCAP Analyzer. Run from inside a
# clone of this repo: ./setup.sh (add --run to launch the GUI afterward).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PYTHON=""

# List candidate interpreters, bare `python3` first (on Homebrew this is
# whichever version `brew install python-tk` would actually target).
python_candidates() {
    command -v python3 >/dev/null 2>&1 && echo python3
    for v in 3.14 3.13 3.12 3.11 3.10 3.9; do
        command -v "python$v" >/dev/null 2>&1 && echo "python$v"
    done
}

# Only accepts a candidate that actually has a working tkinter: on systems
# with multiple Python installs (e.g. several Homebrew python@X.Y kegs), one
# can exist without its matching python-tk sibling while another is fine -
# picking the first *interpreter* found isn't enough, it has to be checked.
find_python_with_tkinter() {
    local c
    while read -r c; do
        if "$c" -c "import tkinter" >/dev/null 2>&1; then
            PYTHON="$c"
            return 0
        fi
    done < <(python_candidates)
    return 1
}

find_any_python() {
    local c
    c="$(python_candidates | head -1)"
    [ -n "$c" ] || return 1
    PYTHON="$c"
    return 0
}

install_python_macos() {
    echo "Python 3 not found. Installing via Homebrew..."
    if ! command -v brew >/dev/null 2>&1; then
        echo "Homebrew not found. Install Python 3 yourself, either:"
        echo "  - Homebrew (https://brew.sh), then: brew install python python-tk"
        echo "  - or from https://www.python.org/downloads/ (includes tkinter)"
        echo "then re-run this script."
        exit 1
    fi
    brew install python python-tk
}

install_tkinter_macos() {
    echo "Found $PYTHON but it's missing tkinter. Installing python-tk via Homebrew..."
    if ! command -v brew >/dev/null 2>&1; then
        echo "Homebrew not found. Install a Python build that bundles tkinter from"
        echo "https://www.python.org/downloads/, then re-run this script."
        exit 1
    fi
    brew install python-tk
}

install_python_linux() {
    echo "Python 3 not found. Installing via the system package manager..."
    if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update && sudo apt-get install -y python3 python3-venv python3-pip python3-tk
    elif command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y python3 python3-pip python3-tkinter
    elif command -v pacman >/dev/null 2>&1; then
        sudo pacman -Sy --noconfirm python python-pip tk
    else
        echo "Could not detect apt/dnf/pacman. Install Python 3.9+ (with tkinter) manually, then re-run this script."
        exit 1
    fi
}

install_tkinter_linux() {
    echo "Found $PYTHON but it's missing tkinter. Installing it..."
    if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update && sudo apt-get install -y python3-tk
    elif command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y python3-tkinter
    elif command -v pacman >/dev/null 2>&1; then
        sudo pacman -Sy --noconfirm tk
    else
        echo "Could not detect apt/dnf/pacman. Install your distro's tkinter package manually, then re-run this script."
        exit 1
    fi
}

if find_python_with_tkinter; then
    : # already have a working interpreter, nothing to install
elif find_any_python; then
    case "$(uname -s)" in
        Darwin) install_tkinter_macos ;;
        Linux)  install_tkinter_linux ;;
        *)      echo "Unsupported OS: $(uname -s). Install tkinter for $PYTHON manually, then re-run this script."; exit 1 ;;
    esac
    find_python_with_tkinter || { echo "Still missing tkinter after install attempt. Install it manually and re-run this script."; exit 1; }
else
    case "$(uname -s)" in
        Darwin) install_python_macos ;;
        Linux)  install_python_linux ;;
        *)      echo "Unsupported OS: $(uname -s). Install Python 3.9+ (with tkinter) manually, then re-run this script."; exit 1 ;;
    esac
    find_python_with_tkinter || { echo "Python 3 install failed or is still missing tkinter. Install it manually and re-run this script."; exit 1; }
fi

echo "Using $PYTHON: $("$PYTHON" --version)"

if [ ! -d venv ]; then
    echo "Creating virtual environment..."
    "$PYTHON" -m venv venv
fi

echo "Installing dependencies..."
venv/bin/pip install --quiet --upgrade pip
venv/bin/pip install --quiet -r requirements.txt

echo ""
echo "Setup complete."
echo "  GUI:       venv/bin/python pcap_analyzer_gui.py"
echo "  CLI tools: ./pcap-tools.sh <tool> <capture.pcap>   (run './pcap-tools.sh help' for the list)"

if [ "${1:-}" = "--run" ]; then
    exec venv/bin/python pcap_analyzer_gui.py
fi
