#!/usr/bin/env bash
# One-liner installer for PCAP Analyzer:
#   curl -fsSL https://raw.githubusercontent.com/ghostinator/pcap-analyzer/main/install.sh | bash
#
# Clones the repo (or updates an existing clone), then hands off to setup.sh
# to install Python/tkinter/git if needed, create a venv, and launch the GUI.
set -euo pipefail

REPO_URL="https://github.com/ghostinator/pcap-analyzer.git"
INSTALL_DIR="${PCAP_ANALYZER_DIR:-$HOME/pcap-analyzer}"

install_git_macos() {
    if command -v brew >/dev/null 2>&1; then
        brew install git
    else
        echo "git not found. Install it via Xcode Command Line Tools (xcode-select --install)"
        echo "or Homebrew (https://brew.sh), then re-run this script."
        exit 1
    fi
}

install_git_linux() {
    if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update && sudo apt-get install -y git
    elif command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y git
    elif command -v pacman >/dev/null 2>&1; then
        sudo pacman -Sy --noconfirm git
    else
        echo "Could not detect apt/dnf/pacman. Install git manually, then re-run this script."
        exit 1
    fi
}

if ! command -v git >/dev/null 2>&1; then
    echo "git not found, installing..."
    case "$(uname -s)" in
        Darwin) install_git_macos ;;
        Linux)  install_git_linux ;;
        *)
            echo "Unsupported OS: $(uname -s). Install git manually, then re-run this script."
            exit 1
            ;;
    esac
fi

if [ -d "$INSTALL_DIR/.git" ]; then
    echo "Found existing install at $INSTALL_DIR, updating..."
    git -C "$INSTALL_DIR" pull --ff-only
else
    echo "Cloning into $INSTALL_DIR..."
    git clone "$REPO_URL" "$INSTALL_DIR"
fi

cd "$INSTALL_DIR"
chmod +x setup.sh pcap-tools.sh
./setup.sh --run
