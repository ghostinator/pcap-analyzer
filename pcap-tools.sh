#!/bin/bash
# PCAP Analysis Tools Wrapper Script
# Usage: ./pcap-tools.sh <tool> [args...]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$SCRIPT_DIR/venv"
TOOLS="$SCRIPT_DIR/tools"

# Activate virtual environment (created by ./setup.sh)
if [ -d "$VENV" ]; then
    source "$VENV/bin/activate"
else
    echo "No venv found at $VENV - run ./setup.sh first." >&2
    exit 1
fi

TOOL=$1
shift

case $TOOL in
    info|summary)
        python "$TOOLS/pcap_info.py" "$@"
        ;;
    streams|tcp)
        python "$TOOLS/tcp_streams.py" "$@"
        ;;
    http)
        python "$TOOLS/http_analysis.py" "$@"
        ;;
    dns)
        python "$TOOLS/dns_analysis.py" "$@"
        ;;
    errors|anomalies)
        python "$TOOLS/errors.py" "$@"
        ;;
    filter)
        python "$TOOLS/filter.py" "$@"
        ;;
    reassemble|stream-data)
        python "$TOOLS/stream_reassemble.py" "$@"
        ;;
    help|-h|--help)
        echo "PCAP Analysis Tools"
        echo ""
        echo "Usage: ./pcap-tools.sh <tool> [args...]"
        echo ""
        echo "Tools:"
        echo "  info|summary      - File summary and protocol statistics"
        echo "  streams|tcp       - TCP stream analysis"
        echo "  http              - HTTP traffic analysis"
        echo "  dns               - DNS query/response analysis"
        echo "  errors|anomalies  - Network error detection"
        echo "  filter            - Filter packets to new file"
        echo "  reassemble        - TCP stream data reassembly"
        echo ""
        echo "Examples:"
        echo "  ./pcap-tools.sh info capture.pcap"
        echo "  ./pcap-tools.sh http capture.pcap --filter api.example.com"
        echo "  ./pcap-tools.sh errors capture.pcap"
        ;;
    *)
        echo "Unknown tool: $TOOL"
        echo "Run './pcap-tools.sh help' for usage information."
        exit 1
        ;;
esac
