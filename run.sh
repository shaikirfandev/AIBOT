#!/bin/bash
# ============================================================
# BBHunter - One-Command Pipeline Runner
# ============================================================
# Usage:
#   ./run.sh                          # full pipeline
#   ./run.sh recon                    # recon only
#   ./run.sh analyze                  # LLM analysis only
#   ./run.sh report                   # report only
#   ./run.sh resume                   # resume from checkpoint
#   ./run.sh target example.com       # set target
# ============================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Activate venv if exists
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
fi

# Add Go bin to PATH
export PATH="$HOME/go/bin:$PATH"
export GOPATH="$HOME/go"

# Default target
export BB_TARGET="${BB_TARGET:-doordash.com}"

echo -e "${CYAN}"
echo "  ╔══════════════════════════════════════╗"
echo "  ║  BBHunter Pipeline Runner            ║"
echo "  ║  Target: $BB_TARGET"
echo "  ╚══════════════════════════════════════╝"
echo -e "${NC}"

case "${1:-all}" in
    recon)
        echo -e "${GREEN}▶ Phase 1: Passive Recon${NC}"
        python3 scripts/hunt.py
        echo -e "${GREEN}✓ Recon complete. Run: ./run.sh analyze${NC}"
        ;;
    analyze)
        echo -e "${GREEN}▶ Phase 2: LLM Chunk Analysis${NC}"
        python3 scripts/llm_analyzer.py --resume
        echo -e "${GREEN}✓ Analysis complete. Run: ./run.sh report${NC}"
        ;;
    report)
        echo -e "${GREEN}▶ Phase 3: Report Generation${NC}"
        python3 scripts/generate_report.py --format markdown
        echo -e "${GREEN}✓ Report saved in reports/${NC}"
        ;;
    resume)
        echo -e "${YELLOW}▶ Resuming pipeline...${NC}"
        python3 scripts/run_pipeline.py --resume
        ;;
    target)
        if [ -z "$2" ]; then
            echo -e "${RED}Usage: ./run.sh target <domain>${NC}"
            exit 1
        fi
        export BB_TARGET="$2"
        echo -e "${GREEN}▶ Full pipeline for: $2${NC}"
        python3 scripts/run_pipeline.py --target "$2"
        ;;
    check)
        echo -e "${CYAN}▶ Checking prerequisites...${NC}"
        python3 scripts/run_pipeline.py --check
        ;;
    all)
        echo -e "${GREEN}▶ Full Pipeline (recon → analyze → report)${NC}"
        python3 scripts/run_pipeline.py
        ;;
    *)
        echo "Usage: ./run.sh {recon|analyze|report|resume|target <domain>|check|all}"
        exit 1
        ;;
esac
