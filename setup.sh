#!/usr/bin/env bash
# ThreatPulse Setup Script
# Run: chmod +x setup.sh && ./setup.sh

set -e

echo ""
echo "╔══════════════════════════════════════╗"
echo "║   ThreatPulse — Setup               ║"
echo "╚══════════════════════════════════════╝"
echo ""

# Check Python 3.11+
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
REQUIRED_VERSION="3.11"
if python3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)"; then
    echo "✓ Python $PYTHON_VERSION detected"
else
    echo "✗ Python 3.11+ is required (found $PYTHON_VERSION)"
    exit 1
fi

# Create virtual environment
if [ ! -d ".venv" ]; then
    echo "→ Creating virtual environment..."
    python3 -m venv .venv
    echo "✓ Virtual environment created"
else
    echo "✓ Virtual environment already exists"
fi

# Activate and install deps
source .venv/bin/activate
echo "→ Installing dependencies..."
pip install --upgrade pip -q
pip install -r requirements.txt -q
echo "✓ Dependencies installed"

# Copy .env if not present
if [ ! -f ".env" ]; then
    cp .env.example .env
    echo "✓ .env created from .env.example"
    echo ""
    echo "  ┌─────────────────────────────────────────┐"
    echo "  │  OPTIONAL: Add API keys to .env for     │"
    echo "  │  enhanced coverage:                     │"
    echo "  │                                         │"
    echo "  │  NVD_API_KEY  → nvd.nist.gov/developers │"
    echo "  │  OTX_API_KEY  → otx.alienvault.com      │"
    echo "  └─────────────────────────────────────────┘"
    echo ""
else
    echo "✓ .env already configured"
fi

echo ""
echo "╔══════════════════════════════════════╗"
echo "║   Setup complete! To start:         ║"
echo "║                                     ║"
echo "║   source .venv/bin/activate         ║"
echo "║   python main.py                    ║"
echo "║                                     ║"
echo "║   API:  http://localhost:8000       ║"
echo "║   Docs: http://localhost:8000/docs  ║"
echo "╚══════════════════════════════════════╝"
echo ""
