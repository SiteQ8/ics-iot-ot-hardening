#!/bin/bash
# Setup script for ICS Hardening Framework
# Author: Ali AlEnezi
# Version: 1.0.0

set -euo pipefail

echo "Setting up ICS Hardening Framework..."

# Check for Python 3
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is required but not installed."
    exit 1
fi

# Check for pip
if ! command -v pip3 &> /dev/null; then
    echo "Error: pip3 is required but not installed."
    exit 1
fi

# Install Python dependencies
echo "Installing Python dependencies..."
pip3 install -r requirements.txt

# Install development dependencies if in dev mode
if [[ "${1:-}" == "--dev" ]]; then
    echo "Installing development dependencies..."
    pip3 install -r requirements-dev.txt
    
    # Install pre-commit hooks
    if command -v pre-commit &> /dev/null; then
        pre-commit install
        echo "Pre-commit hooks installed."
    fi
fi

# Create necessary directories
echo "Creating directory structure..."
mkdir -p logs
mkdir -p output
mkdir -p config
mkdir -p backups

# Set executable permissions on scripts
echo "Setting permissions on scripts..."
find scripts/ -name "*.sh" -exec chmod +x {} \;
find tools/ -name "*.py" -exec chmod +x {} \;

# Copy example configurations
echo "Setting up example configurations..."
if [[ ! -f "config/settings.yaml" ]] && [[ -f "examples/configurations/settings-example.yaml" ]]; then
    cp examples/configurations/settings-example.yaml config/settings.yaml
    echo "Example configuration copied to config/settings.yaml"
fi

echo "Setup complete!"
echo ""
echo "Next steps:"
echo "1. Review and customize config/settings.yaml"
echo "2. Run initial assessment: python3 tools/assessment/ics-security-assessment.py"
echo "3. See docs/implementation/quick-start.md for detailed instructions"
