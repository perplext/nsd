#!/bin/bash
# Pre-removal script for NSD

set -e

# Stop service if running
if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet nsd; then
        echo "Stopping NSD service..."
        systemctl stop nsd
    fi
    
    if systemctl is-enabled --quiet nsd; then
        echo "Disabling NSD service..."
        systemctl disable nsd
    fi
fi

echo "NSD will be removed."