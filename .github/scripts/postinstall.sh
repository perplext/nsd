#!/bin/bash
# Post-installation script for NSD

set -e

# Create nsd user if it doesn't exist
if ! id -u nsd >/dev/null 2>&1; then
    echo "Creating nsd user..."
    useradd -r -s /bin/false -d /var/lib/nsd -m nsd
fi

# Create directories
echo "Creating directories..."
mkdir -p /etc/nsd
mkdir -p /var/log/nsd
mkdir -p /var/lib/nsd
mkdir -p /usr/lib/nsd/plugins

# Set permissions
echo "Setting permissions..."
chown -R nsd:nsd /var/log/nsd
chown -R nsd:nsd /var/lib/nsd
chown -R root:nsd /etc/nsd
chmod 750 /etc/nsd
chmod 750 /var/log/nsd
chmod 750 /var/lib/nsd

# Copy default config if not exists
if [ ! -f /etc/nsd/config.json ]; then
    echo "Installing default configuration..."
    cp /usr/share/doc/nsd/config.json /etc/nsd/config.json
    chmod 640 /etc/nsd/config.json
fi

# Reload systemd if available
if command -v systemctl >/dev/null 2>&1; then
    echo "Reloading systemd..."
    systemctl daemon-reload
fi

# Set capabilities on binary
if command -v setcap >/dev/null 2>&1; then
    echo "Setting capabilities..."
    setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/nsd
fi

echo "NSD installation completed!"
echo ""
echo "To start NSD:"
echo "  systemctl start nsd"
echo ""
echo "To enable NSD at boot:"
echo "  systemctl enable nsd"
echo ""
echo "Configuration file: /etc/nsd/config.json"
echo "Log files: /var/log/nsd/"