# NSD Troubleshooting Guide

This guide covers common issues and their solutions when using NSD (Network Sniffing Dashboard).

## Table of Contents

1. [Installation Issues](#installation-issues)
2. [Permission Problems](#permission-problems)
3. [Network Interface Issues](#network-interface-issues)
4. [Performance Problems](#performance-problems)
5. [UI and Display Issues](#ui-and-display-issues)
6. [Configuration Problems](#configuration-problems)
7. [Plugin Issues](#plugin-issues)
8. [Platform-Specific Issues](#platform-specific-issues)
9. [Debugging and Diagnostics](#debugging-and-diagnostics)

## Installation Issues

### Binary Download Problems

**Problem:** Binary won't run or shows "permission denied"

**Solution:**
```bash
# Make binary executable
chmod +x nsd

# Check if binary is corrupted
file nsd
```

**Problem:** "No such file or directory" on Linux

**Solution:**
```bash
# Check if you need 32-bit libraries on 64-bit system
ldd nsd

# Install missing libraries (Ubuntu/Debian)
sudo apt-get install libc6-dev

# Install missing libraries (CentOS/RHEL)
sudo yum install glibc-devel
```

### Package Manager Issues

**Problem:** Snap installation fails

**Solution:**
```bash
# Check snap is installed
snap version

# Install snap if missing (Ubuntu)
sudo apt update && sudo apt install snapd

# Install with required permissions
sudo snap install nsd --devmode
sudo snap connect nsd:network-control
```

**Problem:** Chocolatey installation fails on Windows

**Solution:**
```powershell
# Run PowerShell as Administrator
# Check execution policy
Get-ExecutionPolicy

# Set policy if needed
Set-ExecutionPolicy RemoteSigned

# Install dependencies manually
choco install npcap -y
choco install nsd -y
```

## Permission Problems

### Root/Administrator Access

**Problem:** "Permission denied" when capturing packets

**Linux Solution:**
```bash
# Run with sudo
sudo nsd -i eth0

# Or set capabilities (preferred)
sudo setcap cap_net_raw,cap_net_admin+eip /path/to/nsd
nsd -i eth0

# Or add user to specific groups
sudo usermod -a -G wireshark $USER
# Log out and log back in
```

**Windows Solution:**
```powershell
# Right-click Command Prompt and "Run as Administrator"
# Or use elevated PowerShell
Start-Process powershell -Verb runAs
```

**macOS Solution:**
```bash
# Run with sudo
sudo nsd -i en0

# Or grant permissions in System Preferences
# System Preferences > Security & Privacy > Privacy > Full Disk Access
```

### Permission Denied on Config Files

**Problem:** Cannot read/write configuration files

**Solution:**
```bash
# Check file permissions
ls -la ~/.config/nsd/

# Fix permissions
chmod 644 ~/.config/nsd/*.json
chmod 755 ~/.config/nsd/

# Create directory if missing
mkdir -p ~/.config/nsd/
```

## Network Interface Issues

### Interface Not Found

**Problem:** "Interface 'eth0' not found"

**Solution:**
```bash
# List available interfaces
ip link show                # Linux
ifconfig -a                 # macOS/BSD
netsh interface show        # Windows

# Use correct interface name
nsd -i enp0s3              # Linux example
nsd -i "Wi-Fi"             # Windows example (quotes needed)
nsd -i en0                 # macOS example
```

### No Packets Captured

**Problem:** Interface shown but no packets captured

**Diagnostics:**
```bash
# Check interface is up
ip link show eth0

# Check if interface has traffic
sudo tcpdump -i eth0 -c 10

# Check firewall rules
sudo iptables -L           # Linux
netsh advfirewall show     # Windows
```

**Solutions:**
```bash
# Bring interface up
sudo ip link set eth0 up

# Try promiscuous mode
nsd -i eth0 --promiscuous

# Try different interface
nsd -i any                 # Capture all interfaces
```

### Monitor Mode Issues

**Problem:** Cannot enable monitor mode on WiFi

**Solution:**
```bash
# Check if interface supports monitor mode
iw list | grep -A 10 "Supported interface modes"

# Enable monitor mode manually
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up

# Use with NSD
nsd -i wlan0
```

## Performance Problems

### High CPU Usage

**Problem:** NSD consuming too much CPU

**Solutions:**
```bash
# Use BPF filters to reduce packet processing
nsd -i eth0 -filter "tcp port 80 or tcp port 443"

# Limit capture rate
nsd -i eth0 --rate-limit 1000

# Reduce update frequency in config
echo '{"update_interval": 2000}' > ~/.config/nsd/config.json
```

### High Memory Usage

**Problem:** Memory usage keeps growing

**Solutions:**
```bash
# Limit packet buffer size
nsd -i eth0 --buffer-size 10MB

# Reduce connection tracking
nsd -i eth0 --max-connections 1000

# Enable garbage collection tuning
export GOGC=50
nsd -i eth0
```

### Packet Loss

**Problem:** Seeing packet loss warnings

**Solutions:**
```bash
# Increase buffer sizes
echo 'net.core.rmem_max = 134217728' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Use dedicated interface
nsd -i eth1  # Use less busy interface

# Reduce processing overhead
nsd -i eth0 --no-gui  # Terminal mode only
```

## UI and Display Issues

### Terminal Display Problems

**Problem:** UI elements not displaying correctly

**Solutions:**
```bash
# Check terminal capabilities
echo $TERM
tput colors

# Set proper terminal
export TERM=xterm-256color

# Try different terminal
# Use tmux/screen
tmux new-session 'nsd -i eth0'
```

**Problem:** Unicode characters not displaying

**Solutions:**
```bash
# Set proper locale
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8

# Use ASCII mode
nsd -i eth0 --ascii-mode
```

### Web Dashboard Issues

**Problem:** Web dashboard not accessible

**Diagnostics:**
```bash
# Check if API server is running
netstat -tlnp | grep :8080
curl http://localhost:8080/api/v1/health

# Check firewall
sudo ufw status                    # Ubuntu
sudo firewall-cmd --list-ports     # CentOS/RHEL
```

**Solutions:**
```bash
# Specify port explicitly
nsd -i eth0 --web-port 8080

# Bind to all interfaces
nsd -i eth0 --web-bind 0.0.0.0

# Check browser console for errors (F12)
```

### Theme Issues

**Problem:** Colors not displaying correctly

**Solutions:**
```bash
# Check terminal color support
tput colors

# Use high-contrast theme
nsd -i eth0 -theme "High-Contrast"

# Use custom theme file
nsd -i eth0 --theme-file /path/to/theme.json

# Auto-detect theme
nsd -i eth0 --auto-theme
```

## Configuration Problems

### Config File Not Found

**Problem:** "Config file not found" error

**Solution:**
```bash
# Check config file locations
ls ~/.config/nsd/
ls /etc/nsd/

# Create default config
mkdir -p ~/.config/nsd/
nsd --generate-config > ~/.config/nsd/config.json
```

### Invalid Configuration

**Problem:** "Invalid configuration" error

**Solution:**
```bash
# Validate JSON config
python -m json.tool ~/.config/nsd/config.json

# Check for common issues
grep -n "," ~/.config/nsd/config.json  # Trailing commas
```

### Language/Localization Issues

**Problem:** Wrong language or missing translations

**Solutions:**
```bash
# Check available translations
ls /usr/share/nsd/examples/i18n/

# Specify language explicitly
nsd -i eth0 --i18n-file /path/to/lang.json

# Set system locale
export LANG=es_ES.UTF-8
nsd -i eth0
```

## Plugin Issues

### Plugin Loading Failures

**Problem:** "Failed to load plugin" error

**Diagnostics:**
```bash
# Check plugin file
file plugin.so
ldd plugin.so  # Check dependencies

# Check plugin directory permissions
ls -la /usr/lib/nsd/plugins/
```

**Solutions:**
```bash
# Build plugin with correct Go version
go build -buildmode=plugin -o plugin.so plugin.go

# Install plugin dependencies
sudo apt-get install libpcap-dev  # Ubuntu
sudo yum install libpcap-devel    # CentOS

# Load plugin explicitly
nsd -i eth0 --plugins /path/to/plugin.so
```

### Plugin Crashes

**Problem:** Plugin causing crashes

**Solution:**
```bash
# Run without plugins to isolate issue
nsd -i eth0 --no-plugins

# Test plugin individually
nsd -i eth0 --plugins plugin1.so

# Check plugin logs
journalctl -u nsd  # systemd systems
tail -f /var/log/nsd.log
```

## Platform-Specific Issues

### Linux Issues

**Problem:** SELinux blocking packet capture

**Solution:**
```bash
# Check SELinux status
sestatus

# Create SELinux policy for NSD
sudo setsebool -P domain_can_mmap_files 1

# Or disable SELinux temporarily
sudo setenforce 0
```

**Problem:** systemd service won't start

**Solution:**
```bash
# Check service status
sudo systemctl status nsd

# Check service file
sudo systemctl edit nsd

# View logs
journalctl -u nsd -f
```

### Windows Issues

**Problem:** WinPcap/Npcap not found

**Solution:**
```powershell
# Install Npcap manually
# Download from https://nmap.org/npcap/
# Install with WinPcap compatibility mode

# Or install via Chocolatey
choco install npcap
```

**Problem:** Antivirus blocking NSD

**Solution:**
- Add NSD to antivirus whitelist
- Temporarily disable real-time protection
- Use Windows Defender exclusions

### macOS Issues

**Problem:** System Integrity Protection blocking access

**Solution:**
```bash
# Check SIP status
csrutil status

# Grant permissions in System Preferences
# System Preferences > Security & Privacy > Privacy > Developer Tools
```

**Problem:** Gatekeeper blocking execution

**Solution:**
```bash
# Remove quarantine attribute
xattr -d com.apple.quarantine nsd

# Or bypass Gatekeeper
sudo spctl --master-disable
```

## Debugging and Diagnostics

### Enable Debug Logging

**Environment Variables:**
```bash
# Enable debug logging
export NSD_DEBUG=1
export NSD_LOG_LEVEL=debug

# Log to file
export NSD_LOG_FILE=/tmp/nsd.log

# Run with debugging
nsd -i eth0
```

### Network Diagnostics

**Test Network Connectivity:**
```bash
# Test basic connectivity
ping 8.8.8.8

# Test DNS resolution
nslookup google.com

# Check routing table
ip route show
netstat -rn
```

### System Resource Monitoring

**Monitor NSD Resource Usage:**
```bash
# Monitor CPU and memory
top -p $(pgrep nsd)
htop -p $(pgrep nsd)

# Monitor network usage
iotop -p $(pgrep nsd)
nethogs
```

### Packet Capture Testing

**Test Raw Packet Capture:**
```bash
# Test with tcpdump
sudo tcpdump -i eth0 -c 10

# Test with tshark
tshark -i eth0 -c 10

# Compare with NSD output
nsd -i eth0 --debug
```

### Generate Debug Report

**Create Support Bundle:**
```bash
#!/bin/bash
# Create debug bundle
mkdir nsd-debug-$(date +%Y%m%d)
cd nsd-debug-$(date +%Y%m%d)

# System info
uname -a > system-info.txt
cat /etc/os-release >> system-info.txt

# Network info
ip addr show > network-config.txt
ip route show >> network-config.txt

# NSD info
nsd --version > nsd-version.txt
nsd --list-interfaces > interfaces.txt

# Logs
journalctl -u nsd --since "1 hour ago" > nsd.log
dmesg | tail -100 > dmesg.log

# Config files
cp ~/.config/nsd/* . 2>/dev/null || true

# Create archive
cd ..
tar czf nsd-debug-$(date +%Y%m%d).tar.gz nsd-debug-$(date +%Y%m%d)/
echo "Debug bundle created: nsd-debug-$(date +%Y%m%d).tar.gz"
```

## Getting Help

### Community Resources

- **GitHub Issues:** https://github.com/perplext/nsd/issues
- **Discussions:** https://github.com/perplext/nsd/discussions
- **Documentation:** https://github.com/perplext/nsd/docs

### Reporting Bugs

When reporting bugs, please include:

1. **System Information:**
   - Operating system and version
   - NSD version (`nsd --version`)
   - Go version (if building from source)

2. **Configuration:**
   - Command line arguments used
   - Configuration file contents
   - Environment variables

3. **Error Details:**
   - Full error messages
   - Debug logs (`NSD_DEBUG=1`)
   - Steps to reproduce

4. **Network Setup:**
   - Interface configuration
   - Network topology (if relevant)
   - Firewall/security software

### Emergency Recovery

**If NSD is completely broken:**

1. **Kill all processes:**
   ```bash
   sudo pkill -f nsd
   ```

2. **Reset configuration:**
   ```bash
   rm -rf ~/.config/nsd/
   sudo rm -rf /etc/nsd/
   ```

3. **Reinstall:**
   ```bash
   # Download fresh binary
   curl -L https://github.com/perplext/nsd/releases/latest/download/nsd-linux-amd64 -o nsd
   chmod +x nsd
   ```

4. **Test with minimal setup:**
   ```bash
   sudo ./nsd -i eth0 --no-config
   ```

This troubleshooting guide should help resolve most common issues with NSD. If you encounter problems not covered here, please consult the community resources or file an issue on GitHub.