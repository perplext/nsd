# NSD User Guide

## Table of Contents

1. [Getting Started](#getting-started)
2. [Basic Usage](#basic-usage)
3. [User Interface](#user-interface)
4. [Visualizations](#visualizations)
5. [Filtering and Analysis](#filtering-and-analysis)
6. [Themes and Customization](#themes-and-customization)
7. [Keyboard Shortcuts](#keyboard-shortcuts)
8. [Export and Reporting](#export-and-reporting)
9. [Plugins](#plugins)
10. [Advanced Features](#advanced-features)
11. [Troubleshooting](#troubleshooting)
12. [FAQ](#faq)

## Getting Started

### Installation

NSD requires administrator/root privileges to capture network packets.

#### Quick Install

**macOS:**
```bash
brew install nsd
```

**Linux:**
```bash
# Download latest release
wget https://github.com/user/nsd/releases/latest/download/nsd-linux-amd64
chmod +x nsd-linux-amd64
sudo mv nsd-linux-amd64 /usr/local/bin/nsd
```

**Windows:**
1. Download the Windows installer from [releases](https://github.com/user/nsd/releases)
2. Install Npcap from https://npcap.com
3. Run the NSD installer

### First Run

1. Open a terminal with administrator privileges
2. List available network interfaces:
   ```bash
   nsd --list-interfaces
   ```
3. Start monitoring your primary interface:
   ```bash
   sudo nsd -i eth0  # Linux
   sudo nsd -i en0   # macOS
   ```

## Basic Usage

### Command Line Options

```bash
nsd [options]

Options:
  -i <interface>        Network interface to monitor
  -filter <expression>  BPF filter expression
  -theme <name>         UI theme (default: Dark+)
  -style <name>         Border style (default: Standard)
  -list-interfaces      List available interfaces
  -list-themes          List available themes
  -help                 Show help message
  -version              Show version
```

### Common Examples

Monitor all traffic on eth0:
```bash
sudo nsd -i eth0
```

Monitor only HTTP/HTTPS traffic:
```bash
sudo nsd -i eth0 -filter "tcp port 80 or tcp port 443"
```

Monitor traffic from a specific host:
```bash
sudo nsd -i eth0 -filter "host 192.168.1.100"
```

Use a specific theme:
```bash
sudo nsd -i eth0 -theme CyberpunkNeon
```

## User Interface

### Layout Overview

```
┌─────────────────────────────────────────────────────────┐
│                    NSD v1.0.0                        │
├─────────────────────┬───────────────────────────────────┤
│                     │                                   │
│   Stats Panel       │      Visualization Area          │
│                     │                                   │
│ • Total Packets     │   [Graph/Chart/Visualization]    │
│ • Bytes/sec         │                                   │
│ • Connections       │                                   │
│ • Top Protocols     │                                   │
│                     │                                   │
├─────────────────────┴───────────────────────────────────┤
│              Connection Details Table                    │
│ Src IP:Port → Dst IP:Port  Protocol  Size  Packets     │
├─────────────────────────────────────────────────────────┤
│ [F1] Help  [Tab] Switch  [Q] Quit  [P] Pause          │
└─────────────────────────────────────────────────────────┘
```

### Navigation

- **Tab**: Switch between panels
- **Arrow Keys**: Navigate within panels
- **Enter**: Select/activate items
- **Escape**: Go back/cancel

### Panels

#### 1. Statistics Panel (Left)
Shows real-time network statistics:
- Total packets captured
- Current throughput (bytes/sec)
- Active connections
- Protocol distribution
- Interface information

#### 2. Visualization Area (Center/Right)
Displays the selected visualization:
- Graphs
- Charts
- Maps
- Custom visualizations

#### 3. Connection Table (Bottom)
Lists active network connections with details:
- Source and destination IP:Port
- Protocol information
- Data transferred
- Connection duration

## Visualizations

NSD includes multiple built-in visualizations. Press number keys 1-9 to switch between them.

### 1. Speedometer (Press 1)
Real-time network speed gauge showing current throughput.

**Controls:**
- `+/-`: Adjust scale
- `r`: Reset peak value

### 2. Matrix Rain (Press 2)
Displays connections as a matrix-style rain effect.

**Features:**
- Green: Normal traffic
- Red: High-volume connections
- Yellow: New connections

### 3. Constellation Map (Press 3)
Shows network topology as interconnected nodes.

**Interaction:**
- Click nodes for details
- Drag to reposition
- Scroll to zoom

### 4. Traffic Heatmap (Press 4)
Visualizes traffic intensity over time.

**Color Scale:**
- Blue: Low traffic
- Green: Moderate traffic
- Yellow: High traffic
- Red: Very high traffic

### 5. Sankey Diagram (Press 5)
Flow diagram showing traffic between endpoints.

**Features:**
- Width indicates volume
- Color shows protocol
- Hover for details

### 6. World Map (Press 6)
Geographic visualization of connections.

**Requirements:**
- GeoIP database (auto-downloaded)
- Internet connection for updates

### 7. Packet Distribution (Press 7)
Shows distribution of packet types and sizes.

### 8. Connection Timeline (Press 8)
Displays connection lifecycle and duration.

### 9. Custom Visualizations (Press 9)
Cycle through any loaded plugin visualizations.

## Filtering and Analysis

### BPF Filters

NSD supports Berkeley Packet Filter (BPF) syntax for traffic filtering.

#### Common Filters

**By Protocol:**
```bash
# TCP traffic only
sudo nsd -i eth0 -filter "tcp"

# UDP traffic only
sudo nsd -i eth0 -filter "udp"

# ICMP traffic only
sudo nsd -i eth0 -filter "icmp"
```

**By Port:**
```bash
# HTTP traffic
sudo nsd -i eth0 -filter "tcp port 80"

# SSH traffic
sudo nsd -i eth0 -filter "tcp port 22"

# Multiple ports
sudo nsd -i eth0 -filter "tcp port 80 or tcp port 443"
```

**By Host:**
```bash
# Traffic to/from specific IP
sudo nsd -i eth0 -filter "host 192.168.1.1"

# Traffic from specific source
sudo nsd -i eth0 -filter "src host 192.168.1.1"

# Traffic to specific destination
sudo nsd -i eth0 -filter "dst host 192.168.1.1"
```

**By Network:**
```bash
# Local network traffic
sudo nsd -i eth0 -filter "net 192.168.1.0/24"

# Exclude local traffic
sudo nsd -i eth0 -filter "not net 192.168.1.0/24"
```

**Complex Filters:**
```bash
# Web traffic from specific subnet
sudo nsd -i eth0 -filter "src net 192.168.1.0/24 and (tcp port 80 or tcp port 443)"

# All traffic except SSH
sudo nsd -i eth0 -filter "not tcp port 22"

# TCP SYN packets only
sudo nsd -i eth0 -filter "tcp[tcpflags] & tcp-syn != 0"
```

### Interactive Filtering

While NSD is running:
- Press `f` to open filter dialog
- Enter BPF expression
- Press Enter to apply
- Press `c` to clear filter

### Quick Filters

Press these keys for quick filtering:
- `h`: HTTP/HTTPS traffic only
- `d`: DNS traffic only
- `s`: SSH traffic only
- `m`: SMTP/Email traffic only
- `a`: Show all traffic (clear filters)

## Themes and Customization

### Built-in Themes

NSD includes several pre-defined themes:

1. **Dark+** (default) - Enhanced dark theme
2. **Light** - Light background theme
3. **Monokai** - Popular color scheme
4. **Solarized** - Solarized dark
5. **Nord** - Nordic color palette
6. **Dracula** - Dracula theme
7. **OneDark** - Atom One Dark
8. **GruvboxDark** - Gruvbox dark theme
9. **CyberpunkNeon** - Neon cyberpunk style
10. **Matrix** - Green matrix theme
11. **Midnight** - Deep blue theme
12. **Synthwave** - 80s aesthetic

List all themes:
```bash
nsd --list-themes
```

### Custom Themes

Create a custom theme file `mytheme.json`:

```json
{
  "themes": [{
    "name": "MyTheme",
    "foreground": "#E0E0E0",
    "background": "#1A1A1A",
    "border": "#404040",
    "title": "#00D4FF",
    "info": "#00FF88",
    "warning": "#FFD700",
    "error": "#FF4444",
    "success": "#00FF00",
    "primary": "#0088FF",
    "secondary": "#FF00FF",
    "tertiary": "#00FFFF",
    "quaternary": "#FFFF00"
  }]
}
```

Load custom theme:
```bash
nsd -i eth0 -theme-file mytheme.json -theme MyTheme
```

### Border Styles

Available border styles:
- **Standard** - Single line borders
- **Rounded** - Rounded corners
- **Double** - Double line borders
- **ASCII** - ASCII-only (no Unicode)
- **Minimal** - Minimal borders
- **Heavy** - Thick borders
- **Dashed** - Dashed lines
- **Neon** - Glowing effect
- **Tech** - Technical style
- **Vintage** - Classic terminal

Example:
```bash
nsd -i eth0 -style Rounded
```

### UI Profiles

Save your UI configuration:
1. Configure UI as desired
2. Press `Ctrl+S`
3. Enter profile name
4. Profile saved to `~/.nsd/profiles/`

Load a profile:
```bash
nsd -i eth0 -profile myprofile
```

## Keyboard Shortcuts

### Navigation
- `Tab` / `Shift+Tab` - Switch between panels
- `↑↓←→` - Navigate within panels
- `Page Up/Down` - Scroll quickly
- `Home/End` - Jump to start/end

### Visualizations
- `1-9` - Switch visualization
- `0` - Dashboard view
- `Space` - Pause/Resume visualization
- `r` - Reset/Refresh view

### Filtering
- `f` - Open filter dialog
- `c` - Clear current filter
- `h` - Quick filter: HTTP/HTTPS
- `d` - Quick filter: DNS
- `s` - Quick filter: SSH
- `a` - Show all (remove filters)

### Display
- `F11` or `Ctrl+F` - Toggle fullscreen
- `+/-` - Zoom in/out
- `t` - Cycle through themes
- `b` - Cycle border styles
- `g` - Toggle gradients

### Data
- `p` - Pause/Resume capture
- `R` - Reset statistics
- `e` - Export current view
- `S` - Take screenshot
- `Ctrl+S` - Save UI profile

### System
- `?` or `F1` - Show help
- `i` - Show interface info
- `v` - Show version
- `q` or `Ctrl+C` - Quit

## Export and Reporting

### Export Formats

NSD can export data in multiple formats:

#### 1. SVG Export
Export current visualization as SVG:
```bash
nsd -i eth0 -export-svg output.svg
```

Or press `e` then select SVG while running.

#### 2. PNG Export
Export as PNG image:
```bash
nsd -i eth0 -export-png output.png
```

#### 3. JSON Export
Export raw data as JSON:
- Press `e` while running
- Select JSON format
- Choose time range

#### 4. CSV Export
Export connection data as CSV:
- Press `e` while running
- Select CSV format
- Opens in default spreadsheet app

### Report Generation

Generate network reports:

```bash
# Daily report
nsd -i eth0 -report daily -output report.html

# Custom time range
nsd -i eth0 -report custom -start "2024-01-01" -end "2024-01-07"
```

### Automated Exports

Schedule automatic exports:

```bash
# Export stats every hour
nsd -i eth0 -auto-export json -interval 3600 -output-dir /var/log/nsd/
```

## Plugins

### Installing Plugins

1. Download plugin file (`.so` extension)
2. Place in plugins directory:
   - Linux: `~/.nsd/plugins/`
   - macOS: `~/Library/Application Support/nsd/plugins/`
   - Windows: `%APPDATA%\nsd\plugins\`

3. Load plugin:
   ```bash
   nsd -i eth0 -plugins myplugin.so
   ```

### Available Plugins

Official plugins available at https://github.com/user/nsd-plugins:

- **nsd-geoip**: Enhanced geolocation features
- **nsd-ml**: Machine learning traffic analysis
- **nsd-export**: Additional export formats
- **nsd-alert**: Custom alerting rules
- **nsd-stats**: Advanced statistics

### Plugin Management

List loaded plugins:
- Press `P` while NSD is running

Enable/disable plugins:
- Press `P` then space to toggle

Configure plugin:
- Press `P` then `c` on selected plugin

## Advanced Features

### Multi-Interface Monitoring

Monitor multiple interfaces:
```bash
nsd -i eth0,eth1,wlan0
```

Or use "any" for all interfaces:
```bash
nsd -i any
```

### Remote Monitoring

Connect to remote NSD instance:
```bash
nsd -remote 192.168.1.100:8080
```

### Packet Recording

Record packets for later analysis:
```bash
# Record to file
nsd -i eth0 -w capture.pcap

# Read from file
nsd -r capture.pcap
```

### Performance Profiling

Enable performance profiling:
```bash
nsd -i eth0 -profile-cpu cpu.prof -profile-mem mem.prof
```

### API Access

Enable REST API:
```bash
nsd -i eth0 -api :8080
```

Access stats via API:
```bash
curl http://localhost:8080/api/stats
curl http://localhost:8080/api/connections
```

### Scripting

Use NSD in scripts:
```bash
#!/bin/bash
# Monitor for high traffic
while true; do
    BYTES=$(nsd -i eth0 -json -duration 10 | jq .bytes_per_sec)
    if [ $BYTES -gt 1000000 ]; then
        echo "High traffic detected: $BYTES bytes/sec"
    fi
    sleep 10
done
```

## Troubleshooting

### Common Issues

#### 1. Permission Denied
**Problem:** "Permission denied" error
**Solution:** Run with sudo/administrator privileges
```bash
sudo nsd -i eth0
```

#### 2. Interface Not Found
**Problem:** "Interface not found" error
**Solution:** List available interfaces
```bash
nsd --list-interfaces
# Then use correct interface name
```

#### 3. High CPU Usage
**Problem:** NSD using too much CPU
**Solutions:**
- Use BPF filters to reduce packet processing
- Disable gradients: `-gradient=false`
- Reduce update frequency
- Use simpler visualizations

#### 4. No Packets Captured
**Problem:** Statistics show 0 packets
**Solutions:**
- Check interface is active: `ip link show eth0`
- Verify no firewall blocking
- Try without filters first
- Check interface has traffic

#### 5. Display Issues
**Problem:** Broken UI or characters
**Solutions:**
- Ensure terminal supports UTF-8
- Try ASCII mode: `-style ASCII`
- Resize terminal window
- Update terminal emulator

### Debug Mode

Enable debug logging:
```bash
nsd -i eth0 -debug
```

Write debug to file:
```bash
nsd -i eth0 -debug -log-file debug.log
```

### Getting Help

In-app help:
- Press `?` or `F1` while running

Command line help:
```bash
nsd -help
nsd -help-filters
nsd -help-themes
```

## FAQ

### General Questions

**Q: Do I need root/admin privileges?**
A: Yes, packet capture requires elevated privileges on all platforms.

**Q: Which interface should I monitor?**
A: Use `nsd --list-interfaces` to see available interfaces. Common names:
- Linux: eth0, wlan0, ens33
- macOS: en0 (WiFi), en1 (Ethernet)
- Windows: Use interface description from list

**Q: Can I monitor WiFi traffic?**
A: Yes, if your WiFi adapter supports monitor mode. Some adapters may have limitations.

**Q: How do I monitor all traffic?**
A: Use `-i any` to monitor all interfaces (may impact performance).

### Performance Questions

**Q: NSD is using too much CPU**
A: Try these optimizations:
- Use specific BPF filters
- Disable gradients
- Use simpler visualizations
- Limit packet rate in settings

**Q: How much memory does NSD use?**
A: Typically 50-200MB depending on traffic volume. Memory usage can be limited in configuration.

**Q: Can NSD handle 10Gbps networks?**
A: Yes, with appropriate hardware and tuning. See deployment guide for optimization tips.

### Feature Questions

**Q: Can I export data to Wireshark?**
A: Yes, use `-w file.pcap` to save in pcap format.

**Q: Does NSD decrypt HTTPS traffic?**
A: No, NSD observes traffic patterns but doesn't decrypt encrypted connections.

**Q: Can I set alerts?**
A: Yes, using the alerts plugin or API integration.

**Q: Is there a GUI version?**
A: NSD is terminal-based by design, but exports can be viewed in browsers.

### Customization Questions

**Q: How do I create custom visualizations?**
A: Write a plugin in Go. See plugin development guide.

**Q: Can I change keybindings?**
A: Yes, create a custom keymap file. See configuration guide.

**Q: How do I integrate with monitoring systems?**
A: Use the REST API or Prometheus metrics endpoint.

## Tips and Tricks

### Power User Tips

1. **Quick Interface Switch**: Use `Ctrl+I` to quickly switch interfaces
2. **Bookmark Filters**: Save frequently used filters with `Ctrl+B`
3. **Time Navigation**: Use `[` and `]` to move through time periods
4. **Focus Mode**: Press `F` to focus on single connection
5. **Multi-Window**: Run multiple instances for different interfaces

### Performance Tips

1. **Pre-filter at Kernel**: Use BPF filters for better performance
2. **Snapshot Length**: Reduce with `-snaplen 96` if headers suffice  
3. **Buffer Tuning**: Increase kernel buffers for high-speed networks
4. **CPU Affinity**: Bind to specific cores on multi-core systems

### Analysis Tips

1. **Baseline First**: Establish normal traffic patterns
2. **Peak Hours**: Monitor during different times
3. **Protocol Focus**: Filter by protocol when investigating issues
4. **Connection Tracking**: Use focus mode to follow single connections
5. **Export and Compare**: Export data for historical comparison

## Next Steps

1. **Explore Visualizations**: Try all built-in visualizations
2. **Master Filters**: Learn BPF syntax for precise filtering
3. **Customize Theme**: Create your perfect theme
4. **Try Plugins**: Enhance functionality with plugins
5. **Automate**: Use API for integration and automation

For more information:
- Advanced Configuration: See `docs/CONFIGURATION.md`
- Plugin Development: See `docs/PLUGINS.md`
- API Reference: See `docs/API.md`
- Deployment Guide: See `docs/DEPLOYMENT.md`

Happy monitoring! 🚀