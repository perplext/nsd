# NSD (Network Sniffing Dashboard) - Feature Demonstrations

This directory contains demonstrations of NSD's various features, themes, and capabilities.

## 🎨 Available Themes

NSD includes 14 built-in themes inspired by popular code editors and terminal applications:

### Dark Themes
- **High-Contrast Dark** - Neon green accents on black background for maximum accessibility
- **Dark+** - VSCode's default dark theme with blue/purple accents  
- **Monokai** - Classic Sublime Text theme with lime green and cyan
- **Solarized Dark** - Popular dark theme with balanced color palette
- **Dracula** - Purple/pink theme popular in developer tools
- **Tokyo Night** - Modern dark theme with blue/purple tones
- **Tokyo Night Storm** - Variation of Tokyo Night with deeper colors
- **Nord** - Arctic-inspired palette with cool blues and grays
- **Gruvbox** - Retro groove theme with warm oranges and greens
- **Catppuccin** - Pastel theme with soft purples and blues
- **One Dark** - Atom editor's default dark theme

### Light Themes  
- **Light+** - VSCode's light theme
- **Solarized Light** - Light variant of the popular Solarized theme

### Accessibility
- **Monochrome Accessibility** - Pure black and white for maximum contrast

## 📊 Visualization Types

NSD supports multiple visualization modes for network data:

### Real-time Graphs
- **Speedometer** - Gauge-style display of current bandwidth usage
- **Matrix** - Connection matrix showing traffic between hosts
- **Heatmap** - Color-coded grid showing traffic intensity over time
- **Radial** - Circular visualization of network connections
- **Sunburst** - Hierarchical network traffic breakdown
- **Constellation** - Network topology with animated connections
- **Sankey** - Flow diagram showing traffic paths between endpoints
- **Heartbeat** - Pulse-style visualization of network activity
- **Weather** - Weather map-style visualization of network conditions

### Dashboard Views
- **Overview** - General network statistics and graphs
- **Security** - Focused on security events and threat detection

## 🔧 Key Features Demonstrated

### Theme Customization
```bash
# Use built-in theme
sudo ./bin/nsd -i en0 -theme "Tokyo Night"

# Load custom theme from file
sudo ./bin/nsd -i en0 -theme-file custom_theme.json -theme "MyTheme"

# Auto-detect theme based on terminal
sudo ./bin/nsd -i en0 -auto-theme
```

### Visualization Modes
```bash
# Start with specific visualization
sudo ./bin/nsd -i en0 -viz speedometer
sudo ./bin/nsd -i en0 -viz matrix
sudo ./bin/nsd -i en0 -viz constellation
```

### Dashboard Modes
```bash
# Start with overview dashboard
sudo ./bin/nsd -i en0 -dashboard overview

# Start with security dashboard  
sudo ./bin/nsd -i en0 -dashboard security
```

### Security Features
```bash
# Enable security monitoring
sudo ./bin/nsd -i en0 -security-mode

# Enable protocol analysis
sudo ./bin/nsd -i en0 -protocol-analysis

# SSL/TLS decryption
sudo ./bin/nsd -i en0 -ssl-decrypt -ssl-cert cert.pem -ssl-key key.pem
```

### Internationalization
```bash
# Use Spanish interface
sudo ./bin/nsd -i en0 -i18n-file examples/i18n/es.json

# Use French interface
sudo ./bin/nsd -i en0 -i18n-file examples/i18n/fr.json
```

### Plugin System
```bash
# Load custom plugins
sudo ./bin/nsd -i en0 -plugins plugin1.so,plugin2.so
```

### Export Features
```bash
# Export traffic graph as PNG
sudo ./bin/nsd -i en0 -export-png traffic_graph.png

# Export traffic graph as SVG
sudo ./bin/nsd -i en0 -export-svg traffic_graph.svg

# Export theme configuration
./bin/nsd -export-theme "Tokyo Night" -export-theme-file tokyo_night.json
```

## 🌍 Supported Languages

NSD includes translations for 30+ languages:

- **European**: English, Spanish, French, German, Italian, Portuguese, Polish, Romanian, Swedish, Norwegian, Finnish, Icelandic, Greek
- **Asian**: Chinese (Simplified/Traditional), Japanese, Korean, Hindi, Bengali, Tamil, Telugu, Vietnamese, Indonesian, Thai, Filipino
- **Middle Eastern/African**: Arabic, Persian, Turkish, Urdu, Marathi, Swahili
- **Other**: Russian, Pidgin

## 🎬 Running the Demonstrations

### Quick Start
```bash
# Run the full demo script
./demo_script.sh

# Basic usage with popular theme
sudo ./bin/nsd -i en0 -theme "Tokyo Night"

# Security dashboard with high contrast
sudo ./bin/nsd -i en0 -dashboard security -theme "High-Contrast Dark"
```

### Custom Theme Examples

**Cyberpunk Theme (demos/themes/custom_cyberpunk.json):**
```json
{
  "Cyberpunk": {
    "BorderColor": "#00ffff",
    "TitleColor": "#ff00ff", 
    "PrimaryColor": "#00ff00",
    "SecondaryColor": "#ffff00",
    "PieBorderColor": "#00ffff",
    "PieTitleColor": "#ff00ff",
    "StatusBarTextColor": "#ffffff",
    "StatusBarBgColor": "#000000"
  }
}
```

**Pastel Theme (demos/themes/custom_pastel.yaml):**
```yaml
Pastel:
  BorderColor: "#ffc0cb"
  TitleColor: "#dda0dd"
  PrimaryColor: "#98fb98"
  SecondaryColor: "#add8e6"
  PieBorderColor: "#ffc0cb"
  PieTitleColor: "#dda0dd"
  StatusBarTextColor: "#2f4f4f"
  StatusBarBgColor: "#f5f5dc"
```

## 🔐 Security Features

NSD includes advanced security monitoring capabilities:

- **Threat Detection** - Real-time analysis of suspicious network patterns
- **Protocol Analysis** - Deep inspection of FTP, SSH, POP3, IMAP traffic
- **SSL/TLS Decryption** - Decrypt HTTPS traffic with certificates
- **File Extraction** - Extract files transferred over the network
- **Security Dashboard** - Dedicated view for security events

## 🎯 Performance Features

- **BPF Filtering** - Efficient packet filtering using Berkeley Packet Filter
- **Multi-threaded Processing** - Optimized for high-throughput networks
- **Memory Management** - Efficient handling of large traffic volumes
- **Cross-platform** - Native support for Linux, macOS, and Windows

## 📋 System Requirements

- **Privileges**: Root/administrator access required for packet capture
- **Network**: libpcap compatible network interface
- **Terminal**: 256-color terminal recommended for best theme experience
- **Memory**: Minimum 64MB RAM, 256MB+ recommended for high traffic

## 🚀 Getting Started

1. **Build NSD:**
   ```bash
   make build
   ```

2. **List available interfaces:**
   ```bash
   ./bin/nsd -list-interfaces
   ```

3. **Start monitoring:**
   ```bash
   sudo ./bin/nsd -i en0
   ```

4. **Try different themes:**
   ```bash
   sudo ./bin/nsd -i en0 -theme "Dracula"
   ```

5. **Enable security mode:**
   ```bash
   sudo ./bin/nsd -i en0 -security-mode -theme "High-Contrast Dark"
   ```

## ⌨️ Keyboard Shortcuts

While running NSD, use these keys to navigate:
- **Tab** - Switch between panels
- **Arrow Keys** - Navigate within panels  
- **Enter** - Select items
- **q** - Quit application
- **h** - Help/keybindings
- **t** - Toggle themes
- **v** - Switch visualizations

## 📝 Notes

- All demonstrations require root privileges due to packet capture requirements
- Use the `en0` interface on macOS for best results (typically the main network interface)
- Custom theme files support both JSON and YAML formats
- Plugin development examples available in `examples/simpleplugin/`
- Language files can be customized or extended for new translations

## 🔗 Related Files

- `pkg/ui/theme.go` - Theme definitions and color schemes
- `examples/i18n/` - Translation files for various languages
- `examples/simpleplugin/` - Plugin development example
- `docs/USER_GUIDE.md` - Comprehensive user documentation
- `CLAUDE.md` - Development guidance and architecture overview