# NSD Sample Outputs and Demonstrations

This file contains sample outputs and usage examples for the Network Sniffing Dashboard (NSD).

## Interface Discovery

```bash
$ ./bin/nsd -list-interfaces
Available network interfaces:
  ap1
  en0 [fe80::c8e:78b4:89e6:98ae, fd00::10ea:deea:2b62:d2ab, 192.168.50.118]
  awdl0 [fe80::542f:6cff:febb:3448]
  llw0 [fe80::542f:6cff:febb:3448]
  utun0 [fe80::1a3a:d926:3d71:a454]
  utun1 [fe80::2325:7040:eeb3:9f04]
  utun2 [fe80::f098:d431:42c4:4a13]
  utun3 [fe80::ce81:b1c:bd2c:69e]
  utun4
  utun5 [fe80::adaa:aeee:ffbc:d811]
  utun6 [fe80::c078:f8f4:9d3b:3c39]
  utun7 [fe80::ead:8802:1650:4418]
  utun8 [fe80::f26e:5b56:fb25:872]
  lo0 [127.0.0.1, ::1, fe80::1]
  anpi1
  anpi0
  anpi2
  en4-en6
  en1-en3
  bridge0
  gif0
  stf0
```

## Help Output

```bash
$ ./bin/nsd --help
Usage of ./bin/nsd:
  -auto-theme
    	Auto-detect dark/light theme based on terminal background
  -dashboard string
    	Start with specific dashboard (e.g., overview, security)
  -export-png string
    	Export traffic graph to PNG file
  -export-svg string
    	Export traffic graph to SVG file
  -export-theme string
    	Theme name to export
  -export-theme-file string
    	File path to write exported theme JSON/YAML file
  -extract-dir string
    	Directory to save extracted files (default "./extracted")
  -extract-files
    	Enable real-time file extraction from network traffic
  -fullscreen
    	Start in fullscreen mode
  -gradient
    	Enable static gradient shading (true/false) (default true)
  -i string
    	Network interface to monitor
  -i18n-file string
    	Path to JSON translation file
  -list-interfaces
    	List available network interfaces and exit
  -max-file-size int
    	Maximum file size for extraction (bytes) (default 52428800)
  -plugins string
    	Comma-separated list of plugin .so files to load
  -profile string
    	Load UI profile on startup
  -protocol-analysis
    	Enable deep protocol analysis for FTP, SSH, POP3, IMAP
  -protocol-filters string
    	Comma-separated list of protocols to analyze (default "ftp,ssh,pop3,imap")
  -security-mode
    	Enable advanced security monitoring and threat detection
  -ssl-cert string
    	Path to SSL certificate for traffic decryption
  -ssl-decrypt
    	Enable SSL/TLS traffic decryption
  -ssl-key string
    	Path to SSL private key for traffic decryption
  -ssl-keylog string
    	Path to SSL key log file (Chrome/Firefox SSLKEYLOGFILE)
  -style string
    	UI style to use (default "Standard")
  -theme string
    	Color theme to use (default "Dark+")
  -theme-file string
    	Path to custom theme JSON/YAML file
  -threat-intel string
    	Comma-separated list of threat intelligence feed URLs
  -version
    	Show version information and exit
  -viz string
    	Start with specific visualization (e.g., speedometer, matrix)
```

## Theme Export Example

```bash
$ ./bin/nsd -export-theme "Tokyo Night" -export-theme-file tokyo_night_export.json
$ cat tokyo_night_export.json
{
  "Tokyo Night": {
    "BorderColor": "#7aa2f7",
    "TitleColor": "#7aa2f7",
    "PrimaryColor": "#7dcfff",
    "SecondaryColor": "#bb9af7",
    "PieBorderColor": "#7aa2f7",
    "PieTitleColor": "#7aa2f7",
    "StatusBarTextColor": "#ffffff",
    "StatusBarBgColor": "#1a1b26"
  }
}
```

## Available Themes List

Based on the theme.go file, NSD includes these 14 built-in themes:

1. **High-Contrast Dark** - Neon green (#00FF00) on black, maximum accessibility
2. **Dark+** - VSCode dark theme with blue (#007ACC) accents  
3. **Light+** - Clean light theme with dark green (#006400) and navy (#00008B)
4. **Monokai** - Classic Sublime Text theme (lime #A6E22E, cyan #66D9EF)
5. **Solarized Light** - Popular light theme (#268BD2 blue, #859900 green)
6. **Solarized Dark** - Dark variant of Solarized (#268BD2, #B58900, #2AA198)
7. **Monochrome Accessibility** - Pure black and white for maximum contrast
8. **Dracula** - Purple theme (#BD93F9 purple, #50FA7B green, #FF79C6 pink)
9. **Tokyo Night** - Modern dark (#7AA2F7 blue, #7DCFFF cyan, #BB9AF7 purple)
10. **Tokyo Night Storm** - Deeper variant (#9D7CD8, #7DCFFF, #7AA2F7)
11. **Nord** - Arctic theme (#5E81AC blue, #88C0D0 cyan, #81A1C1 light blue)
12. **Gruvbox** - Retro theme (#FE8019 orange, #B8BB26 green, #FABD2F yellow)
13. **Catppuccin** - Pastel theme (#F5C2E7 pink, #89DCEB cyan, #F5E0DC cream)
14. **One Dark** - Atom theme (#61AFEF blue, #98C379 green, #E06C75 red)

## Visualization Modes

Based on the UI package analysis, NSD supports these visualization types:

### Real-time Visualizations
- **speedometer** - Gauge-style bandwidth meter
- **matrix** - Connection matrix grid
- **heatmap** - Color-coded traffic intensity map
- **radial** - Circular network topology
- **sunburst** - Hierarchical traffic breakdown
- **constellation** - Animated network connections
- **sankey** - Traffic flow diagrams
- **heartbeat** - Pulse-based activity monitor
- **weather** - Weather map-style network view

### Additional Components
- **worldmap** - Geographic traffic visualization
- **detection_dashboard** - Security event monitoring
- **protocol_dashboard** - Protocol-specific analysis
- **security_dashboard** - Comprehensive security overview

## Sample Command Combinations

### Basic Usage
```bash
# Standard monitoring with default theme
sudo ./bin/nsd -i en0

# Monitor with Tokyo Night theme
sudo ./bin/nsd -i en0 -theme "Tokyo Night"

# Start with speedometer visualization
sudo ./bin/nsd -i en0 -viz speedometer -theme "Dracula"
```

### Security Focused
```bash
# Security dashboard with high contrast
sudo ./bin/nsd -i en0 -dashboard security -theme "High-Contrast Dark"

# Full security mode with protocol analysis
sudo ./bin/nsd -i en0 -security-mode -protocol-analysis -theme "Nord"

# Monitor with threat intelligence
sudo ./bin/nsd -i en0 -security-mode -threat-intel "https://feeds.threatintel.com/malware"
```

### Customization Examples
```bash
# Custom theme file
sudo ./bin/nsd -i en0 -theme-file custom_cyberpunk.json -theme "Cyberpunk"

# Spanish interface
sudo ./bin/nsd -i en0 -i18n-file examples/i18n/es.json -theme "Solarized Dark"

# Fullscreen with constellation view
sudo ./bin/nsd -i en0 -fullscreen -viz constellation -theme "Tokyo Night Storm"

# Load plugins
sudo ./bin/nsd -i en0 -plugins examples/simpleplugin.so -theme "Gruvbox"
```

### Export Options
```bash
# Export traffic graph as PNG
sudo ./bin/nsd -i en0 -export-png network_traffic.png -theme "Monokai"

# Export as SVG with custom theme
sudo ./bin/nsd -i en0 -export-svg traffic.svg -theme "Catppuccin"
```

### Protocol Analysis
```bash
# Monitor specific protocols
sudo ./bin/nsd -i en0 -protocol-analysis -protocol-filters "ssh,ftp" -theme "One Dark"

# SSL decryption with keylog
sudo ./bin/nsd -i en0 -ssl-decrypt -ssl-keylog /path/to/keylog.txt -theme "Dark+"
```

### File Extraction
```bash
# Extract files from network traffic
sudo ./bin/nsd -i en0 -extract-files -extract-dir ./captured_files -max-file-size 104857600
```

## International Language Support

NSD includes translation files for 30+ languages in `examples/i18n/`:

- **af.json** - Afrikaans
- **ar.json** - Arabic  
- **bn.json** - Bengali
- **de.json** - German
- **el.json** - Greek
- **en.json** - English (default)
- **es.json** - Spanish
- **fa.json** - Persian/Farsi
- **fi.json** - Finnish
- **fr.json** - French
- **hi.json** - Hindi
- **id.json** - Indonesian
- **is.json** - Icelandic
- **it.json** - Italian
- **ja.json** - Japanese
- **ko.json** - Korean
- **mr.json** - Marathi
- **no.json** - Norwegian
- **pcm.json** - Nigerian Pidgin
- **pl.json** - Polish
- **pt.json** - Portuguese
- **ro.json** - Romanian
- **ru.json** - Russian
- **sv.json** - Swedish
- **sw.json** - Swahili
- **ta.json** - Tamil
- **te.json** - Telugu
- **tl.json** - Filipino/Tagalog
- **tr.json** - Turkish
- **ur.json** - Urdu
- **vi.json** - Vietnamese
- **zh.json** - Chinese (Simplified)
- **zh-wuu.json** - Wu Chinese
- **zh-yue.json** - Cantonese

## Performance Tips

1. **Interface Selection**: Use `en0` on macOS for best performance (main network interface)
2. **Theme Choice**: Light themes may render faster on some terminals
3. **Visualization**: Simpler visualizations (speedometer) use less CPU than complex ones (constellation)
4. **Memory**: Use `-max-file-size` to limit memory usage during file extraction
5. **Filtering**: Apply BPF filters to focus on specific traffic types

## Accessibility Features

- **Monochrome Accessibility** theme for vision impairments
- **High-Contrast Dark** theme for low vision users
- **Keyboard navigation** for all UI elements
- **Screen reader compatibility** through terminal interface
- **Customizable color schemes** via theme files

## Plugin Development

Example plugin structure available in `examples/simpleplugin/`:
```go
// simpleplugin.go
package main

import "fmt"

// PluginName exported name for the plugin
var PluginName = "SimplePlugin"

// Initialize plugin setup function
func Initialize() error {
    fmt.Println("Simple plugin initialized")
    return nil
}

// Process main plugin processing function
func Process(data interface{}) error {
    fmt.Printf("Processing data: %v\n", data)
    return nil
}
```

Build with:
```bash
go build -buildmode=plugin -o simpleplugin.so simpleplugin.go
```

Use with:
```bash
sudo ./bin/nsd -i en0 -plugins simpleplugin.so
```