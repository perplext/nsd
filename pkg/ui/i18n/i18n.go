package i18n

import (
    "encoding/json"
    "fmt"
    "path/filepath"
    "strings"
    
    "github.com/perplext/nsd/pkg/security"
)

// Translations holds the message mapping for localization.
// Initialized with default English translations.
var Translations = map[string]string{
    "requires_root": "This application requires root/administrator privileges to capture packets.",
    "run_as_root":  "Please run with sudo or as administrator.",
    // UI block titles
    "service_usage_pie": "Service Usage Pie [4]",
    "protocol_usage_pie": "Protocol Usage Pie [5]",
    "secure_nonsecure_pie": "Secure vs Nonsecure Pie [6]",
    "interface_counters": "Interface Counters [I]",
    "packet_size_histogram": "Packet Size Histogram [H]",
    "http_dns_summary": "HTTP/DNS Summary [D]",
    "geo_mapping": "Geo Mapping [G]",
    "help": "Help [?]",
    "raw_packet": "Raw Packet [Enter]",
    "interfaces": "Interfaces",
    "network_statistics": "Network Statistics [1]",
    "network_traffic": "Network Traffic [2]",
    "bandwidth": "Bandwidth",
    "cpu_mem": "CPU% / Mem%",
    "protocols": "Protocols [3]",
    "connections": "Connections [7]",
    "connection_details": "Connection Details [8]",
    "filter_connections": "Filter Connections",
    "bpf_filter": "BPF Filter",
    "captured_packets": "Captured Packets",
    // flag descriptions
    "flag_i_desc": "Network interface to monitor",
    "flag_theme_desc": "Color theme to use",
    "flag_theme_file_desc": "Path to custom theme JSON/YAML file",
    "flag_auto_theme_desc": "Auto-detect dark/light theme based on terminal background",
    "flag_style_desc": "UI style to use",
    "flag_gradient_desc": "Enable static gradient shading (true/false)",
    "flag_export_svg_desc": "Export traffic graph to SVG file",
    "flag_export_png_desc": "Export traffic graph to PNG file",
    "flag_plugins_desc": "Comma-separated list of plugin .so files to load",
    "plugins": "Plugins",
    "world_map": "World Map",
    "remote_ip": "Remote IP",
    "country": "Country",
    "flag_export_theme_desc": "Theme name to export",
    "flag_export_theme_file_desc": "File path to write exported theme JSON/YAML file",
    "flag_i18n_file_desc": "Path to JSON translation file",
    // Exit menu
    "exit_menu_text": "What would you like to do?",
    "options": "Options",
    "quit": "Quit",
    "cancel": "Cancel",
    // Connection table headers
    "source": "Source",
    "destination": "Destination",
    "proto": "Proto",
    "svc": "Service",
    "bytes": "Bytes",
    "pkts": "Packets",
    "activity": "Activity",
    "last_seen": "Last Seen",
}

// LoadTranslations loads a JSON translation file and merges into Translations.
func LoadTranslations(path string) error {
    // Validate file extension before processing
    ext := strings.ToLower(filepath.Ext(path))
    if ext != ".json" {
        return fmt.Errorf("unsupported translation file: %s", ext)
    }
    
    // Use secure file reading with current working directory as allowed base
    // This allows both relative paths (./examples/i18n/en.json) and validates absolute paths
    data, err := security.SafeReadFile(path, ".")
    if err != nil {
        return fmt.Errorf("failed to read translation file: %w", err)
    }
    
    var raw map[string]string
    if err := json.Unmarshal(data, &raw); err != nil {
        return fmt.Errorf("failed to parse JSON translation file: %w", err)
    }
    
    for k, v := range raw {
        Translations[k] = v
    }
    return nil
}

// T returns the localized string for the given key, or the key itself if not found.
func T(key string) string {
    if v, ok := Translations[key]; ok {
        return v
    }
    return key
}

