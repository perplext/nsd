# UI API Reference

## Package: `github.com/user/nsd/pkg/ui`

The ui package provides terminal user interface components for NSD, including themes, visualizations, and interactive dashboards.

## Index

- [Types](#types)
  - [UI](#ui)
  - [Theme](#theme)
  - [ThemeConfig](#themeconfig)
  - [BorderStyle](#borderstyle)
  - [Visualization](#visualization)
- [Functions](#functions)
- [Visualizations](#visualizations)
- [Internationalization](#internationalization)
- [Examples](#examples)

## Types

### UI

UI is the main user interface controller that manages the terminal display.

```go
type UI struct {
    // contains filtered or unexported fields
}
```

#### func NewUI

```go
func NewUI(monitor *netcap.NetworkMonitor) *UI
```

NewUI creates a new UI instance with the given network monitor.

##### Parameters
- `monitor`: NetworkMonitor instance to display data from

##### Example

```go
monitor := netcap.NewNetworkMonitor()
ui := ui.NewUI(monitor)
```

#### UI Methods

##### func (*UI) SetTheme

```go
func (ui *UI) SetTheme(themeName string) *UI
```

SetTheme sets the color theme for the UI. Returns the UI instance for method chaining.

###### Available Themes
- `"Dark+"` - Default dark theme with vibrant colors
- `"Light"` - Light background theme
- `"Monokai"` - Based on the popular Monokai color scheme
- `"Solarized"` - Solarized dark theme
- `"Nord"` - Nord color palette
- `"Dracula"` - Dracula theme
- `"OneDark"` - Atom One Dark theme
- `"GruvboxDark"` - Gruvbox dark theme
- `"CyberpunkNeon"` - Neon cyberpunk theme
- `"Matrix"` - Matrix-inspired green theme
- `"Midnight"` - Deep blue midnight theme
- `"Synthwave"` - 80s synthwave aesthetic

###### Example

```go
ui := ui.NewUI(monitor).SetTheme("Dracula")
```

##### func (*UI) SetStyle

```go
func (ui *UI) SetStyle(styleName string) *UI
```

SetStyle sets the border style for UI components.

###### Available Styles
- `"Standard"` - Single line borders
- `"Rounded"` - Rounded corners
- `"Double"` - Double line borders
- `"ASCII"` - ASCII-only borders
- `"Minimal"` - Minimal borders
- `"Heavy"` - Thick borders
- `"Dashed"` - Dashed line borders
- `"Neon"` - Glowing neon effect
- `"Tech"` - Technical/cyber style
- `"Vintage"` - Classic terminal style

###### Example

```go
ui.SetStyle("Rounded")
```

##### func (*UI) SetGradientEnabled

```go
func (ui *UI) SetGradientEnabled(enabled bool) *UI
```

SetGradientEnabled enables or disables gradient effects in visualizations.

##### func (*UI) Run

```go
func (ui *UI) Run() error
```

Run starts the UI event loop. This method blocks until the UI is closed.

###### Returns
- `error`: Error if the UI cannot be started

###### Example

```go
if err := ui.Run(); err != nil {
    log.Fatal("UI error:", err)
}
```

##### func (*UI) Stop

```go
func (ui *UI) Stop()
```

Stop gracefully shuts down the UI and exits the event loop.

##### func (*UI) LoadProfile

```go
func (ui *UI) LoadProfile(profileName string) error
```

LoadProfile loads a saved UI configuration profile.

###### Parameters
- `profileName`: Name of the profile to load

###### Returns
- `error`: Error if profile cannot be loaded

##### func (*UI) SaveProfile

```go
func (ui *UI) SaveProfile(profileName string) error
```

SaveProfile saves the current UI configuration as a profile.

##### func (*UI) SetStartupVisualization

```go
func (ui *UI) SetStartupVisualization(vizID string, fullscreen bool)
```

SetStartupVisualization sets which visualization to display on startup.

###### Parameters
- `vizID`: Visualization identifier (e.g., "speedometer", "matrix")
- `fullscreen`: Whether to start in fullscreen mode

##### func (*UI) SetStartupDashboard

```go
func (ui *UI) SetStartupDashboard(dashboardName string, fullscreen bool)
```

SetStartupDashboard sets which dashboard to display on startup.

###### Available Dashboards
- `"overview"` - General network overview
- `"security"` - Security-focused dashboard
- `"performance"` - Performance metrics
- `"connections"` - Connection details

##### func (*UI) RegisterPlugin

```go
func (ui *UI) RegisterPlugin(name, description string)
```

RegisterPlugin registers a plugin with the UI system.

##### func (*UI) UpdatePluginOutput

```go
func (ui *UI) UpdatePluginOutput(pluginName, output string)
```

UpdatePluginOutput updates the display output for a plugin.

##### func (*UI) ExportSVG

```go
func (ui *UI) ExportSVG(filename string) error
```

ExportSVG exports the current visualization as an SVG file.

###### Parameters
- `filename`: Path where the SVG file will be saved

###### Returns
- `error`: Error if export fails

##### func (*UI) ExportPNG

```go
func (ui *UI) ExportPNG(filename string) error
```

ExportPNG exports the current visualization as a PNG file.

### Theme

Theme represents a color theme configuration.

```go
type Theme struct {
    Name        string
    Foreground  string
    Background  string
    Border      string
    Title       string
    Info        string
    Warning     string
    Error       string
    Success     string
    Primary     string
    Secondary   string
    Tertiary    string
    Quaternary  string
}
```

#### Theme Functions

##### func GetTheme

```go
func GetTheme(name string) (*Theme, error)
```

GetTheme retrieves a theme by name.

##### func ListThemes

```go
func ListThemes() []string
```

ListThemes returns a list of all available theme names.

### ThemeConfig

ThemeConfig is used for loading themes from files.

```go
type ThemeConfig struct {
    Themes []Theme `json:"themes" yaml:"themes"`
}
```

#### func LoadThemes

```go
func LoadThemes(filename string) error
```

LoadThemes loads custom themes from a JSON or YAML file.

###### Example Theme File (JSON)

```json
{
  "themes": [
    {
      "name": "MyCustomTheme",
      "foreground": "#FFFFFF",
      "background": "#1E1E1E",
      "border": "#808080",
      "title": "#00FF00",
      "info": "#00FFFF",
      "warning": "#FFFF00",
      "error": "#FF0000",
      "success": "#00FF00",
      "primary": "#0080FF",
      "secondary": "#FF00FF",
      "tertiary": "#00FFFF",
      "quaternary": "#FFFF00"
    }
  ]
}
```

#### func ExportTheme

```go
func ExportTheme(themeName, filename string) error
```

ExportTheme exports a theme to a file.

### BorderStyle

BorderStyle defines the appearance of UI borders.

```go
type BorderStyle struct {
    Name            string
    Horizontal      rune
    Vertical        rune
    TopLeft         rune
    TopRight        rune
    BottomLeft      rune
    BottomRight     rune
    VerticalLeft    rune
    VerticalRight   rune
    HorizontalUp    rune
    HorizontalDown  rune
    Cross           rune
}
```

#### func GetBorderStyle

```go
func GetBorderStyle(name string) (*BorderStyle, error)
```

GetBorderStyle retrieves a border style by name.

### Visualization

Visualization interface for custom visualizations.

```go
type Visualization interface {
    Name() string
    Description() string
    Render(data interface{}) string
    Update(monitor *netcap.NetworkMonitor)
    GetMinSize() (width, height int)
}
```

## Functions

### func DetectAutoTheme

```go
func DetectAutoTheme() string
```

DetectAutoTheme automatically selects a theme based on terminal capabilities and time of day.

#### Returns
- `string`: Recommended theme name

### func FormatBytes

```go
func FormatBytes(bytes uint64) string
```

FormatBytes formats byte counts in human-readable format.

#### Example

```go
fmt.Println(ui.FormatBytes(1536))     // "1.5 KB"
fmt.Println(ui.FormatBytes(1048576))  // "1.0 MB"
```

### func FormatDuration

```go
func FormatDuration(d time.Duration) string
```

FormatDuration formats time duration in human-readable format.

### func RenderASCIILogo

```go
func RenderASCIILogo() string
```

RenderASCIILogo returns the NSD ASCII art logo.

## Visualizations

NSD includes several built-in visualizations:

### SpeedometerVisualization

Shows network speed as a speedometer gauge.

```go
viz := NewSpeedometerVisualization()
viz.SetMax(1000) // Max Mbps
viz.Update(monitor)
```

### MatrixVisualization

Displays connections in a matrix rain effect.

```go
viz := NewMatrixVisualization()
viz.SetDensity(0.3)
viz.Update(monitor)
```

### ConstellationVisualization

Shows network topology as a constellation map.

```go
viz := NewConstellationVisualization()
viz.SetNodeLimit(50)
viz.Update(monitor)
```

### HeatmapVisualization

Displays traffic intensity as a heatmap.

```go
viz := NewHeatmapVisualization()
viz.SetColorScheme("thermal")
viz.Update(monitor)
```

### SankeyVisualization

Shows traffic flow between endpoints.

```go
viz := NewSankeyVisualization()
viz.SetFlowLimit(20)
viz.Update(monitor)
```

### Additional Visualizations

- `HeartbeatVisualization` - Network pulse monitor
- `WeatherVisualization` - Traffic weather map
- `RadialVisualization` - Radial connection graph
- `TimelineVisualization` - DNS query timeline
- `SunburstVisualization` - Hierarchical traffic view
- `WorldMapVisualization` - Geographic connection map
- `PacketDistributionVisualization` - Packet type distribution
- `ConnectionLifetimeVisualization` - Connection duration chart

## Internationalization

### i18n Package

```go
import "github.com/user/nsd/pkg/ui/i18n"
```

#### func LoadTranslations

```go
func LoadTranslations(filename string) error
```

LoadTranslations loads translations from a JSON file.

##### Translation File Format

```json
{
  "welcome": "Welcome to NSD",
  "total_packets": "Total Packets",
  "active_connections": "Active Connections",
  "bytes_per_second": "Bytes/sec",
  "error_permission": "Permission denied. Run as administrator.",
  "menu_file": "File",
  "menu_view": "View",
  "menu_help": "Help"
}
```

#### func T

```go
func T(key string, args ...interface{}) string
```

T retrieves a translated string by key.

##### Example

```go
// Simple translation
fmt.Println(i18n.T("welcome"))

// With parameters
fmt.Println(i18n.T("packets_captured", 1000))
```

#### func SetLanguage

```go
func SetLanguage(lang string) error
```

SetLanguage changes the current language.

##### Supported Languages

- `en` - English (default)
- `es` - Spanish
- `fr` - French
- `de` - German
- `it` - Italian
- `pt` - Portuguese
- `ru` - Russian
- `ja` - Japanese
- `ko` - Korean
- `zh` - Chinese (Simplified)
- `ar` - Arabic
- `hi` - Hindi

## Examples

### Complete UI Application

```go
package main

import (
    "log"
    "os"
    "os/signal"
    "syscall"
    
    "github.com/user/nsd/pkg/netcap"
    "github.com/user/nsd/pkg/ui"
    "github.com/user/nsd/pkg/ui/i18n"
)

func main() {
    // Load translations
    if err := i18n.LoadTranslations("translations/es.json"); err != nil {
        log.Printf("Could not load translations: %v", err)
    }
    
    // Create network monitor
    monitor := netcap.NewNetworkMonitor()
    
    // Start capture
    if err := monitor.StartCapture("eth0"); err != nil {
        log.Fatal(err)
    }
    defer monitor.StopAllCaptures()
    
    // Create UI with custom configuration
    ui := ui.NewUI(monitor).
        SetTheme("CyberpunkNeon").
        SetStyle("Neon").
        SetGradientEnabled(true)
    
    // Set startup visualization
    ui.SetStartupVisualization("matrix", false)
    
    // Handle shutdown
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
    
    go func() {
        <-sigChan
        ui.Stop()
    }()
    
    // Run UI (blocks)
    if err := ui.Run(); err != nil {
        log.Fatal("UI error:", err)
    }
}
```

### Custom Theme Loading

```go
// Create custom theme file
themeJSON := `{
  "themes": [{
    "name": "Corporate",
    "foreground": "#333333",
    "background": "#F5F5F5",
    "border": "#CCCCCC",
    "title": "#0066CC",
    "info": "#0099CC",
    "warning": "#FF9900",
    "error": "#CC0000",
    "success": "#009900",
    "primary": "#0066CC",
    "secondary": "#6633CC",
    "tertiary": "#00CCCC",
    "quaternary": "#FFCC00"
  }]
}`

// Save theme file
os.WriteFile("corporate-theme.json", []byte(themeJSON), 0644)

// Load and use theme
ui.LoadThemes("corporate-theme.json")
ui := ui.NewUI(monitor).SetTheme("Corporate")
```

### Keyboard Shortcuts

The UI supports the following keyboard shortcuts:

- `Tab` / `Shift+Tab` - Navigate between panels
- `Enter` - Select/activate
- `Esc` - Go back/cancel
- `q` - Quit application
- `f` - Toggle fullscreen
- `p` - Pause/resume capture
- `r` - Reset statistics
- `s` - Save screenshot
- `e` - Export data
- `h` / `?` - Show help
- `1-9` - Switch visualization

### Creating Custom Visualizations

```go
type MyVisualization struct {
    data []float64
}

func (v *MyVisualization) Name() string {
    return "MyViz"
}

func (v *MyVisualization) Description() string {
    return "Custom visualization"
}

func (v *MyVisualization) Render(data interface{}) string {
    // Render visualization to string
    return "█████████"
}

func (v *MyVisualization) Update(monitor *netcap.NetworkMonitor) {
    stats := monitor.GetStats()
    // Update internal data
    v.data = append(v.data, stats["PacketsPerSecond"].(float64))
}

func (v *MyVisualization) GetMinSize() (int, int) {
    return 40, 10 // minimum width and height
}
```

## Best Practices

1. **Theme Selection**: Use `DetectAutoTheme()` for automatic theme selection
2. **Responsiveness**: Check terminal size and adjust visualizations accordingly
3. **Performance**: Limit UI refresh rate to 10-30 FPS for efficiency
4. **Accessibility**: Provide ASCII-only mode for screen readers
5. **Error Handling**: Always handle UI errors gracefully

## Terminal Requirements

- Minimum terminal size: 80x24
- Recommended: 120x40 or larger
- 256-color support recommended
- UTF-8 encoding for best visualization quality

## Thread Safety

UI methods must be called from the main goroutine. Use channels or other synchronization mechanisms when updating from other goroutines.