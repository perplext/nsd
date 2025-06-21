package ui

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"strconv"
	"github.com/gdamore/tcell/v2"
	"gopkg.in/yaml.v3"
)

// validateThemePath validates a theme file path to prevent directory traversal
func validateThemePath(path string) error {
	// Clean the path to remove any ../ or ./ elements
	cleanPath := filepath.Clean(path)
	
	// Get absolute path
	absPath, err := filepath.Abs(cleanPath)
	if err != nil {
		return fmt.Errorf("invalid theme path: %v", err)
	}
	
	// Check if path contains suspicious patterns
	if strings.Contains(path, "..") {
		return fmt.Errorf("theme path contains directory traversal pattern")
	}
	
	// Ensure the file has a valid theme extension
	ext := strings.ToLower(filepath.Ext(absPath))
	if ext != ".json" && ext != ".yaml" && ext != ".yml" {
		return fmt.Errorf("invalid theme file extension: %s", ext)
	}
	
	return nil
}

// Theme defines UI color scheme inspired by VSCode themes.
type Theme struct {
	BorderColor        tcell.Color
	TitleColor         tcell.Color
	PrimaryColor       tcell.Color
	SecondaryColor     tcell.Color
	PieBorderColor     tcell.Color
	PieTitleColor      tcell.Color
	StatusBarTextColor tcell.Color
	StatusBarBgColor   tcell.Color
	WarningColor       tcell.Color
	SuccessColor       tcell.Color
	// Graph gradient colors (calculated from Primary/Secondary)
	GraphGradient1     tcell.Color
	GraphGradient2     tcell.Color
	GraphGradient3     tcell.Color
}

// calculateGradients computes intermediate gradient colors for smooth transitions
func (t *Theme) calculateGradients() {
	pr, pg, pb := t.PrimaryColor.RGB()
	sr, sg, sb := t.SecondaryColor.RGB()
	
	// Create 3 gradient stops between primary and secondary
	t.GraphGradient1 = tcell.NewRGBColor(
		pr*3/4 + sr*1/4,
		pg*3/4 + sg*1/4,
		pb*3/4 + sb*1/4,
	)
	t.GraphGradient2 = tcell.NewRGBColor(
		pr*1/2 + sr*1/2,
		pg*1/2 + sg*1/2,
		pb*1/2 + sb*1/2,
	)
	t.GraphGradient3 = tcell.NewRGBColor(
		pr*1/4 + sr*3/4,
		pg*1/4 + sg*3/4,
		pb*1/4 + sb*3/4,
	)
}

// GetUsageColor returns a color based on usage percentage (0-100)
// Green (0-50%) -> Yellow (50-80%) -> Red (80-100%)
func GetUsageColor(percentage float64) tcell.Color {
	if percentage < 0 {
		percentage = 0
	}
	if percentage > 100 {
		percentage = 100
	}
	
	// Define color stops
	green := tcell.NewRGBColor(0x00, 0xFF, 0x00)
	yellow := tcell.NewRGBColor(0xFF, 0xFF, 0x00)
	red := tcell.NewRGBColor(0xFF, 0x00, 0x00)
	
	if percentage <= 50 {
		// Interpolate between green and yellow
		ratio := percentage / 50.0
		return interpolateColor(green, yellow, ratio)
	} else {
		// Interpolate between yellow and red
		ratio := (percentage - 50) / 50.0
		return interpolateColor(yellow, red, ratio)
	}
}

// interpolateColor blends two colors based on ratio (0-1)
func interpolateColor(c1, c2 tcell.Color, ratio float64) tcell.Color {
	r1, g1, b1 := c1.RGB()
	r2, g2, b2 := c2.RGB()
	
	r := int32(float64(r1)*(1-ratio) + float64(r2)*ratio)
	g := int32(float64(g1)*(1-ratio) + float64(g2)*ratio)
	b := int32(float64(b1)*(1-ratio) + float64(b2)*ratio)
	
	return tcell.NewRGBColor(r, g, b)
}

// Themes holds predefined color schemes.
var Themes = map[string]Theme{
	// High-Contrast Dark: deep black with neon green & electric blue accents
	"High-Contrast Dark": {
		BorderColor:        tcell.NewRGBColor(0x00, 0xFF, 0x00), // neon green
		TitleColor:         tcell.NewRGBColor(0x00, 0xFF, 0x00),
		PrimaryColor:       tcell.NewRGBColor(0x00, 0x80, 0xFF), // electric blue
		SecondaryColor:     tcell.NewRGBColor(0x00, 0xFF, 0x00),
		PieBorderColor:     tcell.NewRGBColor(0x00, 0xFF, 0x00),
		PieTitleColor:      tcell.NewRGBColor(0x00, 0xFF, 0x00),
		StatusBarTextColor: tcell.NewRGBColor(0x00, 0xFF, 0x00),
		StatusBarBgColor:   tcell.ColorBlack,
		WarningColor:       tcell.NewRGBColor(0xFF, 0xFF, 0x00), // yellow
		SuccessColor:       tcell.NewRGBColor(0x00, 0xFF, 0x00), // green
	},
	"Dark+": {
		BorderColor:        tcell.NewRGBColor(0x00, 0x7A, 0xCC),
		TitleColor:         tcell.NewRGBColor(0x00, 0x7A, 0xCC),
		PrimaryColor:       tcell.NewRGBColor(0x0E, 0xBF, 0xE9),
		SecondaryColor:     tcell.NewRGBColor(0xD4, 0x42, 0xFF),
		PieBorderColor:     tcell.NewRGBColor(0x00, 0x7A, 0xCC),
		PieTitleColor:      tcell.NewRGBColor(0x00, 0x7A, 0xCC),
		StatusBarTextColor: tcell.ColorWhite,
		StatusBarBgColor:   tcell.ColorBlack,
		WarningColor:       tcell.NewRGBColor(0xFF, 0xCC, 0x00), // amber
		SuccessColor:       tcell.NewRGBColor(0x4E, 0xC9, 0xB0), // light green
	},
	"Light+": {
		BorderColor:        tcell.NewRGBColor(0x00, 0x00, 0x00),
		TitleColor:         tcell.NewRGBColor(0x00, 0x00, 0x00),
		PrimaryColor:       tcell.NewRGBColor(0x00, 0x64, 0x00),
		SecondaryColor:     tcell.NewRGBColor(0x00, 0x00, 0x8B),
		PieBorderColor:     tcell.NewRGBColor(0x00, 0x00, 0x00),
		PieTitleColor:      tcell.NewRGBColor(0x00, 0x00, 0x00),
		StatusBarTextColor: tcell.ColorBlack,
		StatusBarBgColor:   tcell.ColorWhite,
		WarningColor:       tcell.NewRGBColor(0xFF, 0x8C, 0x00), // dark orange
		SuccessColor:       tcell.NewRGBColor(0x00, 0x80, 0x00), // dark green
	},
	"Monokai": {
		BorderColor:        tcell.NewRGBColor(0xA6, 0xE2, 0x2E),
		TitleColor:         tcell.NewRGBColor(0xA6, 0xE2, 0x2E),
		PrimaryColor:       tcell.NewRGBColor(0xA6, 0xE2, 0x2E),
		SecondaryColor:     tcell.NewRGBColor(0x66, 0xD9, 0xEF),
		PieBorderColor:     tcell.NewRGBColor(0xA6, 0xE2, 0x2E),
		PieTitleColor:      tcell.NewRGBColor(0xA6, 0xE2, 0x2E),
		StatusBarTextColor: tcell.ColorWhite,
		StatusBarBgColor:   tcell.ColorBlack,
		WarningColor:       tcell.NewRGBColor(0xF9, 0x26, 0x72), // pink
		SuccessColor:       tcell.NewRGBColor(0xA6, 0xE2, 0x2E), // green,
	},
	// Solarized Light: light background with Solarized palette
	"Solarized Light": {
		BorderColor:        tcell.NewRGBColor(0x26, 0x8B, 0xD2), // #268bd2
		TitleColor:         tcell.NewRGBColor(0x26, 0x8B, 0xD2),
		PrimaryColor:       tcell.NewRGBColor(0x85, 0x99, 0x00), // #859900
		SecondaryColor:     tcell.NewRGBColor(0x2A, 0xA1, 0x98),
		PieBorderColor:     tcell.NewRGBColor(0x26, 0x8B, 0xD2),
		PieTitleColor:      tcell.NewRGBColor(0x26, 0x8B, 0xD2),
		StatusBarTextColor: tcell.ColorBlack,
		StatusBarBgColor:   tcell.NewRGBColor(0xFD, 0xF6, 0xE3),
		WarningColor:       tcell.NewRGBColor(0xCB, 0x4B, 0x16), // orange
		SuccessColor:       tcell.NewRGBColor(0x85, 0x99, 0x00), // green, // #fdf6e3
	},
	"Solarized Dark": {
		BorderColor:        tcell.NewRGBColor(0x26, 0x8B, 0xD2),
		TitleColor:         tcell.NewRGBColor(0x26, 0x8B, 0xD2),
		PrimaryColor:       tcell.NewRGBColor(0xB5, 0x89, 0x00),
		SecondaryColor:     tcell.NewRGBColor(0x2A, 0xA1, 0x98),
		PieBorderColor:     tcell.NewRGBColor(0x26, 0x8B, 0xD2),
		PieTitleColor:      tcell.NewRGBColor(0x26, 0x8B, 0xD2),
		StatusBarTextColor: tcell.ColorWhite,
		StatusBarBgColor:   tcell.NewRGBColor(0x00, 0x2B, 0x36),
		WarningColor:       tcell.NewRGBColor(0xCB, 0x4B, 0x16), // orange
		SuccessColor:       tcell.NewRGBColor(0x85, 0x99, 0x00), // green,
	},
	// Monochrome Accessibility: pure black-and-white UI
	"Monochrome Accessibility": {
		BorderColor:        tcell.ColorWhite,
		TitleColor:         tcell.ColorWhite,
		PrimaryColor:       tcell.ColorWhite,
		SecondaryColor:     tcell.ColorWhite,
		PieBorderColor:     tcell.ColorWhite,
		PieTitleColor:      tcell.ColorWhite,
		StatusBarTextColor: tcell.ColorBlack,
		StatusBarBgColor:   tcell.ColorBlack,
		WarningColor:       tcell.ColorWhite,
		SuccessColor:       tcell.ColorWhite,
	},
	"Dracula": {
		BorderColor:        tcell.NewRGBColor(0xBD, 0x93, 0xF9),
		TitleColor:         tcell.NewRGBColor(0xBD, 0x93, 0xF9),
		PrimaryColor:       tcell.NewRGBColor(0x50, 0xFA, 0x7B),
		SecondaryColor:     tcell.NewRGBColor(0xFF, 0x79, 0xC6),
		PieBorderColor:     tcell.NewRGBColor(0xBD, 0x93, 0xF9),
		PieTitleColor:      tcell.NewRGBColor(0xBD, 0x93, 0xF9),
		StatusBarTextColor: tcell.ColorWhite,
		StatusBarBgColor:   tcell.NewRGBColor(0x28, 0x2A, 0x36),
		WarningColor:       tcell.NewRGBColor(0xF1, 0xFA, 0x8C), // yellow
		SuccessColor:       tcell.NewRGBColor(0x50, 0xFA, 0x7B), // green,
	},
	"Tokyo Night": {
		BorderColor:        tcell.NewRGBColor(0x7A, 0xA2, 0xF7),
		TitleColor:         tcell.NewRGBColor(0x7A, 0xA2, 0xF7),
		PrimaryColor:       tcell.NewRGBColor(0x7D, 0xCF, 0xFF),
		SecondaryColor:     tcell.NewRGBColor(0xBB, 0x9A, 0xF7),
		PieBorderColor:     tcell.NewRGBColor(0x7A, 0xA2, 0xF7),
		PieTitleColor:      tcell.NewRGBColor(0x7A, 0xA2, 0xF7),
		StatusBarTextColor: tcell.ColorWhite,
		StatusBarBgColor:   tcell.NewRGBColor(0x1A, 0x1B, 0x26),
		WarningColor:       tcell.NewRGBColor(0xE0, 0xAF, 0x68), // yellow
		SuccessColor:       tcell.NewRGBColor(0x9E, 0xCE, 0x6A), // green,
	},
	"Tokyo Night Storm": {
		BorderColor:        tcell.NewRGBColor(0x9D, 0x7C, 0xD8),
		TitleColor:         tcell.NewRGBColor(0x9D, 0x7C, 0xD8),
		PrimaryColor:       tcell.NewRGBColor(0x7D, 0xCF, 0xFF),
		SecondaryColor:     tcell.NewRGBColor(0x7A, 0xA2, 0xF7),
		PieBorderColor:     tcell.NewRGBColor(0x9D, 0x7C, 0xD8),
		PieTitleColor:      tcell.NewRGBColor(0x9D, 0x7C, 0xD8),
		StatusBarTextColor: tcell.ColorWhite,
		StatusBarBgColor:   tcell.NewRGBColor(0x24, 0x28, 0x3B),
		WarningColor:       tcell.NewRGBColor(0xE0, 0xAF, 0x68), // yellow
		SuccessColor:       tcell.NewRGBColor(0x9E, 0xCE, 0x6A), // green,
	},
	// New btop-inspired themes
	"Nord": {
		BorderColor:        tcell.NewRGBColor(0x5E, 0x81, 0xAC),
		TitleColor:         tcell.NewRGBColor(0x5E, 0x81, 0xAC),
		PrimaryColor:       tcell.NewRGBColor(0x88, 0xC0, 0xD0),
		SecondaryColor:     tcell.NewRGBColor(0x81, 0xA1, 0xC1),
		PieBorderColor:     tcell.NewRGBColor(0x5E, 0x81, 0xAC),
		PieTitleColor:      tcell.NewRGBColor(0x5E, 0x81, 0xAC),
		StatusBarTextColor: tcell.NewRGBColor(0xD8, 0xDE, 0xE9),
		StatusBarBgColor:   tcell.NewRGBColor(0x2E, 0x34, 0x40),
		WarningColor:       tcell.NewRGBColor(0xEB, 0xCB, 0x8B), // yellow
		SuccessColor:       tcell.NewRGBColor(0xA3, 0xBE, 0x8C), // green,
	},
	"Gruvbox": {
		BorderColor:        tcell.NewRGBColor(0xFE, 0x80, 0x19),
		TitleColor:         tcell.NewRGBColor(0xFE, 0x80, 0x19),
		PrimaryColor:       tcell.NewRGBColor(0xB8, 0xBB, 0x26),
		SecondaryColor:     tcell.NewRGBColor(0xFA, 0xBD, 0x2F),
		PieBorderColor:     tcell.NewRGBColor(0xFE, 0x80, 0x19),
		PieTitleColor:      tcell.NewRGBColor(0xFE, 0x80, 0x19),
		StatusBarTextColor: tcell.NewRGBColor(0xEB, 0xDB, 0xB2),
		StatusBarBgColor:   tcell.NewRGBColor(0x28, 0x28, 0x28),
		WarningColor:       tcell.NewRGBColor(0xFA, 0xBD, 0x2F), // yellow
		SuccessColor:       tcell.NewRGBColor(0xB8, 0xBB, 0x26), // green,
	},
	"Catppuccin": {
		BorderColor:        tcell.NewRGBColor(0xF5, 0xC2, 0xE7),
		TitleColor:         tcell.NewRGBColor(0xF5, 0xC2, 0xE7),
		PrimaryColor:       tcell.NewRGBColor(0x89, 0xDC, 0xEB),
		SecondaryColor:     tcell.NewRGBColor(0xF5, 0xE0, 0xDC),
		PieBorderColor:     tcell.NewRGBColor(0xF5, 0xC2, 0xE7),
		PieTitleColor:      tcell.NewRGBColor(0xF5, 0xC2, 0xE7),
		StatusBarTextColor: tcell.NewRGBColor(0xCD, 0xD6, 0xF4),
		StatusBarBgColor:   tcell.NewRGBColor(0x1E, 0x1E, 0x2E),
		WarningColor:       tcell.NewRGBColor(0xF9, 0xE2, 0xAF), // yellow
		SuccessColor:       tcell.NewRGBColor(0xA6, 0xE3, 0xA1), // green,
	},
	"One Dark": {
		BorderColor:        tcell.NewRGBColor(0x61, 0xAF, 0xEF),
		TitleColor:         tcell.NewRGBColor(0x61, 0xAF, 0xEF),
		PrimaryColor:       tcell.NewRGBColor(0x98, 0xC3, 0x79),
		SecondaryColor:     tcell.NewRGBColor(0xE0, 0x6C, 0x75),
		PieBorderColor:     tcell.NewRGBColor(0x61, 0xAF, 0xEF),
		PieTitleColor:      tcell.NewRGBColor(0x61, 0xAF, 0xEF),
		StatusBarTextColor: tcell.NewRGBColor(0xAB, 0xB2, 0xBF),
		StatusBarBgColor:   tcell.NewRGBColor(0x28, 0x2C, 0x34),
		WarningColor:       tcell.NewRGBColor(0xE5, 0xC0, 0x7B), // yellow
		SuccessColor:       tcell.NewRGBColor(0x98, 0xC3, 0x79), // green,
	},
}

// DetectAutoTheme returns a theme name based on the terminal background color from $COLORFGBG
func DetectAutoTheme() string {
    val := os.Getenv("COLORFGBG")
    parts := strings.Split(val, ";")
    if len(parts) >= 2 {
        b, err := strconv.Atoi(parts[len(parts)-1])
        if err == nil {
            if b < 7 {
                return "Dark+"
            }
            return "Light+"
        }
    }
    // default to dark theme
    return "Dark+"
}

// themeConfig defines JSON/YAML schema for custom themes
type themeConfig struct {
	BorderColor        string `json:"BorderColor" yaml:"BorderColor"`
	TitleColor         string `json:"TitleColor" yaml:"TitleColor"`
	PrimaryColor       string `json:"PrimaryColor" yaml:"PrimaryColor"`
	SecondaryColor     string `json:"SecondaryColor" yaml:"SecondaryColor"`
	PieBorderColor     string `json:"PieBorderColor" yaml:"PieBorderColor"`
	PieTitleColor      string `json:"PieTitleColor" yaml:"PieTitleColor"`
	StatusBarTextColor string `json:"StatusBarTextColor" yaml:"StatusBarTextColor"`
	StatusBarBgColor   string `json:"StatusBarBgColor" yaml:"StatusBarBgColor"`
}

// LoadThemes loads custom themes from JSON or YAML file and merges into Themes
func LoadThemes(path string) error {
	// Validate path to prevent directory traversal attacks
	if err := validateThemePath(path); err != nil {
		return err
	}
	
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	ext := strings.ToLower(filepath.Ext(path))
	var raw map[string]themeConfig
	switch ext {
	case ".json":
		err = json.Unmarshal(data, &raw)
	case ".yaml", ".yml":
		err = yaml.Unmarshal(data, &raw)
	default:
		return fmt.Errorf("unsupported theme file type: %s", ext)
	}
	if err != nil {
		return err
	}
	for name, cfg := range raw {
		t := Theme{
			BorderColor:        parseHex(cfg.BorderColor),
			TitleColor:         parseHex(cfg.TitleColor),
			PrimaryColor:       parseHex(cfg.PrimaryColor),
			SecondaryColor:     parseHex(cfg.SecondaryColor),
			PieBorderColor:     parseHex(cfg.PieBorderColor),
			PieTitleColor:      parseHex(cfg.PieTitleColor),
			StatusBarTextColor: parseHex(cfg.StatusBarTextColor),
			StatusBarBgColor:   parseHex(cfg.StatusBarBgColor),
		}
		Themes[name] = t
	}
	return nil
}

// init calculates gradients for all built-in themes
func init() {
	for name, theme := range Themes {
		theme.calculateGradients()
		Themes[name] = theme
	}
}

// ExportTheme writes the theme definition for the given theme name to a JSON or YAML file.
func ExportTheme(name, path string) error {
	t, ok := Themes[name]
	if !ok {
		return fmt.Errorf("theme %s not found", name)
	}
	cfg := themeConfig{
		BorderColor:        colorToHex(t.BorderColor),
		TitleColor:         colorToHex(t.TitleColor),
		PrimaryColor:       colorToHex(t.PrimaryColor),
		SecondaryColor:     colorToHex(t.SecondaryColor),
		PieBorderColor:     colorToHex(t.PieBorderColor),
		PieTitleColor:      colorToHex(t.PieTitleColor),
		StatusBarTextColor: colorToHex(t.StatusBarTextColor),
		StatusBarBgColor:   colorToHex(t.StatusBarBgColor),
	}
	raw := map[string]themeConfig{name: cfg}
	ext := strings.ToLower(filepath.Ext(path))
	var data []byte
	var err error
	switch ext {
	case ".json":
		data, err = json.MarshalIndent(raw, "", "  ")
	case ".yaml", ".yml":
		data, err = yaml.Marshal(raw)
	default:
		return fmt.Errorf("unsupported export file type: %s", ext)
	}
	if err != nil {
		return err
	}
	// Validate path before writing
	if err := validateThemePath(path); err != nil {
		return err
	}
	
	// Use secure file permissions (0600) instead of world-readable (0644)
	return os.WriteFile(path, data, 0600)
}

// colorToHex converts a tcell.Color to a hex string (#rrggbb).
func colorToHex(c tcell.Color) string {
	r, g, b := c.RGB()
	return fmt.Sprintf("#%02x%02x%02x", r, g, b)
}

// parseHex parses a hex color string (#rrggbb) into tcell.Color; defaults white on error
func parseHex(s string) tcell.Color {
	s = strings.TrimPrefix(s, "#")
	if len(s) != 6 {
		return tcell.ColorWhite
	}
	rv, err1 := strconv.ParseInt(s[0:2], 16, 32)
	gv, err2 := strconv.ParseInt(s[2:4], 16, 32)
	bv, err3 := strconv.ParseInt(s[4:6], 16, 32)
	if err1 != nil || err2 != nil || err3 != nil {
		return tcell.ColorWhite
	}
	return tcell.NewRGBColor(int32(rv), int32(gv), int32(bv))
}
