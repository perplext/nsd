package ui

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gdamore/tcell/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestThemeOperations(t *testing.T) {
	// Test themes map exists
	assert.NotNil(t, Themes)
	assert.NotEmpty(t, Themes)
	assert.Contains(t, Themes, "Dark+") // Use a theme that actually exists
	
	// Test getting Dark+ theme
	darkTheme, exists := Themes["Dark+"]
	assert.True(t, exists)
	assert.NotEqual(t, tcell.ColorDefault, darkTheme.BorderColor)
	
	// Test non-existent theme
	_, exists = Themes["NonExistent"]
	assert.False(t, exists)
	
	// Test DetectAutoTheme
	autoTheme := DetectAutoTheme()
	assert.NotEmpty(t, autoTheme)
	
	// Test interpolateColor
	color := interpolateColor(tcell.ColorRed, tcell.ColorGreen, 0.5)
	assert.NotEqual(t, tcell.ColorDefault, color)
	
	// Test parseIntOrDefault
	assert.Equal(t, 42, parseIntOrDefault("42", 10))
	assert.Equal(t, 10, parseIntOrDefault("invalid", 10))
	assert.Equal(t, 10, parseIntOrDefault("", 10))
}

func TestThemeFileOperations(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "theme_test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)
	
	// Create a test theme JSON file
	jsonTheme := `{
		"test_theme": {
			"borderColor": "#ffffff",
			"titleColor": "#ffff00",
			"primaryColor": "#00ff00",
			"secondaryColor": "#0000ff",
			"pieBorderColor": "#ff00ff",
			"pieTitleColor": "#00ffff",
			"statusBarTextColor": "#ffffff",
			"statusBarBgColor": "#000000"
		}
	}`
	
	jsonPath := filepath.Join(tmpDir, "test.json")
	// Use secure permissions for test files
	err = os.WriteFile(jsonPath, []byte(jsonTheme), 0600)
	require.NoError(t, err)
	
	// Create a test theme YAML file
	yamlTheme := `test_theme_yaml:
  borderColor: "#ffffff"
  titleColor: "#ffff00"
  primaryColor: "#00ff00"
  secondaryColor: "#0000ff"
  pieBorderColor: "#ff00ff"
  pieTitleColor: "#00ffff"
  statusBarTextColor: "#ffffff"
  statusBarBgColor: "#000000"`
	
	yamlPath := filepath.Join(tmpDir, "test.yaml")
	// Use secure permissions for test files
	err = os.WriteFile(yamlPath, []byte(yamlTheme), 0600)
	require.NoError(t, err)
	
	// Test LoadThemes from JSON
	err = LoadThemes(jsonPath)
	assert.NoError(t, err)
	
	// Check if theme was loaded
	theme, exists := Themes["test_theme"]
	assert.True(t, exists)
	// parseHex creates RGB colors, not named colors
	assert.NotEqual(t, tcell.ColorDefault, theme.BorderColor)
	assert.NotEqual(t, tcell.ColorDefault, theme.TitleColor)
	
	// Test LoadThemes from YAML
	err = LoadThemes(yamlPath)
	assert.NoError(t, err)
	
	// Check if YAML theme was loaded
	yamlLoadedTheme, yamlExists := Themes["test_theme_yaml"]
	assert.True(t, yamlExists)
	// parseHex creates RGB colors, not named colors
	assert.NotEqual(t, tcell.ColorDefault, yamlLoadedTheme.BorderColor)
}

func TestColorOperations(t *testing.T) {
	// Test colorToHex
	assert.Equal(t, "#ff0000", colorToHex(tcell.ColorRed))
	assert.Equal(t, "#0000ff", colorToHex(tcell.ColorBlue))
	assert.Equal(t, "#ffff00", colorToHex(tcell.ColorYellow))
	assert.Equal(t, "#ffffff", colorToHex(tcell.ColorWhite))
	assert.Equal(t, "#000000", colorToHex(tcell.ColorBlack))
	
	// Test parseHex
	// parseHex creates new RGB colors, not the named colors
	redColor := parseHex("#ff0000")
	assert.NotEqual(t, tcell.ColorDefault, redColor)
	blueColor := parseHex("#0000ff")
	assert.NotEqual(t, tcell.ColorDefault, blueColor)
	yellowColor := parseHex("#ffff00")
	assert.NotEqual(t, tcell.ColorDefault, yellowColor)
	whiteColor := parseHex("#ffffff")
	assert.NotEqual(t, tcell.ColorDefault, whiteColor)
	blackColor := parseHex("#000000")
	assert.NotEqual(t, tcell.ColorDefault, blackColor)
	
	// Test invalid hex - parseHex returns tcell.ColorWhite on error
	assert.Equal(t, tcell.ColorWhite, parseHex("invalid"))
	assert.Equal(t, tcell.ColorWhite, parseHex("#gg0000"))
	assert.Equal(t, tcell.ColorWhite, parseHex("#fff"))
	assert.Equal(t, tcell.ColorWhite, parseHex(""))
}

func TestGetUsageColorRanges(t *testing.T) {
	// Test all usage ranges
	testCases := []struct {
		usage float64
		desc  string
	}{
		{0.0, "zero usage"},
		{0.1, "very low usage"},
		{0.25, "low usage"},
		{0.4, "below medium usage"},
		{0.5, "medium usage"},
		{0.6, "above medium usage"},
		{0.75, "high usage"},
		{0.9, "very high usage"},
		{1.0, "max usage"},
		{1.5, "over max usage"},
	}
	
	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			color := GetUsageColor(tc.usage)
			assert.NotEqual(t, tcell.ColorDefault, color)
		})
	}
}

func TestThemeConstants(t *testing.T) {
	// Ensure all predefined themes are properly loaded
	expectedThemes := []string{
		"High-Contrast Dark",
		"Dark+",
		"Light+",
		"Monokai",
		"Solarized Light",
		"Solarized Dark",
		"Monochrome Accessibility",
		"Dracula",
		"Tokyo Night",
		"Tokyo Night Storm",
		"Nord",
		"Gruvbox",
		"Catppuccin",
		"One Dark",
	}
	
	for _, themeName := range expectedThemes {
		t.Run(themeName, func(t *testing.T) {
			theme, exists := Themes[themeName]
			assert.True(t, exists, "Theme %s should exist", themeName)
			assert.NotEqual(t, tcell.ColorDefault, theme.BorderColor)
			assert.NotEqual(t, tcell.ColorDefault, theme.TitleColor)
			assert.NotEqual(t, tcell.ColorDefault, theme.PrimaryColor)
			assert.NotEqual(t, tcell.ColorDefault, theme.SecondaryColor)
		})
	}
}