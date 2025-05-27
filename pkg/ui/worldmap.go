package ui

import (
	"fmt"
	"strings"
)

// WorldMap represents an ASCII world map for visualization
type WorldMap struct {
	width  int
	height int
	data   [][]rune
}

// CountryCoordinates maps country codes to approximate map coordinates
var CountryCoordinates = map[string]struct{ X, Y int }{
	// North America
	"US": {20, 8},
	"CA": {20, 5},
	"MX": {18, 12},
	
	// South America
	"BR": {35, 18},
	"AR": {32, 23},
	"CL": {30, 22},
	"PE": {28, 17},
	"CO": {27, 15},
	"VE": {30, 13},
	
	// Europe
	"GB": {47, 7},
	"FR": {48, 8},
	"DE": {50, 7},
	"IT": {50, 9},
	"ES": {46, 9},
	"PT": {45, 9},
	"NL": {49, 7},
	"BE": {49, 7},
	"CH": {49, 8},
	"AT": {51, 8},
	"PL": {52, 7},
	"CZ": {51, 7},
	"SE": {52, 5},
	"NO": {50, 4},
	"FI": {54, 4},
	"DK": {50, 6},
	"RU": {60, 6},
	"UA": {55, 8},
	"GR": {53, 10},
	"TR": {56, 9},
	
	// Asia
	"CN": {70, 9},
	"JP": {78, 8},
	"KR": {76, 8},
	"IN": {65, 12},
	"ID": {72, 17},
	"TH": {69, 14},
	"VN": {71, 13},
	"MY": {70, 16},
	"SG": {70, 17},
	"PH": {75, 14},
	"PK": {63, 11},
	"BD": {67, 12},
	"TW": {75, 11},
	"HK": {73, 11},
	
	// Middle East
	"SA": {58, 11},
	"AE": {60, 11},
	"IL": {56, 10},
	"IR": {60, 10},
	"IQ": {58, 10},
	
	// Africa
	"ZA": {53, 24},
	"EG": {55, 11},
	"NG": {49, 15},
	"KE": {57, 17},
	"ET": {57, 14},
	"MA": {46, 11},
	"GH": {47, 15},
	
	// Oceania
	"AU": {76, 22},
	"NZ": {80, 25},
}

// NewWorldMap creates a new ASCII world map
func NewWorldMap() *WorldMap {
	return &WorldMap{
		width:  84,
		height: 28,
		data:   initializeMap(),
	}
}

// initializeMap creates the base ASCII world map
func initializeMap() [][]rune {
	// Simple ASCII world map representation
	mapStr := `
    . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .
    . . . ┌─────────┐ . . . . . . . . . . . . . . ┌─────────────────────┐ . . . . . . .
    . . . │ . . . . │ . . . . . . . ┌───────────┐ │ . . . . . . . . . . │ . . . . . . .
    . . . │ . . . . └─┐ . . . ┌─────┘ . . . . . └─┘ . . . . . . . . . . └───┐ . . . . .
    . . . │ . . . . . └───────┘ . . . . . . . . . . . . . . . . . . . . . . │ . . . . .
    . . . │ . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . │ . . . . .
    . . . │ . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . │ . . . . .
    . . . └─┐ . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . │ . . . . .
    . . . . └─┐ . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ┌┘ . . . . .
    . . . . . └┐ . . . . . . . . . . . . . . . . . . . . . . . . . . . . ┌┘ . . . . . .
    . . . . . . └┐ . . . . . . . . . . . . . . . . . . . . . . . . . . ┌┘ . . . . . . .
    . . . . . . . └─┐ . . . . . . . . . . . . . . . . . . . . . . . . ┌┘ . . . . . . . .
    . . . . . . . . │ . . . . . . . . . . . . . . . . . . . . . . . . │ . . . . . . . . .
    . . . . . . . . └┐ . . . . . . . . . . . . . . . . . . . . . . . └┐ . . . . . . . . .
    . . . . . . . . . └┐ . . . . . . . . . . . . . . . . . . . . . . . └┐ . . . . . . . .
    . . . . . . . . . . └──┐ . . . . . . . . . . . . . . . . . . . . . . └┐ . . . . . . .
    . . . . . . . . . . . . └─┐ . . . . . . . . . . . . . . . . . . . . . │ . . . . . . .
    . . . . . . . . . . . . . └──────┐ . . . . . . . . . . . . . . . . . . └──┐ . . . . .
    . . . . . . . . . . . . . . . . . └─┐ . . . . . . . . . . . . . . . . . . └──┐ . . .
    . . . . . . . . . . . . . . . . . . └──┐ . . . . . . . . . . . . . . . . . . │ . . .
    . . . . . . . . . . . . . . . . . . . . └─┐ . . . . . . . . . . . . . . . . . │ . . .
    . . . . . . . . . . . . . . . . . . . . . └──┐ . . . . . . . . . . . . . ┌───┘ . . .
    . . . . . . . . . . . . . . . . . . . . . . . └─┐ . . . . . . . . . . ┌──┘ . . . . .
    . . . . . . . . . . . . . . . . . . . . . . . . └───┐ . . . . . . . ┌─┘ . . . . . . .
    . . . . . . . . . . . . . . . . . . . . . . . . . . └───────────────┘ . . . . . . . .
    . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .
    `
	
	lines := strings.Split(strings.TrimSpace(mapStr), "\n")
	data := make([][]rune, len(lines))
	for i, line := range lines {
		data[i] = []rune(line)
	}
	return data
}

// MarkCountry marks a country on the map with a special character
func (m *WorldMap) MarkCountry(countryCode string, marker rune) {
	if coord, ok := CountryCoordinates[countryCode]; ok {
		if coord.Y < len(m.data) && coord.X < len(m.data[coord.Y]) {
			m.data[coord.Y][coord.X] = marker
		}
	}
}

// Clear resets the map to its original state
func (m *WorldMap) Clear() {
	m.data = initializeMap()
}

// Render returns the map as a string
func (m *WorldMap) Render() string {
	var result strings.Builder
	for _, row := range m.data {
		result.WriteString(string(row))
		result.WriteRune('\n')
	}
	return result.String()
}

// RenderWithColors returns the map with color codes for different connection counts
func (m *WorldMap) RenderWithColors(countryCounts map[string]int, maxCount int) string {
	var result strings.Builder
	
	// Define color thresholds
	getColor := func(count int) string {
		if count == 0 {
			return "[white]"
		}
		percentage := float64(count) / float64(maxCount) * 100
		switch {
		case percentage >= 75:
			return "[red]"
		case percentage >= 50:
			return "[orange]"
		case percentage >= 25:
			return "[yellow]"
		default:
			return "[green]"
		}
	}
	
	// Mark countries with appropriate symbols
	for country, count := range countryCounts {
		var marker rune
		switch {
		case count >= 100:
			marker = '█'
		case count >= 50:
			marker = '▓'
		case count >= 10:
			marker = '▒'
		case count > 0:
			marker = '░'
		default:
			marker = '·'
		}
		m.MarkCountry(country, marker)
	}
	
	// Render with colors
	for y, row := range m.data {
		for x, char := range row {
			// Check if this position corresponds to a country
			isCountry := false
			for country, coord := range CountryCoordinates {
				if coord.X == x && coord.Y == y {
					if count, ok := countryCounts[country]; ok && count > 0 {
						result.WriteString(getColor(count))
						result.WriteRune(char)
						result.WriteString("[white]")
						isCountry = true
						break
					}
				}
			}
			if !isCountry {
				result.WriteRune(char)
			}
		}
		result.WriteRune('\n')
	}
	
	return result.String()
}

// GetLegend returns a legend for the map visualization
func GetMapLegend() string {
	return fmt.Sprintf(`[yellow]═══ Connection Density ═══[white]
  █ Very High (100+ connections)
  ▓ High      (50-99 connections)  
  ▒ Medium    (10-49 connections)
  ░ Low       (1-9 connections)
  · No connections
  
[yellow]═══ Color Scale ═══[white]
  [red]■[white] 75-100%% of max connections
  [orange]■[white] 50-74%% of max connections
  [yellow]■[white] 25-49%% of max connections
  [green]■[white] 1-24%% of max connections`)
}