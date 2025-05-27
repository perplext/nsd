package ui

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWorldMapMarkCountry(t *testing.T) {
	worldmap := WorldMap{}
	worldmap.data = initializeMap()
	worldmap.width = 80
	worldmap.height = 26
	
	// Test marking valid countries
	worldmap.MarkCountry("US", '*')
	worldmap.MarkCountry("GB", '+')
	worldmap.MarkCountry("JP", '#')
	
	// Check that coordinates exist for these countries
	coord, exists := CountryCoordinates["US"]
	assert.True(t, exists)
	if coord.Y < len(worldmap.data) && coord.X < len(worldmap.data[coord.Y]) {
		assert.Equal(t, '*', worldmap.data[coord.Y][coord.X])
	}
	
	coord, exists = CountryCoordinates["GB"]
	assert.True(t, exists)
	if coord.Y < len(worldmap.data) && coord.X < len(worldmap.data[coord.Y]) {
		assert.Equal(t, '+', worldmap.data[coord.Y][coord.X])
	}
}

func TestWorldMapMarkInvalidCountry(t *testing.T) {
	worldmap := WorldMap{}
	worldmap.data = initializeMap()
	
	// Test marking invalid country (should not panic)
	assert.NotPanics(t, func() {
		worldmap.MarkCountry("XX", '*')
	})
}

func TestWorldMapClear(t *testing.T) {
	worldmap := WorldMap{}
	worldmap.data = initializeMap()
	
	// Mark some countries
	worldmap.MarkCountry("US", '*')
	worldmap.MarkCountry("GB", '+')
	
	// Clear the map
	worldmap.Clear()
	
	// Check that the map has been reset
	originalData := initializeMap()
	assert.Equal(t, len(originalData), len(worldmap.data))
	for i := range originalData {
		if i < len(worldmap.data) {
			assert.Equal(t, len(originalData[i]), len(worldmap.data[i]))
		}
	}
}

func TestWorldMapRender(t *testing.T) {
	worldmap := WorldMap{}
	worldmap.data = initializeMap()
	
	// Test rendering
	rendered := worldmap.Render()
	assert.NotEmpty(t, rendered)
	assert.Contains(t, rendered, "\n") // Should contain newlines
}

func TestWorldMapRenderWithColors(t *testing.T) {
	worldmap := WorldMap{}
	worldmap.data = initializeMap()
	
	// Test rendering with colors
	countryCounts := map[string]int{
		"US": 150,
		"GB": 75,
		"FR": 50,
		"DE": 25,
	}
	
	rendered := worldmap.RenderWithColors(countryCounts, 200)
	assert.NotEmpty(t, rendered)
	assert.Contains(t, rendered, "\n") // Should contain newlines
}

func TestCountryCoordinates(t *testing.T) {
	// Test that country coordinates are defined for major countries
	expectedCountries := []string{
		"US", "CA", "MX", "BR", "AR", "GB", "FR", "DE", "IT", "ES",
		"RU", "CN", "JP", "IN", "AU", "ZA", "EG", "NG", "KE", "SA",
	}
	
	for _, country := range expectedCountries {
		coord, exists := CountryCoordinates[country]
		assert.True(t, exists, "Country %s should have coordinates", country)
		assert.GreaterOrEqual(t, coord.X, 0, "X coordinate should be non-negative for %s", country)
		assert.GreaterOrEqual(t, coord.Y, 0, "Y coordinate should be non-negative for %s", country)
	}
}

func TestInitializeMap(t *testing.T) {
	// Test map initialization
	data := initializeMap()
	assert.NotNil(t, data)
	assert.Greater(t, len(data), 0, "Map should have rows")
	
	// Check that all rows have content
	for i, row := range data {
		assert.Greater(t, len(row), 0, "Row %d should have columns", i)
	}
}

func TestWorldMapMultipleMarkers(t *testing.T) {
	worldmap := WorldMap{}
	worldmap.data = initializeMap()
	
	// Test marking multiple countries with different markers
	markers := map[string]rune{
		"US": '*',
		"GB": '+',
		"FR": '#',
		"DE": '@',
		"JP": '%',
	}
	
	for country, marker := range markers {
		worldmap.MarkCountry(country, marker)
	}
	
	// Verify markers are set (if coordinates are valid)
	for country, expectedMarker := range markers {
		if coord, ok := CountryCoordinates[country]; ok {
			if coord.Y < len(worldmap.data) && coord.X < len(worldmap.data[coord.Y]) {
				assert.Equal(t, expectedMarker, worldmap.data[coord.Y][coord.X], 
					"Country %s should have marker %c", country, expectedMarker)
			}
		}
	}
}

func TestWorldMapOverwriteMarker(t *testing.T) {
	worldmap := WorldMap{}
	worldmap.data = initializeMap()
	
	// Mark a country with one marker
	worldmap.MarkCountry("US", '*')
	
	// Overwrite with different marker
	worldmap.MarkCountry("US", '+')
	
	// Check that the marker was overwritten
	if coord, ok := CountryCoordinates["US"]; ok {
		if coord.Y < len(worldmap.data) && coord.X < len(worldmap.data[coord.Y]) {
			assert.Equal(t, '+', worldmap.data[coord.Y][coord.X])
		}
	}
}

func TestWorldMapBoundaryChecks(t *testing.T) {
	worldmap := WorldMap{}
	worldmap.data = initializeMap()
	
	// Test that marking countries doesn't cause index out of bounds
	for countryCode := range CountryCoordinates {
		assert.NotPanics(t, func() {
			worldmap.MarkCountry(countryCode, 'X')
		}, "Marking country %s should not panic", countryCode)
	}
}

func TestWorldMapCoordinateRanges(t *testing.T) {
	// Test that all coordinates are within reasonable ranges
	maxX, maxY := 0, 0
	for _, coord := range CountryCoordinates {
		if coord.X > maxX {
			maxX = coord.X
		}
		if coord.Y > maxY {
			maxY = coord.Y
		}
	}
	
	// Coordinates should be reasonable for a text-based map
	assert.LessOrEqual(t, maxX, 150, "X coordinates should be within map bounds")
	assert.LessOrEqual(t, maxY, 50, "Y coordinates should be within map bounds")
}

func TestWorldMapEmptyOperations(t *testing.T) {
	worldmap := WorldMap{}
	
	// Test operations on uninitialized map (should not panic)
	assert.NotPanics(t, func() {
		worldmap.MarkCountry("US", '*')
		worldmap.Clear()
		worldmap.Render()
		worldmap.RenderWithColors(map[string]int{"US": 10}, 100)
	})
}