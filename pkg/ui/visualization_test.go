package ui

import (
	"testing"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"github.com/stretchr/testify/assert"
	"github.com/user/nsd/pkg/netcap"
)

func TestNewVisualizationRegistry(t *testing.T) {
	registry := NewVisualizationRegistry()
	assert.NotNil(t, registry)
	assert.NotNil(t, registry.visualizations)
	assert.Equal(t, 0, len(registry.visualizations))
}

func TestVisualizationRegistryRegister(t *testing.T) {
	registry := NewVisualizationRegistry()
	
	// Create a test visualization factory
	factory := func() Visualization {
		return &TestVisualizationImpl{
			id:          "test1",
			name:        "Test Viz",
			description: "A test visualization",
		}
	}
	
	// Register the visualization
	registry.Register("test1", factory)
	assert.Equal(t, 1, len(registry.visualizations))
	
	// Register another
	factory2 := func() Visualization {
		return &TestVisualizationImpl{
			id:          "test2",
			name:        "Test Viz 2",
			description: "Another test visualization",
		}
	}
	registry.Register("test2", factory2)
	assert.Equal(t, 2, len(registry.visualizations))
}

func TestVisualizationRegistryGet(t *testing.T) {
	registry := NewVisualizationRegistry()
	
	// Create and register a test visualization
	factory := func() Visualization {
		return &TestVisualizationImpl{
			id:          "test1",
			name:        "Test Viz",
			description: "A test visualization",
		}
	}
	registry.Register("test1", factory)
	
	// Get the visualization
	viz := registry.Get("test1")
	assert.NotNil(t, viz)
	assert.Equal(t, "test1", viz.GetID())
	assert.Equal(t, "Test Viz", viz.GetName())
	assert.Equal(t, "A test visualization", viz.GetDescription())
	
	// Get non-existent visualization
	nonExistent := registry.Get("nonexistent")
	assert.Nil(t, nonExistent)
}

func TestVisualizationRegistryGetAll(t *testing.T) {
	registry := NewVisualizationRegistry()
	
	// Initially empty
	all := registry.GetAll()
	assert.Equal(t, 0, len(all))
	
	// Register some visualizations
	for i := 0; i < 3; i++ {
		id := "test" + string(rune('1'+i))
		factory := func(testID string) func() Visualization {
			return func() Visualization {
				return &TestVisualizationImpl{
					id:          testID,
					name:        "Test " + testID,
					description: "Test visualization " + testID,
				}
			}
		}(id)
		registry.Register(id, factory)
	}
	
	// Get all visualizations
	all = registry.GetAll()
	assert.Equal(t, 3, len(all))
	
	// Check that all visualizations are returned
	ids := make(map[string]bool)
	for _, viz := range all {
		ids[viz.GetID()] = true
	}
	assert.True(t, ids["test1"])
	assert.True(t, ids["test2"])
	assert.True(t, ids["test3"])
}

func TestVisualizationRegistryList(t *testing.T) {
	registry := NewVisualizationRegistry()
	
	// Register some visualizations
	registry.Register("viz1", func() Visualization {
		return &TestVisualizationImpl{id: "viz1", name: "Viz 1"}
	})
	registry.Register("viz2", func() Visualization {
		return &TestVisualizationImpl{id: "viz2", name: "Viz 2"}
	})
	
	// List should return the IDs
	list := registry.List()
	assert.Equal(t, 2, len(list))
	assert.Contains(t, list, "viz1")
	assert.Contains(t, list, "viz2")
}

func TestVisualizationRegistryOverwrite(t *testing.T) {
	registry := NewVisualizationRegistry()
	
	// Register a visualization
	registry.Register("test1", func() Visualization {
		return &TestVisualizationImpl{id: "test1", name: "Original"}
	})
	assert.Equal(t, 1, len(registry.visualizations))
	
	// Overwrite with new registration
	registry.Register("test1", func() Visualization {
		return &TestVisualizationImpl{id: "test1", name: "Overwritten"}
	})
	assert.Equal(t, 1, len(registry.visualizations))
	
	// Get should return the new one
	viz := registry.Get("test1")
	assert.Equal(t, "Overwritten", viz.GetName())
}

func TestVisualizationRegistryHasVisualization(t *testing.T) {
	registry := NewVisualizationRegistry()
	
	// Initially empty
	viz := registry.Get("test1")
	assert.Nil(t, viz)
	
	// Register and check
	registry.Register("test1", func() Visualization {
		return &TestVisualizationImpl{id: "test1"}
	})
	viz = registry.Get("test1")
	assert.NotNil(t, viz)
	
	// Non-existent should still be nil
	viz2 := registry.Get("test2")
	assert.Nil(t, viz2)
}

func TestVisualizationRegistryReplaceRegistration(t *testing.T) {
	registry := NewVisualizationRegistry()
	
	// Register initial visualization
	registry.Register("test1", func() Visualization {
		return &TestVisualizationImpl{id: "test1", name: "Original"}
	})
	
	viz1 := registry.Get("test1")
	assert.Equal(t, "Original", viz1.GetName())
	
	// Replace with new registration
	registry.Register("test1", func() Visualization {
		return &TestVisualizationImpl{id: "test1", name: "Replaced"}
	})
	
	viz2 := registry.Get("test1")
	assert.Equal(t, "Replaced", viz2.GetName())
	
	// Should still have only one visualization
	assert.Equal(t, 1, len(registry.visualizations))
}

func TestVisualizationRegistryEmptyOperations(t *testing.T) {
	registry := NewVisualizationRegistry()
	
	// Operations on empty registry should not panic
	assert.NotPanics(t, func() {
		registry.Get("nonexistent")
		registry.List()
		registry.GetAll()
	})
}

// TestVisualizationImpl is a mock implementation of the Visualization interface
type TestVisualizationImpl struct {
	id          string
	name        string
	description string
	theme       Theme
}

func (tv *TestVisualizationImpl) GetID() string {
	return tv.id
}

func (tv *TestVisualizationImpl) GetName() string {
	return tv.name
}

func (tv *TestVisualizationImpl) GetDescription() string {
	return tv.description
}

func (tv *TestVisualizationImpl) CreateView() tview.Primitive {
	view := tview.NewTextView()
	view.SetTitle(tv.name)
	view.SetText(tv.description)
	return view
}

func (tv *TestVisualizationImpl) Update(monitor *netcap.NetworkMonitor) {
	// Mock update - in real implementation this would process network data
}

func (tv *TestVisualizationImpl) SetTheme(theme Theme) {
	tv.theme = theme
}

func (tv *TestVisualizationImpl) GetMinSize() (width, height int) {
	return 40, 20
}

func (tv *TestVisualizationImpl) SupportsFullscreen() bool {
	return true
}

func TestVisualizationInterface(t *testing.T) {
	// Test that our implementation satisfies the interface
	viz := &TestVisualizationImpl{
		id:          "interface_test",
		name:        "Interface Test",
		description: "Testing the visualization interface",
	}
	
	// Test all interface methods
	assert.Equal(t, "interface_test", viz.GetID())
	assert.Equal(t, "Interface Test", viz.GetName())
	assert.Equal(t, "Testing the visualization interface", viz.GetDescription())
	
	// Test CreateView returns a tview primitive
	view := viz.CreateView()
	assert.NotNil(t, view)
	
	// Test Update doesn't panic
	assert.NotPanics(t, func() {
		viz.Update(&netcap.NetworkMonitor{})
	})
	
	// Test SetTheme
	theme := Theme{
		BorderColor:  tcell.ColorWhite,
		TitleColor:   tcell.ColorYellow,
		PrimaryColor: tcell.ColorBlue,
	}
	assert.NotPanics(t, func() {
		viz.SetTheme(theme)
	})
	assert.Equal(t, theme, viz.theme)
	
	// Test GetMinSize
	width, height := viz.GetMinSize()
	assert.Equal(t, 40, width)
	assert.Equal(t, 20, height)
	
	// Test SupportsFullscreen
	assert.True(t, viz.SupportsFullscreen())
}

func TestVisualizationRegistrySequentialOperations(t *testing.T) {
	registry := NewVisualizationRegistry()
	
	// Test sequential operations to ensure registry works properly
	viz1 := &TestVisualizationImpl{id: "seq1", name: "Sequential 1"}
	viz2 := &TestVisualizationImpl{id: "seq2", name: "Sequential 2"}
	
	// Register visualizations
	registry.Register("seq1", func() Visualization { return viz1 })
	registry.Register("seq2", func() Visualization { return viz2 })
	
	// Get all and verify
	all := registry.GetAll()
	assert.Equal(t, 2, len(all))
	
	// List and verify
	list := registry.List()
	assert.Equal(t, 2, len(list))
	assert.Contains(t, list, "seq1")
	assert.Contains(t, list, "seq2")
	
	// Get individual visualizations
	retrieved1 := registry.Get("seq1")
	retrieved2 := registry.Get("seq2")
	assert.NotNil(t, retrieved1)
	assert.NotNil(t, retrieved2)
	assert.Equal(t, "seq1", retrieved1.GetID())
	assert.Equal(t, "seq2", retrieved2.GetID())
}