package ui

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/user/nsd/pkg/graph"
	"github.com/user/nsd/pkg/netcap"
)

// Test UI ExportSVG method
func TestUI_ExportSVG(t *testing.T) {
	// Create temporary directory
	tmpDir, err := os.MkdirTemp("", "netmon_export_test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)
	
	// Create UI with mock data
	monitor := netcap.NewNetworkMonitor()
	ui := NewUI(monitor)
	
	// Initialize traffic graph
	ui.trafficGraph = graph.NewMultiGraph()
	widget := graph.NewGraphWidget()
	widget.SetDataFunc(func() (float64, float64) {
		return 100.0, 50.0
	})
	widget.Start()
	time.Sleep(100 * time.Millisecond) // Let it collect some data
	widget.Stop()
	ui.trafficGraph.AddGraph(widget)
	
	// Test export
	svgPath := filepath.Join(tmpDir, "test.svg")
	err = ui.ExportSVG(svgPath)
	assert.NoError(t, err)
	
	// Check file was created
	info, err := os.Stat(svgPath)
	assert.NoError(t, err)
	assert.Greater(t, info.Size(), int64(0))
	
	// Test with invalid path
	err = ui.ExportSVG("/invalid/path/test.svg")
	assert.Error(t, err)
}

// Test UI ExportPNG method
func TestUI_ExportPNG(t *testing.T) {
	// Create temporary directory
	tmpDir, err := os.MkdirTemp("", "netmon_export_test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)
	
	// Create UI with mock data
	monitor := netcap.NewNetworkMonitor()
	ui := NewUI(monitor)
	
	// Initialize traffic graph
	ui.trafficGraph = graph.NewMultiGraph()
	widget := graph.NewGraphWidget()
	widget.SetDataFunc(func() (float64, float64) {
		return 200.0, 100.0
	})
	widget.Start()
	time.Sleep(100 * time.Millisecond) // Let it collect some data
	widget.Stop()
	ui.trafficGraph.AddGraph(widget)
	
	// Test export
	pngPath := filepath.Join(tmpDir, "test.png")
	err = ui.ExportPNG(pngPath)
	assert.NoError(t, err)
	
	// Check file was created
	info, err := os.Stat(pngPath)
	assert.NoError(t, err)
	assert.Greater(t, info.Size(), int64(0))
	
	// Test with invalid path
	err = ui.ExportPNG("/invalid/path/test.png")
	assert.Error(t, err)
}

// Test export with empty data
func TestUI_ExportEmptyData(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "netmon_export_test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)
	
	// Create UI without data
	monitor := netcap.NewNetworkMonitor()
	ui := NewUI(monitor)
	ui.trafficGraph = graph.NewMultiGraph()
	
	// Test SVG export with no data
	svgPath := filepath.Join(tmpDir, "empty.svg")
	err = ui.ExportSVG(svgPath)
	// Should handle gracefully (might succeed with empty chart)
	
	// Test PNG export with no data
	pngPath := filepath.Join(tmpDir, "empty.png")
	err = ui.ExportPNG(pngPath)
	// Should handle gracefully
}

// Test export with multiple graph widgets
func TestUI_ExportMultipleGraphs(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "netmon_export_test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)
	
	// Create UI with multiple graphs
	monitor := netcap.NewNetworkMonitor()
	ui := NewUI(monitor)
	ui.trafficGraph = graph.NewMultiGraph()
	
	// Add multiple widgets
	for i := 0; i < 3; i++ {
		widget := graph.NewGraphWidget()
		idx := i
		widget.SetDataFunc(func() (float64, float64) {
			return float64(100 * (idx + 1)), float64(50 * (idx + 1))
		})
		widget.Start()
		time.Sleep(50 * time.Millisecond)
		widget.Stop()
		ui.trafficGraph.AddGraph(widget)
	}
	
	// Export both formats
	svgPath := filepath.Join(tmpDir, "multi.svg")
	err = ui.ExportSVG(svgPath)
	assert.NoError(t, err)
	
	pngPath := filepath.Join(tmpDir, "multi.png")
	err = ui.ExportPNG(pngPath)
	assert.NoError(t, err)
}