package ui

import (
	"os"
	"time"

	chart "github.com/wcharczuk/go-chart/v2"
	"github.com/perplext/nsd/pkg/graph"
)

// ensure graph import is used
var _ = graph.NewMultiGraph

// ExportSVG exports the combined traffic graph to an SVG file.
func (ui *UI) ExportSVG(path string) error {
	widgets := ui.trafficGraph.GraphWidgets()
	series := make([]chart.Series, 0)
	for _, w := range widgets {
		// Primary data series
		primaryPts := w.DataPoints()
		xs := make([]time.Time, len(primaryPts))
		ys := make([]float64, len(primaryPts))
		for i, p := range primaryPts {
			xs[i] = p.Timestamp
			ys[i] = p.Value
		}
		primaryLabel, _ := w.Labels()
		series = append(series, chart.TimeSeries{
			Name:    primaryLabel,
			XValues: xs,
			YValues: ys,
		})

		// Secondary data series
		secondaryPts := w.SecondaryDataPoints()
		xs2 := make([]time.Time, len(secondaryPts))
		ys2 := make([]float64, len(secondaryPts))
		for i, p := range secondaryPts {
			xs2[i] = p.Timestamp
			ys2[i] = p.Value
		}
		_, secondaryLabel := w.Labels()
		series = append(series, chart.TimeSeries{
			Name:    secondaryLabel,
			XValues: xs2,
			YValues: ys2,
		})
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	return chart.Chart{
		Series: series,
	}.Render(chart.SVG, f)
}

// ExportPNG exports the combined traffic graph to a PNG file.
func (ui *UI) ExportPNG(path string) error {
	widgets := ui.trafficGraph.GraphWidgets()
	series := make([]chart.Series, 0)
	for _, w := range widgets {
		// Primary data series
		primaryPts := w.DataPoints()
		xs := make([]time.Time, len(primaryPts))
		ys := make([]float64, len(primaryPts))
		for i, p := range primaryPts {
			xs[i] = p.Timestamp
			ys[i] = p.Value
		}
		primaryLabel, _ := w.Labels()
		series = append(series, chart.TimeSeries{
			Name:    primaryLabel,
			XValues: xs,
			YValues: ys,
		})

		// Secondary data series
		secondaryPts := w.SecondaryDataPoints()
		xs2 := make([]time.Time, len(secondaryPts))
		ys2 := make([]float64, len(secondaryPts))
		for i, p := range secondaryPts {
			xs2[i] = p.Timestamp
			ys2[i] = p.Value
		}
		_, secondaryLabel := w.Labels()
		series = append(series, chart.TimeSeries{
			Name:    secondaryLabel,
			XValues: xs2,
			YValues: ys2,
		})
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	return chart.Chart{
		Series: series,
	}.Render(chart.PNG, f)
}
