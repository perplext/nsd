package ui

import (
	"fmt"
	"strings"

	"github.com/rivo/tview"
	"github.com/perplext/nsd/pkg/netcap"
)

// PacketDistributionVisualization shows packet size distribution
type PacketDistributionVisualization struct {
	BaseVisualization
	distribution map[int]int // size bucket -> count
}

// NewPacketDistributionVisualization creates a new packet distribution visualization
func NewPacketDistributionVisualization() Visualization {
	p := &PacketDistributionVisualization{
		distribution: make(map[int]int),
	}
	p.textView = tview.NewTextView().
		SetDynamicColors(true).
		SetWrap(false)
	p.textView.SetBorder(true).
		SetTitle("Packet Size Distribution")
	return p
}

// GetID returns the unique identifier
func (p *PacketDistributionVisualization) GetID() string {
	return "packet_dist"
}

// GetName returns the display name
func (p *PacketDistributionVisualization) GetName() string {
	return "Packet Size Distribution"
}

// GetDescription returns a description
func (p *PacketDistributionVisualization) GetDescription() string {
	return "Enhanced histogram of packet sizes"
}

// CreateView creates the view
func (p *PacketDistributionVisualization) CreateView() tview.Primitive {
	return p.textView
}

// Update updates the visualization
func (p *PacketDistributionVisualization) Update(monitor *netcap.NetworkMonitor) {
	p.monitor = monitor
	
	// Reset distribution
	p.distribution = make(map[int]int)
	
	// Get packet buffer
	packets := monitor.GetPacketBuffer()
	
	// Categorize packets by size
	for _, pkt := range packets {
		bucket := p.getBucket(int(pkt.Length))
		p.distribution[bucket]++
	}
	
	// Build visualization
	var output strings.Builder
	
	// Header
	output.WriteString("[white]Size Distribution (bytes)\n\n")
	
	// Define buckets in order
	buckets := []struct {
		size  int
		label string
	}{
		{64, "   64"},
		{128, "  128"},
		{256, "  256"},
		{512, "  512"},
		{1024, " 1024"},
		{1500, " 1500"},
		{2048, " 2048"},
		{4096, " 4096"},
		{9000, " 9000"}, // Jumbo frames
		{16384, "16384"},
	}
	
	// Find max count for scaling
	maxCount := 0
	totalPackets := 0
	for _, count := range p.distribution {
		if count > maxCount {
			maxCount = count
		}
		totalPackets += count
	}
	
	if maxCount == 0 {
		maxCount = 1
	}
	
	// Draw histogram
	barWidth := 50
	for _, bucket := range buckets {
		count := p.distribution[bucket.size]
		percentage := 0.0
		if totalPackets > 0 {
			percentage = float64(count) / float64(totalPackets) * 100
		}
		
		// Calculate bar length
		barLen := int(float64(count) / float64(maxCount) * float64(barWidth))
		
		// Choose bar style based on percentage
		var bar string
		color := p.getSizeColor(bucket.size)
		
		if barLen > 0 {
			// Use different block characters for visual variety
			if percentage > 30 {
				bar = strings.Repeat("█", barLen)
			} else if percentage > 20 {
				bar = strings.Repeat("▓", barLen)
			} else if percentage > 10 {
				bar = strings.Repeat("▒", barLen)
			} else {
				bar = strings.Repeat("░", barLen)
			}
		}
		
		// Format line
		output.WriteString(fmt.Sprintf("%s │%s%s[white]%s %5.1f%% (%d)\n",
			bucket.label,
			color,
			bar,
			strings.Repeat(" ", barWidth-len(bar)),
			percentage,
			count))
	}
	
	// Statistics
	output.WriteString("\n[white]Packet Statistics:\n")
	output.WriteString(fmt.Sprintf("Total Packets: %d\n", totalPackets))
	
	// Size analysis
	// Convert packets to slice of pointers
	var packetPtrs []*netcap.PacketInfo
	for i := range packets {
		packetPtrs = append(packetPtrs, &packets[i])
	}
	avgSize := p.calculateAverageSize(packetPtrs)
	output.WriteString(fmt.Sprintf("Average Size: %d bytes\n", avgSize))
	
	// MTU analysis
	mtuCount := p.distribution[1500]
	if totalPackets > 0 {
		mtuPercentage := float64(mtuCount) / float64(totalPackets) * 100
		output.WriteString(fmt.Sprintf("MTU-sized packets (1500): %.1f%%\n", mtuPercentage))
	}
	
	// Small vs large packets
	smallPackets := 0
	largePackets := 0
	for size, count := range p.distribution {
		if size <= 128 {
			smallPackets += count
		} else if size >= 1024 {
			largePackets += count
		}
	}
	
	if totalPackets > 0 {
		output.WriteString(fmt.Sprintf("\nSmall packets (≤128): %.1f%%\n", 
			float64(smallPackets)/float64(totalPackets)*100))
		output.WriteString(fmt.Sprintf("Large packets (≥1024): %.1f%%\n", 
			float64(largePackets)/float64(totalPackets)*100))
	}
	
	// Protocol breakdown by size
	output.WriteString("\n[white]Size by Protocol:\n")
	protocolSizes := p.getProtocolSizes(packetPtrs)
	for proto, sizes := range protocolSizes {
		avgProtoSize := 0
		if sizes.count > 0 {
			avgProtoSize = sizes.total / sizes.count
		}
		
		color := p.getProtocolColor(proto)
		output.WriteString(fmt.Sprintf("%s%-6s[white]: avg %4d bytes (%d packets)\n",
			color, proto, avgProtoSize, sizes.count))
	}
	
	p.textView.SetText(output.String())
}

// getBucket returns the bucket for a packet size
func (p *PacketDistributionVisualization) getBucket(size int) int {
	buckets := []int{64, 128, 256, 512, 1024, 1500, 2048, 4096, 9000, 16384}
	
	for _, bucket := range buckets {
		if size <= bucket {
			return bucket
		}
	}
	
	return 16384 // Max bucket
}

// calculateAverageSize calculates average packet size
func (p *PacketDistributionVisualization) calculateAverageSize(packets []*netcap.PacketInfo) int {
	if len(packets) == 0 {
		return 0
	}
	
	total := 0
	for _, pkt := range packets {
		total += int(pkt.Length)
	}
	
	return total / len(packets)
}

type protocolSize struct {
	total int
	count int
}

// getProtocolSizes gets size statistics by protocol
func (p *PacketDistributionVisualization) getProtocolSizes(packets []*netcap.PacketInfo) map[string]*protocolSize {
	sizes := make(map[string]*protocolSize)
	
	for _, pkt := range packets {
		if sizes[pkt.Protocol] == nil {
			sizes[pkt.Protocol] = &protocolSize{}
		}
		sizes[pkt.Protocol].total += int(pkt.Length)
		sizes[pkt.Protocol].count++
	}
	
	return sizes
}

// getSizeColor returns color based on packet size
func (p *PacketDistributionVisualization) getSizeColor(size int) string {
	switch {
	case size <= 128:
		return "[blue]"
	case size <= 512:
		return "[cyan]"
	case size <= 1500:
		return "[green]"
	case size <= 4096:
		return "[yellow]"
	default:
		return "[red]"
	}
}

// getProtocolColor returns color for protocol
func (p *PacketDistributionVisualization) getProtocolColor(protocol string) string {
	switch protocol {
	case "TCP":
		return "[green]"
	case "UDP":
		return "[blue]"
	case "ICMP":
		return "[yellow]"
	default:
		return "[white]"
	}
}

// GetMinSize returns minimum size requirements
func (p *PacketDistributionVisualization) GetMinSize() (width, height int) {
	return 70, 35
}