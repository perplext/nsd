package reassembly

import (
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"github.com/stretchr/testify/assert"
)

// Helper to create test packet
func createTestPacket(srcIP, dstIP string, srcPort, dstPort uint16, payload []byte) gopacket.Packet {
	// Create layers
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.ParseIP(srcIP),
		DstIP:    net.ParseIP(dstIP),
	}

	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     12345,
		Window:  14600,
	}
	tcp.SetNetworkLayerForChecksum(ip)

	// Create packet
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload(payload))
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

// Test FileExtractor creation
func TestNewFileExtractor(t *testing.T) {
	tmpDir := t.TempDir()
	
	fe := NewFileExtractor(tmpDir, 10*1024*1024)
	assert.NotNil(t, fe)
	assert.Equal(t, tmpDir, fe.outputDir)
	assert.Equal(t, int64(10*1024*1024), fe.maxFileSize)
	assert.NotNil(t, fe.assembler)
	assert.NotNil(t, fe.streamFactory)
	assert.NotNil(t, fe.extractedFiles)
	assert.NotNil(t, fe.allowedTypes)
}

// Test NewFileExtractor with invalid directory
func TestNewFileExtractorInvalidDir(t *testing.T) {
	fe := NewFileExtractor("/non/existent/directory", 1024)
	// Should still create the extractor, even with invalid dir
	assert.NotNil(t, fe)
}

// Test ProcessPacket
func TestProcessPacket(t *testing.T) {
	tmpDir := t.TempDir()
	fe := NewFileExtractor(tmpDir, 10*1024*1024)

	// Create HTTP request packet
	httpRequest := "GET /test.txt HTTP/1.1\r\nHost: example.com\r\n\r\n"
	packet := createTestPacket("192.168.1.100", "192.168.1.200", 50000, 80, []byte(httpRequest))
	
	// Process packet (shouldn't panic)
	fe.ProcessPacket(packet)
}

// Test allowed file types
func TestSetAllowedTypes(t *testing.T) {
	tmpDir := t.TempDir()
	fe := NewFileExtractor(tmpDir, 10*1024*1024)

	// Test setting allowed types
	types := []string{"image/jpeg", "image/png", "application/pdf"}
	fe.SetAllowedTypes(types)
	
	assert.Len(t, fe.allowedTypes, 3)
	assert.True(t, fe.allowedTypes["image/jpeg"])
	assert.True(t, fe.allowedTypes["image/png"])
	assert.True(t, fe.allowedTypes["application/pdf"])
}

// Test GetExtractedFiles channel
func TestGetExtractedFiles(t *testing.T) {
	tmpDir := t.TempDir()
	fe := NewFileExtractor(tmpDir, 10*1024*1024)

	channel := fe.GetExtractedFiles()
	assert.NotNil(t, channel)
	
	// Should be able to read from it (non-blocking)
	select {
	case <-channel:
		// No file expected
	default:
		// This is expected
	}
}

// Test GetStats
func TestGetStats(t *testing.T) {
	tmpDir := t.TempDir()
	fe := NewFileExtractor(tmpDir, 10*1024*1024)

	stats := fe.GetStats()
	assert.Equal(t, int64(0), stats.TotalFiles)
	assert.Equal(t, int64(0), stats.TotalSize)
	assert.Equal(t, int64(0), stats.ActiveTransfers)
}


// Test ExtractedFile structure
func TestExtractedFileStructure(t *testing.T) {
	ef := ExtractedFile{
		ID:           "test-123",
		Protocol:     "HTTP",
		Source:       net.ParseIP("192.168.1.100"),
		Destination:  net.ParseIP("192.168.1.200"),
		SourcePort:   50000,
		DestPort:     80,
		Filename:     "extracted_123.dat",
		OriginalName: "test.txt",
		ContentType:  "text/plain",
		Size:         1024,
		MD5Hash:      "d41d8cd98f00b204e9800998ecf8427e",
		SHA256Hash:   "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		Timestamp:    time.Now(),
		FilePath:     "/tmp/extracted_123.dat",
		Metadata: map[string]interface{}{
			"user-agent": "test",
		},
		Direction:    DirectionDownload,
		Complete:     true,
	}

	assert.Equal(t, "test-123", ef.ID)
	assert.Equal(t, "HTTP", ef.Protocol)
	assert.Equal(t, int64(1024), ef.Size)
}

// Test ExtractionStats structure
func TestExtractionStatsStructure(t *testing.T) {
	stats := ExtractionStats{
		TotalFiles:        10,
		TotalSize:         1024000,
		ActiveTransfers:   2,
		FilesByType: map[string]int64{
			"image/jpeg": 5,
			"text/plain": 5,
		},
		FilesByProtocol: map[string]int64{
			"HTTP": 10,
		},
		TransfersByDir: map[TransferDirection]int64{
			DirectionDownload: 8,
			DirectionUpload:   2,
		},
		IncompleteFiles: 3,
		LastExtraction:  time.Now(),
	}

	assert.Equal(t, int64(10), stats.TotalFiles)
	assert.Equal(t, int64(1024000), stats.TotalSize)
	assert.Equal(t, int64(2), stats.ActiveTransfers)
	assert.Equal(t, int64(5), stats.FilesByType["image/jpeg"])
	assert.Equal(t, int64(3), stats.IncompleteFiles)
}

// Test httpStream creation
func TestHTTPStreamCreation(t *testing.T) {
	tmpDir := t.TempDir()
	fe := NewFileExtractor(tmpDir, 10*1024*1024)

	stream := &httpStream{
		net:          gopacket.NewFlow(layers.EndpointIPv4, []byte{192, 168, 1, 1}, []byte{192, 168, 1, 2}),
		transport:    gopacket.NewFlow(layers.EndpointTCPPort, []byte{0, 80}, []byte{0x30, 0x39}),
		extractor:    fe,
			r:            tcpreader.ReaderStream{},
		isClient:     true,
	}

	assert.NotNil(t, stream.net)
	assert.NotNil(t, stream.transport)
	assert.True(t, stream.isClient)
}





// Benchmark tests
func BenchmarkProcessPacket(b *testing.B) {
	tmpDir := b.TempDir()
	fe := NewFileExtractor(tmpDir, 10*1024*1024)

	httpRequest := "GET /test.txt HTTP/1.1\r\nHost: example.com\r\n\r\n"
	packet := createTestPacket("192.168.1.100", "192.168.1.200", 50000, 80, []byte(httpRequest))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fe.ProcessPacket(packet)
	}
}

