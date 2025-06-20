package protocols

import (
	"bufio"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"github.com/perplext/nsd/pkg/security"
)

// ProtocolAnalyzer defines the interface for protocol-specific analyzers
type ProtocolAnalyzer interface {
	// GetProtocolName returns the name of the protocol
	GetProtocolName() string
	
	// GetPorts returns the standard ports for this protocol
	GetPorts() []uint16
	
	// AnalyzeStream analyzes a TCP stream for this protocol
	AnalyzeStream(flow gopacket.Flow, reader *tcpreader.ReaderStream) []ProtocolEvent
	
	// IsProtocolTraffic determines if the given data belongs to this protocol
	IsProtocolTraffic(data []byte) bool
}

// ProtocolEvent represents a protocol-specific event
type ProtocolEvent struct {
	ID          string                 `json:"id"`
	Protocol    string                 `json:"protocol"`
	EventType   EventType              `json:"event_type"`
	Timestamp   time.Time              `json:"timestamp"`
	SourceIP    net.IP                 `json:"source_ip"`
	DestIP      net.IP                 `json:"dest_ip"`
	SourcePort  uint16                 `json:"source_port"`
	DestPort    uint16                 `json:"dest_port"`
	Command     string                 `json:"command,omitempty"`
	Response    string                 `json:"response,omitempty"`
	Username    string                 `json:"username,omitempty"`
	Filename    string                 `json:"filename,omitempty"`
	FileSize    int64                  `json:"file_size,omitempty"`
	Status      string                 `json:"status,omitempty"`
	Direction   TransferDirection      `json:"direction"`
	Data        map[string]interface{} `json:"data,omitempty"`
	Raw         []byte                 `json:"raw,omitempty"`
}

// EventType categorizes different protocol events
type EventType string

const (
	EventTypeConnection    EventType = "connection"
	EventTypeAuthentication EventType = "authentication"
	EventTypeCommand       EventType = "command"
	EventTypeDataTransfer  EventType = "data_transfer"
	EventTypeFileTransfer  EventType = "file_transfer"
	EventTypeEmail         EventType = "email"
	EventTypeError         EventType = "error"
	EventTypeDisconnection EventType = "disconnection"
)

// TransferDirection indicates data flow direction
type TransferDirection string

const (
	DirectionUpload   TransferDirection = "upload"
	DirectionDownload TransferDirection = "download"
	DirectionInbound  TransferDirection = "inbound"
	DirectionOutbound TransferDirection = "outbound"
)

// ProtocolManager manages all protocol analyzers
type ProtocolManager struct {
	analyzers    map[string]ProtocolAnalyzer
	assembler    *tcpassembly.Assembler
	events       chan ProtocolEvent
	maxEvents    int
}

// NewProtocolManager creates a new protocol manager
func NewProtocolManager(maxEvents int) *ProtocolManager {
	pm := &ProtocolManager{
		analyzers: make(map[string]ProtocolAnalyzer),
		events:    make(chan ProtocolEvent, maxEvents),
		maxEvents: maxEvents,
	}
	
	// Register built-in analyzers
	pm.RegisterAnalyzer(NewFTPAnalyzer())
	pm.RegisterAnalyzer(NewSSHAnalyzer())
	pm.RegisterAnalyzer(NewPOP3Analyzer())
	pm.RegisterAnalyzer(NewIMAPAnalyzer())
	
	// Create assembler with factory
	streamFactory := &protocolStreamFactory{manager: pm}
	pm.assembler = tcpassembly.NewAssembler(tcpassembly.NewStreamPool(streamFactory))
	
	return pm
}

// RegisterAnalyzer registers a new protocol analyzer
func (pm *ProtocolManager) RegisterAnalyzer(analyzer ProtocolAnalyzer) {
	pm.analyzers[analyzer.GetProtocolName()] = analyzer
}

// ProcessPacket processes a packet through all analyzers
func (pm *ProtocolManager) ProcessPacket(packet gopacket.Packet) {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		pm.assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(),
			tcp, packet.Metadata().Timestamp)
	}
}

// GetEvents returns the events channel
func (pm *ProtocolManager) GetEvents() <-chan ProtocolEvent {
	return pm.events
}

// GetAnalyzers returns all registered analyzers
func (pm *ProtocolManager) GetAnalyzers() map[string]ProtocolAnalyzer {
	return pm.analyzers
}

// FlushConnections flushes all connections
func (pm *ProtocolManager) FlushConnections() {
	pm.assembler.FlushAll()
}

// protocolStreamFactory creates streams for protocol analysis
type protocolStreamFactory struct {
	manager *ProtocolManager
}

func (factory *protocolStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	stream := &protocolStream{
		net:       net,
		transport: transport,
		r:         tcpreader.NewReaderStream(),
		manager:   factory.manager,
	}
	go stream.run()
	return &stream.r
}

// protocolStream processes a single TCP stream
type protocolStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
	manager        *ProtocolManager
}

func (stream *protocolStream) run() {
	defer stream.r.Close()
	
	// Determine which protocol analyzer to use based on port
	// FastHash returns uint64, we need to safely convert to uint16
	srcHash := stream.transport.Src().FastHash()
	dstHash := stream.transport.Dst().FastHash()
	
	// Use secure conversion to ensure we stay within uint16 range
	srcPort := security.SafeUint64ToUint16WithMod(srcHash)
	dstPort := security.SafeUint64ToUint16WithMod(dstHash)
	
	var analyzer ProtocolAnalyzer
	
	// Check each analyzer to see if it handles this port
	for _, a := range stream.manager.analyzers {
		ports := a.GetPorts()
		for _, port := range ports {
			if srcPort == port || dstPort == port {
				analyzer = a
				break
			}
		}
		if analyzer != nil {
			break
		}
	}
	
	if analyzer == nil {
		// Try to identify protocol by content
		buf := make([]byte, 1024)
		n, err := stream.r.Read(buf)
		if err != nil {
			return
		}
		
		for _, a := range stream.manager.analyzers {
			if a.IsProtocolTraffic(buf[:n]) {
				analyzer = a
				break
			}
		}
		
		if analyzer == nil {
			return // Unknown protocol
		}
	}
	
	// Analyze the stream with the identified protocol analyzer
	events := analyzer.AnalyzeStream(stream.transport, &stream.r)
	
	// Send events to the manager
	for _, event := range events {
		// Set connection details
		event.SourceIP = net.ParseIP(stream.net.Src().String())
		event.DestIP = net.ParseIP(stream.net.Dst().String())
		event.SourcePort = srcPort
		event.DestPort = dstPort
		event.Timestamp = time.Now()
		
		// Send to channel (non-blocking)
		select {
		case stream.manager.events <- event:
		default:
			// Channel full, drop event
		}
	}
}

// BaseAnalyzer provides common functionality for protocol analyzers
type BaseAnalyzer struct {
	protocolName string
	ports        []uint16
}

// GetProtocolName returns the protocol name
func (ba *BaseAnalyzer) GetProtocolName() string {
	return ba.protocolName
}

// GetPorts returns the standard ports
func (ba *BaseAnalyzer) GetPorts() []uint16 {
	return ba.ports
}

// Helper functions for protocol analyzers

// ReadLine reads a line from the stream
func ReadLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// ReadUntil reads until a specific delimiter
func ReadUntil(reader *bufio.Reader, delimiter byte) ([]byte, error) {
	var data []byte
	for {
		b, err := reader.ReadByte()
		if err != nil {
			return data, err
		}
		data = append(data, b)
		if b == delimiter {
			break
		}
	}
	return data, nil
}

// ParseCommand parses a protocol command
func ParseCommand(line string) (command string, args []string) {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return "", nil
	}
	return strings.ToUpper(parts[0]), parts[1:]
}

// GenerateEventID generates a unique event ID
func GenerateEventID(protocol string) string {
	return fmt.Sprintf("%s_%d_%d", protocol, time.Now().UnixNano(), rand.Intn(1000))
}