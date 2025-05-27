package protocols

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestProtocolManagerCreation(t *testing.T) {
	pm := NewProtocolManager(1000)
	assert.NotNil(t, pm)
	assert.NotNil(t, pm.analyzers)
	assert.NotNil(t, pm.events)
	assert.Equal(t, 1000, pm.maxEvents)
	
	// Test that analyzers are registered
	analyzers := pm.GetAnalyzers()
	assert.NotEmpty(t, analyzers)
	assert.Contains(t, analyzers, "FTP")
	assert.Contains(t, analyzers, "SSH")
	assert.Contains(t, analyzers, "POP3")
	assert.Contains(t, analyzers, "IMAP")
}

func TestEventTypes(t *testing.T) {
	// Test that event type constants have expected values
	assert.Equal(t, EventType("connection"), EventTypeConnection)
	assert.Equal(t, EventType("authentication"), EventTypeAuthentication)
	assert.Equal(t, EventType("command"), EventTypeCommand)
	assert.Equal(t, EventType("data_transfer"), EventTypeDataTransfer)
	assert.Equal(t, EventType("file_transfer"), EventTypeFileTransfer)
	assert.Equal(t, EventType("email"), EventTypeEmail)
	assert.Equal(t, EventType("error"), EventTypeError)
	assert.Equal(t, EventType("disconnection"), EventTypeDisconnection)
}

func TestDirectionTypes(t *testing.T) {
	// Test that direction constants have expected values
	assert.Equal(t, TransferDirection("upload"), DirectionUpload)
	assert.Equal(t, TransferDirection("download"), DirectionDownload)
	assert.Equal(t, TransferDirection("inbound"), DirectionInbound)
	assert.Equal(t, TransferDirection("outbound"), DirectionOutbound)
}

func TestProtocolEventStructure(t *testing.T) {
	// Test creating a protocol event
	now := time.Now()
	srcIP := net.ParseIP("192.168.1.100")
	dstIP := net.ParseIP("192.168.1.200")
	
	event := ProtocolEvent{
		ID:          "test-id",
		Protocol:    "TEST",
		EventType:   EventTypeCommand,
		Timestamp:   now,
		SourceIP:    srcIP,
		DestIP:      dstIP,
		SourcePort:  8080,
		DestPort:    9090,
		Command:     "TEST_COMMAND",
		Status:      "OK",
		Direction:   DirectionUpload,
		Data:        make(map[string]interface{}),
	}
	
	if event.Protocol != "TEST" {
		t.Errorf("Expected protocol TEST, got %s", event.Protocol)
	}
}