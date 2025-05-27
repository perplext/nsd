package protocols

import (
	"bufio"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test FTP Analyzer
func TestFTPAnalyzer(t *testing.T) {
	analyzer := NewFTPAnalyzer()
	
	// Test protocol name and ports
	assert.Equal(t, "FTP", analyzer.GetProtocolName())
	ports := analyzer.GetPorts()
	assert.Contains(t, ports, uint16(21))
	assert.Contains(t, ports, uint16(20))
	
	// Test IsProtocolTraffic
	assert.True(t, analyzer.IsProtocolTraffic([]byte("220 FTP Server Ready\r\n")))
	assert.True(t, analyzer.IsProtocolTraffic([]byte("USER anonymous\r\n")))
	assert.False(t, analyzer.IsProtocolTraffic([]byte("GET / HTTP/1.1\r\n")))
}

// Test SMTP Analyzer
func TestSMTPAnalyzer(t *testing.T) {
	analyzer := NewSMTPAnalyzer()
	
	// Test protocol name and ports
	assert.Equal(t, "SMTP", analyzer.GetProtocolName())
	ports := analyzer.GetPorts()
	assert.Contains(t, ports, uint16(25))
	assert.Contains(t, ports, uint16(587))
	assert.Contains(t, ports, uint16(465))
	
	// Test IsProtocolTraffic
	assert.True(t, analyzer.IsProtocolTraffic([]byte("220 mail.example.com ESMTP\r\n")))
	assert.True(t, analyzer.IsProtocolTraffic([]byte("EHLO client.example.com\r\n")))
	assert.False(t, analyzer.IsProtocolTraffic([]byte("GET / HTTP/1.1\r\n")))
}

// Test IMAP Analyzer
func TestIMAPAnalyzer(t *testing.T) {
	analyzer := NewIMAPAnalyzer()
	
	// Test protocol name and ports
	assert.Equal(t, "IMAP", analyzer.GetProtocolName())
	ports := analyzer.GetPorts()
	assert.Contains(t, ports, uint16(143))
	assert.Contains(t, ports, uint16(993))
	
	// Test IsProtocolTraffic
	assert.True(t, analyzer.IsProtocolTraffic([]byte("* OK IMAP4rev1 Service Ready\r\n")))
	assert.True(t, analyzer.IsProtocolTraffic([]byte("A001 LOGIN user pass\r\n")))
	assert.False(t, analyzer.IsProtocolTraffic([]byte("GET / HTTP/1.1\r\n")))
}

// Test POP3 Analyzer
func TestPOP3Analyzer(t *testing.T) {
	analyzer := NewPOP3Analyzer()
	
	// Test protocol name and ports
	assert.Equal(t, "POP3", analyzer.GetProtocolName())
	ports := analyzer.GetPorts()
	assert.Contains(t, ports, uint16(110))
	assert.Contains(t, ports, uint16(995))
	
	// Test IsProtocolTraffic
	assert.True(t, analyzer.IsProtocolTraffic([]byte("+OK POP3 server ready\r\n")))
	assert.True(t, analyzer.IsProtocolTraffic([]byte("USER john\r\n")))
	assert.False(t, analyzer.IsProtocolTraffic([]byte("GET / HTTP/1.1\r\n")))
}

// Test SSH Analyzer
func TestSSHAnalyzer(t *testing.T) {
	analyzer := NewSSHAnalyzer()
	
	// Test protocol name and ports
	assert.Equal(t, "SSH", analyzer.GetProtocolName())
	ports := analyzer.GetPorts()
	assert.Contains(t, ports, uint16(22))
	
	// Test IsProtocolTraffic
	assert.True(t, analyzer.IsProtocolTraffic([]byte("SSH-2.0-OpenSSH_8.2\r\n")))
	assert.True(t, analyzer.IsProtocolTraffic([]byte("SSH-1.99-OpenSSH_8.2\r\n")))
	assert.False(t, analyzer.IsProtocolTraffic([]byte("GET / HTTP/1.1\r\n")))
}

// Test IRC Analyzer
func TestIRCAnalyzer(t *testing.T) {
	analyzer := NewIRCAnalyzer()
	
	// Test protocol name and ports
	assert.Equal(t, "IRC", analyzer.GetProtocolName())
	ports := analyzer.GetPorts()
	assert.Contains(t, ports, uint16(6667))
	assert.Contains(t, ports, uint16(6697))
	
	// Test IsProtocolTraffic
	assert.True(t, analyzer.IsProtocolTraffic([]byte("NICK johndoe\r\n")))
	assert.True(t, analyzer.IsProtocolTraffic([]byte(":server 001 user :Welcome\r\n")))
	assert.False(t, analyzer.IsProtocolTraffic([]byte("GET / HTTP/1.1\r\n")))
}

// Test helper functions
func TestReadLine(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader("Hello\nWorld\n"))
	
	line, err := ReadLine(reader)
	assert.NoError(t, err)
	assert.Equal(t, "Hello", line)
	
	line, err = ReadLine(reader)
	assert.NoError(t, err)
	assert.Equal(t, "World", line)
}

func TestParseCommand(t *testing.T) {
	tests := []struct {
		input    string
		expCmd   string
		expArgs  []string
	}{
		{"USER john", "USER", []string{"john"}},
		{"PASS secret", "PASS", []string{"secret"}},
		{"LIST", "LIST", []string{}},
		{"", "", nil},
		{"  TRIM  spaces  ", "TRIM", []string{"spaces"}},
	}
	
	for _, tt := range tests {
		cmd, args := ParseCommand(tt.input)
		assert.Equal(t, tt.expCmd, cmd)
		assert.Equal(t, tt.expArgs, args)
	}
}

func TestGenerateEventID(t *testing.T) {
	id1 := GenerateEventID("FTP")
	id2 := GenerateEventID("FTP")
	
	assert.Contains(t, id1, "FTP_")
	assert.Contains(t, id2, "FTP_")
	assert.NotEqual(t, id1, id2) // Should be unique
}

// Mock reader stream for testing
type mockReaderStream struct {
	data   []byte
	closed bool
}

func (m *mockReaderStream) Read(p []byte) (n int, err error) {
	if m.closed || len(m.data) == 0 {
		return 0, io.EOF
	}
	n = copy(p, m.data)
	m.data = m.data[n:]
	return n, nil
}

func (m *mockReaderStream) Close() error {
	m.closed = true
	return nil
}

// Test stream analysis with mock data
func TestFTPStreamAnalysis(t *testing.T) {
	t.Skip("Skipping stream analysis test - requires complex TCP reassembly setup")
}

// Test SMTP stream analysis
func TestSMTPStreamAnalysis(t *testing.T) {
	t.Skip("Skipping stream analysis test - requires complex TCP reassembly setup")
}

// Test concurrent access to analyzers
func TestAnalyzerConcurrency(t *testing.T) {
	analyzers := []ProtocolAnalyzer{
		NewFTPAnalyzer(),
		NewSMTPAnalyzer(),
		NewIMAPAnalyzer(),
		NewPOP3Analyzer(),
		NewSSHAnalyzer(),
		NewIRCAnalyzer(),
	}
	
	// Run concurrent IsProtocolTraffic checks
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			for _, analyzer := range analyzers {
				analyzer.IsProtocolTraffic([]byte("test data"))
			}
			done <- true
		}()
	}
	
	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}

// Test protocol manager integration
func TestProtocolManagerIntegration(t *testing.T) {
	pm := NewProtocolManager(100)
	
	// Should have default analyzers registered
	analyzers := pm.GetAnalyzers()
	assert.NotEmpty(t, analyzers)
	assert.Contains(t, analyzers, "FTP")
	assert.Contains(t, analyzers, "SSH")
	assert.Contains(t, analyzers, "POP3")
	assert.Contains(t, analyzers, "IMAP")
	
	// Create a simple test packet
	// Note: Full packet creation requires complex setup
	
	// Flush connections
	pm.FlushConnections()
}

// Benchmark protocol detection
func BenchmarkIsProtocolTrafficSimple(b *testing.B) {
	analyzer := NewFTPAnalyzer()
	data := []byte("220 FTP Server Ready\r\n")
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		analyzer.IsProtocolTraffic(data)
	}
}

// Benchmark event ID generation
func BenchmarkGenerateEventID(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GenerateEventID("FTP")
	}
}