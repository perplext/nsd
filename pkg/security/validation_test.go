package security

import (
	"strings"
	"testing"
	
	"github.com/stretchr/testify/assert"
)

func TestValidator_ValidateInterfaceName(t *testing.T) {
	v := NewValidator()
	
	tests := []struct {
		name    string
		input   string
		wantErr bool
		errMsg  string
	}{
		// Valid cases
		{"Valid eth0", "eth0", false, ""},
		{"Valid wlan0", "wlan0", false, ""},
		{"Valid docker0", "docker0", false, ""},
		{"Valid ens33", "ens33", false, ""},
		{"Valid lo", "lo", false, ""},
		{"Valid with dash", "br-1234abcd", false, ""},
		{"Valid with dot", "vlan.100", false, ""},
		
		// Invalid cases
		{"Empty", "", true, "empty"},
		{"Null bytes", "eth0\x00", true, "null bytes"},
		{"Shell metachar semicolon", "eth0;ls", true, "metacharacters"},
		{"Shell metachar pipe", "eth0|cat", true, "metacharacters"},
		{"Shell metachar dollar", "eth$0", true, "metacharacters"},
		{"Shell metachar backtick", "eth`cmd`", true, "metacharacters"},
		{"Shell metachar quote", "eth'0'", true, "metacharacters"},
		{"Too long", strings.Repeat("a", 257), true, "too long"},
		{"Invalid format", "123eth", true, "invalid interface name"},
		{"Special chars", "eth@#", true, "invalid interface name"},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.ValidateInterfaceName(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidator_ValidateBPFFilter(t *testing.T) {
	v := NewValidator()
	
	tests := []struct {
		name    string
		input   string
		wantErr bool
		errMsg  string
	}{
		// Valid cases
		{"Empty filter", "", false, ""},
		{"Simple TCP", "tcp", false, ""},
		{"Port filter", "tcp port 80", false, ""},
		{"Complex filter", "tcp and (port 80 or port 443)", false, ""},
		{"Host filter", "host 192.168.1.1", false, ""},
		{"Net filter", "net 10.0.0.0/8", false, ""},
		
		// Invalid cases
		{"Null bytes", "tcp\x00", true, "null bytes"},
		{"Unmatched paren", "tcp and (port 80", true, "unmatched"},
		{"Extra paren", "tcp and port 80)", true, "unmatched"},
		{"Dangerous keyword exec", "tcp and exec", true, "dangerous keyword"},
		{"Dangerous keyword system", "system('ls')", true, "dangerous keyword"},
		{"Too long", strings.Repeat("tcp or ", 200), true, "too long"},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.ValidateBPFFilter(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidator_ValidateFilePath(t *testing.T) {
	v := NewValidator()
	
	tests := []struct {
		name    string
		input   string
		wantErr bool
		errMsg  string
	}{
		// Valid cases
		{"Simple file", "output.json", false, ""},
		{"With directory", "logs/capture.pcap", false, ""},
		{"Absolute path", "/tmp/nsd.log", false, ""},
		
		// Invalid cases
		{"Empty", "", true, "empty"},
		{"Null bytes", "file\x00.txt", true, "null bytes"},
		{"Directory traversal", "../../../etc/passwd", true, "directory traversal"},
		{"Hidden traversal", "logs/../../../etc/passwd", true, "directory traversal"},
		{"System path etc", "/etc/passwd", true, "system path"},
		{"System path proc", "/proc/self/environ", true, "system path"},
		{"System path sys", "/sys/kernel/config", true, "system path"},
		{"Too long", strings.Repeat("a", 4097), true, "too long"},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.ValidateFilePath(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidator_ValidateThemeName(t *testing.T) {
	v := NewValidator()
	
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		// Valid cases
		{"Simple", "Dark", false},
		{"With number", "Dark2", false},
		{"With dash", "Dark-Mode", false},
		{"With underscore", "Dark_Mode", false},
		{"With plus", "Dark+", false},
		
		// Invalid cases
		{"Empty", "", true},
		{"Special chars", "Dark@Mode", true},
		{"Spaces", "Dark Mode", true},
		{"Path chars", "Dark/Mode", true},
		{"Too long", strings.Repeat("a", 65), true},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.ValidateThemeName(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidator_ValidatePort(t *testing.T) {
	v := NewValidator()
	
	tests := []struct {
		port    int
		wantErr bool
	}{
		{80, false},
		{443, false},
		{8080, false},
		{65535, false},
		{0, true},
		{-1, true},
		{65536, true},
		{70000, true},
	}
	
	for _, tt := range tests {
		t.Run(string(rune(tt.port)), func(t *testing.T) {
			err := v.ValidatePort(tt.port)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidator_ValidateIPAddress(t *testing.T) {
	v := NewValidator()
	
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		// Valid IPv4
		{"IPv4 localhost", "127.0.0.1", false},
		{"IPv4 private", "192.168.1.1", false},
		{"IPv4 public", "8.8.8.8", false},
		
		// Valid IPv6
		{"IPv6 localhost", "::1", false},
		{"IPv6 full", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", false},
		{"IPv6 compressed", "2001:db8::8a2e:370:7334", false},
		
		// Invalid
		{"Empty", "", true},
		{"Invalid format", "192.168.1", true},
		{"Out of range", "256.1.1.1", true},
		{"With port", "192.168.1.1:80", true},
		{"Hostname", "example.com", true},
		{"Garbage", "not-an-ip", true},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.ValidateIPAddress(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidator_ValidateCIDR(t *testing.T) {
	v := NewValidator()
	
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		// Valid
		{"IPv4 /24", "192.168.1.0/24", false},
		{"IPv4 /32", "10.0.0.1/32", false},
		{"IPv4 /8", "10.0.0.0/8", false},
		{"IPv6 /64", "2001:db8::/64", false},
		{"IPv6 /128", "::1/128", false},
		
		// Invalid
		{"Empty", "", true},
		{"No prefix", "192.168.1.0", true},
		{"Invalid prefix", "192.168.1.0/33", true},
		{"Invalid IP", "256.1.1.0/24", true},
		{"Negative prefix", "10.0.0.0/-1", true},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.ValidateCIDR(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSanitizeString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		maxLen   int
		expected string
	}{
		{"Normal string", "hello world", 20, "hello world"},
		{"With null bytes", "hello\x00world", 20, "helloworld"},
		{"With newlines", "hello\nworld", 20, "hello\nworld"},
		{"Non-printable", "hello\x01\x02world", 20, "helloworld"},
		{"Too long", "hello world", 5, "hello"},
		{"Unicode", "hello 世界", 20, "hello 世界"},
		{"Mixed bad chars", "test\x00\x01\n\r\x02end", 20, "test\n\rend"},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeString(tt.input, tt.maxLen)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestInputSanitizer(t *testing.T) {
	is := NewInputSanitizer()
	
	t.Run("SanitizeInterfaceName", func(t *testing.T) {
		// Valid
		result, err := is.SanitizeInterfaceName("  eth0  ")
		assert.NoError(t, err)
		assert.Equal(t, "eth0", result)
		
		// Invalid
		_, err = is.SanitizeInterfaceName("eth0;ls")
		assert.Error(t, err)
	})
	
	t.Run("SanitizeBPFFilter", func(t *testing.T) {
		// Valid with normalization
		result, err := is.SanitizeBPFFilter("  tcp   and   port   80  ")
		assert.NoError(t, err)
		assert.Equal(t, "tcp and port 80", result)
		
		// Invalid
		_, err = is.SanitizeBPFFilter("tcp and system('ls')")
		assert.Error(t, err)
	})
	
	t.Run("SanitizeFilePath", func(t *testing.T) {
		// Valid with cleaning
		result, err := is.SanitizeFilePath("  ./logs//capture.pcap  ")
		assert.NoError(t, err)
		assert.Equal(t, "logs/capture.pcap", result)
		
		// Invalid
		_, err = is.SanitizeFilePath("../../../etc/passwd")
		assert.Error(t, err)
	})
}

func TestContainsShellMetachars(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"clean", false},
		{"eth0", false},
		{"br-1234", false},
		{"eth0;ls", true},
		{"eth0|cat", true},
		{"eth$0", true},
		{"eth`cmd`", true},
		{"eth'0'", true},
		{"eth\"0\"", true},
		{"eth0 && ls", true},
		{"eth0\nls", true},
	}
	
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := containsShellMetachars(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}