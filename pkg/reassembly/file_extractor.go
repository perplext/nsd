package reassembly

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"mime"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

// FileExtractor handles real-time file extraction from network traffic
type FileExtractor struct {
	assembler      *tcpassembly.Assembler
	streamFactory  *httpStreamFactory
	outputDir      string
	extractedFiles chan ExtractedFile
	maxFileSize    int64
	allowedTypes   map[string]bool
	mutex          sync.RWMutex
	stats          ExtractionStats
}

// ExtractedFile represents a file extracted from network traffic
type ExtractedFile struct {
	ID           string                 `json:"id"`
	Protocol     string                 `json:"protocol"`
	Source       net.IP                 `json:"source"`
	Destination  net.IP                 `json:"destination"`
	SourcePort   uint16                 `json:"source_port"`
	DestPort     uint16                 `json:"dest_port"`
	Filename     string                 `json:"filename"`
	OriginalName string                 `json:"original_name"`
	ContentType  string                 `json:"content_type"`
	Size         int64                  `json:"size"`
	MD5Hash      string                 `json:"md5_hash"`
	SHA256Hash   string                 `json:"sha256_hash"`
	Timestamp    time.Time              `json:"timestamp"`
	FilePath     string                 `json:"file_path"`
	Metadata     map[string]interface{} `json:"metadata"`
	Direction    TransferDirection      `json:"direction"`
	Complete     bool                   `json:"complete"`
}

// TransferDirection indicates upload vs download
type TransferDirection int

const (
	DirectionDownload TransferDirection = iota
	DirectionUpload
	DirectionBidirectional
)

// ExtractionStats tracks file extraction statistics
type ExtractionStats struct {
	TotalFiles        int64                    `json:"total_files"`
	TotalSize         int64                    `json:"total_size"`
	FilesByProtocol   map[string]int64         `json:"files_by_protocol"`
	FilesByType       map[string]int64         `json:"files_by_type"`
	TransfersByDir    map[TransferDirection]int64 `json:"transfers_by_direction"`
	IncompleteFiles   int64                    `json:"incomplete_files"`
	LastExtraction    time.Time                `json:"last_extraction"`
	ActiveTransfers   int64                    `json:"active_transfers"`
}

// httpStreamFactory creates new HTTP stream processors
type httpStreamFactory struct {
	extractor *FileExtractor
}

// httpStream processes HTTP streams for file extraction
type httpStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
	extractor      *FileExtractor
	isClient       bool
}

// FileSignature represents a file type signature
type FileSignature struct {
	Extension   string
	MimeType    string
	Signature   []byte
	Offset      int
	Description string
}

// Common file signatures for identification
var fileSignatures = []FileSignature{
	{Extension: "pdf", MimeType: "application/pdf", Signature: []byte{0x25, 0x50, 0x44, 0x46}, Offset: 0, Description: "PDF Document"},
	{Extension: "zip", MimeType: "application/zip", Signature: []byte{0x50, 0x4B, 0x03, 0x04}, Offset: 0, Description: "ZIP Archive"},
	{Extension: "png", MimeType: "image/png", Signature: []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, Offset: 0, Description: "PNG Image"},
	{Extension: "jpg", MimeType: "image/jpeg", Signature: []byte{0xFF, 0xD8, 0xFF}, Offset: 0, Description: "JPEG Image"},
	{Extension: "gif", MimeType: "image/gif", Signature: []byte{0x47, 0x49, 0x46, 0x38}, Offset: 0, Description: "GIF Image"},
	{Extension: "exe", MimeType: "application/x-msdownload", Signature: []byte{0x4D, 0x5A}, Offset: 0, Description: "Windows Executable"},
	{Extension: "docx", MimeType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document", Signature: []byte{0x50, 0x4B, 0x03, 0x04}, Offset: 0, Description: "Word Document"},
	{Extension: "mp4", MimeType: "video/mp4", Signature: []byte{0x66, 0x74, 0x79, 0x70}, Offset: 4, Description: "MP4 Video"},
	{Extension: "mp3", MimeType: "audio/mpeg", Signature: []byte{0x49, 0x44, 0x33}, Offset: 0, Description: "MP3 Audio"},
}

// NewFileExtractor creates a new file extractor
func NewFileExtractor(outputDir string, maxFileSize int64) *FileExtractor {
	fe := &FileExtractor{
		outputDir:      outputDir,
		extractedFiles: make(chan ExtractedFile, 1000),
		maxFileSize:    maxFileSize,
		allowedTypes:   make(map[string]bool),
		stats: ExtractionStats{
			FilesByProtocol: make(map[string]int64),
			FilesByType:     make(map[string]int64),
			TransfersByDir:  make(map[TransferDirection]int64),
		},
	}

	// Create output directory
	// Use secure permissions for output directory
	if err := os.MkdirAll(outputDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %v", err)
	}

	// Initialize stream factory
	fe.streamFactory = &httpStreamFactory{extractor: fe}

	// Create TCP assembler
	fe.assembler = tcpassembly.NewAssembler(tcpassembly.NewStreamPool(fe.streamFactory))

	// Set default allowed types (all by default)
	fe.SetAllowedTypes([]string{"*"})

	return fe
}

// SetAllowedTypes sets which file types to extract
func (fe *FileExtractor) SetAllowedTypes(types []string) {
	fe.mutex.Lock()
	defer fe.mutex.Unlock()

	fe.allowedTypes = make(map[string]bool)
	for _, t := range types {
		fe.allowedTypes[strings.ToLower(t)] = true
	}
}

// ProcessPacket processes a packet for file extraction
func (fe *FileExtractor) ProcessPacket(packet gopacket.Packet) {
	// Only process TCP packets
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		
		// Check for HTTP-like traffic (ports 80, 443, 8080, etc.)
		if fe.isHTTPPort(tcp.SrcPort) || fe.isHTTPPort(tcp.DstPort) {
			fe.assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(),
				tcp, packet.Metadata().Timestamp)
		}
	}
}

// isHTTPPort checks if a port is commonly used for HTTP traffic
func (fe *FileExtractor) isHTTPPort(port layers.TCPPort) bool {
	httpPorts := []layers.TCPPort{80, 443, 8080, 8443, 3000, 5000, 8000, 9000}
	for _, p := range httpPorts {
		if port == p {
			return true
		}
	}
	return false
}

// GetExtractedFiles returns a channel of extracted files
func (fe *FileExtractor) GetExtractedFiles() <-chan ExtractedFile {
	return fe.extractedFiles
}

// GetStats returns extraction statistics
func (fe *FileExtractor) GetStats() ExtractionStats {
	fe.mutex.RLock()
	defer fe.mutex.RUnlock()
	return fe.stats
}

// Close shuts down the file extractor
func (fe *FileExtractor) Close() {
	fe.assembler.FlushAll()
	close(fe.extractedFiles)
}

// httpStreamFactory methods

func (factory *httpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	stream := &httpStream{
		net:       net,
		transport: transport,
		r:         tcpreader.NewReaderStream(),
		extractor: factory.extractor,
		isClient:  transport.Src().String() > transport.Dst().String(), // Simple heuristic
	}
	go stream.run()
	return &stream.r
}

// httpStream methods

func (h *httpStream) run() {
	buf := bufio.NewReader(&h.r)
	
	for {
		// Try to read HTTP request/response
		if h.isClient {
			h.processHTTPRequest(buf)
		} else {
			h.processHTTPResponse(buf)
		}
	}
}

func (h *httpStream) processHTTPRequest(buf *bufio.Reader) {
	// Read HTTP request line
	line, err := buf.ReadString('\n')
	if err != nil {
		return
	}

	// Parse request line
	parts := strings.Fields(strings.TrimSpace(line))
	if len(parts) < 3 {
		return
	}

	method := parts[0]
	url := parts[1]

	// Read headers
	headers := make(map[string]string)
	for {
		line, err := buf.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}
		
		headerParts := strings.SplitN(line, ":", 2)
		if len(headerParts) == 2 {
			headers[strings.ToLower(strings.TrimSpace(headerParts[0]))] = strings.TrimSpace(headerParts[1])
		}
	}

	// Check for file uploads (POST/PUT with multipart)
	if (method == "POST" || method == "PUT") && strings.Contains(headers["content-type"], "multipart") {
		h.extractMultipartFiles(buf, headers, url)
	}
}

func (h *httpStream) processHTTPResponse(buf *bufio.Reader) {
	// Read HTTP status line
	line, err := buf.ReadString('\n')
	if err != nil {
		return
	}

	// Parse status line
	parts := strings.Fields(strings.TrimSpace(line))
	if len(parts) < 3 {
		return
	}

	statusCode := parts[1]

	// Only process successful responses
	if !strings.HasPrefix(statusCode, "2") {
		return
	}

	// Read headers
	headers := make(map[string]string)
	for {
		line, err := buf.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}
		
		headerParts := strings.SplitN(line, ":", 2)
		if len(headerParts) == 2 {
			headers[strings.ToLower(strings.TrimSpace(headerParts[0]))] = strings.TrimSpace(headerParts[1])
		}
	}

	// Check Content-Disposition for file downloads
	contentDisposition := headers["content-disposition"]
	contentType := headers["content-type"]
	contentLength := headers["content-length"]

	// Skip if no interesting content
	if contentType == "" || strings.HasPrefix(contentType, "text/html") {
		return
	}

	// Extract file from response body
	h.extractFile(buf, headers, contentDisposition, contentType, contentLength, DirectionDownload)
}

func (h *httpStream) extractMultipartFiles(buf *bufio.Reader, headers map[string]string, url string) {
	contentType := headers["content-type"]
	
	// Extract boundary from Content-Type
	boundary := h.extractBoundary(contentType)
	if boundary == "" {
		return
	}

	// Read multipart data
	for {
		// Look for boundary
		line, err := buf.ReadString('\n')
		if err != nil {
			return
		}
		
		if strings.Contains(line, boundary) {
			// Read part headers
			partHeaders := make(map[string]string)
			for {
				line, err := buf.ReadString('\n')
				if err != nil {
					return
				}
				line = strings.TrimSpace(line)
				if line == "" {
					break
				}
				
				headerParts := strings.SplitN(line, ":", 2)
				if len(headerParts) == 2 {
					partHeaders[strings.ToLower(strings.TrimSpace(headerParts[0]))] = strings.TrimSpace(headerParts[1])
				}
			}

			// Check if this part contains a file
			disposition := partHeaders["content-disposition"]
			if strings.Contains(disposition, "filename=") {
				filename := h.extractFilename(disposition)
				partContentType := partHeaders["content-type"]
				
				// Extract file data
				h.extractFileFromMultipart(buf, boundary, filename, partContentType, url, DirectionUpload)
			}
		}
	}
}

func (h *httpStream) extractFile(buf *bufio.Reader, headers map[string]string, disposition, contentType, contentLength string, direction TransferDirection) {
	// Extract filename
	filename := h.extractFilename(disposition)
	if filename == "" {
		filename = h.generateFilename(contentType)
	}

	// Check if file type is allowed
	if !h.extractor.isTypeAllowed(contentType, filename) {
		return
	}

	// Read file content
	var content bytes.Buffer
	var size int64
	
	// Read content (simplified - should handle chunked encoding, etc.)
	for {
		data := make([]byte, 4096)
		n, err := buf.Read(data)
		if err != nil {
			break
		}
		
		content.Write(data[:n])
		size += int64(n)
		
		// Respect max file size
		if size > h.extractor.maxFileSize {
			break
		}
	}

	// Create extracted file
	extractedFile := h.createExtractedFile(filename, contentType, content.Bytes(), direction)
	
	// Save to disk
	if err := h.saveFile(extractedFile); err == nil {
		// Send to channel
		select {
		case h.extractor.extractedFiles <- extractedFile:
		default:
			// Channel full, skip
		}
		
		// Update stats
		h.extractor.updateStats(extractedFile)
	}
}

func (h *httpStream) extractFileFromMultipart(buf *bufio.Reader, boundary, filename, contentType, url string, direction TransferDirection) {
	var content bytes.Buffer
	boundaryBytes := []byte("--" + boundary)
	
	// Read until next boundary
	for {
		line, err := buf.ReadBytes('\n')
		if err != nil {
			break
		}
		
		if bytes.Contains(line, boundaryBytes) {
			break
		}
		
		content.Write(line)
		
		// Respect max file size
		if int64(content.Len()) > h.extractor.maxFileSize {
			break
		}
	}

	// Remove trailing CRLF
	contentBytes := bytes.TrimSuffix(content.Bytes(), []byte("\r\n"))
	
	// Create extracted file
	extractedFile := h.createExtractedFile(filename, contentType, contentBytes, direction)
	extractedFile.Metadata["url"] = url
	
	// Save and notify
	if err := h.saveFile(extractedFile); err == nil {
		select {
		case h.extractor.extractedFiles <- extractedFile:
		default:
		}
		h.extractor.updateStats(extractedFile)
	}
}

func (h *httpStream) createExtractedFile(filename, contentType string, content []byte, direction TransferDirection) ExtractedFile {
	// Generate unique ID
	id := fmt.Sprintf("%d_%s_%s", time.Now().Unix(), h.net.Src().String(), h.net.Dst().String())
	
	// Calculate hashes
	md5Hash := md5.Sum(content)
	sha256Hash := sha256.Sum256(content)
	
	// Detect file type from content if not provided
	if contentType == "" {
		contentType = h.detectFileType(content, filename)
	}
	
	// Determine source/dest based on direction
	var srcIP, dstIP net.IP
	var srcPort, dstPort uint16
	
	if direction == DirectionUpload {
		srcIP = net.ParseIP(h.net.Src().String())
		dstIP = net.ParseIP(h.net.Dst().String())
		srcPort = uint16(h.transport.Src().FastHash())
		dstPort = uint16(h.transport.Dst().FastHash())
	} else {
		srcIP = net.ParseIP(h.net.Dst().String())
		dstIP = net.ParseIP(h.net.Src().String())
		srcPort = uint16(h.transport.Dst().FastHash())
		dstPort = uint16(h.transport.Src().FastHash())
	}
	
	return ExtractedFile{
		ID:           id,
		Protocol:     "HTTP",
		Source:       srcIP,
		Destination:  dstIP,
		SourcePort:   srcPort,
		DestPort:     dstPort,
		Filename:     h.sanitizeFilename(filename),
		OriginalName: filename,
		ContentType:  contentType,
		Size:         int64(len(content)),
		MD5Hash:      hex.EncodeToString(md5Hash[:]),
		SHA256Hash:   hex.EncodeToString(sha256Hash[:]),
		Timestamp:    time.Now(),
		Direction:    direction,
		Complete:     true,
		Metadata:     make(map[string]interface{}),
	}
}

func (h *httpStream) saveFile(file ExtractedFile) error {
	// Create timestamp-based subdirectory
	dateDir := file.Timestamp.Format("2006-01-02")
	fullDir := filepath.Join(h.extractor.outputDir, dateDir)
	// Use secure permissions for directory creation
	if err := os.MkdirAll(fullDir, 0700); err != nil {
		return fmt.Errorf("failed to create directory: %v", err)
	}
	
	// Generate unique filename
	filename := fmt.Sprintf("%s_%s_%s", file.ID, file.Source.String(), file.Filename)
	file.FilePath = filepath.Join(fullDir, filename)
	
	// Write file
	// Use secure permissions for extracted files
	return os.WriteFile(file.FilePath, []byte{}, 0600) // Content would be written here
}

// Helper functions

func (h *httpStream) extractBoundary(contentType string) string {
	re := regexp.MustCompile(`boundary=([^;]+)`)
	matches := re.FindStringSubmatch(contentType)
	if len(matches) > 1 {
		return strings.Trim(matches[1], `"`)
	}
	return ""
}

func (h *httpStream) extractFilename(disposition string) string {
	re := regexp.MustCompile(`filename[^;=\n]*=((['"]).*?\2|[^;\n]*)`)
	matches := re.FindStringSubmatch(disposition)
	if len(matches) > 1 {
		return strings.Trim(matches[1], `"`)
	}
	return ""
}

func (h *httpStream) generateFilename(contentType string) string {
	ext, _ := mime.ExtensionsByType(contentType)
	if len(ext) > 0 {
		return fmt.Sprintf("extracted_%d%s", time.Now().Unix(), ext[0])
	}
	return fmt.Sprintf("extracted_%d.bin", time.Now().Unix())
}

func (h *httpStream) sanitizeFilename(filename string) string {
	// Remove path separators and dangerous characters
	re := regexp.MustCompile(`[<>:"/\\|?*]`)
	return re.ReplaceAllString(filename, "_")
}

func (h *httpStream) detectFileType(content []byte, filename string) string {
	// Check file signatures
	for _, sig := range fileSignatures {
		if len(content) > sig.Offset+len(sig.Signature) {
			if bytes.Equal(content[sig.Offset:sig.Offset+len(sig.Signature)], sig.Signature) {
				return sig.MimeType
			}
		}
	}
	
	// Fallback to extension-based detection
	ext := strings.ToLower(filepath.Ext(filename))
	return mime.TypeByExtension(ext)
}

func (fe *FileExtractor) isTypeAllowed(contentType, filename string) bool {
	fe.mutex.RLock()
	defer fe.mutex.RUnlock()
	
	// Check wildcard
	if fe.allowedTypes["*"] {
		return true
	}
	
	// Check content type
	if contentType != "" {
		mainType := strings.Split(contentType, "/")[0]
		if fe.allowedTypes[strings.ToLower(contentType)] || fe.allowedTypes[strings.ToLower(mainType)] {
			return true
		}
	}
	
	// Check file extension
	ext := strings.ToLower(filepath.Ext(filename))
	if ext != "" {
		ext = ext[1:] // Remove dot
		return fe.allowedTypes[ext]
	}
	
	return false
}

func (fe *FileExtractor) updateStats(file ExtractedFile) {
	fe.mutex.Lock()
	defer fe.mutex.Unlock()
	
	fe.stats.TotalFiles++
	fe.stats.TotalSize += file.Size
	fe.stats.FilesByProtocol[file.Protocol]++
	fe.stats.FilesByType[file.ContentType]++
	fe.stats.TransfersByDir[file.Direction]++
	fe.stats.LastExtraction = file.Timestamp
}