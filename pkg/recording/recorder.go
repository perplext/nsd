package recording

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
	"github.com/perplext/nsd/pkg/security"
)

type RecordingMode int

const (
	ModePackets RecordingMode = iota
	ModeStats
	ModeBoth
)

type PacketRecord struct {
	Timestamp time.Time         `json:"timestamp"`
	Length    int               `json:"length"`
	Protocol  string            `json:"protocol"`
	Source    string            `json:"source"`
	Dest      string            `json:"destination"`
	Data      []byte            `json:"data,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

type StatsRecord struct {
	Timestamp    time.Time          `json:"timestamp"`
	TotalPackets int64              `json:"total_packets"`
	TotalBytes   int64              `json:"total_bytes"`
	PacketRate   float64            `json:"packet_rate"`
	ByteRate     float64            `json:"byte_rate"`
	Protocols    map[string]int64   `json:"protocols"`
	Interfaces   map[string]int64   `json:"interfaces"`
}

type Recording struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	StartTime   time.Time     `json:"start_time"`
	EndTime     *time.Time    `json:"end_time,omitempty"`
	Duration    time.Duration `json:"duration"`
	Mode        RecordingMode `json:"mode"`
	FilePath    string        `json:"file_path"`
	Size        int64         `json:"size"`
	PacketCount int64         `json:"packet_count"`
	Compressed  bool          `json:"compressed"`
}

type Recorder struct {
	recording     *Recording
	mode          RecordingMode
	outputDir     string
	maxFileSize   int64
	compress      bool
	currentWriter io.WriteCloser
	pcapWriter    *pcapgo.Writer
	jsonEncoder   *json.Encoder
	mutex         sync.RWMutex
	isRecording   bool
	packetCount   int64
}

type Player struct {
	recording     *Recording
	currentReader io.ReadCloser
	pcapReader    *pcapgo.Reader
	jsonDecoder   *json.Decoder
	isPlaying     bool
	playbackRate  float64
	startTime     time.Time
	pauseTime     *time.Time
	mutex         sync.RWMutex
	onPacket      func(*PacketRecord)
	onStats       func(*StatsRecord)
}

func NewRecorder(outputDir string, maxFileSize int64, compress bool) *Recorder {
	return &Recorder{
		outputDir:   outputDir,
		maxFileSize: maxFileSize,
		compress:    compress,
		mode:        ModeBoth,
	}
}

func (r *Recorder) StartRecording(name, description string, mode RecordingMode) (*Recording, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if r.isRecording {
		return nil, fmt.Errorf("recording already in progress")
	}

	// Create recording metadata
	recording := &Recording{
		ID:          fmt.Sprintf("rec_%d", time.Now().Unix()),
		Name:        name,
		Description: description,
		StartTime:   time.Now(),
		Mode:        mode,
		Compressed:  r.compress,
	}

	// Create output file
	ext := ".json"
	if mode == ModePackets {
		ext = ".pcap"
	}
	if r.compress {
		ext += ".gz"
	}

	filename := fmt.Sprintf("%s_%s%s", recording.ID, recording.StartTime.Format("20060102_150405"), ext)
	recording.FilePath = filepath.Join(r.outputDir, filename)

	// Ensure output directory exists with secure permissions
	if err := os.MkdirAll(r.outputDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %v", err)
	}

	// Validate the constructed file path
	if err := validateRecordingPath(recording.FilePath); err != nil {
		return nil, fmt.Errorf("invalid recording file path: %v", err)
	}
	
	// Open output file
	file, err := os.Create(recording.FilePath) // #nosec G304 - path validated above
	if err != nil {
		return nil, fmt.Errorf("failed to create recording file: %v", err)
	}

	if r.compress {
		r.currentWriter = gzip.NewWriter(file)
	} else {
		r.currentWriter = file
	}

	// Initialize appropriate writer
	switch mode {
	case ModePackets:
		r.pcapWriter = pcapgo.NewWriter(r.currentWriter)
		if err := r.pcapWriter.WriteFileHeader(65536, 1); err != nil {
			if closeErr := r.currentWriter.Close(); closeErr != nil {
				log.Printf("Failed to close writer after error: %v", closeErr)
			}
			return nil, fmt.Errorf("failed to write PCAP header: %v", err)
		}
	case ModeStats, ModeBoth:
		r.jsonEncoder = json.NewEncoder(r.currentWriter)
	}

	r.recording = recording
	r.mode = mode
	r.isRecording = true
	r.packetCount = 0

	return recording, nil
}

func (r *Recorder) StopRecording() error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if !r.isRecording {
		return fmt.Errorf("no recording in progress")
	}

	// Close writers
	if r.currentWriter != nil {
		if err := r.currentWriter.Close(); err != nil {
			log.Printf("Failed to close writer: %v", err)
		}
	}

	// Update recording metadata
	now := time.Now()
	r.recording.EndTime = &now
	r.recording.Duration = now.Sub(r.recording.StartTime)
	r.recording.PacketCount = r.packetCount

	// Get file size
	if stat, err := os.Stat(r.recording.FilePath); err == nil {
		r.recording.Size = stat.Size()
	}

	// Save metadata
	metadataPath := r.recording.FilePath + ".meta"
	if metadataFile, err := security.SafeCreateFile(metadataPath, r.outputDir); err == nil {
		if err := json.NewEncoder(metadataFile).Encode(r.recording); err != nil {
			log.Printf("Failed to encode metadata: %v", err)
		}
		if err := metadataFile.Close(); err != nil {
			log.Printf("Failed to close metadata file: %v", err)
		}
	}

	r.isRecording = false
	r.currentWriter = nil
	r.pcapWriter = nil
	r.jsonEncoder = nil

	return nil
}

func (r *Recorder) RecordPacket(packet gopacket.Packet) error {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	if !r.isRecording || (r.mode != ModePackets && r.mode != ModeBoth) {
		return nil
	}

	if r.pcapWriter != nil {
		err := r.pcapWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		if err != nil {
			return fmt.Errorf("failed to write packet: %v", err)
		}
		r.packetCount++
	}

	return nil
}

func (r *Recorder) RecordStats(stats *StatsRecord) error {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	if !r.isRecording || (r.mode != ModeStats && r.mode != ModeBoth) {
		return nil
	}

	if r.jsonEncoder != nil {
		return r.jsonEncoder.Encode(stats)
	}

	return nil
}

func (r *Recorder) IsRecording() bool {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	return r.isRecording
}

func (r *Recorder) GetCurrentRecording() *Recording {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	if r.recording != nil {
		copy := *r.recording
		return &copy
	}
	return nil
}

func NewPlayer() *Player {
	return &Player{
		playbackRate: 1.0,
	}
}

func (p *Player) LoadRecording(recordingPath string) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	// Validate path to prevent directory traversal
	if err := validateRecordingPath(recordingPath); err != nil {
		return err
	}
	
	// Load metadata
	metadataPath := recordingPath + ".meta"
	metadataFile, err := security.SafeOpenFile(metadataPath, filepath.Dir(recordingPath))
	if err != nil {
		return fmt.Errorf("failed to open metadata file: %v", err)
	}
	defer func() {
		if err := metadataFile.Close(); err != nil {
			log.Printf("Failed to close metadata file: %v", err)
		}
	}()

	var recording Recording
	if err := json.NewDecoder(metadataFile).Decode(&recording); err != nil {
		return fmt.Errorf("failed to decode metadata: %v", err)
	}

	p.recording = &recording
	return nil
}

func (p *Player) Play() error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if p.recording == nil {
		return fmt.Errorf("no recording loaded")
	}

	if p.isPlaying {
		return fmt.Errorf("playback already in progress")
	}

	// Validate and open recording file
	if err := validateRecordingPath(p.recording.FilePath); err != nil {
		return err
	}
	
	file, err := os.Open(p.recording.FilePath)
	if err != nil {
		return fmt.Errorf("failed to open recording file: %v", err)
	}

	var reader io.ReadCloser = file
	if p.recording.Compressed {
		gzReader, err := gzip.NewReader(file)
		if err != nil {
			if closeErr := file.Close(); closeErr != nil {
				log.Printf("Failed to close file after error: %v", closeErr)
			}
			return fmt.Errorf("failed to create gzip reader: %v", err)
		}
		reader = gzReader
	}

	p.currentReader = reader
	p.isPlaying = true
	p.startTime = time.Now()

	// Start playback in goroutine
	go p.playbackLoop()

	return nil
}

func (p *Player) playbackLoop() {
	defer func() {
		p.mutex.Lock()
		if p.currentReader != nil {
			p.currentReader.Close()
		}
		p.isPlaying = false
		p.mutex.Unlock()
	}()

	switch p.recording.Mode {
	case ModePackets:
		p.playPackets()
	case ModeStats:
		p.playStats()
	case ModeBoth:
		p.playStats() // For now, just play stats
	}
}

func (p *Player) playPackets() {
	pcapReader, err := pcapgo.NewReader(p.currentReader)
	if err != nil {
		return
	}

	var lastTimestamp time.Time

	for {
		data, ci, err := pcapReader.ReadPacketData()
		if err != nil {
			break
		}

		// Calculate timing for realistic playback
		if !lastTimestamp.IsZero() {
			realInterval := ci.Timestamp.Sub(lastTimestamp)
			playbackInterval := time.Duration(float64(realInterval) / p.playbackRate)
			
			time.Sleep(playbackInterval)
		}

		// Create packet record
		record := &PacketRecord{
			Timestamp: ci.Timestamp,
			Length:    ci.Length,
			Data:      data,
		}

		if p.onPacket != nil {
			p.onPacket(record)
		}

		lastTimestamp = ci.Timestamp

		// Check if we should pause or stop
		p.mutex.RLock()
		if !p.isPlaying {
			p.mutex.RUnlock()
			break
		}
		p.mutex.RUnlock()
	}
}

func (p *Player) playStats() {
	decoder := json.NewDecoder(p.currentReader)
	
	var lastTimestamp time.Time
	
	for {
		var record StatsRecord
		if err := decoder.Decode(&record); err != nil {
			break
		}

		// Calculate timing for realistic playback
		if !lastTimestamp.IsZero() {
			realInterval := record.Timestamp.Sub(lastTimestamp)
			playbackInterval := time.Duration(float64(realInterval) / p.playbackRate)
			
			time.Sleep(playbackInterval)
		}

		if p.onStats != nil {
			p.onStats(&record)
		}

		lastTimestamp = record.Timestamp

		// Check if we should pause or stop
		p.mutex.RLock()
		if !p.isPlaying {
			p.mutex.RUnlock()
			break
		}
		p.mutex.RUnlock()
	}
}

func (p *Player) Stop() {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	
	p.isPlaying = false
	if p.currentReader != nil {
		p.currentReader.Close()
		p.currentReader = nil
	}
}

func (p *Player) SetPlaybackRate(rate float64) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.playbackRate = rate
}

func (p *Player) SetPacketHandler(handler func(*PacketRecord)) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.onPacket = handler
}

func (p *Player) SetStatsHandler(handler func(*StatsRecord)) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.onStats = handler
}

func (p *Player) IsPlaying() bool {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	return p.isPlaying
}

func ListRecordings(recordingDir string) ([]Recording, error) {
	var recordings []Recording

	files, err := filepath.Glob(filepath.Join(recordingDir, "*.meta"))
	if err != nil {
		return nil, err
	}

	for _, metaFile := range files {
		file, err := security.SafeOpenFile(metaFile, recordingDir)
		if err != nil {
			continue
		}

		var recording Recording
		if err := json.NewDecoder(file).Decode(&recording); err != nil {
			file.Close()
			continue
		}
		file.Close()

		recordings = append(recordings, recording)
	}

	return recordings, nil
}

// validateRecordingPath validates a recording file path to prevent directory traversal
func validateRecordingPath(path string) error {
	// Clean the path to remove any ../ or ./ elements
	cleanPath := filepath.Clean(path)
	
	// Get absolute path
	absPath, err := filepath.Abs(cleanPath)
	if err != nil {
		return fmt.Errorf("invalid recording path: %v", err)
	}
	
	// Check if path contains suspicious patterns
	if strings.Contains(path, "..") {
		return fmt.Errorf("recording path contains directory traversal pattern")
	}
	
	// Ensure the file has valid extension
	ext := strings.ToLower(filepath.Ext(absPath))
	validExts := map[string]bool{
		".json": true,
		".pcap": true,
		".gz": true,
		".meta": true,
	}
	
	// Check for compound extensions like .json.gz
	if strings.HasSuffix(absPath, ".json.gz") || strings.HasSuffix(absPath, ".pcap.gz") {
		return nil
	}
	
	if !validExts[ext] {
		return fmt.Errorf("invalid recording file extension: %s", ext)
	}
	
	return nil
}