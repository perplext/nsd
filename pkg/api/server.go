package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/perplext/nsd/pkg/netcap"
)

type Server struct {
	monitor  *netcap.NetworkMonitor
	port     int
	upgrader websocket.Upgrader
}

type APIResponse struct {
	Status string      `json:"status"`
	Data   interface{} `json:"data,omitempty"`
	Error  string      `json:"error,omitempty"`
}

type StatsResponse struct {
	Timestamp    time.Time          `json:"timestamp"`
	TotalPackets int64              `json:"total_packets"`
	TotalBytes   int64              `json:"total_bytes"`
	PacketRate   float64            `json:"packet_rate"`
	ByteRate     float64            `json:"byte_rate"`
	Protocols    map[string]int64   `json:"protocols"`
	Connections  []ConnectionInfo   `json:"connections"`
	Interfaces   []InterfaceInfo    `json:"interfaces"`
}

type ConnectionInfo struct {
	Source      string    `json:"source"`
	Destination string    `json:"destination"`
	Protocol    string    `json:"protocol"`
	Service     string    `json:"service"`
	Bytes       int64     `json:"bytes"`
	Packets     int64     `json:"packets"`
	LastSeen    time.Time `json:"last_seen"`
}

type InterfaceInfo struct {
	Name        string  `json:"name"`
	PacketCount int64   `json:"packet_count"`
	ByteCount   int64   `json:"byte_count"`
	PacketRate  float64 `json:"packet_rate"`
	ByteRate    float64 `json:"byte_rate"`
}

func NewServer(monitor *netcap.NetworkMonitor, port int) *Server {
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true // Allow connections from any origin
		},
	}

	return &Server{
		monitor:  monitor,
		port:     port,
		upgrader: upgrader,
	}
}

func (s *Server) Start() error {
	r := mux.NewRouter()

	// API routes
	api := r.PathPrefix("/api/v1").Subrouter()
	api.HandleFunc("/stats", s.handleStats).Methods("GET")
	api.HandleFunc("/connections", s.handleConnections).Methods("GET")
	api.HandleFunc("/interfaces", s.handleInterfaces).Methods("GET")
	api.HandleFunc("/protocols", s.handleProtocols).Methods("GET")
	api.HandleFunc("/health", s.handleHealth).Methods("GET")

	// WebSocket endpoint for real-time updates
	api.HandleFunc("/ws", s.handleWebSocket)

	// Static file serving for web UI
	r.PathPrefix("/").Handler(http.FileServer(http.Dir("./web/")))

	// CORS middleware
	r.Use(corsMiddleware)

	// Create server with proper timeouts to prevent slowloris attacks
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", s.port),
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Printf("Starting NSD API server on port %d", s.port)
	return srv.ListenAndServe()
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	stats := s.monitor.GetStats()
	
	response := StatsResponse{
		Timestamp:    time.Now(),
		TotalPackets: stats["TotalPackets"].(int64),
		TotalBytes:   stats["TotalBytes"].(int64),
		PacketRate:   stats["PacketRate"].(float64),
		ByteRate:     stats["ByteRate"].(float64),
		Protocols:    s.getProtocolStats(),
		Connections:  s.getConnectionStats(),
		Interfaces:   s.getInterfaceStats(),
	}

	s.sendJSONResponse(w, "success", response)
}

func (s *Server) handleConnections(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil {
			limit = parsed
		}
	}

	connections := s.getConnectionStats()
	if len(connections) > limit {
		connections = connections[:limit]
	}

	s.sendJSONResponse(w, "success", connections)
}

func (s *Server) handleInterfaces(w http.ResponseWriter, r *http.Request) {
	interfaces := s.getInterfaceStats()
	s.sendJSONResponse(w, "success", interfaces)
}

func (s *Server) handleProtocols(w http.ResponseWriter, r *http.Request) {
	protocols := s.getProtocolStats()
	s.sendJSONResponse(w, "success", protocols)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	health := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now(),
		"version":   "1.0.0",
		"uptime":    time.Since(time.Now()),
	}
	s.sendJSONResponse(w, "success", health)
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}
	defer func() {
		if err := conn.Close(); err != nil {
			log.Printf("WebSocket close failed: %v", err)
		}
	}()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			stats := s.monitor.GetStats()
			response := StatsResponse{
				Timestamp:    time.Now(),
				TotalPackets: stats["TotalPackets"].(int64),
				TotalBytes:   stats["TotalBytes"].(int64),
				PacketRate:   stats["PacketRate"].(float64),
				ByteRate:     stats["ByteRate"].(float64),
				Protocols:    s.getProtocolStats(),
				Connections:  s.getConnectionStats(),
				Interfaces:   s.getInterfaceStats(),
			}

			if err := conn.WriteJSON(response); err != nil {
				log.Printf("WebSocket write error: %v", err)
				return
			}
		}
	}
}

func (s *Server) getProtocolStats() map[string]int64 {
	// TODO: Implement protocol statistics from monitor
	return map[string]int64{
		"TCP":  1000,
		"UDP":  500,
		"ICMP": 100,
		"HTTP": 300,
		"HTTPS": 400,
	}
}

func (s *Server) getConnectionStats() []ConnectionInfo {
	// TODO: Implement connection statistics from monitor
	return []ConnectionInfo{
		{
			Source:      "192.168.1.100:12345",
			Destination: "10.0.0.1:80",
			Protocol:    "TCP",
			Service:     "HTTP",
			Bytes:       1024,
			Packets:     10,
			LastSeen:    time.Now(),
		},
	}
}

func (s *Server) getInterfaceStats() []InterfaceInfo {
	// TODO: Implement interface statistics from monitor
	return []InterfaceInfo{
		{
			Name:        "eth0",
			PacketCount: 1000,
			ByteCount:   50000,
			PacketRate:  10.5,
			ByteRate:    1024.0,
		},
	}
}

func (s *Server) sendJSONResponse(w http.ResponseWriter, status string, data interface{}) {
	response := APIResponse{
		Status: status,
		Data:   data,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}