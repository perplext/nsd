package ratelimit

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
	
	"golang.org/x/time/rate"
)

// RateLimiter provides rate limiting for various operations
type RateLimiter struct {
	// Packet rate limiting
	packetLimiter *rate.Limiter
	packetBurst   int
	
	// Byte rate limiting
	byteLimiter *rate.Limiter
	byteBurst   int
	
	// Connection rate limiting
	connLimiter *rate.Limiter
	connBurst   int
	
	// Statistics
	droppedPackets uint64
	droppedBytes   uint64
	droppedConns   uint64
	
	mu sync.RWMutex
}

// Config holds rate limiter configuration
type Config struct {
	// Packets per second (0 = unlimited)
	PacketsPerSecond int
	PacketBurst      int
	
	// Bytes per second (0 = unlimited)
	BytesPerSecond int
	ByteBurst      int
	
	// New connections per second (0 = unlimited)
	ConnectionsPerSecond int
	ConnectionBurst      int
}

// DefaultConfig returns a default rate limiter configuration
func DefaultConfig() *Config {
	return &Config{
		PacketsPerSecond:     10000,  // 10k packets/sec
		PacketBurst:          1000,   // Burst of 1k packets
		BytesPerSecond:       10485760, // 10 MB/sec
		ByteBurst:            1048576,  // Burst of 1 MB
		ConnectionsPerSecond: 100,     // 100 new connections/sec
		ConnectionBurst:      20,      // Burst of 20 connections
	}
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(cfg *Config) *RateLimiter {
	rl := &RateLimiter{}
	
	// Initialize packet limiter
	if cfg.PacketsPerSecond > 0 {
		rl.packetLimiter = rate.NewLimiter(rate.Limit(cfg.PacketsPerSecond), cfg.PacketBurst)
		rl.packetBurst = cfg.PacketBurst
	}
	
	// Initialize byte limiter
	if cfg.BytesPerSecond > 0 {
		rl.byteLimiter = rate.NewLimiter(rate.Limit(cfg.BytesPerSecond), cfg.ByteBurst)
		rl.byteBurst = cfg.ByteBurst
	}
	
	// Initialize connection limiter
	if cfg.ConnectionsPerSecond > 0 {
		rl.connLimiter = rate.NewLimiter(rate.Limit(cfg.ConnectionsPerSecond), cfg.ConnectionBurst)
		rl.connBurst = cfg.ConnectionBurst
	}
	
	return rl
}

// AllowPacket checks if a packet should be allowed
func (rl *RateLimiter) AllowPacket() bool {
	if rl.packetLimiter == nil {
		return true
	}
	
	allowed := rl.packetLimiter.Allow()
	if !allowed {
		atomic.AddUint64(&rl.droppedPackets, 1)
	}
	return allowed
}

// AllowPacketN checks if n packets should be allowed
func (rl *RateLimiter) AllowPacketN(n int) bool {
	if rl.packetLimiter == nil {
		return true
	}
	
	allowed := rl.packetLimiter.AllowN(time.Now(), n)
	if !allowed {
		atomic.AddUint64(&rl.droppedPackets, uint64(n))
	}
	return allowed
}

// AllowBytes checks if bytes should be allowed
func (rl *RateLimiter) AllowBytes(bytes int) bool {
	if rl.byteLimiter == nil {
		return true
	}
	
	allowed := rl.byteLimiter.AllowN(time.Now(), bytes)
	if !allowed {
		atomic.AddUint64(&rl.droppedBytes, uint64(bytes))
	}
	return allowed
}

// AllowConnection checks if a new connection should be allowed
func (rl *RateLimiter) AllowConnection() bool {
	if rl.connLimiter == nil {
		return true
	}
	
	allowed := rl.connLimiter.Allow()
	if !allowed {
		atomic.AddUint64(&rl.droppedConns, 1)
	}
	return allowed
}

// WaitPacket waits until a packet can be processed
func (rl *RateLimiter) WaitPacket(ctx context.Context) error {
	if rl.packetLimiter == nil {
		return nil
	}
	return rl.packetLimiter.Wait(ctx)
}

// WaitBytes waits until bytes can be processed
func (rl *RateLimiter) WaitBytes(ctx context.Context, bytes int) error {
	if rl.byteLimiter == nil {
		return nil
	}
	return rl.byteLimiter.WaitN(ctx, bytes)
}

// GetStats returns rate limiter statistics
func (rl *RateLimiter) GetStats() Stats {
	return Stats{
		DroppedPackets: atomic.LoadUint64(&rl.droppedPackets),
		DroppedBytes:   atomic.LoadUint64(&rl.droppedBytes),
		DroppedConns:   atomic.LoadUint64(&rl.droppedConns),
	}
}

// ResetStats resets the statistics
func (rl *RateLimiter) ResetStats() {
	atomic.StoreUint64(&rl.droppedPackets, 0)
	atomic.StoreUint64(&rl.droppedBytes, 0)
	atomic.StoreUint64(&rl.droppedConns, 0)
}

// Stats holds rate limiter statistics
type Stats struct {
	DroppedPackets uint64
	DroppedBytes   uint64
	DroppedConns   uint64
}

// String returns a string representation of stats
func (s Stats) String() string {
	return fmt.Sprintf("Dropped: %d packets, %d bytes, %d connections",
		s.DroppedPackets, s.DroppedBytes, s.DroppedConns)
}

// AdaptiveLimiter adjusts limits based on system resources
type AdaptiveLimiter struct {
	*RateLimiter
	config        *Config
	monitor       ResourceMonitor
	mu            sync.Mutex
	adjustPeriod  time.Duration
	lastAdjust    time.Time
}

// ResourceMonitor provides system resource information
type ResourceMonitor interface {
	GetCPUUsage() float64
	GetMemoryUsage() float64
	GetDroppedPackets() uint64
}

// NewAdaptiveLimiter creates a new adaptive rate limiter
func NewAdaptiveLimiter(cfg *Config, monitor ResourceMonitor) *AdaptiveLimiter {
	return &AdaptiveLimiter{
		RateLimiter:  NewRateLimiter(cfg),
		config:       cfg,
		monitor:      monitor,
		adjustPeriod: 10 * time.Second,
	}
}

// Adjust adjusts rate limits based on system resources
func (al *AdaptiveLimiter) Adjust() {
	al.mu.Lock()
	defer al.mu.Unlock()
	
	// Check if it's time to adjust
	if time.Since(al.lastAdjust) < al.adjustPeriod {
		return
	}
	
	cpuUsage := al.monitor.GetCPUUsage()
	memUsage := al.monitor.GetMemoryUsage()
	droppedPackets := al.monitor.GetDroppedPackets()
	
	// Adjust based on CPU usage
	if cpuUsage > 0.8 {
		// Reduce limits by 20%
		al.reduceLimits(0.8)
	} else if cpuUsage < 0.5 && droppedPackets > 0 {
		// Increase limits by 10%
		al.increaseLimits(1.1)
	}
	
	// Adjust based on memory usage
	if memUsage > 0.8 {
		// Reduce limits more aggressively
		al.reduceLimits(0.7)
	}
	
	al.lastAdjust = time.Now()
}

// reduceLimits reduces rate limits by factor
func (al *AdaptiveLimiter) reduceLimits(factor float64) {
	if al.packetLimiter != nil {
		newLimit := rate.Limit(float64(al.config.PacketsPerSecond) * factor)
		al.packetLimiter.SetLimit(newLimit)
	}
	
	if al.byteLimiter != nil {
		newLimit := rate.Limit(float64(al.config.BytesPerSecond) * factor)
		al.byteLimiter.SetLimit(newLimit)
	}
}

// increaseLimits increases rate limits by factor
func (al *AdaptiveLimiter) increaseLimits(factor float64) {
	if al.packetLimiter != nil {
		currentLimit := float64(al.packetLimiter.Limit())
		maxLimit := float64(al.config.PacketsPerSecond)
		newLimit := currentLimit * factor
		if newLimit > maxLimit {
			newLimit = maxLimit
		}
		al.packetLimiter.SetLimit(rate.Limit(newLimit))
	}
	
	if al.byteLimiter != nil {
		currentLimit := float64(al.byteLimiter.Limit())
		maxLimit := float64(al.config.BytesPerSecond)
		newLimit := currentLimit * factor
		if newLimit > maxLimit {
			newLimit = maxLimit
		}
		al.byteLimiter.SetLimit(rate.Limit(newLimit))
	}
}

// TokenBucket implements a token bucket rate limiter
type TokenBucket struct {
	capacity int64
	tokens   int64
	refillRate int64
	lastRefill time.Time
	mu         sync.Mutex
}

// NewTokenBucket creates a new token bucket
func NewTokenBucket(capacity, refillRate int64) *TokenBucket {
	return &TokenBucket{
		capacity:   capacity,
		tokens:     capacity,
		refillRate: refillRate,
		lastRefill: time.Now(),
	}
}

// Take attempts to take n tokens from the bucket
func (tb *TokenBucket) Take(n int64) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	
	tb.refill()
	
	if tb.tokens >= n {
		tb.tokens -= n
		return true
	}
	return false
}

// refill adds tokens based on elapsed time
func (tb *TokenBucket) refill() {
	now := time.Now()
	elapsed := now.Sub(tb.lastRefill)
	tokensToAdd := int64(elapsed.Seconds() * float64(tb.refillRate))
	
	if tokensToAdd > 0 {
		tb.tokens += tokensToAdd
		if tb.tokens > tb.capacity {
			tb.tokens = tb.capacity
		}
		tb.lastRefill = now
	}
}