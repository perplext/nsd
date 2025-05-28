package netcap

import (
	"context"
	"fmt"
	"runtime"
	"testing"
	"time"
	
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/perplext/nsd/pkg/ratelimit"
	"github.com/perplext/nsd/pkg/resource"
)

// BenchmarkPacketProcessing benchmarks packet processing performance
func BenchmarkPacketProcessing(b *testing.B) {
	nm := NewNetworkMonitor()
	packets := generateTestPackets(1000)
	
	b.ResetTimer()
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		for _, packet := range packets {
			nm.processPacket("test0", packet)
		}
	}
	
	b.ReportMetric(float64(b.N*1000), "packets/op")
}

// BenchmarkRateLimiting benchmarks rate limiting overhead
func BenchmarkRateLimiting(b *testing.B) {
	configs := []struct {
		name string
		cfg  *ratelimit.Config
	}{
		{
			name: "NoLimit",
			cfg: &ratelimit.Config{
				PacketsPerSecond: 0, // Unlimited
			},
		},
		{
			name: "10kPPS",
			cfg: &ratelimit.Config{
				PacketsPerSecond: 10000,
				PacketBurst:      1000,
			},
		},
		{
			name: "100kPPS",
			cfg: &ratelimit.Config{
				PacketsPerSecond: 100000,
				PacketBurst:      10000,
			},
		},
		{
			name: "1MPPS",
			cfg: &ratelimit.Config{
				PacketsPerSecond: 1000000,
				PacketBurst:      100000,
			},
		},
	}
	
	for _, config := range configs {
		b.Run(config.name, func(b *testing.B) {
			rl := ratelimit.NewRateLimiter(config.cfg)
			
			b.ResetTimer()
			b.ReportAllocs()
			
			allowed := 0
			for i := 0; i < b.N; i++ {
				if rl.AllowPacket() {
					allowed++
				}
			}
			
			b.ReportMetric(float64(allowed)/float64(b.N)*100, "allowed%")
		})
	}
}

// BenchmarkMemoryPool benchmarks memory pool performance
func BenchmarkMemoryPool(b *testing.B) {
	sizes := []int{64, 256, 1024, 4096, 16384, 65536}
	
	b.Run("WithPool", func(b *testing.B) {
		pool := resource.NewMemoryPool()
		
		b.ResetTimer()
		b.ReportAllocs()
		
		for i := 0; i < b.N; i++ {
			size := sizes[i%len(sizes)]
			buf := pool.Get(size)
			// Simulate some work
			for j := 0; j < size && j < 100; j++ {
				buf[j] = byte(j)
			}
			pool.Put(buf)
		}
	})
	
	b.Run("WithoutPool", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()
		
		for i := 0; i < b.N; i++ {
			size := sizes[i%len(sizes)]
			buf := make([]byte, size)
			// Simulate some work
			for j := 0; j < size && j < 100; j++ {
				buf[j] = byte(j)
			}
		}
	})
}

// BenchmarkControlledCapture benchmarks controlled capture performance
func BenchmarkControlledCapture(b *testing.B) {
	configs := []struct {
		name string
		cfg  *ControlledConfig
	}{
		{
			name: "Default",
			cfg:  DefaultControlledConfig(),
		},
		{
			name: "HighRate",
			cfg: &ControlledConfig{
				RateLimitConfig: &ratelimit.Config{
					PacketsPerSecond: 1000000,
					PacketBurst:      100000,
					BytesPerSecond:   1073741824, // 1 GB/s
					ByteBurst:        104857600,  // 100 MB
				},
				ResourceConfig: resource.DefaultConfig(),
				MaxQueueSize:   100000,
				DropWhenFull:   true,
				AdaptiveMode:   false,
			},
		},
		{
			name: "Adaptive",
			cfg: &ControlledConfig{
				RateLimitConfig: ratelimit.DefaultConfig(),
				ResourceConfig:  resource.DefaultConfig(),
				MaxQueueSize:    50000,
				DropWhenFull:    true,
				AdaptiveMode:    true,
			},
		},
	}
	
	for _, config := range configs {
		b.Run(config.name, func(b *testing.B) {
			cm, err := NewControlledMonitor(config.cfg)
			if err != nil {
				b.Fatal(err)
			}
			defer cm.StopGracefully(5 * time.Second)
			
			packets := generateTestPackets(1000)
			
			b.ResetTimer()
			b.ReportAllocs()
			
			ctx := context.Background()
			for i := 0; i < b.N; i++ {
				for _, packet := range packets {
					// Simulate packet arrival
					select {
					case cm.packetQueue <- packet:
					case <-ctx.Done():
						return
					default:
						// Dropped
					}
				}
			}
			
			stats := cm.GetStatistics()
			b.ReportMetric(float64(stats.ProcessedPackets), "processed")
			b.ReportMetric(float64(stats.DroppedPackets), "dropped")
			b.ReportMetric(float64(stats.ThrottledPackets), "throttled")
		})
	}
}

// BenchmarkResourceController benchmarks resource monitoring overhead
func BenchmarkResourceController(b *testing.B) {
	cfg := resource.DefaultConfig()
	cfg.CheckInterval = 100 * time.Millisecond
	
	rc, err := resource.NewController(cfg)
	if err != nil {
		b.Fatal(err)
	}
	
	rc.Start()
	defer rc.Stop()
	
	b.ResetTimer()
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		usage := rc.GetUsage()
		_ = usage.MemoryMB
		_ = usage.CPUPercent
		
		// Simulate some work that uses resources
		data := make([]byte, 1024)
		for j := range data {
			data[j] = byte(j)
		}
		
		// Check if throttled
		if rc.IsThrottled() {
			time.Sleep(time.Microsecond)
		}
	}
}

// BenchmarkConcurrentPacketProcessing benchmarks concurrent packet processing
func BenchmarkConcurrentPacketProcessing(b *testing.B) {
	workers := []int{1, 2, 4, 8, 16}
	
	for _, numWorkers := range workers {
		b.Run(fmt.Sprintf("Workers-%d", numWorkers), func(b *testing.B) {
			cm, err := NewControlledMonitor(DefaultControlledConfig())
			if err != nil {
				b.Fatal(err)
			}
			defer cm.StopGracefully(5 * time.Second)
			
			packets := generateTestPackets(10000)
			
			b.ResetTimer()
			b.ReportAllocs()
			
			// Start workers
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			
			for w := 0; w < numWorkers; w++ {
				go func() {
					for {
						select {
						case <-ctx.Done():
							return
						default:
							for _, packet := range packets {
								select {
								case cm.packetQueue <- packet:
								case <-ctx.Done():
									return
								default:
								}
							}
						}
					}
				}()
			}
			
			// Let it run
			time.Sleep(time.Duration(b.N) * time.Microsecond)
			
			stats := cm.GetStatistics()
			b.ReportMetric(float64(stats.ProcessedPackets)/b.Elapsed().Seconds(), "packets/sec")
		})
	}
}

// BenchmarkPacketSizes benchmarks processing of different packet sizes
func BenchmarkPacketSizes(b *testing.B) {
	sizes := []int{64, 256, 512, 1024, 1500, 9000} // Including jumbo frames
	
	for _, size := range sizes {
		b.Run(fmt.Sprintf("Size-%d", size), func(b *testing.B) {
			nm := NewNetworkMonitor()
			packet := generatePacketWithSize(size)
			
			b.ResetTimer()
			b.ReportAllocs()
			b.SetBytes(int64(size))
			
			for i := 0; i < b.N; i++ {
				nm.processPacket("test0", packet)
			}
		})
	}
}

// generatePacketWithSize generates a test packet of specific size
func generatePacketWithSize(size int) gopacket.Packet {
	// Create layers
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}
	
	ipv4 := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    []byte{10, 0, 0, 1},
		DstIP:    []byte{10, 0, 0, 2},
	}
	
	tcp := &layers.TCP{
		SrcPort: 12345,
		DstPort: 80,
		Seq:     1,
		Ack:     1,
		Window:  65535,
		SYN:     true,
	}
	tcp.SetNetworkLayerForChecksum(ipv4)
	
	// Calculate payload size
	headerSize := 14 + 20 + 20 // Ethernet + IP + TCP
	payloadSize := size - headerSize
	if payloadSize < 0 {
		payloadSize = 0
	}
	
	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte(i % 256)
	}
	
	// Serialize
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	
	gopacket.SerializeLayers(buf, opts, eth, ipv4, tcp, gopacket.Payload(payload))
	
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

// BenchmarkMemoryUsage measures memory usage during packet processing
func BenchmarkMemoryUsage(b *testing.B) {
	b.Run("Baseline", func(b *testing.B) {
		var m runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&m)
		startAlloc := m.Alloc
		
		nm := NewNetworkMonitor()
		packets := generateTestPackets(10000)
		
		b.ResetTimer()
		
		for i := 0; i < b.N; i++ {
			for _, packet := range packets {
				nm.processPacket("test0", packet)
			}
		}
		
		runtime.GC()
		runtime.ReadMemStats(&m)
		endAlloc := m.Alloc
		
		b.ReportMetric(float64(endAlloc-startAlloc)/1024/1024, "MB/op")
	})
	
	b.Run("WithPooling", func(b *testing.B) {
		var m runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&m)
		startAlloc := m.Alloc
		
		cm, _ := NewControlledMonitor(DefaultControlledConfig())
		defer cm.StopGracefully(5 * time.Second)
		
		packets := generateTestPackets(10000)
		
		b.ResetTimer()
		
		for i := 0; i < b.N; i++ {
			for _, packet := range packets {
				cm.processPacketPooled(packet)
			}
		}
		
		runtime.GC()
		runtime.ReadMemStats(&m)
		endAlloc := m.Alloc
		
		b.ReportMetric(float64(endAlloc-startAlloc)/1024/1024, "MB/op")
	})
}