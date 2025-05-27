// Package main for Go plugin example
package main

import (
    "fmt"
    "sync"
    "time"

    "github.com/user/nsd/pkg/netcap"
    pluginapi "github.com/user/nsd/pkg/plugin"
)

// SimplePlugin logs packet buffer length periodically
type SimplePlugin struct {
    output []string
    mu     sync.Mutex
}

// Init starts a goroutine printing packet buffer size every 10s
func (p *SimplePlugin) Init(nm *netcap.NetworkMonitor) error {
    go func() {
        for {
            buf := nm.GetPacketBuffer()
            msg := fmt.Sprintf("Packet buffer length: %d", len(buf))
            fmt.Printf("[SimplePlugin] %s\n", msg)
            
            // Store output for UI
            p.mu.Lock()
            p.output = append(p.output, msg)
            if len(p.output) > 50 {
                p.output = p.output[len(p.output)-50:]
            }
            p.mu.Unlock()
            
            time.Sleep(10 * time.Second)
        }
    }()
    return nil
}

// Name returns plugin name
func (p *SimplePlugin) Name() string {
    return "SimplePlugin"
}

// GetDescription returns plugin description
func (p *SimplePlugin) GetDescription() string {
    return "Monitors packet buffer size and reports statistics"
}

// GetOutput returns current plugin output
func (p *SimplePlugin) GetOutput() []string {
    p.mu.Lock()
    defer p.mu.Unlock()
    
    output := make([]string, len(p.output))
    copy(output, p.output)
    return output
}

// Plugin exported symbol
var Plugin pluginapi.Plugin = &SimplePlugin{}
