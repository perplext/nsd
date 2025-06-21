//go:build windows

package netcap

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"
	
	"github.com/google/gopacket/pcap"
)

// checkWindowsDependencies verifies that Npcap/WinPcap is installed
func checkWindowsDependencies() error {
	// Try to find devices - this will fail if Npcap/WinPcap is not installed
	_, err := pcap.FindAllDevs()
	if err != nil {
		if strings.Contains(err.Error(), "PacketGetAdapterNames") ||
		   strings.Contains(err.Error(), "failed to load") ||
		   strings.Contains(err.Error(), "cannot load") {
			return fmt.Errorf("Npcap or WinPcap is not installed. Please install Npcap from https://npcap.com/#download. Error: %w", err)
		}
		return fmt.Errorf("failed to initialize packet capture: %w", err)
	}
	
	// Check if Npcap service is running
	if err := checkNpcapService(); err != nil {
		return err
	}
	
	return nil
}

// checkNpcapService verifies the Npcap service is running
func checkNpcapService() error {
	// Check for npcap service
	cmd := exec.Command("sc", "query", "npcap")
	output, err := cmd.CombinedOutput()
	if err == nil && strings.Contains(string(output), "RUNNING") {
		return nil
	}
	
	// Check for npf service (legacy WinPcap)
	cmd = exec.Command("sc", "query", "npf")
	output, err = cmd.CombinedOutput()
	if err == nil && strings.Contains(string(output), "RUNNING") {
		return nil
	}
	
	return fmt.Errorf("Npcap service is not running. Please start it with: sc start npcap")
}

// getWindowsInterfaceDescription returns a user-friendly description for Windows interfaces
func getWindowsInterfaceDescription(device pcap.Interface) string {
	// Windows interface names are like \Device\NPF_{GUID}
	// The description is usually more user-friendly
	if device.Description != "" {
		return device.Description
	}
	
	// Try to extract a meaningful name from the device name
	if strings.HasPrefix(device.Name, "\\Device\\NPF_") {
		// This is a GUID-based name, use description or return simplified version
		return fmt.Sprintf("Network Adapter %s", device.Name[12:20])
	}
	
	return device.Name
}

// ListWindowsInterfaces returns a formatted list of available interfaces on Windows
func ListWindowsInterfaces() ([]string, error) {
	if err := checkWindowsDependencies(); err != nil {
		return nil, err
	}
	
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("failed to list network interfaces: %w", err)
	}
	
	var interfaces []string
	for _, device := range devices {
		// Skip loopback unless it has addresses
		if device.Name == "\\Device\\NPF_Loopback" && len(device.Addresses) == 0 {
			continue
		}
		
		desc := getWindowsInterfaceDescription(device)
		var addrs []string
		for _, addr := range device.Addresses {
			if addr.IP != nil {
				addrs = append(addrs, addr.IP.String())
			}
		}
		
		addrStr := ""
		if len(addrs) > 0 {
			addrStr = fmt.Sprintf(" [%s]", strings.Join(addrs, ", "))
		}
		
		interfaces = append(interfaces, fmt.Sprintf("%s: %s%s", device.Name, desc, addrStr))
	}
	
	if len(interfaces) == 0 {
		return nil, fmt.Errorf("no network interfaces found. Make sure Npcap is installed and running")
	}
	
	return interfaces, nil
}

// openWindowsLive opens a live capture handle with Windows-specific error handling
func openWindowsLive(device string, snaplen int32, promisc bool, timeout time.Duration) (*pcap.Handle, error) {
	handle, err := pcap.OpenLive(device, snaplen, promisc, timeout)
	if err != nil {
		errStr := err.Error()
		
		// Provide Windows-specific error messages
		switch {
		case strings.Contains(errStr, "Access is denied"):
			return nil, fmt.Errorf("access denied: NSD requires Administrator privileges on Windows. Please run as Administrator")
		
		case strings.Contains(errStr, "The system cannot find the device specified"):
			interfaces, _ := ListWindowsInterfaces()
			return nil, fmt.Errorf("interface '%s' not found. Available interfaces:\n%s", 
				device, strings.Join(interfaces, "\n"))
		
		case strings.Contains(errStr, "failed to set hardware filter"):
			return nil, fmt.Errorf("failed to set packet filter: %w (try running as Administrator)", err)
			
		case strings.Contains(errStr, "PacketOpenAdapter"):
			return nil, fmt.Errorf("failed to open adapter: %w (is Npcap installed?)", err)
			
		default:
			return nil, fmt.Errorf("failed to open interface %s: %w", device, err)
		}
	}
	
	return handle, nil
}

// init performs Windows-specific initialization
func init() {
	// On Windows, we need to ensure we're running on a supported architecture
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "386" && runtime.GOARCH != "arm64" {
		panic(fmt.Sprintf("unsupported Windows architecture: %s", runtime.GOARCH))
	}
}