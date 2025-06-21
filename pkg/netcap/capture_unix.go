//go:build !windows

package netcap

import (
	"fmt"
	"strings"
	"time"
	
	"github.com/google/gopacket/pcap"
)

// checkWindowsDependencies is a no-op on Unix systems
func checkWindowsDependencies() error {
	return nil
}

// getWindowsInterfaceDescription returns the interface name on Unix
func getWindowsInterfaceDescription(device pcap.Interface) string {
	return device.Name
}

// ListWindowsInterfaces returns standard interface list on Unix
func ListWindowsInterfaces() ([]string, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("failed to list network interfaces: %w", err)
	}
	
	var interfaces []string
	for _, device := range devices {
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
		
		desc := ""
		if device.Description != "" && device.Description != device.Name {
			desc = fmt.Sprintf(" (%s)", device.Description)
		}
		
		interfaces = append(interfaces, fmt.Sprintf("%s%s%s", device.Name, desc, addrStr))
	}
	
	return interfaces, nil
}

// openWindowsLive is just a wrapper for pcap.OpenLive on Unix
func openWindowsLive(device string, snaplen int32, promisc bool, timeout time.Duration) (*pcap.Handle, error) {
	return pcap.OpenLive(device, snaplen, promisc, timeout)
}