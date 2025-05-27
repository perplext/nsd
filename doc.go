/*
Package nsd provides a comprehensive network sniffing dashboard with
a terminal user interface.

NSD (Network Sniffing Dashboard) captures and analyzes network packets in real-time, 
providing detailed statistics, connection tracking, and various visualizations. 
It features a customizable UI with themes, internationalization support, and a 
plugin system for extensibility.

# Installation

To install NSD:

	go install github.com/user/nsd/cmd/nsd@latest

Or build from source:

	git clone https://github.com/user/nsd
	cd nsd
	make build

# Basic Usage

NSD requires root/administrator privileges to capture network packets:

	sudo nsd -i eth0

With BPF filtering:

	sudo nsd -i eth0 -filter "tcp port 443"

With custom theme:

	sudo nsd -i eth0 -theme CyberpunkNeon

# Architecture

NSD is organized into several packages:

  - netcap: Network packet capture and analysis
  - ui: Terminal user interface and visualizations
  - graph: Data visualization components
  - plugin: Plugin system for extensions
  - security: Input validation and privilege management
  - errors: Custom error types and handling
  - ratelimit: Rate limiting for resource protection
  - resource: System resource monitoring and control

# Network Capture

The netcap package provides the core packet capture functionality:

	import "github.com/user/nsd/pkg/netcap"

	monitor := netcap.NewNetworkMonitor()
	err := monitor.StartCapture("eth0")
	if err != nil {
		log.Fatal(err)
	}
	defer monitor.StopAllCaptures()

	// Get statistics
	stats := monitor.GetStats()
	fmt.Printf("Packets: %d\n", stats["TotalPackets"])

# User Interface

The ui package provides a rich terminal interface:

	import "github.com/user/nsd/pkg/ui"

	ui := ui.NewUI(monitor).
		SetTheme("Dark+").
		SetStyle("Rounded")

	if err := ui.Run(); err != nil {
		log.Fatal(err)
	}

# Security

NSD includes comprehensive security features:

	import "github.com/user/nsd/pkg/security"

	// Validate inputs
	validator := security.NewValidator()
	err := validator.ValidateInterfaceName("eth0")

	// Drop privileges
	pm := security.NewPrivilegeManager()
	err := pm.DropPrivileges("nobody")

# Plugins

Extend NSD with custom plugins:

	type MyPlugin struct {
		monitor *netcap.NetworkMonitor
	}

	func (p *MyPlugin) Name() string { return "MyPlugin" }
	func (p *MyPlugin) Init(m *netcap.NetworkMonitor) error {
		p.monitor = m
		return nil
	}
	func (p *MyPlugin) Stop() error { return nil }

	var Plugin plugin.Plugin = &MyPlugin{}

Build as a shared object:

	go build -buildmode=plugin -o myplugin.so myplugin.go

Load with NSD:

	nsd -i eth0 -plugins myplugin.so

# Themes

NSD includes many built-in themes:

  - Dark+ (default)
  - Light
  - Monokai
  - Solarized
  - Nord
  - Dracula
  - CyberpunkNeon
  - Matrix
  - And more...

Custom themes can be loaded from JSON/YAML files:

	{
	  "themes": [{
	    "name": "MyTheme",
	    "foreground": "#FFFFFF",
	    "background": "#000000",
	    "border": "#808080",
	    ...
	  }]
	}

# Visualizations

NSD provides various network visualizations:

  - Speedometer: Real-time speed gauge
  - Matrix: Connection matrix rain
  - Constellation: Network topology map
  - Heatmap: Traffic intensity
  - Sankey: Flow diagram
  - World Map: Geographic connections
  - And more...

# Internationalization

NSD supports multiple languages:

	nsd -i eth0 -i18n-file translations/es.json

Included languages: English, Spanish, French, German, Italian, Portuguese,
Russian, Japanese, Korean, Chinese, Arabic, Hindi, and more.

# Performance

For high-traffic environments:

  - Use BPF filters to reduce packet processing
  - Enable rate limiting
  - Set resource limits
  - Use specific interfaces instead of "any"

# Security Considerations

  - Always validate user inputs
  - Drop privileges after initialization
  - Use BPF filters to limit captured traffic
  - Enable rate limiting and resource controls
  - Review security documentation

# Examples

See the examples directory for:

  - Basic usage examples
  - Plugin development
  - Custom visualizations
  - Theme creation
  - i18n translations

# License

NSD is released under the MIT License. See LICENSE file for details.
*/
package nsd