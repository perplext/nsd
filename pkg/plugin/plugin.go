package plugin

import (
    "fmt"
    stdplugin "plugin"

    "github.com/user/nsd/pkg/netcap"
)

// UIHandler interface for plugins that want to interact with the UI
type UIHandler interface {
    // GetDescription returns a description of the plugin
    GetDescription() string
    // GetOutput returns the current output/status of the plugin
    GetOutput() []string
}

// Plugin defines the interface for NSD plugins.
type Plugin interface {
    // Init is called once with the NetworkMonitor instance.
    Init(nm *netcap.NetworkMonitor) error
    // Name returns the plugin display name.
    Name() string
}

// Load opens a Go plugin (.so) file and looks for a symbol "Plugin" implementing the Plugin interface.
func Load(path string) (Plugin, error) {
    p, err := stdplugin.Open(path)
    if err != nil {
        return nil, fmt.Errorf("error opening plugin %s: %w", path, err)
    }
    sym, err := p.Lookup("Plugin")
    if err != nil {
        return nil, fmt.Errorf("symbol Plugin not found in %s: %w", path, err)
    }
    plug, ok := sym.(Plugin)
    if !ok {
        return nil, fmt.Errorf("symbol Plugin in %s does not implement plugin.Plugin", path)
    }
    return plug, nil
}
