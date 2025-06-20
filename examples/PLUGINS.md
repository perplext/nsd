# NSD Plugin System

NSD supports a plugin system that allows you to extend its functionality with custom Go plugins.

## Plugin Interface

Plugins must implement the `Plugin` interface from `github.com/perplext/nsd/pkg/plugin`:

```go
type Plugin interface {
    // Init is called once with the NetworkMonitor instance
    Init(nm *netcap.NetworkMonitor) error
    // Name returns the plugin display name
    Name() string
}
```

## UI Integration

Plugins can optionally implement the `UIHandler` interface to integrate with the NSD UI:

```go
type UIHandler interface {
    // GetDescription returns a description of the plugin
    GetDescription() string
    // GetOutput returns the current output/status of the plugin
    GetOutput() []string
}
```

## Building Plugins

Build your plugin as a shared object (.so file):

```bash
go build -buildmode=plugin -o myplugin.so myplugin.go
```

## Loading Plugins

Use the `--plugins` flag to load plugins:

```bash
sudo ./nsd -i eth0 --plugins examples/simpleplugin.so
```

Multiple plugins can be loaded:

```bash
sudo ./nsd -i eth0 --plugins plugin1.so,plugin2.so
```

## Viewing Plugin Output

Press `G` in the NSD UI to view loaded plugins and their output.

## Example Plugin

See `examples/simpleplugin/simpleplugin.go` for a complete example that:
- Monitors packet buffer size
- Reports statistics every 10 seconds
- Integrates with the UI to display output

## Plugin Development Tips

1. **Error Handling**: Return errors from `Init()` if initialization fails
2. **Goroutines**: Use goroutines for background work to avoid blocking
3. **Thread Safety**: Use mutexes when sharing data between goroutines
4. **UI Output**: Keep output concise and limit history (e.g., last 50 lines)
5. **Cleanup**: Consider implementing cleanup logic if your plugin uses resources

## Security Note

Plugins run with the same privileges as NSD (typically root). Only load trusted plugins.