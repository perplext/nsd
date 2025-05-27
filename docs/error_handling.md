# Error Handling in NSD

This document describes the comprehensive error handling system implemented in NSD to ensure robustness and fault tolerance.

## Error Types

### Custom Error Types

1. **Network Errors** (`NetworkError`)
   - Wraps network-related errors with context (interface, operation)
   - Example: capture failures, interface not found, permission denied

2. **UI Errors** (`UIError`)
   - Wraps UI-related errors with component and operation context
   - Example: rendering failures, theme loading errors

3. **Configuration Errors** (`ConfigError`)
   - Wraps configuration errors with field and value context
   - Example: invalid settings, missing required fields

### Predefined Errors

```go
var (
    ErrNoInterface        = errors.New("no network interface specified")
    ErrInterfaceNotFound  = errors.New("network interface not found")
    ErrPermissionDenied   = errors.New("permission denied (requires root/admin)")
    ErrCaptureTimeout     = errors.New("packet capture timeout")
    ErrInvalidBPF        = errors.New("invalid BPF filter expression")
    // ... more errors
)
```

## Error Handling Strategies

### 1. Retry Logic

The system implements automatic retry for transient errors:

```go
func (eh *ErrorHandler) Handle(operation func() error) error {
    for attempt := 0; attempt <= eh.MaxRetries; attempt++ {
        err := operation()
        if err == nil {
            return nil
        }
        
        if !errors.IsRetryable(err) {
            return err
        }
        
        time.Sleep(eh.RetryDelay)
    }
    return fmt.Errorf("max retries exceeded")
}
```

### 2. Graceful Degradation

When errors occur, the system attempts to continue with reduced functionality:

- **Fallback UI Mode**: Simplified UI when advanced features fail
- **Partial Capture**: Continue capturing on working interfaces
- **Plugin Isolation**: Failed plugins don't crash the application

### 3. Panic Recovery

All goroutines include panic recovery:

```go
defer RecoverFromPanic("component", func(r interface{}) {
    log.Printf("Recovered from panic: %v", r)
    // Save state and attempt recovery
})
```

### 4. Context Cancellation

Proper context handling for graceful shutdown:

```go
func (nm *ImprovedNetworkMonitor) StopAllCapturesGracefully(timeout time.Duration) error {
    nm.cancel() // Cancel context
    
    done := make(chan struct{})
    go func() {
        nm.wg.Wait()
        close(done)
    }()
    
    select {
    case <-done:
        return nil
    case <-time.After(timeout):
        nm.forceCloseAllHandles()
        return fmt.Errorf("timeout stopping captures")
    }
}
```

## Recovery Mechanisms

### 1. Checkpoint System

Regular state checkpoints for recovery:

```go
type Checkpoint struct {
    Timestamp   time.Time
    Version     string
    State       map[string]interface{}
    MemoryUsage runtime.MemStats
}
```

### 2. Crash Reports

Detailed crash reports for debugging:

```go
type CrashReport struct {
    Timestamp  time.Time
    Panic      string
    Stack      string
    Memory     MemInfo
    Goroutines int
}
```

### 3. Health Checks

Periodic health monitoring:

```go
healthChecker.AddCheck("capture", func() error {
    stats, err := monitor.GetCaptureStatistics("eth0")
    if err != nil {
        return err
    }
    if stats.PacketsDropped > 1000 {
        return fmt.Errorf("excessive packet drops")
    }
    return nil
})
```

## UI Error Display

User-friendly error presentation:

1. **Modal Dialogs**: Important errors shown in modal dialogs
2. **Error Log**: Persistent error log accessible via hotkey
3. **Status Bar**: Brief error notifications in status bar
4. **Detailed View**: Full error details with stack traces available

## Best Practices

1. **Always wrap errors with context**:
   ```go
   return errors.WrapNetworkError(iface, "capture", err)
   ```

2. **Use predefined errors for common cases**:
   ```go
   if !hasPermission {
       return errors.ErrPermissionDenied
   }
   ```

3. **Validate inputs early**:
   ```go
   if err := ValidateInterface(name); err != nil {
       return err
   }
   ```

4. **Log errors appropriately**:
   ```go
   errorHandler.Logger.Printf("Warning: non-critical error: %v", err)
   ```

5. **Provide recovery suggestions**:
   ```go
   func suggestRecovery(err error) {
       if errors.Is(err, ErrPermissionDenied) {
           fmt.Println("Try running with sudo")
       }
   }
   ```

## Testing Error Handling

Comprehensive tests ensure error handling works correctly:

- Unit tests for all error types
- Integration tests for error propagation
- Chaos testing for recovery mechanisms
- Performance tests under error conditions

## Monitoring and Metrics

Error metrics are tracked for monitoring:

- Error rates by type
- Retry success rates  
- Recovery success rates
- Crash frequency

This comprehensive error handling system ensures NSD remains stable and provides a good user experience even when errors occur.