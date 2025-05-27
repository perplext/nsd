# NSD Security Guide

## Overview

NSD implements multiple layers of security to ensure safe operation when monitoring network traffic. This guide covers the security features, best practices, and configuration options.

## Security Features

### 1. Input Validation

All user inputs are validated to prevent injection attacks and ensure safe operation:

- **Interface Names**: Validated against shell metacharacters and path traversal attempts
- **BPF Filters**: Compiled and validated before use to prevent malicious filters
- **File Paths**: Checked for directory traversal and restricted to safe directories
- **Theme Names**: Limited to alphanumeric characters with specific allowed symbols
- **Port Numbers**: Validated to be within valid range (1-65535)
- **IP Addresses**: Validated for correct format (IPv4 and IPv6)

### 2. Privilege Separation

NSD supports dropping privileges after initialization:

```bash
# Run with privilege dropping (default)
sudo nsd -i eth0 --drop-privileges --user nobody

# Run without privilege dropping (not recommended)
sudo nsd -i eth0 --drop-privileges=false
```

The privilege separation process:
1. Start as root to access network interfaces
2. Initialize packet capture
3. Drop to unprivileged user
4. Continue operation with minimal privileges

### 3. Secure Defaults

NSD uses secure defaults out of the box:

- **No Promiscuous Mode**: Disabled by default
- **Rate Limiting**: Enabled to prevent resource exhaustion
- **Plugin Loading**: Disabled by default
- **File Export**: Disabled by default
- **Audit Logging**: Enabled by default
- **Resource Limits**: Conservative limits set

### 4. Rate Limiting

Built-in rate limiting prevents resource exhaustion:

- **Packet Rate**: Maximum 10,000 packets/second (configurable)
- **Byte Rate**: Maximum 100MB/second (configurable)
- **Connection Limit**: Maximum 1,000 concurrent connections (configurable)

### 5. Resource Controls

Resource usage is monitored and controlled:

- **Memory Limit**: 512MB default (configurable)
- **CPU Limit**: 50% default (configurable)
- **Goroutine Limit**: 100 concurrent (configurable)

### 6. Plugin Security

When plugins are enabled:

- Plugin paths are validated
- Plugins run in restricted environment
- Plugin names and metadata are validated
- Only .so files are accepted

## Configuration

### Security Configuration File

Create a security configuration file (e.g., `/etc/nsd/security.json`):

```json
{
  "drop_privileges": true,
  "unprivileged_user": "nsd",
  "enable_promiscuous": false,
  "allowed_interfaces": ["eth0", "eth1"],
  "enable_plugins": false,
  "allow_file_export": false,
  "enable_rate_limiting": true,
  "max_packets_per_sec": 10000,
  "max_bytes_per_sec": 104857600,
  "max_connections": 1000,
  "enable_audit_log": true,
  "audit_log_path": "/var/log/nsd/audit.log",
  "max_memory_mb": 512,
  "max_cpu_percent": 50.0,
  "max_goroutines": 100
}
```

### Command Line Options

Security-related command line options:

```bash
# Drop privileges after initialization
--drop-privileges         # Enable privilege dropping (default: true)
--user <username>        # User to drop privileges to (default: nobody)

# BPF filtering
--filter <expression>    # Apply BPF filter (validated before use)

# Resource limits (when using enhanced binary)
--max-memory <MB>        # Maximum memory usage
--max-cpu <percent>      # Maximum CPU usage
--rate-limit             # Enable rate limiting
```

## Best Practices

### 1. Running NSD

- Always run with privilege dropping enabled
- Create a dedicated user for NSD:
  ```bash
  sudo useradd -r -s /bin/false nsd
  ```
- Use specific interface names instead of "any"
- Apply BPF filters to limit captured traffic

### 2. File Permissions

Set appropriate permissions for NSD files:

```bash
# Configuration files (read-only for nsd user)
sudo chown root:nsd /etc/nsd/
sudo chmod 750 /etc/nsd/
sudo chmod 640 /etc/nsd/*.json

# Log directory (writable for nsd user)
sudo mkdir -p /var/log/nsd
sudo chown nsd:nsd /var/log/nsd
sudo chmod 750 /var/log/nsd

# Export directory (if exports enabled)
sudo mkdir -p /var/lib/nsd/exports
sudo chown nsd:nsd /var/lib/nsd/exports
sudo chmod 750 /var/lib/nsd/exports
```

### 3. Network Isolation

For maximum security, run NSD on an isolated monitoring interface:

1. Use a dedicated network interface for monitoring
2. Configure the interface without an IP address
3. Use BPF filters to limit captured traffic

### 4. Audit Logging

Monitor NSD activity through audit logs:

```bash
# View recent security events
sudo tail -f /var/log/nsd/audit.log

# Check for validation failures
sudo grep "VALIDATION_FAILED" /var/log/nsd/audit.log

# Monitor privilege operations
sudo grep "PRIVILEGE" /var/log/nsd/audit.log
```

## Security Considerations

### What NSD Protects Against

1. **Shell Injection**: All inputs are validated against shell metacharacters
2. **Path Traversal**: File paths are restricted and validated
3. **Resource Exhaustion**: Rate limiting and resource controls prevent DoS
4. **Privilege Escalation**: Privileges are dropped after initialization
5. **Malicious Filters**: BPF filters are validated before compilation

### What NSD Does NOT Protect Against

1. **Malicious Network Traffic**: NSD observes but doesn't filter traffic
2. **Physical Access**: Assumes the host system is physically secure
3. **Kernel Vulnerabilities**: Relies on the underlying OS security
4. **Supply Chain Attacks**: Ensure you download from official sources

## Incident Response

If you suspect a security issue:

1. **Stop NSD**: `sudo killall nsd`
2. **Check Logs**: Review `/var/log/nsd/audit.log`
3. **Verify Files**: Check for unauthorized modifications
4. **Report**: File an issue with security details

## Security Updates

Stay informed about security updates:

1. Watch the GitHub repository for security advisories
2. Subscribe to release notifications
3. Regularly update to the latest version
4. Review the changelog for security fixes

## Compliance

NSD's security features help with compliance requirements:

- **Audit Trails**: Comprehensive logging for compliance
- **Access Control**: Privilege separation and user restrictions
- **Data Protection**: No storage of captured packet contents by default
- **Resource Limits**: Prevents impact on production systems

## Contact

For security concerns or to report vulnerabilities:

- Email: security@nsd.example.com
- Use responsible disclosure practices
- Allow 90 days for fixes before public disclosure