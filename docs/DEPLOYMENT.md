# NSD Deployment Guide

## Table of Contents

1. [Overview](#overview)
2. [System Requirements](#system-requirements)
3. [Installation Methods](#installation-methods)
4. [Production Configuration](#production-configuration)
5. [Security Hardening](#security-hardening)
6. [Performance Tuning](#performance-tuning)
7. [Monitoring and Logging](#monitoring-and-logging)
8. [High Availability](#high-availability)
9. [Containerization](#containerization)
10. [Automation](#automation)
11. [Troubleshooting](#troubleshooting)
12. [Maintenance](#maintenance)

## Overview

This guide covers deploying NSD in production environments, including security hardening, performance optimization, and operational best practices.

## System Requirements

### Minimum Requirements

- **CPU**: 2 cores (x86_64 or ARM64)
- **RAM**: 2GB
- **Storage**: 100MB for application + space for logs
- **Network**: Gigabit Ethernet recommended
- **OS**: Linux (kernel 3.10+), macOS 10.14+, Windows 10+

### Recommended Production Requirements

- **CPU**: 4+ cores
- **RAM**: 4-8GB
- **Storage**: 1GB SSD + separate partition for logs
- **Network**: 10 Gigabit for high-traffic environments
- **OS**: Linux (kernel 5.0+) with real-time patches

### Software Dependencies

- libpcap 1.8+ (Linux/macOS) or Npcap (Windows)
- Go 1.21+ (for building from source)
- systemd (for Linux service management)

## Installation Methods

### 1. Binary Installation

#### Download Pre-built Binaries

```bash
# Linux AMD64
wget https://github.com/user/nsd/releases/latest/download/nsd-linux-amd64
chmod +x nsd-linux-amd64
sudo mv nsd-linux-amd64 /usr/local/bin/nsd

# Linux ARM64
wget https://github.com/user/nsd/releases/latest/download/nsd-linux-arm64
chmod +x nsd-linux-arm64
sudo mv nsd-linux-arm64 /usr/local/bin/nsd

# macOS
wget https://github.com/user/nsd/releases/latest/download/nsd-darwin-amd64
chmod +x nsd-darwin-amd64
sudo mv nsd-darwin-amd64 /usr/local/bin/nsd
```

### 2. Building from Source

```bash
# Clone repository
git clone https://github.com/user/nsd.git
cd nsd

# Install dependencies
make deps

# Build binary
make build

# Install system-wide
sudo make install
```

### 3. Package Managers

#### APT (Debian/Ubuntu)

```bash
# Add repository
curl -fsSL https://nsd.example.com/apt/gpg | sudo apt-key add -
echo "deb https://nsd.example.com/apt stable main" | sudo tee /etc/apt/sources.list.d/nsd.list

# Install
sudo apt update
sudo apt install nsd
```

#### YUM/DNF (RHEL/CentOS/Fedora)

```bash
# Add repository
sudo tee /etc/yum.repos.d/nsd.repo <<EOF
[nsd]
name=NSD Repository
baseurl=https://nsd.example.com/rpm
enabled=1
gpgcheck=1
gpgkey=https://nsd.example.com/rpm/gpg
EOF

# Install
sudo yum install nsd
```

#### Homebrew (macOS)

```bash
brew tap user/nsd
brew install nsd
```

### 4. Docker Installation

```bash
docker pull nsd/nsd:latest
```

## Production Configuration

### 1. Create Dedicated User

```bash
# Create system user for NSD
sudo useradd -r -s /bin/false -d /var/lib/nsd -m nsd

# Create directories
sudo mkdir -p /etc/nsd
sudo mkdir -p /var/log/nsd
sudo mkdir -p /var/lib/nsd

# Set permissions
sudo chown -R nsd:nsd /var/log/nsd
sudo chown -R nsd:nsd /var/lib/nsd
sudo chown -R root:nsd /etc/nsd
sudo chmod 750 /etc/nsd
```

### 2. Configuration File

Create `/etc/nsd/config.json`:

```json
{
  "interface": "eth0",
  "bpf_filter": "",
  "theme": "Dark+",
  "style": "Standard",
  "drop_privileges": true,
  "unprivileged_user": "nsd",
  "log_level": "info",
  "log_file": "/var/log/nsd/nsd.log",
  "stats_interval": 5,
  "packet_buffer_size": 1000,
  "connection_timeout": 300,
  "export_dir": "/var/lib/nsd/exports",
  "plugin_dir": "/usr/lib/nsd/plugins",
  "rate_limiting": {
    "enabled": true,
    "max_packets_per_sec": 100000,
    "max_bytes_per_sec": 1073741824,
    "max_connections": 10000
  },
  "resource_limits": {
    "max_memory_mb": 2048,
    "max_cpu_percent": 80.0,
    "max_goroutines": 1000
  }
}
```

### 3. Security Configuration

Create `/etc/nsd/security.json`:

```json
{
  "drop_privileges": true,
  "unprivileged_user": "nsd",
  "enable_promiscuous": false,
  "allowed_interfaces": ["eth0", "eth1"],
  "enable_plugins": false,
  "allow_file_export": true,
  "export_directory": "/var/lib/nsd/exports",
  "max_export_size": 104857600,
  "allowed_export_types": ["json", "csv"],
  "enable_rate_limiting": true,
  "max_packets_per_sec": 100000,
  "max_bytes_per_sec": 1073741824,
  "max_connections": 10000,
  "enable_audit_log": true,
  "audit_log_path": "/var/log/nsd/audit.log",
  "log_sensitive_data": false,
  "max_memory_mb": 2048,
  "max_cpu_percent": 80.0,
  "max_goroutines": 1000
}
```

### 4. Systemd Service

Create `/etc/systemd/system/nsd.service`:

```ini
[Unit]
Description=NSD Network Sniffing Dashboard
Documentation=https://github.com/user/nsd
After=network.target

[Service]
Type=simple
User=root
Group=nsd
ExecStartPre=/usr/bin/test -f /etc/nsd/config.json
ExecStart=/usr/local/bin/nsd -config /etc/nsd/config.json
Restart=on-failure
RestartSec=10

# Security
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/nsd /var/lib/nsd
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
LockPersonality=true
RestrictRealtime=true
RestrictNamespaces=true
RestrictSUIDSGID=true

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096
MemoryMax=2G
CPUQuota=80%

# Capabilities
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN CAP_SETUID CAP_SETGID
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN CAP_SETUID CAP_SETGID

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable nsd
sudo systemctl start nsd
```

## Security Hardening

### 1. Network Isolation

```bash
# Create dedicated network namespace (optional)
sudo ip netns add nsd
sudo ip link set eth1 netns nsd

# Run NSD in namespace
sudo ip netns exec nsd nsd -i eth1
```

### 2. SELinux Policy (RHEL/CentOS)

```bash
# Install policy development tools
sudo yum install selinux-policy-devel

# Create policy module
cat > nsd.te <<EOF
policy_module(nsd, 1.0.0)

require {
    type nsd_t;
    type nsd_exec_t;
    class capability { net_raw net_admin setuid setgid };
    class packet_socket { create bind ioctl };
}

# Allow NSD to capture packets
allow nsd_t self:capability { net_raw net_admin setuid setgid };
allow nsd_t self:packet_socket { create bind ioctl };
EOF

# Compile and install
make -f /usr/share/selinux/devel/Makefile
sudo semodule -i nsd.pp
```

### 3. AppArmor Profile (Ubuntu/Debian)

Create `/etc/apparmor.d/usr.local.bin.nsd`:

```
#include <tunables/global>

/usr/local/bin/nsd {
  #include <abstractions/base>
  
  capability net_raw,
  capability net_admin,
  capability setuid,
  capability setgid,
  
  network raw,
  network packet,
  
  /usr/local/bin/nsd mr,
  /etc/nsd/* r,
  /var/log/nsd/* w,
  /var/lib/nsd/** rw,
  /proc/sys/net/core/* r,
  /sys/class/net/ r,
  /sys/class/net/** r,
}
```

Load the profile:

```bash
sudo apparmor_parser -r /etc/apparmor.d/usr.local.bin.nsd
```

### 4. Firewall Configuration

```bash
# iptables rules for monitoring interface
sudo iptables -A INPUT -i eth0 -j NFLOG --nflog-group 1
sudo iptables -A OUTPUT -o eth0 -j NFLOG --nflog-group 1

# Save rules
sudo iptables-save > /etc/iptables/rules.v4
```

## Performance Tuning

### 1. Kernel Parameters

Add to `/etc/sysctl.d/99-nsd.conf`:

```bash
# Increase network buffer sizes
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728

# Increase packet processing rate
net.core.netdev_budget = 600
net.core.netdev_budget_usecs = 20000

# Enable packet timestamping
net.core.tstamp_allow_data = 1
```

Apply settings:

```bash
sudo sysctl -p /etc/sysctl.d/99-nsd.conf
```

### 2. CPU Affinity

```bash
# Bind NSD to specific CPU cores
sudo taskset -c 2,3 nsd -i eth0

# Or in systemd service
[Service]
CPUAffinity=2 3
```

### 3. Network Card Optimization

```bash
# Increase ring buffer sizes
sudo ethtool -G eth0 rx 4096 tx 4096

# Enable offloading features
sudo ethtool -K eth0 rx-checksumming on
sudo ethtool -K eth0 tx-checksumming on
sudo ethtool -K eth0 gso on
sudo ethtool -K eth0 gro on

# Set interrupt coalescing
sudo ethtool -C eth0 adaptive-rx on adaptive-tx on
```

### 4. NUMA Optimization

```bash
# Run on specific NUMA node
numactl --cpunodebind=0 --membind=0 nsd -i eth0
```

## Monitoring and Logging

### 1. Log Rotation

Create `/etc/logrotate.d/nsd`:

```
/var/log/nsd/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 nsd nsd
    sharedscripts
    postrotate
        systemctl reload nsd > /dev/null 2>&1 || true
    endscript
}
```

### 2. Monitoring with Prometheus

NSD can export metrics in Prometheus format:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'nsd'
    static_configs:
      - targets: ['localhost:9100']
```

### 3. Alerting Rules

```yaml
# nsd_alerts.yml
groups:
  - name: nsd
    rules:
      - alert: NSDHighPacketLoss
        expr: nsd_packet_loss_rate > 0.01
        for: 5m
        annotations:
          summary: "High packet loss detected"
          
      - alert: NSDHighMemoryUsage
        expr: nsd_memory_usage_mb > 1800
        for: 10m
        annotations:
          summary: "NSD memory usage is high"
```

### 4. Integration with ELK Stack

```json
// filebeat.yml
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/log/nsd/*.log
    fields:
      service: nsd
    multiline.pattern: '^\d{4}-\d{2}-\d{2}'
    multiline.negate: true
    multiline.match: after
```

## High Availability

### 1. Active-Passive Setup

```bash
# Install keepalived
sudo apt install keepalived

# Configure VRRP
cat > /etc/keepalived/keepalived.conf <<EOF
vrrp_instance VI_1 {
    state MASTER
    interface eth0
    virtual_router_id 51
    priority 100
    advert_int 1
    authentication {
        auth_type PASS
        auth_pass secret123
    }
    virtual_ipaddress {
        192.168.1.100
    }
    notify_master /etc/keepalived/nsd_master.sh
    notify_backup /etc/keepalived/nsd_backup.sh
}
EOF
```

### 2. Load Balancing with HAProxy

```
# haproxy.cfg
frontend nsd_frontend
    bind *:8080
    default_backend nsd_backend

backend nsd_backend
    balance roundrobin
    server nsd1 192.168.1.10:8080 check
    server nsd2 192.168.1.11:8080 check
```

### 3. Data Replication

```bash
# Sync data between nodes
*/5 * * * * rsync -avz /var/lib/nsd/ nsd2:/var/lib/nsd/
```

## Containerization

### 1. Docker Deployment

Create `Dockerfile`:

```dockerfile
FROM alpine:3.18

RUN apk add --no-cache \
    libpcap \
    ca-certificates \
    tzdata

COPY nsd /usr/local/bin/
COPY config.json /etc/nsd/

RUN adduser -D -s /bin/false nsd

USER root
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/nsd"]
CMD ["-config", "/etc/nsd/config.json"]
```

Build and run:

```bash
# Build image
docker build -t nsd:latest .

# Run with host network
docker run -d \
  --name nsd \
  --network host \
  --cap-add NET_RAW \
  --cap-add NET_ADMIN \
  -v /etc/nsd:/etc/nsd:ro \
  -v /var/log/nsd:/var/log/nsd \
  nsd:latest
```

### 2. Docker Compose

```yaml
version: '3.8'

services:
  nsd:
    image: nsd:latest
    container_name: nsd
    network_mode: host
    cap_add:
      - NET_RAW
      - NET_ADMIN
    volumes:
      - ./config:/etc/nsd:ro
      - nsd-logs:/var/log/nsd
      - nsd-data:/var/lib/nsd
    restart: unless-stopped
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G
        reservations:
          cpus: '1'
          memory: 1G

volumes:
  nsd-logs:
  nsd-data:
```

### 3. Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: nsd
  namespace: monitoring
spec:
  selector:
    matchLabels:
      app: nsd
  template:
    metadata:
      labels:
        app: nsd
    spec:
      hostNetwork: true
      containers:
      - name: nsd
        image: nsd:latest
        securityContext:
          capabilities:
            add:
              - NET_RAW
              - NET_ADMIN
          runAsUser: 0
        resources:
          limits:
            memory: "2Gi"
            cpu: "2"
          requests:
            memory: "1Gi"
            cpu: "1"
        volumeMounts:
        - name: config
          mountPath: /etc/nsd
        - name: logs
          mountPath: /var/log/nsd
      volumes:
      - name: config
        configMap:
          name: nsd-config
      - name: logs
        hostPath:
          path: /var/log/nsd
          type: DirectoryOrCreate
```

## Automation

### 1. Ansible Playbook

```yaml
---
- name: Deploy NSD
  hosts: monitoring
  become: yes
  tasks:
    - name: Create nsd user
      user:
        name: nsd
        system: yes
        shell: /bin/false
        home: /var/lib/nsd

    - name: Create directories
      file:
        path: "{{ item }}"
        state: directory
        owner: nsd
        group: nsd
        mode: '0750'
      loop:
        - /etc/nsd
        - /var/log/nsd
        - /var/lib/nsd

    - name: Copy binary
      copy:
        src: nsd
        dest: /usr/local/bin/nsd
        mode: '0755'

    - name: Copy configuration
      template:
        src: config.json.j2
        dest: /etc/nsd/config.json
        owner: root
        group: nsd
        mode: '0640'

    - name: Install systemd service
      copy:
        src: nsd.service
        dest: /etc/systemd/system/nsd.service

    - name: Start NSD
      systemd:
        name: nsd
        state: started
        enabled: yes
        daemon_reload: yes
```

### 2. Terraform Module

```hcl
# modules/nsd/main.tf
resource "aws_instance" "nsd" {
  ami           = var.ami_id
  instance_type = var.instance_type
  
  user_data = templatefile("${path.module}/user-data.sh", {
    nsd_version = var.nsd_version
    config         = var.nsd_config
  })
  
  tags = {
    Name = "nsd-${var.environment}"
    Type = "monitoring"
  }
}

resource "aws_security_group" "nsd" {
  name_prefix = "nsd-"
  
  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidrs
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
```

## Troubleshooting

### Common Issues

#### 1. Permission Denied

```bash
# Check user permissions
id nsd

# Check file permissions
ls -la /etc/nsd/
ls -la /var/log/nsd/

# Check SELinux context
ls -Z /usr/local/bin/nsd

# Fix permissions
sudo chown -R nsd:nsd /var/log/nsd
sudo restorecon -R /usr/local/bin/nsd
```

#### 2. High CPU Usage

```bash
# Check process details
top -p $(pgrep nsd)

# Check goroutine count
curl http://localhost:6060/debug/pprof/goroutine?debug=1

# Limit CPU usage
systemctl edit nsd
# Add: CPUQuota=50%
```

#### 3. Memory Leaks

```bash
# Generate memory profile
curl http://localhost:6060/debug/pprof/heap > heap.prof
go tool pprof heap.prof

# Check memory usage
ps aux | grep nsd
```

#### 4. Packet Loss

```bash
# Check interface statistics
ip -s link show eth0

# Check ring buffer
ethtool -S eth0 | grep -i drop

# Increase buffer sizes
sudo ethtool -G eth0 rx 4096
```

### Debug Mode

```bash
# Run with debug logging
nsd -i eth0 -log-level debug

# Enable pprof endpoint
nsd -i eth0 -pprof :6060

# Trace execution
strace -f -e trace=network nsd -i eth0
```

## Maintenance

### 1. Regular Tasks

```bash
# Weekly maintenance script
#!/bin/bash
# /etc/cron.weekly/nsd-maintenance

# Rotate logs
logrotate -f /etc/logrotate.d/nsd

# Clean old exports
find /var/lib/nsd/exports -mtime +30 -delete

# Check disk space
df -h /var/log/nsd

# Verify service health
systemctl is-active nsd || systemctl restart nsd
```

### 2. Backup Strategy

```bash
# Backup configuration and data
#!/bin/bash
BACKUP_DIR="/backup/nsd/$(date +%Y%m%d)"
mkdir -p "$BACKUP_DIR"

# Backup configs
tar -czf "$BACKUP_DIR/config.tar.gz" /etc/nsd/

# Backup data
tar -czf "$BACKUP_DIR/data.tar.gz" /var/lib/nsd/

# Backup logs
tar -czf "$BACKUP_DIR/logs.tar.gz" /var/log/nsd/

# Keep last 30 days
find /backup/nsd -mtime +30 -delete
```

### 3. Monitoring Checklist

- [ ] Service status and uptime
- [ ] CPU and memory usage
- [ ] Disk space for logs
- [ ] Network interface errors
- [ ] Packet capture statistics
- [ ] Error rate in logs
- [ ] Security audit logs

### 4. Update Procedure

```bash
# 1. Download new version
wget https://github.com/user/nsd/releases/latest/download/nsd-linux-amd64

# 2. Verify checksum
sha256sum -c nsd-linux-amd64.sha256

# 3. Backup current version
sudo cp /usr/local/bin/nsd /usr/local/bin/nsd.bak

# 4. Stop service
sudo systemctl stop nsd

# 5. Replace binary
sudo mv nsd-linux-amd64 /usr/local/bin/nsd
sudo chmod +x /usr/local/bin/nsd

# 6. Start service
sudo systemctl start nsd

# 7. Verify
sudo systemctl status nsd
journalctl -u nsd -n 50
```

## Best Practices Summary

1. **Security First**
   - Always drop privileges after initialization
   - Use strict file permissions
   - Enable SELinux/AppArmor policies
   - Implement network isolation where possible

2. **Performance**
   - Use BPF filters to reduce processing
   - Tune kernel parameters for packet capture
   - Set appropriate resource limits
   - Monitor performance metrics

3. **Reliability**
   - Implement proper logging and rotation
   - Set up monitoring and alerting
   - Plan for high availability
   - Regular backups and maintenance

4. **Operations**
   - Automate deployment with configuration management
   - Use version control for configurations
   - Document custom configurations
   - Test updates in staging environment

## Support

For deployment support:
- Documentation: https://nsd.example.com/docs
- Issues: https://github.com/user/nsd/issues
- Community: https://forum.nsd.example.com