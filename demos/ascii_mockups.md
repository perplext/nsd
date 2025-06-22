# NSD Visual Interface Mockups

These ASCII mockups demonstrate how NSD appears with different themes and visualizations.

## Tokyo Night Theme - Overview Dashboard

```
┌─ NSD v1.0 - Network Sniffing Dashboard ─────────────────────────────────────────┐
│ Interface: en0 [192.168.50.118]                    Theme: Tokyo Night    ↑↓ 12Mb │
├──────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│ ┌─ Traffic Overview ──────────────────┐  ┌─ Top Connections ──────────────────┐ │
│ │                                     │  │ 192.168.50.1    → 443      15.2MB │ │
│ │     ██████████████████████████      │  │ 17.253.144.10   → 443       8.7MB │ │
│ │   ████████████████████████████████  │  │ 140.82.112.3    → 443       4.1MB │ │
│ │ ████████████████████████████████████│  │ 199.232.57.219  → 443       2.3MB │ │
│ │████████████████████████████████████ │  │ 54.230.87.15    → 80        1.8MB │ │
│ │████████████████████████████████████ │  │ 185.199.108.153 → 443       1.2MB │ │
│ │  ████████████████████████████████   │  │ 151.101.193.140 → 443       0.9MB │ │
│ │    ████████████████████████████     │  │ 104.16.249.249  → 443       0.7MB │ │
│ │      ████████████████████████       │  └─────────────────────────────────────┘ │
│ │        ████████████████████         │                                          │
│ │          ████████████████           │  ┌─ Protocol Breakdown ───────────────┐ │
│ │            ████████████             │  │ HTTPS  ████████████████████ 76.3%  │ │
│ │              ████████               │  │ HTTP   ████████░░░░░░░░░░░░ 15.2%  │ │
│ │                ████                 │  │ DNS    ██░░░░░░░░░░░░░░░░░░░  4.1%  │ │
│ │                 ██                  │  │ SSH    █░░░░░░░░░░░░░░░░░░░░  2.8%  │ │
│ │                  █                  │  │ OTHER  █░░░░░░░░░░░░░░░░░░░░  1.6%  │ │
│ │ ┌───────────────┬───────────────────┐ │  └─────────────────────────────────────┘ │
│ │ │    Upload     │    Download       │ │                                          │
│ │ │   2.4 MB/s    │    9.8 MB/s       │ │  ┌─ Security Alerts ──────────────────┐ │
│ │ └───────────────┴───────────────────┘ │  │ ⚠️  Port Scan Detected              │ │
│ └─────────────────────────────────────────┘  │     192.168.50.254 → Multiple      │ │
│                                              │                                    │ │
│ ┌─ Active Connections ────────────────────────┐  │ ℹ️  New Device Connected            │ │
│ │ Local         Remote            State  Time │  │     iPhone-12 [192.168.50.205]    │ │
│ │ 192.168.50.118:62847 → 17.57.146.52:443    │  │                                    │ │
│ │ ESTABLISHED                           00:45 │  │ ✅ SSL Certificate Valid           │ │
│ │ 192.168.50.118:62851 → 140.82.112.3:443    │  │     github.com                     │ │
│ │ ESTABLISHED                           00:32 │  └─────────────────────────────────────┘ │
│ │ 192.168.50.118:62853 → 151.101.193.140:443 │                                          │
│ │ ESTABLISHED                           00:18 │                                          │
│ │ 192.168.50.118:53012 → 8.8.8.8:53          │                                          │
│ │ TIME_WAIT                             00:01 │                                          │
│ └─────────────────────────────────────────────┘                                          │
├──────────────────────────────────────────────────────────────────────────────────┤
│ [Tab] Switch Panels  [v] Visualizations  [t] Themes  [s] Security  [q] Quit      │
└──────────────────────────────────────────────────────────────────────────────────┘
```

## High-Contrast Dark Theme - Security Dashboard

```
┏━ NSD - SECURITY DASHBOARD ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Interface: en0                    Theme: High-Contrast Dark        SECURITY MODE ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃                                                                                  ┃
┃ ┏━ THREAT DETECTION ━━━━━━━━━━━━━━━┓  ┏━ ANOMALY DETECTION ━━━━━━━━━━━━━━━━━━━━━━━┓ ┃
┃ ┃                                ┃  ┃                                          ┃ ┃
┃ ┃ 🚨 CRITICAL: Port Scan         ┃  ┃ ⚡ Traffic Spike: +340% baseline        ┃ ┃
┃ ┃    Source: 192.168.50.254      ┃  ┃    Protocol: HTTPS                       ┃ ┃
┃ ┃    Ports: 22,80,443,8080,3389  ┃  ┃    Duration: 00:02:34                    ┃ ┃
┃ ┃    Time: 14:23:45              ┃  ┃                                          ┃ ┃
┃ ┃                                ┃  ┃ ⚡ New Geographic Location               ┃ ┃
┃ ┃ ⚠️  MEDIUM: Brute Force         ┃  ┃    Country: Romania                      ┃ ┃
┃ ┃    Protocol: SSH               ┃  ┃    ASN: AS13335 Cloudflare              ┃ ┃
┃ ┃    Target: 192.168.50.118:22   ┃  ┃    Confidence: 85%                       ┃ ┃
┃ ┃    Attempts: 127               ┃  ┃                                          ┃ ┃
┃ ┃    Duration: 00:08:12          ┃  ┃ ⚡ Protocol Anomaly                      ┃ ┃
┃ ┃                                ┃  ┃    Unexpected DNS over HTTPS             ┃ ┃
┃ ┃ ℹ️  INFO: SSL Cert Change       ┃  ┃    Destination: 1.1.1.1:853             ┃ ┃
┃ ┃    Domain: api.github.com      ┃  ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛ ┃
┃ ┃    Old: SHA256:ABC123...       ┃                                             ┃
┃ ┃    New: SHA256:DEF456...       ┃  ┏━ BLOCKED CONNECTIONS ━━━━━━━━━━━━━━━━━━━━━┓ ┃
┃ ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛  ┃                                          ┃ ┃
┃                                   ┃ 🛡️  192.168.50.254 → 192.168.50.118:22  ┃ ┃
┃ ┏━ TRAFFIC ANALYSIS ━━━━━━━━━━━━━━┓  ┃     Reason: SSH Brute Force              ┃ ┃
┃ ┃                               ┃  ┃     Count: 127 attempts                  ┃ ┃
┃ ┃ ████████████████████████████  ┃  ┃                                          ┃ ┃
┃ ┃ ████░░░░░░░░░░░░░░░░░░░░░░░░░░ ┃  ┃ 🛡️  45.32.18.94 → 192.168.50.118:80   ┃ ┃
┃ ┃ ████░░░░░░░░░░░░░░░░░░░░░░░░░░ ┃  ┃     Reason: Malware C&C                  ┃ ┃
┃ ┃ ████░░░░░░░░░░░░░░░░░░░░░░░░░░ ┃  ┃     Threat Intel: AlienVault             ┃ ┃
┃ ┃ ████░░░░░░░░░░░░░░░░░░░░░░░░░░ ┃  ┃                                          ┃ ┃
┃ ┃ Normal ████████████████████   ┃  ┃ 🛡️  bad-actor.net → Multiple Ports      ┃ ┃
┃ ┃ Suspicious ████░░░░░░░░░░░░░░ ┃  ┃     Reason: Known Bad Domain             ┃ ┃
┃ ┃ Malicious ██░░░░░░░░░░░░░░░░░ ┃  ┃     Last Seen: 00:00:12 ago              ┃ ┃
┃ ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛  ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛ ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ [ENTER] Details  [f] Filter  [a] Alert Config  [b] Block IP  [q] Quit          ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
```

## Dracula Theme - Speedometer Visualization

```
╭─ NSD - Network Traffic Monitor ─────────────────────────────────────────────────╮
│ Interface: en0 [192.168.50.118]                       Theme: Dracula     14:25:33│
├──────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│                    ┌─ NETWORK SPEEDOMETER ─────────────┐                        │
│                    │                                   │                        │
│                    │         ╭─────────────╮           │                        │
│                    │      ╭─╯    100 Mbps   ╰─╮        │                        │
│                    │    ╭─╯                   ╰─╮      │                        │
│                    │   ╱                       ╲      │                        │
│                    │  ╱           ╭─────╮       ╲     │                        │
│                    │ ╱            │ 12.4│        ╲    │                        │
│                    │╱             │ Mbps│         ╲   │                        │
│                    │              ╰─────╯          ╲  │                        │
│                    │ ╲                            ╱   │                        │
│                    │  ╲                          ╱    │                        │
│                    │   ╲                        ╱     │                        │
│                    │    ╰─╲                  ╱─╯      │                        │
│                    │      ╰─╲              ╱─╯        │                        │
│                    │         ╰─────███────╯           │                        │
│                    │              ╱███╲               │                        │
│                    │             ╱     ╲              │                        │
│                    │            0       50            │                        │
│                    └───────────────────────────────────┘                        │
│                                                                                  │
│ ┌─ Real-time Stats ──────────────┐  ┌─ Traffic History ────────────────────────┐ │
│ │                                │  │                                          │ │
│ │ Download: ████████░░░░ 9.8 MB/s│  │ ████                                     │ │
│ │ Upload:   ███░░░░░░░░░ 2.6 MB/s│  │ ████                                     │ │
│ │                                │  │ ████████                                 │ │
│ │ Packets/sec: 1,247             │  │ ████████                                 │ │
│ │ Active Connections: 23         │  │ ████████████                             │ │
│ │ Bandwidth Utilization: 12.4%   │  │ ████████████████                         │ │
│ │                                │  │ ████████████████████                     │ │
│ │ Peak Today: 24.8 MB/s          │  │ ████████████████████████                 │ │
│ │ Average: 8.2 MB/s              │  │ ████████████████████████████             │ │
│ │ Duration: 02:34:12             │  │ ████████████████████████████████         │ │
│ │                                │  │ ████████████████████████████████████     │ │
│ └────────────────────────────────┘  │ ████████████████████████████████████████ │ │
│                                     │ 0    5min   10min  15min  20min   25min │ │
│                                     └──────────────────────────────────────────┘ │
│                                                                                  │
│ ┌─ Top Applications ─────────────────────────────────────────────────────────────┐ │
│ │ Chrome         ████████████████████████████████████ 8.2 MB/s    │ 65.2%      │ │
│ │ Zoom           ████████████░░░░░░░░░░░░░░░░░░░░░░░░░░ 2.1 MB/s    │ 16.8%      │ │
│ │ Slack          ███░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ 0.8 MB/s    │  6.4%      │ │
│ │ Spotify        ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ 0.6 MB/s    │  4.8%      │ │
│ │ System         █░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ 0.4 MB/s    │  3.2%      │ │
│ │ Other          █░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ 0.3 MB/s    │  2.4%      │ │
│ └────────────────────────────────────────────────────────────────────────────────┘ │
├──────────────────────────────────────────────────────────────────────────────────┤
│ [Space] Pause  [r] Reset  [t] Themes  [v] Visualizations  [q] Quit              │
└──────────────────────────────────────────────────────────────────────────────────┘
```

## Nord Theme - Matrix Visualization

```
┌─ NSD - Connection Matrix ────────────────────────────────────────────────────────┐
│ Interface: en0                                Theme: Nord            Matrix View │
├──────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│ ┌─ Network Connection Matrix ─────────────────────────────────────────────────────┐ │
│ │                                                                                │ │
│ │       192.168.50.1  17.253.144.10  140.82.112.3  199.232.57.219  8.8.8.8    │ │
│ │                                                                                │ │
│ │ .118  ████████████  ████████████   ██████████    ████████       ██████       │ │
│ │                                                                                │ │
│ │ .205  ████████      ██████         ████          ██              ████        │ │
│ │                                                                                │ │
│ │ .187  ██████        ████████       ██████        ████            ██          │ │
│ │                                                                                │ │
│ │ .223  ████          ██             ████          ██████          ████████    │ │
│ │                                                                                │ │
│ │ .154                ██████         ██            ████            ██          │ │
│ │                                                                                │ │
│ │ Legend: ████ >10MB  ████ 1-10MB  ██ 100KB-1MB  ██ <100KB  ░░ No Traffic     │ │
│ └────────────────────────────────────────────────────────────────────────────────┘ │
│                                                                                  │
│ ┌─ Connection Details ────────────────┐  ┌─ Traffic Flow ─────────────────────┐  │
│ │                                     │  │                                    │  │
│ │ Selected: 192.168.50.118            │  │ Outbound: ████████████████ 8.2MB  │  │
│ │ Target: 17.253.144.10 (Apple)       │  │ Inbound:  ██████████████ 6.8MB    │  │
│ │ Protocol: HTTPS (443)               │  │                                    │  │
│ │ Duration: 00:23:45                  │  │ ┌─ Protocol Distribution ─────────┐ │  │
│ │ Bytes Sent: 2.4 MB                  │  │ │ HTTPS  ████████████████ 76.3%  │ │  │
│ │ Bytes Received: 8.9 MB              │  │ │ HTTP   ████░░░░░░░░░░░░ 12.1%  │ │  │
│ │ Packets: 8,432                      │  │ │ DNS    ██░░░░░░░░░░░░░░░  6.2%  │ │  │
│ │ Connection State: ESTABLISHED       │  │ │ SSH    █░░░░░░░░░░░░░░░░  3.8%  │ │  │
│ │                                     │  │ │ Other  █░░░░░░░░░░░░░░░░  1.6%  │ │  │
│ │ Geographic Info:                    │  │ └─────────────────────────────────┘ │  │
│ │ Country: United States              │  └────────────────────────────────────┘  │
│ │ AS: AS714 Apple Inc.                │                                         │
│ │ City: Cupertino, CA                 │  ┌─ Recent Connections ────────────────┐  │
│ │ Coordinates: 37.3230, -122.0322    │  │ 14:25:12 New: github.com:443       │  │
│ │                                     │  │ 14:24:58 Closed: slack.com:443     │  │
│ └─────────────────────────────────────┘  │ 14:24:33 New: api.spotify.com:443  │  │
│                                          │ 14:24:01 New: zoom.us:443          │  │
│                                          │ 14:23:45 Timeout: 8.8.8.8:53       │  │
│                                          └─────────────────────────────────────┘  │
├──────────────────────────────────────────────────────────────────────────────────┤
│ [Arrow Keys] Navigate  [Enter] Details  [m] Map View  [v] Visualizations [q] Quit│
└──────────────────────────────────────────────────────────────────────────────────┘
```

## Gruvbox Theme - Constellation Visualization

```
╔═ NSD - Network Constellation ═══════════════════════════════════════════════════╗
║ Interface: en0 [192.168.50.118]                     Theme: Gruvbox    Realtime ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║                                                                                  ║
║  ╔═ Network Topology ══════════════════════════════════════════════════════════╗ ║
║  ║                                                                              ║ ║
║  ║        ┌─ Router ─┐                ┌─ DNS ─┐                                ║ ║
║  ║        │192.168   │◄──────────────►│8.8.8.8│                               ║ ║
║  ║        │.50.1     │                │       │                               ║ ║
║  ║        └─────┬────┘                └───────┘                               ║ ║
║  ║              │                                                              ║ ║
║  ║              ▼                                                              ║ ║
║  ║        ┌─ THIS HOST ─┐                                                      ║ ║
║  ║        │ 192.168     │                                                      ║ ║
║  ║        │ .50.118     │◄─────┐                                              ║ ║
║  ║        │ [MacBook]   │      │                                              ║ ║
║  ║        └──┬────┬─────┘      │                                              ║ ║
║  ║           │    │            │                                              ║ ║
║  ║           ▼    ▼            │                                              ║ ║
║  ║    ┌─ Apple ─┐ ┌─ GitHub ─┐ │                                              ║ ║
║  ║    │17.253   │ │140.82    │ │    ┌─ Cloudflare ─┐                         ║ ║
║  ║    │.144.10  │ │.112.3    │ └───►│199.232.57    │                         ║ ║
║  ║    │iCloud   │ │          │      │.219          │                         ║ ║
║  ║    └─────────┘ └──────────┘      └──────────────┘                         ║ ║
║  ║                                                                              ║ ║
║  ║    Connection Strength:                                                      ║ ║
║  ║    ████████████████ Very Strong (>10MB/s)                                  ║ ║
║  ║    ████████░░░░░░░░ Strong (1-10MB/s)                                      ║ ║
║  ║    ████░░░░░░░░░░░░ Medium (100KB-1MB/s)                                   ║ ║
║  ║    ██░░░░░░░░░░░░░░ Weak (<100KB/s)                                        ║ ║
║  ║                                                                              ║ ║
║  ╚══════════════════════════════════════════════════════════════════════════════╝ ║
║                                                                                  ║
║ ╔═ Active Data Flows ═════════════════════════════════════════════════════════╗  ║
║ ║                                                                             ║  ║
║ ║ github.com          ████████████████████████████ → 4.2 MB/s HTTPS          ║  ║
║ ║ icloud.com          ████████████████████░░░░░░░░ → 3.1 MB/s HTTPS          ║  ║
║ ║ api.spotify.com     ████████░░░░░░░░░░░░░░░░░░░░ → 1.2 MB/s HTTPS          ║  ║
║ ║ cloudflare-dns.com  ██░░░░░░░░░░░░░░░░░░░░░░░░░░ → 0.1 MB/s DNS            ║  ║
║ ║                                                                             ║  ║
║ ╚═════════════════════════════════════════════════════════════════════════════╝  ║
║                                                                                  ║
║ ╔═ Network Statistics ════════════════════════════════════════════════════════╗  ║
║ ║ Total Nodes: 12              Active Connections: 8                         ║  ║
║ ║ Data Centers: 4              Geographic Locations: 6                       ║  ║
║ ║ Protocols: HTTPS(76%) HTTP(15%) DNS(6%) SSH(3%)                           ║  ║
║ ║ Latency: Avg 23ms  Min 8ms  Max 156ms                                     ║  ║
║ ╚═════════════════════════════════════════════════════════════════════════════╝  ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║ [Click] Select Node  [Space] Pause  [+/-] Zoom  [r] Reset  [q] Quit             ║
╚══════════════════════════════════════════════════════════════════════════════════╝
```

## Light+ Theme - Protocol Analysis

```
┌─ NSD - Protocol Analysis Dashboard ──────────────────────────────────────────────┐
│ Interface: en0                                   Theme: Light+      Protocol Mode│
├──────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│ ┌─ SSH Session Analysis ──────────────────┐  ┌─ HTTP/HTTPS Traffic ─────────────┐ │
│ │                                         │  │                                  │ │
│ │ 🔐 Active SSH Sessions: 2               │  │ 🌐 Active HTTP Sessions: 23      │ │
│ │                                         │  │                                  │ │
│ │ Session 1:                              │  │ Top Domains:                     │ │
│ │ ├─ 192.168.50.118 → server.example.com │  │ ├─ github.com        (15 req/s)  │ │
│ │ ├─ User: developer                      │  │ ├─ api.openai.com    (8 req/s)   │ │
│ │ ├─ Duration: 01:23:45                   │  │ ├─ fonts.googleapis. (4 req/s)   │ │
│ │ ├─ Data: 2.4 MB transferred             │  │ ├─ cdn.jsdelivr.net  (3 req/s)   │ │
│ │ └─ Status: ✅ Authenticated             │  │ └─ api.stripe.com    (2 req/s)   │ │
│ │                                         │  │                                  │ │
│ │ Session 2:                              │  │ Status Codes:                    │ │
│ │ ├─ 192.168.50.118 → git.company.com    │  │ 200 OK      ██████████████ 89%  │ │
│ │ ├─ User: admin                          │  │ 404 Not Found ██░░░░░░░░░  6%   │ │
│ │ ├─ Duration: 00:45:12                   │  │ 301 Redirect  █░░░░░░░░░░  3%   │ │
│ │ ├─ Data: 156 KB transferred             │  │ 500 Error     ░░░░░░░░░░░  2%   │ │
│ │ └─ Status: ⚠️  Authentication Failed    │  │                                  │ │
│ └─────────────────────────────────────────┘  └──────────────────────────────────┘ │
│                                                                                  │
│ ┌─ FTP Activity ──────────────────────────┐  ┌─ POP3/IMAP Email ───────────────┐ │
│ │                                         │  │                                  │ │
│ │ 📁 No Active FTP Sessions               │  │ 📧 Email Connections: 1          │ │
│ │                                         │  │                                  │ │
│ │ Recent Activity:                        │  │ IMAP Session:                    │ │
│ │ ├─ 14:20:15 Failed login attempt        │  │ ├─ Server: mail.company.com     │ │
│ │ │  User: anonymous                      │  │ ├─ User: user@company.com       │ │
│ │ │  IP: 192.168.50.254                   │  │ ├─ Status: ✅ Connected          │ │
│ │ └─ 14:18:30 Successful upload           │  │ ├─ Mailbox: INBOX (47 messages) │ │
│ │    File: report.pdf (2.1 MB)           │  │ └─ Last Sync: 00:00:23 ago      │ │
│ │    User: ftpuser                        │  │                                  │ │
│ │    Destination: /uploads/               │  │ Security:                        │ │
│ │                                         │  │ ├─ Encryption: TLS 1.3          │ │
│ │ Security Alerts:                        │  │ ├─ Certificate: ✅ Valid         │ │
│ │ ⚠️  Anonymous login attempts detected   │  │ └─ Auth Method: OAUTH2           │ │
│ │    Count: 15 in last hour              │  │                                  │ │
│ └─────────────────────────────────────────┘  └──────────────────────────────────┘ │
│                                                                                  │
│ ┌─ Protocol Statistics ───────────────────────────────────────────────────────────┐ │
│ │                                                                                │ │
│ │ SSH    ████████████████████░░░░░░░░░░░░░░░░░░░░ 2.1 MB/s  (Sessions: 2)       │ │
│ │ HTTPS  ████████████████████████████████████████ 8.7 MB/s  (Connections: 23)  │ │
│ │ HTTP   ████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ 1.4 MB/s  (Connections: 5)   │ │
│ │ FTP    ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ 0.3 MB/s  (Sessions: 0)      │ │
│ │ IMAP   █░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ 0.1 MB/s  (Sessions: 1)      │ │
│ │ POP3   ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ 0.0 MB/s  (Sessions: 0)      │ │
│ │                                                                                │ │
│ └────────────────────────────────────────────────────────────────────────────────┘ │
├──────────────────────────────────────────────────────────────────────────────────┤
│ [Tab] Switch Protocols  [d] Details  [f] Filter  [a] Alerts  [q] Quit            │
└──────────────────────────────────────────────────────────────────────────────────┘
```

## Solarized Dark Theme with Spanish i18n

```
┌─ NSD - Monitor de Tráfico de Red ────────────────────────────────────────────────┐
│ Interfaz: en0 [192.168.50.118]              Tema: Solarized Dark   Idioma: ES   │
├──────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│ ┌─ Resumen de Tráfico ────────────────────┐  ┌─ Conexiones Principales ───────┐ │
│ │                                         │  │ 192.168.50.1  → 443    15.2MB │ │
│ │     ████████████████████████████████    │  │ 17.253.144.10 → 443     8.7MB │ │
│ │   ████████████████████████████████████  │  │ 140.82.112.3  → 443     4.1MB │ │
│ │ ████████████████████████████████████████│  │ 8.8.8.8       → 53      2.3MB │ │
│ │████████████████████████████████████████ │  │ 151.101.1.140 → 443     1.2MB │ │
│ │████████████████████████████████████████ │  │ 185.199.108.3 → 443     0.9MB │ │
│ │  ████████████████████████████████████   │  │ 104.16.249.29 → 80      0.7MB │ │
│ │    ████████████████████████████████     │  └────────────────────────────────┘ │
│ │      ████████████████████████████       │                                     │
│ │        ████████████████████████         │  ┌─ Análisis de Protocolos ──────┐ │
│ │          ████████████████████           │  │ HTTPS  ████████████████ 76.3% │ │
│ │            ████████████████             │  │ HTTP   ████░░░░░░░░░░░░ 15.2% │ │
│ │              ████████████               │  │ DNS    ██░░░░░░░░░░░░░░  4.1% │ │
│ │                ████████                 │  │ SSH    █░░░░░░░░░░░░░░░  2.8% │ │
│ │                  ████                   │  │ OTROS  █░░░░░░░░░░░░░░░  1.6% │ │
│ │                   ██                    │  └────────────────────────────────┘ │
│ │ ┌─────────────────┬───────────────────┐ │                                     │
│ │ │   Subida        │    Descarga       │ │  ┌─ Alertas de Seguridad ────────┐ │
│ │ │   2.4 MB/s      │    9.8 MB/s       │ │  │ ⚠️  Escaneo de puertos         │ │
│ │ └─────────────────┴───────────────────┘ │  │     192.168.50.254 → Múltiple │ │
│ └─────────────────────────────────────────┘  │                                │ │
│                                              │ ℹ️  Nuevo dispositivo           │ │
│ ┌─ Conexiones Activas ─────────────────────────│     iPhone-12 [.50.205]       │ │
│ │ Local           Remoto          Estado Tiempo│                                │ │
│ │ 192.168.50.118:62847 → 17.57.146.52:443    │ ✅ Certificado SSL válido      │ │
│ │ ESTABLECIDA                         00:45   │     github.com                 │ │
│ │ 192.168.50.118:62851 → 140.82.112.3:443    └────────────────────────────────┘ │
│ │ ESTABLECIDA                         00:32   │                                  │
│ │ 192.168.50.118:62853 → 151.101.193.140:443 │                                  │
│ │ ESTABLECIDA                         00:18   │                                  │
│ │ 192.168.50.118:53012 → 8.8.8.8:53          │                                  │
│ │ TIEMPO_ESPERA                       00:01   │                                  │
│ └─────────────────────────────────────────────┘                                  │
├──────────────────────────────────────────────────────────────────────────────────┤
│ [Tab] Cambiar Panel [v] Visualizaciones [t] Temas [s] Seguridad [q] Salir       │
└──────────────────────────────────────────────────────────────────────────────────┘
```

## Command Line Usage Examples

### Theme Switching
```bash
# List available themes by inspecting the binary
$ ./bin/nsd --help | grep theme
  -auto-theme
    Auto-detect dark/light theme based on terminal background
  -theme string
    Color theme to use (default "Dark+")
  -theme-file string
    Path to custom theme JSON/YAML file

# Use specific theme
$ sudo ./bin/nsd -i en0 -theme "Tokyo Night"
$ sudo ./bin/nsd -i en0 -theme "High-Contrast Dark"
$ sudo ./bin/nsd -i en0 -theme "Gruvbox"
```

### Visualization Modes
```bash
# Different visualization types
$ sudo ./bin/nsd -i en0 -viz speedometer -theme "Dracula"
$ sudo ./bin/nsd -i en0 -viz matrix -theme "Nord"  
$ sudo ./bin/nsd -i en0 -viz constellation -theme "Gruvbox"
$ sudo ./bin/nsd -i en0 -viz heatmap -theme "Tokyo Night"
```

### Security Features
```bash
# Security dashboard
$ sudo ./bin/nsd -i en0 -dashboard security -theme "High-Contrast Dark"

# Full security mode with protocol analysis
$ sudo ./bin/nsd -i en0 -security-mode -protocol-analysis
```

### Custom Themes
```bash
# Create custom theme file
$ cat > my_theme.json << EOF
{
  "Custom Blue": {
    "BorderColor": "#0066cc",
    "TitleColor": "#0066cc",
    "PrimaryColor": "#3399ff",
    "SecondaryColor": "#66ccff",
    "PieBorderColor": "#0066cc",
    "PieTitleColor": "#0066cc", 
    "StatusBarTextColor": "#ffffff",
    "StatusBarBgColor": "#000033"
  }
}
EOF

# Use custom theme
$ sudo ./bin/nsd -i en0 -theme-file my_theme.json -theme "Custom Blue"
```

These mockups demonstrate the rich visual interface and extensive customization options available in NSD, showcasing how different themes completely transform the appearance while maintaining full functionality.