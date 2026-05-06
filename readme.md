# netcut-cli

A Go-based CLI for scanning local networks and isolating devices. Designed for local admin use on trusted networks.

## Features
- **Network scanning** (ARP-based)
- **Device cut-off** (ARP spoofing style isolation)
- **Web UI** for scanning and control
- **Safety controls** (allowlist/denylist, dry-run, restore)
- **Bandwidth limiting** *(in development)*

## Requirements
- Linux/macOS
- Root privileges (raw packet access)
- Go 1.20+

## Install
```bash
git clone https://github.com/abdulmalikabdulkehar-ug-hash/netcut-cli
cd netcut-cli
go mod tidy
```

## Usage

### 1) Scan a network (auto interface, auto CIDR)
```bash
sudo go run ./main.go -scan
```

### 2) Scan a network (explicit)
```bash
sudo go run ./main.go -scan -cidr 192.168.0.0/24 -i wlp49s0
```

### 3) Cut off a device by IP (with duration)
```bash
sudo go run ./main.go -cut -ip 192.168.0.2 -g 192.168.0.1 -duration 2m
```

### 4) Start the web UI
```bash
sudo go run ./main.go -web -i auto -web-gateway 192.168.0.1
```
Then open http://localhost:8080 in your browser.

## Flags
| Flag | Description |
|------|-------------|
| `-scan` | Scan the network |
| `-cidr` | CIDR for scan (defaults to interface subnet) |
| `-cut` | Cut off a device |
| `-ip` | Target IP (required for cut) |
| `-mac` | Target MAC (optional) |
| `-g` | Gateway IP (required for cut) |
| `-i` | Interface name or `auto` (default: `auto`) |
| `-duration` | How long to keep the device offline (0 = until interrupted) |
| `-restore` | Restore device ARP cache when cut ends (default: true) |
| `-dry-run` | Do not send packets; log actions only |
| `-allowlist` | Comma-separated IPs/CIDRs allowed for cut |
| `-denylist` | Comma-separated IPs/CIDRs blocked for cut |
| `-web` | Run the web UI server |
| `-web-addr` | Web UI listen address (default: :8080) |
| `-web-gateway` | Default gateway for web actions |
| `-web-cidr` | Default CIDR for web scan |
| `-web-allowlist` | Comma-separated IPs/CIDRs allowed for web actions |
| `-web-denylist` | Comma-separated IPs/CIDRs blocked for web actions |
| `-web-dry-run` | Do not send packets from web actions |
| `-web-restore` | Restore device after web cut (default: true) |

## Example Output
```
Scanning network 192.168.0.0/24...
Waiting for responses...
Discovered device: IP=192.168.0.2, MAC=7c:fd:6b:xx:xx:xx, HOSTNAME: []
Stopping packet capture after scan completion.
2024/10/23 15:42:25 Cut off device: IP: 192.168.0.2, MAC: 7c:fd:6b:xx:xx:xx, HOSTNAME: []
```

## Disclaimer
Use only on networks you own or are authorized to manage.
