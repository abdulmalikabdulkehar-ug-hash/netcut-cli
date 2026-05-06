# netcut-cli

A Go-based CLI (and optional web UI) for scanning local networks and isolating devices. Designed for local admin use on trusted networks.

## Features
- **Network scanning** (ARP-based)
- **Device cut-off** (ARP spoofing style isolation)
- **Duration-based cut-off with auto-restore** – cut a device for a fixed window, then automatically repair its ARP table
- **Web UI + JSON API** – browser-based dashboard served on `:8080` by default
- **Allowlist / denylist safety guards** – protect specific devices from accidental cut-off
- **Dry-run mode** – preview actions without sending any packets
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

### 1) Scan a network
```bash
sudo go run ./main.go -scan -cidr 192.168.0.0/24 -i wlp49s0
```

### 2) Cut off a device by IP
```bash
sudo go run ./main.go -cut -ip 192.168.0.2 -g 192.168.0.1 -i wlp49s0
```

### 3) Cut off a device by IP + MAC
```bash
sudo go run ./main.go -cut -ip 192.168.0.2 -mac 7c:fd:6b:aa:bb:cc -g 192.168.0.1 -i wlp49s0
```

### 4) Cut off for a fixed duration, then restore
```bash
# Cuts the device for 5 minutes and then automatically restores it
sudo go run ./main.go -cut -ip 192.168.0.2 -g 192.168.0.1 -i wlp49s0 -duration 5m
```

### 5) Start the web UI
```bash
sudo go run ./main.go -web -g 192.168.0.1 -i wlp49s0
# Open http://localhost:8080 in your browser
```

Use `-port` to change the default listen address:
```bash
sudo go run ./main.go -web -g 192.168.0.1 -i wlp49s0 -port :9090
```

### 6) Safety guards – allowlist & denylist
```bash
# Only allow cutting devices 192.168.0.5 and 192.168.0.6
sudo go run ./main.go -cut -ip 192.168.0.5 -g 192.168.0.1 -allow "192.168.0.5,192.168.0.6"

# Never cut the printer or NAS
sudo go run ./main.go -web -g 192.168.0.1 -deny "192.168.0.10,aa:bb:cc:dd:ee:ff"
```

### 7) Dry-run (no packets sent)
```bash
sudo go run ./main.go -cut -ip 192.168.0.2 -g 192.168.0.1 -dry
```

## Flags
| Flag | Description |
|------|-------------|
| `-scan` | Scan the network |
| `-cidr` | CIDR for scan (e.g., `192.168.0.0/24`) |
| `-cut` | Cut off a device |
| `-ip` | Target IP (required for `-cut`) |
| `-mac` | Target MAC (optional for `-cut`) |
| `-g` | Gateway IP (required for `-cut` and `-web`) |
| `-i` | Interface name (default: `wlp49s0`) |
| `-duration` | Cut-off window, then auto-restore (e.g., `30s`, `5m`, `1h`) |
| `-web` | Start the web UI on the address given by `-port` |
| `-port` | Web UI listen address (default: `:8080`) |
| `-allow` | Comma-separated allowlist of IPs/MACs (empty = allow all) |
| `-deny` | Comma-separated denylist of IPs/MACs (never touched) |
| `-dry` | Dry-run: print intended actions but send no packets |

## Web UI API
The web UI also exposes a JSON API for scripting:

| Method | Path | Body | Description |
|--------|------|------|-------------|
| `POST` | `/api/scan` | `{"cidr":"..."}` | ARP-scan the given CIDR |
| `POST` | `/api/cut` | `{"ip":"...","mac":"...","gateway":"...","duration":"..."}` | Cut off a device |
| `POST` | `/api/restore` | `{"ip":"...","mac":"...","gateway":"..."}` | Restore a device |

All responses are JSON. Successful cut/restore requests return HTTP `202 Accepted` and run asynchronously.

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
