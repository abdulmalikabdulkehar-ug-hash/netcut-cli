# netcut-cli

A Go-based CLI for scanning local networks and isolating devices. Designed for local admin use on trusted networks.

## Features
- **Network scanning** (ARP-based)
- **Device cut-off** (ARP spoofing style isolation)
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

### 1) Scan a network (auto interface + subnet)
```bash
sudo go run ./main.go -scan
```

### 2) Scan a network (custom interface + CIDR)
```bash
sudo go run ./main.go -scan -cidr 192.168.0.0/24 -i wlp49s0
```

### 3) Cut off a device by IP
```bash
sudo go run ./main.go -cut -ip 192.168.0.2 -g 192.168.0.1 -i wlp49s0
```

### 4) Cut off a device by IP + MAC
```bash
sudo go run ./main.go -cut -ip 192.168.0.2 -mac 7c:fd:6b:aa:bb:cc -g 192.168.0.1 -i wlp49s0
```

## Flags
| Flag | Description |
|------|-------------|
| `-scan` | Scan the network |
| `-cidr` | CIDR for scan (defaults to interface subnet) |
| `-cut` | Cut off a device |
| `-ip` | Target IP (required for cut) |
| `-mac` | Target MAC (optional) |
| `-g` | Gateway IP (required for cut) |
| `-i` | Interface name (default: auto-detect) |

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
