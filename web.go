package main

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/enigma522/netcut-cli/networkScan"
)

type WebOptions struct {
	Addr      string
	Gateway   string
	CIDR      string
	Allowlist []string
	Denylist  []string
	DryRun    bool
	Restore   bool
}

type deviceResponse struct {
	IP       string   `json:"ip"`
	MAC      string   `json:"mac"`
	Hostname []string `json:"hostname"`
}

type cutRequest struct {
	IP       string `json:"ip"`
	MAC      string `json:"mac"`
	Gateway  string `json:"gateway"`
	Duration string `json:"duration"`
	Restore  *bool  `json:"restore"`
}

type restoreRequest struct {
	IP      string `json:"ip"`
	Gateway string `json:"gateway"`
}

type apiResponse struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

func runWebServer(scanner *networkscan.NetworkScanner, options WebOptions) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", serveIndex)
	mux.HandleFunc("/api/scan", func(w http.ResponseWriter, r *http.Request) {
		cidr := r.URL.Query().Get("cidr")
		if cidr == "" {
			cidr = options.CIDR
		}
		if cidr == "" {
			cidr = scanner.DefaultCIDR()
		}
		if cidr == "" {
			writeJSON(w, http.StatusBadRequest, apiResponse{Status: "error", Message: "CIDR is required for scan"})
			return
		}
		devices := scanner.NetScan(cidr)
		response := make([]deviceResponse, 0, len(devices))
		for _, device := range devices {
			response = append(response, deviceResponse{
				IP:       device.IP.String(),
				MAC:      device.MAC.String(),
				Hostname: device.HOSTNAME,
			})
		}
		writeJSON(w, http.StatusOK, response)
	})
	mux.HandleFunc("/api/cut", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Status: "error", Message: "POST only"})
			return
		}
		var req cutRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, apiResponse{Status: "error", Message: "Invalid JSON"})
			return
		}
		if req.IP == "" {
			writeJSON(w, http.StatusBadRequest, apiResponse{Status: "error", Message: "IP is required"})
			return
		}
		if !isAllowed(req.IP, options.Allowlist, options.Denylist) {
			writeJSON(w, http.StatusForbidden, apiResponse{Status: "error", Message: "IP blocked by policy"})
			return
		}
		gateway := req.Gateway
		if gateway == "" {
			gateway = options.Gateway
		}
		if gateway == "" {
			writeJSON(w, http.StatusBadRequest, apiResponse{Status: "error", Message: "Gateway is required"})
			return
		}
		targetIP := net.ParseIP(req.IP)
		if targetIP == nil {
			writeJSON(w, http.StatusBadRequest, apiResponse{Status: "error", Message: "Invalid IP"})
			return
		}
		var device *networkscan.Device
		if req.MAC != "" {
			macAddr, err := net.ParseMAC(req.MAC)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, apiResponse{Status: "error", Message: "Invalid MAC"})
				return
			}
			device = &networkscan.Device{IP: targetIP, MAC: macAddr}
		} else {
			resolved, ok := scanner.ResolveDevice(targetIP)
			if !ok {
				writeJSON(w, http.StatusNotFound, apiResponse{Status: "error", Message: "Device not found"})
				return
			}
			device = resolved
		}

		restore := options.Restore
		if req.Restore != nil {
			restore = *req.Restore
		}

		if options.DryRun {
			log.Printf("[dry-run] web cut IP=%s MAC=%s gateway=%s", device.IP, device.MAC, gateway)
			writeJSON(w, http.StatusOK, apiResponse{Status: "ok", Message: "Dry run: no packets sent"})
			return
		}

		ctx := context.Background()
		var cancel context.CancelFunc
		if req.Duration != "" {
			d, err := time.ParseDuration(req.Duration)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, apiResponse{Status: "error", Message: "Invalid duration"})
				return
			}
			ctx, cancel = context.WithTimeout(ctx, d)
		} else {
			ctx, cancel = context.WithCancel(ctx)
		}
		go func() {
			defer cancel()
			err := scanner.CutOffDevice(ctx, *device, gateway)
			if err != nil && err != context.Canceled && err != context.DeadlineExceeded {
				log.Printf("Cut off stopped with error: %v", err)
			}
			if restore {
				if err := scanner.RestoreDevice(*device, gateway); err != nil {
					log.Printf("Restore failed: %v", err)
				}
			}
		}()
		writeJSON(w, http.StatusOK, apiResponse{Status: "ok", Message: "Cut started"})
	})
	mux.HandleFunc("/api/restore", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Status: "error", Message: "POST only"})
			return
		}
		var req restoreRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, apiResponse{Status: "error", Message: "Invalid JSON"})
			return
		}
		if req.IP == "" {
			writeJSON(w, http.StatusBadRequest, apiResponse{Status: "error", Message: "IP is required"})
			return
		}
		if !isAllowed(req.IP, options.Allowlist, options.Denylist) {
			writeJSON(w, http.StatusForbidden, apiResponse{Status: "error", Message: "IP blocked by policy"})
			return
		}
		gateway := req.Gateway
		if gateway == "" {
			gateway = options.Gateway
		}
		if gateway == "" {
			writeJSON(w, http.StatusBadRequest, apiResponse{Status: "error", Message: "Gateway is required"})
			return
		}
		targetIP := net.ParseIP(req.IP)
		if targetIP == nil {
			writeJSON(w, http.StatusBadRequest, apiResponse{Status: "error", Message: "Invalid IP"})
			return
		}
		device, ok := scanner.ResolveDevice(targetIP)
		if !ok {
			writeJSON(w, http.StatusNotFound, apiResponse{Status: "error", Message: "Device not found"})
			return
		}
		if options.DryRun {
			log.Printf("[dry-run] web restore IP=%s gateway=%s", device.IP, gateway)
			writeJSON(w, http.StatusOK, apiResponse{Status: "ok", Message: "Dry run: no packets sent"})
			return
		}
		if err := scanner.RestoreDevice(*device, gateway); err != nil {
			writeJSON(w, http.StatusInternalServerError, apiResponse{Status: "error", Message: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, apiResponse{Status: "ok", Message: "Device restored"})
	})

	addr := options.Addr
	if addr == "" {
		addr = ":8080"
	}
	log.Printf("Web UI running at http://localhost%s", addr)
	return http.ListenAndServe(addr, mux)
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func serveIndex(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(indexHTML))
}

const indexHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>netcut-cli</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 24px; }
    table { border-collapse: collapse; width: 100%; margin-top: 12px; }
    th, td { border: 1px solid #ddd; padding: 8px; }
    th { background: #f4f4f4; }
    input, button { margin: 4px; }
  </style>
</head>
<body>
  <h1>netcut-cli Web UI</h1>
  <section>
    <h2>Scan</h2>
    <input id="cidr" placeholder="CIDR (optional)" />
    <button onclick="scan()">Scan</button>
    <div id="scan-status"></div>
    <table>
      <thead><tr><th>IP</th><th>MAC</th><th>Hostname</th></tr></thead>
      <tbody id="devices"></tbody>
    </table>
  </section>
  <section>
    <h2>Cut / Restore</h2>
    <input id="ip" placeholder="IP" />
    <input id="mac" placeholder="MAC (optional)" />
    <input id="gateway" placeholder="Gateway (optional)" />
    <input id="duration" placeholder="Duration (e.g. 2m)" />
    <button onclick="cut()">Cut</button>
    <button onclick="restore()">Restore</button>
    <div id="action-status"></div>
  </section>
<script>
async function scan() {
  const cidr = document.getElementById('cidr').value;
  const url = cidr ? `/api/scan?cidr=${encodeURIComponent(cidr)}` : '/api/scan';
  document.getElementById('scan-status').textContent = 'Scanning...';
  const res = await fetch(url);
  const data = await res.json();
  if (!res.ok) {
    document.getElementById('scan-status').textContent = data.message || 'Scan failed';
    return;
  }
  const tbody = document.getElementById('devices');
  tbody.innerHTML = '';
  data.forEach(item => {
    const row = document.createElement('tr');
    row.innerHTML = `<td>${item.ip}</td><td>${item.mac}</td><td>${(item.hostname || []).join(', ')}</td>`;
    tbody.appendChild(row);
  });
  document.getElementById('scan-status').textContent = `Found ${data.length} devices`;
}

async function cut() {
  const payload = {
    ip: document.getElementById('ip').value,
    mac: document.getElementById('mac').value,
    gateway: document.getElementById('gateway').value,
    duration: document.getElementById('duration').value
  };
  const res = await fetch('/api/cut', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(payload)
  });
  const data = await res.json();
  document.getElementById('action-status').textContent = data.message || data.status;
}

async function restore() {
  const payload = {
    ip: document.getElementById('ip').value,
    gateway: document.getElementById('gateway').value
  };
  const res = await fetch('/api/restore', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(payload)
  });
  const data = await res.json();
  document.getElementById('action-status').textContent = data.message || data.status;
}
</script>
</body>
</html>`
