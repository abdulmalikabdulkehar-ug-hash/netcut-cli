package networkscan

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"
)

// WebServer wraps a NetworkScanner and serves a browser-based UI together
// with a simple JSON API so operators can scan, cut, and restore devices
// without restarting the CLI.
type WebServer struct {
	scanner   *NetworkScanner
	gateway   string
	allowList []string
	denyList  []string
	dryRun    bool
	addr      string
}

// NewWebServer creates a WebServer. addr is the listen address (e.g. ":8080").
func NewWebServer(scanner *NetworkScanner, gateway string,
	allowList, denyList []string, dryRun bool, addr string) *WebServer {
	return &WebServer{
		scanner:   scanner,
		gateway:   gateway,
		allowList: allowList,
		denyList:  denyList,
		dryRun:    dryRun,
		addr:      addr,
	}
}

// ListenAndServe registers routes and starts the HTTP server.
func (ws *WebServer) ListenAndServe() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", ws.handleUI)
	mux.HandleFunc("/api/scan", ws.handleScan)
	mux.HandleFunc("/api/cut", ws.handleCut)
	mux.HandleFunc("/api/restore", ws.handleRestore)

	log.Printf("Web UI listening on http://%s", ws.addr)
	return http.ListenAndServe(ws.addr, mux)
}

// ---- API request / response types ----------------------------------------

type scanRequest struct {
	CIDR string `json:"cidr"`
}

type deviceJSON struct {
	IP       string   `json:"ip"`
	MAC      string   `json:"mac"`
	Hostname []string `json:"hostname"`
}

type cutRequest struct {
	IP       string `json:"ip"`
	MAC      string `json:"mac,omitempty"`
	Gateway  string `json:"gateway,omitempty"`
	Duration string `json:"duration,omitempty"` // e.g. "30s", "5m"
}

type restoreRequest struct {
	IP      string `json:"ip"`
	MAC     string `json:"mac"`
	Gateway string `json:"gateway,omitempty"`
}

type apiError struct {
	Error string `json:"error"`
}

// ---- helpers ---------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// ---- handlers --------------------------------------------------------------

// handleUI serves the embedded single-page web UI.
func (ws *WebServer) handleUI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, webUIHTML)
}

// handleScan handles POST /api/scan  { "cidr": "192.168.0.0/24" }
func (ws *WebServer) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiError{"POST required"})
		return
	}
	var req scanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.CIDR == "" {
		writeJSON(w, http.StatusBadRequest, apiError{"cidr is required"})
		return
	}
	devices := ws.scanner.NetScan(req.CIDR)
	var out []deviceJSON
	for _, d := range devices {
		out = append(out, deviceJSON{
			IP:       d.IP.String(),
			MAC:      d.MAC.String(),
			Hostname: d.HOSTNAME,
		})
	}
	if out == nil {
		out = []deviceJSON{}
	}
	writeJSON(w, http.StatusOK, out)
}

// handleCut handles POST /api/cut
func (ws *WebServer) handleCut(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiError{"POST required"})
		return
	}
	var req cutRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IP == "" {
		writeJSON(w, http.StatusBadRequest, apiError{"ip is required"})
		return
	}

	gw := req.Gateway
	if gw == "" {
		gw = ws.gateway
	}
	if gw == "" {
		writeJSON(w, http.StatusBadRequest, apiError{"gateway is required"})
		return
	}

	// Build the Device to cut.
	var device Device
	if req.MAC != "" {
		macAddr, err := net.ParseMAC(req.MAC)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{fmt.Sprintf("invalid mac: %v", err)})
			return
		}
		device = Device{IP: net.ParseIP(req.IP), MAC: macAddr}
	} else {
		devices := ws.scanner.NetScan(req.IP + "/32")
		for _, d := range devices {
			if d.IP.String() == req.IP {
				device = d
				break
			}
		}
		if device.IP == nil {
			writeJSON(w, http.StatusNotFound, apiError{fmt.Sprintf("device %s not found", req.IP)})
			return
		}
	}

	// Safety checks.
	if IsGateway(device, gw) {
		writeJSON(w, http.StatusForbidden, apiError{"refusing to cut off gateway"})
		return
	}
	if !SafeToOperate(device, ws.allowList, ws.denyList, ws.dryRun) {
		msg := "operation blocked by safety policy"
		if ws.dryRun {
			msg = "dry-run: operation would be executed but no packets sent"
		}
		writeJSON(w, http.StatusForbidden, apiError{msg})
		return
	}

	// Run asynchronously so the HTTP response is returned immediately.
	if req.Duration != "" {
		dur, err := time.ParseDuration(req.Duration)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{fmt.Sprintf("invalid duration: %v", err)})
			return
		}
		go ws.scanner.CutOffDeviceFor(device, gw, dur)
		writeJSON(w, http.StatusAccepted, map[string]string{
			"status":   "cutting",
			"ip":       device.IP.String(),
			"mac":      device.MAC.String(),
			"duration": req.Duration,
		})
	} else {
		go ws.scanner.CutOffDevice(device, gw)
		writeJSON(w, http.StatusAccepted, map[string]string{
			"status": "cutting",
			"ip":     device.IP.String(),
			"mac":    device.MAC.String(),
		})
	}
}

// handleRestore handles POST /api/restore
func (ws *WebServer) handleRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiError{"POST required"})
		return
	}
	var req restoreRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IP == "" || req.MAC == "" {
		writeJSON(w, http.StatusBadRequest, apiError{"ip and mac are required"})
		return
	}
	gw := req.Gateway
	if gw == "" {
		gw = ws.gateway
	}
	if gw == "" {
		writeJSON(w, http.StatusBadRequest, apiError{"gateway is required"})
		return
	}

	macAddr, err := net.ParseMAC(req.MAC)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{fmt.Sprintf("invalid mac: %v", err)})
		return
	}
	device := Device{IP: net.ParseIP(req.IP), MAC: macAddr}

	go ws.scanner.RestoreDevice(device, gw)
	writeJSON(w, http.StatusAccepted, map[string]string{
		"status": "restoring",
		"ip":     device.IP.String(),
		"mac":    device.MAC.String(),
	})
}

// ---- embedded HTML ---------------------------------------------------------

const webUIHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>netcut-cli Web UI</title>
<style>
  body { font-family: sans-serif; margin: 2rem; background: #f4f4f4; color: #222; }
  h1 { color: #c0392b; }
  h2 { border-bottom: 2px solid #c0392b; padding-bottom: .3rem; }
  input, button, select { padding: .4rem .7rem; margin: .2rem 0; border-radius: 4px; border: 1px solid #ccc; }
  button { background: #c0392b; color: #fff; border: none; cursor: pointer; }
  button:hover { background: #a93226; }
  button.restore { background: #27ae60; }
  button.restore:hover { background: #1e8449; }
  table { border-collapse: collapse; width: 100%; background: #fff; margin-top: 1rem; }
  th, td { border: 1px solid #ddd; padding: .5rem .8rem; text-align: left; }
  th { background: #eee; }
  .msg { margin: .5rem 0; padding: .5rem; border-radius: 4px; }
  .ok { background: #d5f5e3; }
  .err { background: #fadbd8; }
</style>
</head>
<body>
<h1>&#x2702; netcut-cli Web UI</h1>

<h2>Scan Network</h2>
<input id="cidr" type="text" placeholder="192.168.0.0/24" size="22">
<button onclick="scan()">Scan</button>
<div id="scanMsg"></div>
<table id="devTable">
  <thead><tr><th>IP</th><th>MAC</th><th>Hostname</th><th>Actions</th></tr></thead>
  <tbody id="devBody"></tbody>
</table>

<h2>Manual Cut / Restore</h2>
<input id="manIp"  type="text" placeholder="IP address" size="18">
<input id="manMac" type="text" placeholder="MAC (optional)" size="20">
<input id="manGw"  type="text" placeholder="Gateway IP" size="18">
<input id="manDur" type="text" placeholder="Duration e.g. 30s (optional)" size="24">
<br>
<button onclick="cutManual()">Cut Off</button>
<button class="restore" onclick="restoreManual()">Restore</button>
<div id="manMsg"></div>

<script>
async function post(url, body) {
  const r = await fetch(url, { method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify(body) });
  return { status: r.status, data: await r.json() };
}

function msg(id, ok, text) {
  const el = document.getElementById(id);
  el.className = 'msg ' + (ok ? 'ok' : 'err');
  el.textContent = text;
}

async function scan() {
  const cidr = document.getElementById('cidr').value.trim();
  if (!cidr) { msg('scanMsg', false, 'Enter a CIDR'); return; }
  msg('scanMsg', true, 'Scanning…');
  const { status, data } = await post('/api/scan', { cidr });
  if (status !== 200) { msg('scanMsg', false, data.error || 'scan failed'); return; }
  const tbody = document.getElementById('devBody');
  tbody.innerHTML = '';
  data.forEach(d => {
    const tr = document.createElement('tr');
    tr.innerHTML =
      '<td>' + d.ip + '</td>' +
      '<td>' + d.mac + '</td>' +
      '<td>' + (d.hostname||[]).join(', ') + '</td>' +
      '<td>' +
        '<button onclick="cutDev(\'' + d.ip + '\',\'' + d.mac + '\')">Cut</button> ' +
        '<button class="restore" onclick="restoreDev(\'' + d.ip + '\',\'' + d.mac + '\')">Restore</button>' +
      '</td>';
    tbody.appendChild(tr);
  });
  msg('scanMsg', true, 'Found ' + data.length + ' device(s).');
}

async function cutDev(ip, mac) {
  const gw = document.getElementById('manGw').value.trim();
  const dur = document.getElementById('manDur').value.trim();
  const body = { ip, mac };
  if (gw)  body.gateway  = gw;
  if (dur) body.duration = dur;
  const { status, data } = await post('/api/cut', body);
  msg('scanMsg', status===202, status===202 ? 'Cutting ' + ip : (data.error||'error'));
}

async function restoreDev(ip, mac) {
  const gw = document.getElementById('manGw').value.trim();
  const { status, data } = await post('/api/restore', { ip, mac, gateway: gw });
  msg('scanMsg', status===202, status===202 ? 'Restoring ' + ip : (data.error||'error'));
}

async function cutManual() {
  const ip  = document.getElementById('manIp').value.trim();
  const mac = document.getElementById('manMac').value.trim();
  const gw  = document.getElementById('manGw').value.trim();
  const dur = document.getElementById('manDur').value.trim();
  if (!ip) { msg('manMsg', false, 'IP is required'); return; }
  const body = { ip };
  if (mac) body.mac      = mac;
  if (gw)  body.gateway  = gw;
  if (dur) body.duration = dur;
  const { status, data } = await post('/api/cut', body);
  msg('manMsg', status===202, status===202 ? 'Cutting ' + ip : (data.error||'error'));
}

async function restoreManual() {
  const ip  = document.getElementById('manIp').value.trim();
  const mac = document.getElementById('manMac').value.trim();
  const gw  = document.getElementById('manGw').value.trim();
  if (!ip || !mac) { msg('manMsg', false, 'IP and MAC are required for restore'); return; }
  const { status, data } = await post('/api/restore', { ip, mac, gateway: gw });
  msg('manMsg', status===202, status===202 ? 'Restoring ' + ip : (data.error||'error'));
}
</script>
</body>
</html>`
