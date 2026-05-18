const WebSocket = require('ws');
const net = require('net');
const dgram = require('dgram');
const fetch = require('node-fetch');
const http = require('http');
const url = require('url');

// Proteksi Global: Mencegah server mati jika terjadi unhandled error di tengah tunnel
process.on('uncaughtException', (err) => {
    console.error(' [STABILITY WARNING] Uncaught Exception:', err.message);
});
process.on('unhandledRejection', (reason, promise) => {
    console.error(' [STABILITY WARNING] Unhandled Rejection at:', promise, 'reason:', reason);
});

// ==================== KONSTANTA & CONFIG ====================
const vmessUUID = "3b01a777-55e7-49f6-8637-d94ee69607c6";
const PROXY_LIST_URL = "https://raw.githubusercontent.com/FoolVPN-ID/Nautica/refs/heads/main/proxyList.txt";
const CHECK_API_URL = "https://cprx.pages.dev/api/check";

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;

const CORS_HEADER_OPTIONS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,HEAD,POST,OPTIONS",
  "Access-Control-Max-Age": "86400",
};

// Region definitions
const REGIONS = {
    "ASIA": ["ID", "SG", "MY", "PH", "TH", "VN", "JP", "KR", "CN", "HK", "TW", "IN"],
    "ASIA2": ["ID", "SG", "MY", "PH", "TH", "VN"],
    "ASIA3": ["JP", "KR", "CN", "HK", "TW"],
    "ASEAN": ["ID", "SG", "MY", "PH", "TH", "VN"],
    "SEA": ["ID", "SG", "MY", "PH", "TH", "VN"],
    "EASTASIA": ["JP", "KR", "CN", "HK", "TW"],
    "SOUTHASIA": ["IN", "BD", "PK", "LK", "NP"],
    "EUROPE": ["GB", "FR", "DE", "NL", "IT", "ES", "RU", "UA", "PL", "SE", "NO", "DK", "FI", "CH", "BE", "AT", "CZ", "GR", "PT", "IE", "HU", "RO"],
    "EU": ["GB", "FR", "DE", "NL", "IT", "ES"],
    "EUW": ["GB", "FR", "DE", "NL"],
    "EUE": ["PL", "CZ", "HU", "RO"],
    "AMERICA": ["US", "CA", "MX", "BR", "AR", "CL", "CO", "PE", "VE"],
    "USA": ["US"],
    "US": ["US"],
    "NORTHAMERICA": ["US", "CA", "MX"],
    "SOUTHAMERICA": ["BR", "AR", "CL", "CO", "PE", "VE"],
    "LATAM": ["MX", "BR", "AR", "CL", "CO", "PE", "VE"],
    "AFRICA": ["ZA", "NG", "EG", "MA", "KE", "DZ", "TN"],
    "OCEANIA": ["AU", "NZ"],
    "AUSTRALIA": ["AU"],
    "MIDDLEEAST": ["AE", "SA", "IL", "TR", "IR"],
    "GLOBAL": []
};

const MANUAL_PROXY = {
    "SG": ["178.128.80.43:443", "91.192.81.154:2053", "51.79.158.58:8443", "34.143.159.175:443"],
    "ID": ["103.6.207.108:8080"],
    "JP": ["18.179.45.123:443", "52.194.12.34:8443"],
    "US": ["167.172.234.12:443", "159.203.182.32:2053"],
    "AE": ["176.97.66.175:443", "152.32.181.246:44070", "193.123.90.82:12648", "139.185.50.5:14594"]
};

class GatewayServer {
  constructor() {
    this.cachedProxyList = null;
    this.cacheTime = 0;
    this.CACHE_TTL = 300000;
    this.httpServer = null;
    this.wss = null;
  }

  // ==================== PROXY LIST FETCHERS ====================
  async fetchProxyList() {
    const now = Date.now();
    if (this.cachedProxyList && (now - this.cacheTime) < this.CACHE_TTL) {
        return this.cachedProxyList;
    }
    
    try {
        const response = await fetch(PROXY_LIST_URL, { timeout: 5000 }); // Ditambahkan timeout fetch agar tidak gantung
        const text = await response.text();
        const lines = text.split('\n');
        const proxyMap = new Map();
        
        for (const line of lines) {
            if (line.trim() && !line.startsWith('#')) {
                const parts = line.split(',');
                if (parts.length >= 3) {
                    const ip = parts[0].trim();
                    const port = parts[1].trim();
                    const country = parts[2].trim();
                    const proxyString = `${ip}:${port}`;
                    
                    if (!proxyMap.has(country)) {
                        proxyMap.set(country, []);
                    }
                    proxyMap.get(country).push(proxyString);
                }
            }
        }
        
        this.cachedProxyList = proxyMap;
        this.cacheTime = now;
        return proxyMap;
    } catch (error) {
        console.error('Error fetching proxy list:', error.message);
        return this.cachedProxyList || new Map();
    }
  }

  async getProxyFromPath(pathname) {
    if (!pathname || pathname === '/') return null;
    
    const parts = pathname.substring(1).split('/');
    const command = parts[0].toUpperCase();
    
    const proxyMap = await this.fetchProxyList();
    
    for (const [country, proxies] of Object.entries(MANUAL_PROXY)) {
        if (!proxyMap.has(country)) {
            proxyMap.set(country, []);
        }
        for (const proxy of proxies) {
            if (!proxyMap.get(country).includes(proxy)) {
                proxyMap.get(country).push(proxy);
            }
        }
    }
    
    if (proxyMap.has(command)) {
        const proxies = proxyMap.get(command);
        if (proxies && proxies.length > 0) {
            return proxies[Math.floor(Math.random() * proxies.length)];
        }
    }
    
    const matchIndex = command.match(/^([A-Z]{2})(\d+)$/);
    if (matchIndex && proxyMap.has(matchIndex[1])) {
        const country = matchIndex[1];
        const index = parseInt(matchIndex[2]) - 1;
        const proxies = proxyMap.get(country);
        if (proxies && proxies[index]) {
            return proxies[index];
        }
    }
    
    if (command === "ALL") {
        const allProxies = [];
        for (const proxies of proxyMap.values()) {
            allProxies.push(...proxies);
        }
        if (allProxies.length > 0) {
            return allProxies[Math.floor(Math.random() * allProxies.length)];
        }
    }
    
    if (command.startsWith("REGION_")) {
        const regionName = command.replace("REGION_", "");
        if (REGIONS[regionName]) {
            const regionProxies = [];
            for (const country of REGIONS[regionName]) {
                if (proxyMap.has(country)) {
                    regionProxies.push(...proxyMap.get(country));
                }
            }
            if (regionProxies.length > 0) {
                return regionProxies[Math.floor(Math.random() * regionProxies.length)];
            }
        }
    }
    
    if (REGIONS[command]) {
        const regionProxies = [];
        for (const country of REGIONS[command]) {
            if (proxyMap.has(country)) {
                regionProxies.push(...proxyMap.get(country));
            }
        }
        if (regionProxies.length > 0) {
            return regionProxies[Math.floor(Math.random() * regionProxies.length)];
        }
    }
    
    const ipPortMatch = pathname.match(/^\/([\d\.]+)[:=:-](\d+)$/);
    if (ipPortMatch) {
        return `${ipPortMatch[1]}:${ipPortMatch[2]}`;
    }
    
    return null;
  }

  // ==================== HTTP HANDLER (DASHBOARD UI) ====================
  async handleHttpRequest(req, res) {
    const parsedUrl = url.parse(req.url, true);
    
    if (req.method === 'OPTIONS') {
      res.writeHead(200, CORS_HEADER_OPTIONS);
      res.end();
      return;
    }

    // Railway Healthcheck Interceptor (Sama seperti Kode 1 yang super stabil)
    if (parsedUrl.pathname === '/health') {
      res.writeHead(200, { 'Content-Type': 'text/plain', ...CORS_HEADER_OPTIONS });
      res.end('OK');
      return;
    }

    if (parsedUrl.pathname === '/') {
      const systemUptime = Math.floor(process.uptime());
      const ramAllocation = Math.round(process.memoryUsage().heapUsed / 1024 / 1024);

      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(`<!DOCTYPE html>
<html lang="en" id="htmlRoot">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=yes">
    <title>VPN Config Manager</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * { transition: background-color 0.3s ease, border-color 0.3s ease, color 0.3s ease; }
        .cloud-blur { position: fixed; border-radius: 50%; filter: blur(80px); pointer-events: none; z-index: 0; animation: floatCloud 20s ease-in-out infinite; }
        @keyframes floatCloud { 0%, 100% { transform: translate(0, 0) scale(1); } 33% { transform: translate(30px, -30px) scale(1.1); } 66% { transform: translate(-20px, 20px) scale(0.9); } }
        body { background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 100%); color: #f1f5f9; }
        body.light { background: linear-gradient(135deg, #f0f9ff 0%, #e0f2fe 100%); color: #0f172a; }
        body.light .glass-deep { background: rgba(255, 255, 255, 0.7); backdrop-filter: blur(12px); border: 1px solid rgba(255, 255, 255, 0.3); }
        .glass-deep { background: rgba(15, 23, 42, 0.5); backdrop-filter: blur(12px); border: 1px solid rgba(255, 255, 255, 0.1); }
        .dropdown-menu { display: none; position: absolute; right: 0; top: 100%; margin-top: 0.5rem; width: 220px; z-index: 50; background: rgba(30, 41, 59, 0.95); backdrop-filter: blur(16px); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 12px; padding: 8px; box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3); }
        body.light .dropdown-menu { background: rgba(255, 255, 255, 0.95); border: 1px solid rgba(0, 0, 0, 0.05); }
        .dropdown-menu.show { display: block; animation: fadeIn 0.2s ease-out; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(-10px); } to { opacity: 1; transform: translateY(0); } }
        .action-btn { transition: all 0.2s ease; } .action-btn:active { transform: scale(0.95); }
        .status-badge { display: inline-flex; align-items: center; gap: 4px; padding: 2px 8px; border-radius: 20px; font-size: 11px; font-weight: bold; }
        .status-active { background: rgba(16, 185, 129, 0.2); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.3); }
        .status-inactive { background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.3); }
        .status-checking { background: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.3); }
        .tooltip { position: relative; cursor: help; }
        .tooltip:hover::after { content: attr(data-tooltip); position: absolute; bottom: 100%; left: 50%; transform: translateX(-50%); background: rgba(0,0,0,0.9); color: white; padding: 4px 8px; border-radius: 6px; font-size: 10px; white-space: nowrap; z-index: 100; margin-bottom: 5px; }
    </style>
</head>
<body class="min-h-screen py-4 md:py-8 px-3 md:px-6 relative transition-colors duration-300">
    <div class="cloud-blur w-[500px] h-[500px] top-[-150px] left-[-150px]" style="background: radial-gradient(circle, rgba(59,130,246,0.4) 0%, rgba(139,92,246,0.2) 100%);"></div>
    <div class="cloud-blur w-[600px] h-[600px] bottom-[-200px] right-[-200px]" style="background: radial-gradient(circle, rgba(6,182,212,0.3) 0%, rgba(59,130,246,0.15) 100%);"></div>
    <div class="max-w-7xl mx-auto relative z-10">
        <div class="flex flex-col md:flex-row justify-between items-center mb-6 gap-4">
            <div class="text-center md:text-left">
                <div class="inline-flex items-center gap-2 px-3 py-1 rounded-full glass-deep text-xs font-semibold mb-3" style="color: #60a5fa;">
                    <i class="fas fa-shield-alt text-[10px]"></i> <span>NETWORK SECURE</span>
                    <span class="w-1.5 h-1.5 bg-emerald-500 rounded-full animate-pulse ml-1"></span>
                </div>
                <h1 class="text-3xl md:text-5xl font-black tracking-tight bg-gradient-to-r from-blue-400 via-cyan-400 to-purple-400 bg-clip-text text-transparent">VPN Config Manager</h1>
            </div>
            <button id="themeToggle" class="fixed top-4 right-4 z-50 w-10 h-10 rounded-full glass-deep flex items-center justify-center text-lg hover:scale-110 transition-all"><i class="fas fa-moon"></i></button>
        </div>
        <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
          <div class="glass-deep p-4 rounded-xl flex items-center justify-between">
            <div><p class="text-[10px] text-slate-400 font-bold mb-1">SYSTEM UPTIME</p><p id="uptime-val" class="text-md font-extrabold">${systemUptime}s</p></div>
            <i class="fa-solid fa-clock text-slate-500 text-lg"></i>
          </div>
          <div class="glass-deep p-4 rounded-xl flex items-center justify-between">
            <div><p class="text-[10px] text-slate-400 font-bold mb-1">RAM ALLOCATION</p><p class="text-md font-extrabold">${ramAllocation} MB</p></div>
            <i class="fa-solid fa-microchip text-slate-500 text-lg"></i>
          </div>
          <div class="glass-deep p-4 rounded-xl flex items-center justify-between">
            <div><p class="text-[10px] text-slate-400 font-bold mb-1">GATEWAY ENGINE</p><p class="text-md font-extrabold text-emerald-400">NODE_JS</p></div>
            <i class="fa-brands fa-node-js text-emerald-500/40 text-lg"></i>
          </div>
          <div class="glass-deep p-4 rounded-xl flex items-center justify-between">
            <div><p class="text-[10px] text-slate-400 font-bold mb-1">UDP SERVICE</p><p class="text-md font-extrabold text-cyan-400">ENABLED</p></div>
            <i class="fa-solid fa-bolt text-cyan-500/40 text-lg"></i>
          </div>
        </div>
        <div class="glass-deep rounded-2xl overflow-hidden shadow-2xl">
            <div class="p-4 md:p-6 border-b" style="border-color: rgba(255,255,255,0.1);">
                <div class="relative group">
                    <div class="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none"><i class="fas fa-search text-slate-500 group-focus-within:text-blue-400 transition-colors"></i></div>
                    <input type="text" id="searchInput" placeholder="Search country or ISP..." class="w-full bg-white/10 backdrop-blur-sm border rounded-xl py-3 pl-12 pr-4 focus:outline-none focus:ring-2 transition-all" style="border-color: rgba(255,255,255,0.1);">
                </div>
            </div>
            <div class="overflow-x-auto p-2 md:p-4">
                <table class="w-full border-collapse">
                    <thead>
                        <tr class="border-b" style="border-color: rgba(255,255,255,0.05);">
                            <th class="py-4 px-4 text-left text-xs font-semibold uppercase tracking-wider text-slate-400">Location</th>
                            <th class="py-4 px-4 text-left text-xs font-semibold uppercase tracking-wider text-slate-400">Provider</th>
                            <th class="py-4 px-4 text-center text-xs font-semibold uppercase tracking-wider text-slate-400">Status</th>
                            <th class="py-4 px-4 text-right text-xs font-semibold uppercase tracking-wider text-slate-400">Action</th>
                        </tr>
                    </thead>
                    <tbody id="proxyTableBody"></tbody>
                </table>
            </div>
            <div id="loading" class="py-24 text-center flex flex-col items-center gap-4">
                <div class="animate-spin rounded-full h-10 w-10 border-t-2 border-b-2 border-blue-500"></div>
                <p class="text-slate-400 text-sm">Fetching proxy list...</p>
            </div>
            <div class="p-4 md:p-6 border-t flex flex-col md:flex-row justify-between items-center gap-4" style="border-color: rgba(255,255,255,0.1);">
                <div id="paginationInfo" class="text-slate-400 text-xs font-mono"></div>
                <div class="flex gap-3 items-center" id="paginationControls"></div>
            </div>
        </div>
    </div>
    <script>
        const themeToggleBtn = document.getElementById('themeToggle'); const bodyElement = document.body;
        themeToggleBtn.addEventListener('click', () => { bodyElement.classList.toggle('light'); const isLight = bodyElement.classList.contains('light'); themeToggleBtn.innerHTML = isLight ? '<i class="fas fa-sun"></i>' : '<i class="fas fa-moon"></i>'; localStorage.setItem('theme', isLight ? 'light' : 'dark'); });
        if (localStorage.getItem('theme') === 'light') { bodyElement.classList.add('light'); themeToggleBtn.innerHTML = '<i class="fas fa-sun"></i>'; }
        const uuid = "${vmessUUID}"; const host = window.location.hostname + (window.location.port ? ':' + window.location.port : ''); const CHECK_API_URL = '${CHECK_API_URL}';
        const VMS_PRE = 'vmess://'; const VLS_PRE = 'vless://'; const TRJ_PRE = 'trojan://';
        const countryNameFormatter = new Intl.DisplayNames(['en'], { type: 'region' });
        function getCountryFullName(countryCode) { if (!countryCode) return 'Unknown'; try { const upperCode = countryCode.toUpperCase().trim(); return countryNameFormatter.of(upperCode) || countryCode; } catch (e) { return countryCode; } }
        let allProxies = []; let filteredProxies = []; let currentPage = 1; const itemsPerPage = 10; let statusCache = new Map();
        async function checkProxyStatus(ip, port) { const cacheKey = ip + ':' + port; if (statusCache.has(cacheKey)) return statusCache.get(cacheKey); try { const apiUrl = CHECK_API_URL + '?ip=' + ip + ':' + port; const response = await fetch(apiUrl); const data = await response.json(); const isActive = data.proxyip === true; const result = { status: isActive ? 'ACTIVE' : 'INACTIVE', delay: data.delay || 'N/A', speed: data.delay || 'N/A', isp: data.asOrganization || '', country: data.country || '', asn: data.asn || '', colo: data.colo ? data.colo.iata : '', proxyip: data.ip || '', hostname: data.hostname || '' }; statusCache.set(cacheKey, result); return result; } catch (error) { const errorResult = { status: 'ERROR', delay: 'N/A', speed: 'N/A' }; statusCache.set(cacheKey, errorResult); return errorResult; } }
        async function fetchProxies() { try { const response = await fetch('/api/raw-proxies'); const text = await response.text(); const lines = text.trim().split('\\n'); allProxies = lines.map(line => { const [ip, port, country, isp] = line.split(','); return { ip, port, country: getCountryFullName(country), isp, countryCode: country, status: null, delay: null, speed: null }; }).filter(p => p.ip && p.port); filteredProxies = [...allProxies]; renderTable(); document.getElementById('loading').classList.add('hidden'); checkAllProxyStatuses(); } catch (error) { console.error('Error fetching data:', error); } }
        async function checkAllProxyStatuses() { const batchSize = 5; for (let i = 0; i < filteredProxies.length; i += batchSize) { const batch = filteredProxies.slice(i, i + batchSize); await Promise.all(batch.map(async (proxy, idx) => { const globalIdx = i + idx; const statusData = await checkProxyStatus(proxy.ip, proxy.port); proxy.status = statusData.status; proxy.delay = statusData.delay; proxy.speed = statusData.speed; proxy.checkInfo = statusData; updateProxyRowInTable(globalIdx, proxy); })); } }
        function updateProxyRowInTable(proxyIndex, proxy) { const start = (currentPage - 1) * itemsPerPage; const end = start + itemsPerPage; if (proxyIndex >= start && proxyIndex < end) { const rowIndex = proxyIndex - start; const tbody = document.getElementById('proxyTableBody'); const rows = tbody.getElementsByTagName('tr'); if (rows[rowIndex]) { const statusCell = rows[rowIndex].querySelector('.status-cell'); if (statusCell) statusCell.innerHTML = getStatusHtml(proxy); } } }
        function generateVmess(proxy) { const path = '/' + proxy.ip + '=' + proxy.port; const vmessObj = { v: "2", ps: "[VMess-TLS] " + proxy.country + " - " + proxy.isp, add: window.location.hostname, port: window.location.port || 80, id: uuid, aid: "0", scy: "zero", net: "ws", type: "none", host: window.location.hostname, path: path, tls: "none", sni: "" }; return VMS_PRE + btoa(JSON.stringify(vmessObj)); }
        function generateVless(proxy) { const path = encodeURIComponent('/' + proxy.ip + '=' + proxy.port); return VLS_PRE + uuid + "@" + host + "?encryption=none&security=none&type=ws&host=" + window.location.hostname + "&path=" + path + "#" + encodeURIComponent("[VLESS-WS] " + proxy.country); }
        function generateTrojan(proxy) { const path = encodeURIComponent('/' + proxy.ip + '=' + proxy.port); return TRJ_PRE + uuid + "@" + host + "?security=none&type=ws&host=" + window.location.hostname + "&path=" + path + "#" + encodeURIComponent("[Trojan-WS] " + proxy.country); }
        function generateShadowsocks(proxy) { const encodedAuth = btoa('none:' + uuid); const path = encodeURIComponent('/' + proxy.ip + '=' + proxy.port); return 'ss://' + encodedAuth + '@' + host + '?path=' + path + '&security=none&host=' + window.location.hostname + '&type=ws#' + encodeURIComponent("[SS-WS] " + proxy.country); }
        function toggleDropdown(id) { document.querySelectorAll('.dropdown-menu').forEach(el => { if(el.id !== 'drop-' + id) el.classList.remove('show'); }); document.getElementById('drop-' + id).classList.toggle('show'); }
        window.onclick = function(event) { if (!event.target.closest('.dropdown-container')) { document.querySelectorAll('.dropdown-menu').forEach(el => el.classList.remove('show')); } }
        function copyToClipboard(text, btn) { navigator.clipboard.writeText(text).then(() => { const original = btn.innerHTML; btn.innerHTML = '<i class="fas fa-check"></i> Copied'; setTimeout(() => { btn.innerHTML = original; }, 1500); }); }
        function getStatusHtml(proxy) { if (!proxy.status) return '<div class="status-badge status-checking"><i class="fas fa-spinner fa-pulse"></i><span>Checking...</span></div>'; if (proxy.status === 'ACTIVE') { return '<div class="status-badge status-active tooltip" data-tooltip="Delay: ' + proxy.delay + '"><i class="fas fa-check-circle text-green-500"></i><span class="text-green-500 font-semibold">ACTIVE</span></div>'; } else if (proxy.status === 'ERROR') { return '<div class="status-badge status-inactive"><i class="fas fa-exclamation-triangle"></i><span>ERROR</span></div>'; } else { return '<div class="status-badge status-inactive"><i class="fas fa-times-circle"></i><span>INACTIVE</span></div>'; } }
        function renderTable() { const start = (currentPage - 1) * itemsPerPage; const paged = filteredProxies.slice(start, start + itemsPerPage); const tbody = document.getElementById('proxyTableBody'); tbody.innerHTML = ''; paged.forEach((proxy, idx) => { const id = start + idx; const vmess = generateVmess(proxy); const vless = generateVless(proxy); const trojan = generateTrojan(proxy); const shadowsocks = generateShadowsocks(proxy); tbody.innerHTML += '<tr class="border-b border-white/5 hover:bg-white/5 transition-all">' + '<td class="py-4 px-4"><div class="flex items-center gap-3"><span class="text-2xl">' + getFlagEmoji(proxy.countryCode) + '</span><div><div class="font-bold text-sm md:text-base">' + proxy.country + '</div><div class="text-[11px] text-slate-400 font-mono">' + proxy.ip + ':' + proxy.port + '</div></div></div></td>' + '<td class="py-4 px-4"><div class="text-sm">' + (proxy.isp || '-') + '</div></td>' + '<td class="py-4 px-4 text-center status-cell">' + getStatusHtml(proxy) + '</td>' + '<td class="py-4 px-4 text-right relative dropdown-container">' + '<button onclick="toggleDropdown(\\'' + id + '\\')" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg text-xs font-bold transition-all inline-flex items-center gap-2"><i class="fas fa-cog"></i> Config <i class="fas fa-chevron-down text-[10px]"></i></button>' + '<div id="drop-' + id + '" class="dropdown-menu"><div class="grid grid-cols-2 gap-2">' + '<button onclick="copyToClipboard(\\'' + vless + '\\', this)" class="bg-indigo-600 hover:bg-indigo-700 p-2 rounded-md text-[10px] font-bold text-white flex flex-col items-center gap-1"><i class="fas fa-link"></i> VLESS</button>' + '<button onclick="copyToClipboard(\\'' + trojan + '\\', this)" class="bg-purple-600 hover:bg-purple-700 p-2 rounded-md text-[10px] font-bold text-white flex flex-col items-center gap-1"><i class="fas fa-shield-halved"></i> TROJAN</button>' + '<button onclick="copyToClipboard(\\'' + shadowsocks + '\\', this)" class="bg-cyan-600 hover:bg-cyan-700 p-2 rounded-md text-[10px] font-bold text-white flex flex-col items-center gap-1"><i class="fas fa-lock"></i> SS</button>' + '<button onclick="copyToClipboard(\\'' + vmess + '\\', this)" class="bg-emerald-600 hover:bg-emerald-700 p-2 rounded-md text-[10px] font-bold text-white flex flex-col items-center gap-1"><i class="fas fa-bolt"></i> VMESS</button>' + '</div></div></td></tr>'; }); updatePagination(); }
        function updatePagination() { const totalPages = Math.ceil(filteredProxies.length / itemsPerPage); document.getElementById('paginationInfo').innerText = 'Page ' + currentPage + ' of ' + totalPages; const controls = document.getElementById('paginationControls'); controls.innerHTML = ''; const btnClass = "px-3 py-1 rounded-lg bg-white/5 border border-white/10 text-xs hover:bg-white/10 disabled:opacity-30 text-slate-300"; const prev = document.createElement('button'); prev.className = btnClass; prev.innerHTML = '<i class="fas fa-chevron-left"></i> Prev'; prev.disabled = currentPage === 1; prev.onclick = () => { currentPage--; renderTable(); }; const next = document.createElement('button'); next.className = btnClass; next.innerHTML = 'Next <i class="fas fa-chevron-right"></i>'; next.disabled = currentPage === totalPages; next.onclick = () => { currentPage++; renderTable(); }; controls.append(prev, next); }
        function getFlagEmoji(countryCode) { if (!countryCode || countryCode.trim().length !== 2) return '🌐'; const codePoints = countryCode.toUpperCase().trim().split('').map(char => 127397 + char.charCodeAt()); return String.fromCodePoint(...codePoints); }
        document.getElementById('searchInput').oninput = (e) => { const query = e.target.value.toLowerCase(); filteredProxies = allProxies.filter(p => p.country.toLowerCase().includes(query) || p.isp.toLowerCase().includes(query)); currentPage = 1; renderTable(); };
        let start = ${systemUptime}; setInterval(() => { start++; document.getElementById('uptime-val').innerText = start + 's'; }, 1000);
        fetchProxies();
    </script>
</body>
</html>`);
      return;
    }

    if (parsedUrl.pathname === '/api/raw-proxies') {
      try {
        const response = await fetch(PROXY_LIST_URL);
        const text = await response.text();
        res.writeHead(200, { 'Content-Type': 'text/plain', ...CORS_HEADER_OPTIONS });
        res.end(text);
      } catch (err) {
        res.writeHead(500);
        res.end("Internal Server Error");
      }
      return;
    }

    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found');
  }

  // ==================== WEBSOCKET TUNNELING HANDLERS ====================
  async handleWebSocketConnection(ws, request) {
    try {
        const parsedUrl = url.parse(request.url, true);
        const pathname = parsedUrl.pathname;
        
        const selectedProxy = await this.getProxyFromPath(pathname);
        if (!selectedProxy) {
            ws.close(1000, "Proxy not found or invalid route mapping");
            return;
        }

        console.log(`Connecting via Tunnel Proxy IP: ${selectedProxy}`);
        await this.websocketTunnelHandler(ws, selectedProxy);
    } catch (err) {
        console.error('WebSocket connection setup error:', err.message);
        try { ws.close(1011, 'Internal connection handler breakdown'); } catch(e){}
    }
  }

  async websocketTunnelHandler(ws, selectedProxy) {
    let tcpSocket = null;
    const proxyData = selectedProxy.split(':');
    const targetHost = proxyData[0];
    const targetPort = parseInt(proxyData[1]);
    
    // Antrean buffer jika data ws datang sebelum TCP socket terkoneksi sepenuhnya (Stabilitas Tambahan)
    let bufferQueue = [];
    let isConnected = false;

    ws.on('message', (message) => {
        const chunk = Buffer.from(message);
        if (isConnected && tcpSocket) {
            tcpSocket.write(chunk);
            return;
        }
        
        if (tcpSocket) {
            bufferQueue.push(chunk);
            return;
        }

        // Inisialisasi Socket Outbound TCP (Node Native Sockets) - Dioptimalkan Penanganan Lifecycle-nya seperti Kode 1
        tcpSocket = net.createConnection({
            host: targetHost,
            port: targetPort
        }, () => {
            isConnected = true;
            console.log(`[TCP Outbound] Tunnel successfully mapped into ${targetHost}:${targetPort}`);
            
            // Siram sisa antrean data
            if (bufferQueue.length > 0) {
                bufferQueue.forEach(b => tcpSocket.write(b));
                bufferQueue = [];
            }
        });

        tcpSocket.on('data', (data) => {
            if (ws.readyState === WS_READY_STATE_OPEN) {
                ws.send(data);
            }
        });

        // Manajemen penutupan socket yang super bersih agar memori RAM Railway tidak leak/bocor
        tcpSocket.on('close', () => {
            isConnected = false;
            try { ws.close(); } catch(e){}
        });

        tcpSocket.on('error', (err) => {
            console.error('[Socket Error Path]', err.message);
            isConnected = false;
            try { ws.close(); } catch(e){}
        });
    });

    ws.on('close', () => {
        isConnected = false;
        if (tcpSocket) {
            tcpSocket.end();
            tcpSocket.destroy();
            tcpSocket = null;
        }
        bufferQueue = [];
    });

    ws.on('error', () => {
        isConnected = false;
        if (tcpSocket) {
            tcpSocket.destroy();
            tcpSocket = null;
        }
        bufferQueue = [];
    });
  }

  // ==================== SERVER CORE INITIALIZATION ====================
  start(port = process.env.PORT || 8080) {
    const server = http.createServer((req, res) => {
      this.handleHttpRequest(req, res).catch(error => {
        console.error('Core Engine Server Error:', error.message);
        try {
          res.writeHead(500, { 'Content-Type': 'text/plain' });
          res.end('Internal Engine Stack Error');
        } catch(e){}
      });
    });

    // Menghilangkan batasan perMessageDeflate untuk performa maksimal & hemat RAM pada infrastruktur Docker Railway
    this.wss = new WebSocket.Server({ server, perMessageDeflate: false });
    this.wss.on('connection', (ws, req) => {
      this.handleWebSocketConnection(ws, req);
    });

    server.listen(port, '0.0.0.0', () => {
      console.log(`✅ Gateway Engine running on environment port : ${port}`);
    });
  }
}

if (require.main === module) {
  const server = new GatewayServer();
  // Di-lock default port ke 8080 menyesuaikan railway.json agar healthcheck 100% mulus terus
  server.start(process.env.PORT || 8080);
}

module.exports = GatewayServer;
