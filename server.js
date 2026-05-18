const http = require('http');
const net = require('net');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

// ==================== KONSTANTA & CONFIG ====================
// Perbaikan: Membaca process.env.PORT terlebih dahulu untuk kompatibilitas Railway
const PORT = process.env.PORT || process.argv[2] || 3000;
const vmessUUID = "3b01a777-55e7-49f6-8637-d94ee69607c6";
const proxyListUrl = 'https://raw.githubusercontent.com/jaka1m/botak/refs/heads/main/cek/proxyList.txt';
const CHECK_API_URL = 'https://cprx-sshvless.wasmer.app/api/check';
const PROXY_LIST_URL = "https://raw.githubusercontent.com/FoolVPN-ID/Nautica/refs/heads/main/proxyList.txt";

const DNS_PORT = 53;
const PROTOCOLS = { P1: 'Trojan', P2: 'VLESS', P3: 'Shadowsocks', P4: 'VMess' };
const ADDRESS_TYPES = { IPV4: 1, DOMAIN: 2, IPV6: 3, DOMAIN_ALT: 3 };
const COMMAND_TYPES = { TCP: 1, UDP: 2, UDP_ALT: 3 };

let prxIP = "";
let cachedProxyList = null;
let cacheTime = 0;
const CACHE_TTL = 300000;

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
    "USA": ["US"], "US": ["US"],
    "NORTHAMERICA": ["US", "CA", "MX"],
    "SOUTHAMERICA": ["BR", "AR", "CL", "CO", "PE", "VE"],
    "LATAM": ["MX", "BR", "AR", "CL", "CO", "PE", "VE"],
    "AFRICA": ["ZA", "NG", "EG", "MA", "KE", "DZ", "TN"],
    "OCEANIA": ["AU", "NZ"], "AUSTRALIA": ["AU"],
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

// ==================== HELPER BACKEND UTILITY ====================
async function fetchProxyList() {
    const now = Date.now();
    if (cachedProxyList && (now - cacheTime) < CACHE_TTL) return cachedProxyList;
    try {
        const response = await fetch(PROXY_LIST_URL);
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
                    if (!proxyMap.has(country)) proxyMap.set(country, []);
                    proxyMap.get(country).push(proxyString);
                }
            }
        }
        cachedProxyList = proxyMap;
        cacheTime = now;
        return proxyMap;
    } catch (error) {
        return cachedProxyList || new Map();
    }
}

async function getProxyFromPath(pathname) {
    if (!pathname || pathname === '/') return null;
    const parts = pathname.substring(1).split('/');
    const command = parts[0].toUpperCase();
    const proxyMap = await fetchProxyList();

    for (const [country, proxies] of Object.entries(MANUAL_PROXY)) {
        if (!proxyMap.has(country)) proxyMap.set(country, []);
        for (const proxy of proxies) {
            if (!proxyMap.get(country).includes(proxy)) proxyMap.get(country).push(proxy);
        }
    }

    if (proxyMap.has(command)) {
        const proxies = proxyMap.get(command);
        if (proxies && proxies.length > 0) return proxies[Math.floor(Math.random() * proxies.length)];
    }

    const matchIndex = command.match(/^([A-Z]{2})(\d+)$/);
    if (matchIndex && proxyMap.has(matchIndex[1])) {
        const country = matchIndex[1];
        const index = parseInt(matchIndex[2]) - 1;
        const proxies = proxyMap.get(country);
        if (proxies && proxies[index]) return proxies[index];
    }

    if (command === "ALL") {
        const allProxies = [];
        for (const proxies of proxyMap.values()) allProxies.push(...proxies);
        if (allProxies.length > 0) return allProxies[Math.floor(Math.random() * allProxies.length)];
    }

    if (command.startsWith("REGION_") || REGIONS[command]) {
        const regionName = command.replace("REGION_", "");
        const targetRegion = REGIONS[regionName] || REGIONS[command];
        if (targetRegion) {
            const regionProxies = [];
            for (const country of targetRegion) {
                if (proxyMap.has(country)) regionProxies.push(...proxyMap.get(country));
            }
            if (regionProxies.length > 0) return regionProxies[Math.floor(Math.random() * regionProxies.length)];
        }
    }

    const ipPortMatch = pathname.match(/^\/([\d\.]+)[:=:-](\d+)$/);
    if (ipPortMatch) return `${ipPortMatch[1]}:${ipPortMatch[2]}`;
    return null;
}

// ==================== CRYPTO ENGINE (NODE.JS METHOD) ====================
function kdf(key, path) {
    let hmac = crypto.createHmac('sha256', "VMess AEAD KDF");
    for (const p of path) hmac = crypto.createHmac('sha256', p);
    return hmac.update(key).digest();
}

function md5(data, salt) {
    const hash = crypto.createHash('md5');
    hash.update(data);
    if (salt) hash.update(salt);
    return hash.digest();
}

function toBuffer(uuidStr) {
    return Buffer.from(uuidStr.replace(/-/g, ''), 'hex');
}

// ==================== PARSER PROTOKOL BACKEND ====================
async function detectProtocol(buffer) {
    if (buffer.length >= 42) {
        try {
            const uuidBytes = toBuffer(vmessUUID);
            const auth_id = buffer.subarray(0, 16);
            if (auth_id.length === 16) return PROTOCOLS.P4; // VMess
        } catch(e){}
    }
    if (buffer.length >= 62) {
        const delimiter = buffer.subarray(56, 60);
        if (delimiter[0] === 0x0d && delimiter[1] === 0x0a) return PROTOCOLS.P1; // Trojan
    }
    const hexString = buffer.subarray(1, 17).toString('hex');
    if (/^\w{32}$/.test(hexString)) return PROTOCOLS.P2; // VLESS
    return PROTOCOLS.P3; // Shadowsocks
}

function parseVlessHeader(buffer) {
    const version = buffer[0];
    const optLength = buffer[17];
    const cmd = buffer[18 + optLength];
    const isUDP = (cmd === COMMAND_TYPES.UDP);
    
    const portIndex = 18 + optLength + 1;
    const portRemote = buffer.readUInt16BE(portIndex);
    
    let addressIndex = portIndex + 2;
    const addressType = buffer[addressIndex];
    let addressRemote = "";
    let rawDataIndex = addressIndex + 1;

    if (addressType === ADDRESS_TYPES.IPV4) {
        addressRemote = [...buffer.subarray(rawDataIndex, rawDataIndex + 4)].join('.');
        rawDataIndex += 4;
    } else if (addressType === ADDRESS_TYPES.DOMAIN) {
        const len = buffer[rawDataIndex];
        addressRemote = buffer.subarray(rawDataIndex + 1, rawDataIndex + 1 + len).toString();
        rawDataIndex += 1 + len;
    }

    return { addressRemote, portRemote, isUDP, rawClientData: buffer.subarray(rawDataIndex), version: Buffer.from([version, 0]) };
}

function parseTrojanHeader(buffer) {
    const dataBuffer = buffer.subarray(58);
    const cmd = dataBuffer[0];
    const isUDP = (cmd === COMMAND_TYPES.UDP_ALT);
    const addressType = dataBuffer[1];
    
    let addressRemote = "";
    let portIndex = 2;

    if (addressType === ADDRESS_TYPES.IPV4) {
        addressRemote = [...dataBuffer.subarray(2, 6)].join('.');
        portIndex = 6;
    } else if (addressType === ADDRESS_TYPES.DOMAIN_ALT) {
        const len = dataBuffer[2];
        addressRemote = dataBuffer.subarray(3, 3 + len).toString();
        portIndex = 3 + len;
    }
    
    const portRemote = dataBuffer.readUInt16BE(portIndex);
    return { addressRemote, portRemote, isUDP, rawClientData: dataBuffer.subarray(portIndex + 4), version: null };
}

// ==================== UI HTML FRONTEND ====================
const UI_HTML = `<!DOCTYPE html>
<html lang="en" id="htmlRoot">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VPN Config Manager (Node.js)</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * { transition: background-color 0.3s ease, border-color 0.3s ease, color 0.3s ease; }
        .cloud-blur { position: fixed; border-radius: 50%; filter: blur(80px); pointer-events: none; z-index: 0; animation: floatCloud 20s ease-in-out infinite; }
        @keyframes floatCloud {
            0%, 100% { transform: translate(0, 0) scale(1); }
            33% { transform: translate(30px, -30px) scale(1.1); }
            66% { transform: translate(-20px, 20px) scale(0.9); }
        }
        body { background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 100%); color: #f1f5f9; }
        body.light { background: linear-gradient(135deg, #f0f9ff 0%, #e0f2fe 100%); color: #0f172a; }
        body.light .glass-deep { background: rgba(255, 255, 255, 0.7); backdrop-filter: blur(12px); border: 1px solid rgba(255, 255, 255, 0.3); }
        .glass-deep { background: rgba(15, 23, 42, 0.5); backdrop-filter: blur(12px); border: 1px solid rgba(255, 255, 255, 0.1); }
        .dropdown-menu { display: none; position: absolute; right: 0; top: 100%; margin-top: 0.5rem; width: 220px; z-index: 50; background: rgba(30, 41, 59, 0.95); backdrop-filter: blur(16px); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 12px; padding: 8px; box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3); }
        body.light .dropdown-menu { background: rgba(255, 255, 255, 0.95); border: 1px solid rgba(0, 0, 0, 0.05); }
        .dropdown-menu.show { display: block; animation: fadeIn 0.2s ease-out; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(-10px); } to { opacity: 1; transform: translateY(0); } }
        .status-badge { display: inline-flex; align-items: center; gap: 4px; padding: 2px 8px; border-radius: 20px; font-size: 11px; font-weight: bold; }
        .status-active { background: rgba(16, 185, 129, 0.2); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.3); }
        .status-inactive { background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.3); }
        .status-checking { background: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.3); }
        .tooltip { position: relative; cursor: help; }
        .tooltip:hover::after { content: attr(data-tooltip); position: absolute; bottom: 100%; left: 50%; transform: translateX(-50%); background: rgba(0,0,0,0.9); color: white; padding: 4px 8px; border-radius: 6px; font-size: 10px; white-space: nowrap; z-index: 100; margin-bottom: 5px; }
    </style>
</head>
<body class="min-h-screen py-4 md:py-8 px-3 md:px-6 relative">
    <div class="cloud-blur w-[500px] h-[500px] top-[-150px] left-[-150px]" style="background: radial-gradient(circle, rgba(59,130,246,0.4) 0%, rgba(139,92,246,0.2) 100%);"></div>
    <div class="max-w-7xl mx-auto relative z-10">
        <div class="flex flex-col md:flex-row justify-between items-center mb-8 gap-4">
            <div>
                <h1 class="text-3xl md:text-5xl font-black bg-gradient-to-r from-blue-400 via-cyan-400 to-purple-400 bg-clip-text text-transparent">VPN Config Manager</h1>
            </div>
            <button id="themeToggle" class="w-10 h-10 rounded-full glass-deep flex items-center justify-center text-lg"><i class="fas fa-moon"></i></button>
        </div>

        <div class="glass-deep rounded-2xl overflow-hidden shadow-2xl">
            <div class="p-4 md:p-6 border-b border-white/10">
                <input type="text" id="searchInput" placeholder="Search country or ISP..." class="w-full bg-white/10 border border-white/10 rounded-xl py-3 px-4 focus:outline-none">
            </div>
            <div class="overflow-x-auto p-2 md:p-4">
                <table class="w-full border-collapse">
                    <thead>
                        <tr class="border-b border-white/5 text-left text-xs uppercase tracking-wider text-slate-400">
                            <th class="py-4 px-4">Location</th>
                            <th class="py-4 px-4">Provider</th>
                            <th class="py-4 px-4 text-center">Status</th>
                            <th class="py-4 px-4 text-right">Action</th>
                        </tr>
                    </thead>
                    <tbody id="proxyTableBody"></tbody>
                </table>
            </div>
            <div id="loading" class="py-24 text-center flex flex-col items-center gap-4">
                <div class="animate-spin rounded-full h-10 w-10 border-t-2 border-b-2 border-blue-500"></div>
                <p class="text-slate-400 text-sm">Fetching proxy list...</p>
            </div>
            <div class="p-4 md:p-6 border-t border-white/10 flex flex-col md:flex-row justify-between items-center gap-4">
                <div id="paginationInfo" class="text-slate-400 text-xs font-mono"></div>
                <div class="flex gap-3 items-center" id="paginationControls"></div>
            </div>
        </div>
    </div>

    <script>
        const themeToggleBtn = document.getElementById('themeToggle');
        themeToggleBtn.addEventListener('click', () => {
            document.body.classList.toggle('light');
            themeToggleBtn.innerHTML = document.body.classList.contains('light') ? '<i class="fas fa-sun"></i>' : '<i class="fas fa-moon"></i>';
        });

        const uuid = "${vmessUUID}";
        const host = window.location.host;
        const proxyListUrl = "${proxyListUrl}";
        const CHECK_API_URL = "${CHECK_API_URL}";

        let allProxies = [];
        let filteredProxies = [];
        let currentPage = 1;
        const itemsPerPage = 10;
        let statusCache = new Map();

        async function fetchProxies() {
            try {
                const response = await fetch(proxyListUrl);
                const text = await response.text();
                allProxies = text.trim().split('\\n').map(line => {
                    const [ip, port, country, isp] = line.split(',');
                    return { ip, port, country, isp, countryCode: country, status: null };
                }).filter(p => p.ip && p.port);
                filteredProxies = [...allProxies];
                renderTable();
                document.getElementById('loading').classList.add('hidden');
            } catch (error) { console.error(error); }
        }

        function renderTable() {
            const start = (currentPage - 1) * itemsPerPage;
            const paged = filteredProxies.slice(start, start + itemsPerPage);
            const tbody = document.getElementById('proxyTableBody');
            tbody.innerHTML = '';
            
            paged.forEach((proxy, idx) => {
                const id = start + idx;
                const path = encodeURIComponent('/' + proxy.ip + '=' + proxy.port);
                const vless = 'vless://' + uuid + '@' + host + ':443?encryption=none&security=tls&type=ws&host=' + host + '&path=' + path + '&sni=' + host + '#' + proxy.country;
                
                tbody.innerHTML += '<tr class="border-b border-white/5 hover:bg-white/5">' +
                    '<td class="py-4 px-4 font-bold text-sm">' + proxy.country + '<br><span class="text-xs font-mono text-slate-400">' + proxy.ip + ':' + proxy.port + '</span></td>' +
                    '<td class="py-4 px-4 text-sm">' + (proxy.isp || '-') + '</td>' +
                    '<td class="py-4 px-4 text-center status-cell"><div class="status-badge status-inactive">READY</div></td>' +
                    '<td class="py-4 px-4 text-right relative dropdown-container">' +
                    '<button onclick="toggleDropdown(\\'' + id + '\\')" class="bg-blue-600 text-white px-4 py-2 rounded-lg text-xs font-bold">Config</button>' +
                    '<div id="drop-' + id + '" class="dropdown-menu">' +
                    '<button onclick="copyToClipboard(\\'' + vless + '\\', this)" class="w-full bg-indigo-600 text-white p-2 rounded text-xs">Copy VLESS</button>' +
                    '</div></td></tr>';
            });
            updatePagination();
        }

        function toggleDropdown(id) {
            document.querySelectorAll('.dropdown-menu').forEach(el => el.classList.remove('show'));
            document.getElementById('drop-' + id).classList.toggle('show');
        }

        function updatePagination() {
            const totalPages = Math.ceil(filteredProxies.length / itemsPerPage) || 1;
            document.getElementById('paginationInfo').innerText = 'Page ' + currentPage + ' of ' + totalPages;
            const controls = document.getElementById('paginationControls');
            controls.innerHTML = '';
            
            const prev = document.createElement('button');
            prev.className = "px-3 py-1 rounded bg-white/10 text-xs";
            prev.innerText = "Prev";
            prev.disabled = currentPage === 1;
            prev.onclick = () => { currentPage--; renderTable(); };

            const next = document.createElement('button');
            next.className = "px-3 py-1 rounded bg-white/10 text-xs";
            next.innerText = "Next";
            next.disabled = currentPage === totalPages;
            next.onclick = () => { currentPage++; renderTable(); };

            controls.append(prev, next);
        }

        function copyToClipboard(text, btn) {
            navigator.clipboard.writeText(text).then(() => {
                btn.innerText = "Copied!";
                setTimeout(() => { btn.innerText = "Copy VLESS"; }, 1500);
            });
        }

        fetchProxies();
    </script>
</body>
</html>`;

// ==================== HTTP SERVER ROOT ====================
const server = http.createServer((req, res) => {
    // Tambahan: Endpoint Healthcheck untuk Railway
    if (req.url === '/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'UP', timestamp: new Date().toISOString() }));
    } 
    else if (req.url === '/' || req.url === '/index.html') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(UI_HTML);
    } 
    else {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Not Found');
    }
});

// ==================== CORE TUNNEL WEBSOCKET SERVER ====================
const wss = new WebSocketServer({ server });

wss.on('connection', async (ws, req) => {
    console.log(`[Proxy] Terhubung via WebSocket dari path: ${req.url}`);
    
    // Abaikan websocket handshake jika request menuju ke path healthcheck
    if (req.url === '/health') {
        ws.close();
        return;
    }

    const proxyFromPath = await getProxyFromPath(req.url);
    if (proxyFromPath) prxIP = proxyFromPath;

    let remoteSocket = null;
    let isHeaderParsed = false;

    ws.on('message', async (message) => {
        let chunk = Buffer.isBuffer(message) ? message : Buffer.from(message);

        if (!isHeaderParsed) {
            const protocol = await detectProtocol(chunk);
            let targetHost = "";
            let targetPort = 443;
            let rawClientData = chunk;
            let responseHeader = null;

            if (protocol === PROTOCOLS.P2) { // VLESS
                const parsed = parseVlessHeader(chunk);
                targetHost = parsed.addressRemote;
                targetPort = parsed.portRemote;
                rawClientData = parsed.rawClientData;
                responseHeader = parsed.version;
            } else if (protocol === PROTOCOLS.P1) { // Trojan
                const parsed = parseTrojanHeader(chunk);
                targetHost = parsed.addressRemote;
                targetPort = parsed.portRemote;
                rawClientData = parsed.rawClientData;
            }

            if (prxIP) {
                const [pHost, pPort] = prxIP.split(/[:=-]/);
                targetHost = pHost;
                targetPort = parseInt(pPort) || 443;
            }

            console.log(`[Proxy Outbound] Dial ke target: ${targetHost}:${targetPort}`);

            remoteSocket = net.connect(targetPort, targetHost, () => {
                if (responseHeader) ws.send(responseHeader);
                remoteSocket.write(rawClientData);
            });

            remoteSocket.on('data', (remoteChunk) => {
                if (ws.readyState === ws.OPEN) ws.send(remoteChunk);
            });

            remoteSocket.on('end', () => ws.close());
            remoteSocket.on('error', (err) => {
                console.log('[TCP Error]', err.message);
                ws.close();
            });

            isHeaderParsed = true;
        } else {
            if (remoteSocket && remoteSocket.writable) {
                remoteSocket.write(chunk);
            }
        }
    });

    ws.on('close', () => {
        if (remoteSocket) remoteSocket.end();
        console.log('[Proxy] WebSocket diputus oleh client.');
    });
});

// Jalankan Server
server.listen(PORT, () => {
    console.log(`=================================================`);
    console.log(` VPN Config Manager Node.js Aktif!`);
    console.log(` URL Dashboard: http://localhost:${PORT}/`);
    console.log(` Healthcheck Endpoint: http://localhost:${PORT}/health`);
    console.log(`=================================================`);
});
