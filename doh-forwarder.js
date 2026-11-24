/**
 * DNS-over-HTTPS Forwarder for Short-Polling VPN
 * 
 * Listens on UDP port 5353 (or $PORT env var), receives plain DNS queries,
 * forwards them to dns.google via DNS-over-HTTPS, and returns the response.
 * 
 * Usage:
 *   node doh-forwarder.js
 *   # or: set PORT=5353 && node doh-forwarder.js
 */

const dgram = require('dgram');
const https = require('https');
const http = require('http');

const PORT = parseInt(process.env.PORT || '5533', 10);
const BIND = process.env.BIND || '127.0.0.1';
const DOH_URL = process.env.DOH_URL || 'https://dns.google/dns-query';

// Simple DNS-over-HTTPS client (RFC 8484: application/dns-message)
function dohQuery(dnsMessage) {
    return new Promise((resolve, reject) => {
        const url = new URL(DOH_URL);
        const isGet = url.searchParams.has('name'); // GET-style endpoint
        const options = {
            hostname: url.hostname,
            port: url.port || 443,
            path: url.pathname + url.search,
            method: isGet ? 'GET' : 'POST',
            headers: {
                'Accept': 'application/dns-message',
                'Content-Type': 'application/dns-message',
            },
            timeout: 10000,
        };
        if (!isGet) {
            options.headers['Content-Length'] = dnsMessage.length;
        }

        const req = https.request(options, (res) => {
            const chunks = [];
            res.on('data', (chunk) => chunks.push(chunk));
            res.on('end', () => {
                if (res.statusCode === 200) {
                    resolve(Buffer.concat(chunks));
                } else {
                    reject(new Error(`DOH HTTP ${res.statusCode}`));
                }
            });
        });

        req.on('error', reject);
        req.on('timeout', () => { req.destroy(); reject(new Error('DOH timeout')); });
        
        if (!isGet) {
            req.write(dnsMessage);
        }
        req.end();
    });
}

// Start UDP DNS server
const server = dgram.createSocket('udp4');

server.on('message', (msg, rinfo) => {
    if (msg.length < 12) return; // invalid DNS packet

    dohQuery(msg)
        .then((response) => {
            server.send(response, rinfo.port, rinfo.address);
        })
        .catch((err) => {
            console.error(`[${new Date().toISOString()}] DOH error: ${err.message}`);
            // Return SERVFAIL on error
            const servfail = Buffer.from(msg);
            servfail[2] = 0x85;  // QR=1, RD=1
            servfail[3] = 0x82;  // RA=1, RCODE=2 (SERVFAIL)
            server.send(servfail, rinfo.port, rinfo.address);
        });
});

server.on('listening', () => {
    const addr = server.address();
    console.log(`[${new Date().toISOString()}] DoH forwarder listening on ${addr.address}:${addr.port}`);
    console.log(`  Upstream: ${DOH_URL}`);
    console.log(`  Configure VPN: "tun_dns_upstream": "${addr.address}:${addr.port}"`);
    console.log(`  OR set env: PORT=${addr.port} BIND=${addr.address}`);
});

server.on('error', (err) => {
    console.error(`[${new Date().toISOString()}] Server error: ${err.message}`);
    process.exit(1);
});

server.bind(PORT, BIND);

// Graceful shutdown
process.on('SIGINT', () => {
    console.log(`[${new Date().toISOString()}] Shutting down...`);
    server.close(() => process.exit(0));
});
process.on('SIGTERM', () => {
    console.log(`[${new Date().toISOString()}] Shutting down...`);
    server.close(() => process.exit(0));
});