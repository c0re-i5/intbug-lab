// Loopback-published Node.js http2 lab server.
// Stdlib only: TLS + ALPN h2, allowHTTP1 so a client can fall back.
// Certs must be mounted at /certs/lab.{crt,key} (same as Caddy/Envoy).
// Basic Range support so cleanup_overcredit fill/canary can run.
'use strict';

const http2 = require('http2');
const fs = require('fs');

function loadCerts() {
  const crtPath = process.env.LAB_CERT || '/certs/lab.crt';
  const keyPath = process.env.LAB_KEY || '/certs/lab.key';
  if (fs.existsSync(crtPath) && fs.existsSync(keyPath)) {
    return { cert: fs.readFileSync(crtPath), key: fs.readFileSync(keyPath) };
  }
  throw new Error(
    'mount certs/lab.crt + lab.key (same as Caddy/Envoy); refusing to start without them'
  );
}

const bodyPath = process.env.LAB_INDEX || '/srv/index.html';
const body = fs.readFileSync(bodyPath);
const { cert, key } = loadCerts();

const server = http2.createSecureServer(
  { cert, key, allowHTTP1: true },
  (req, res) => {
    req.on('error', () => {});
    res.on('error', () => {});
    const raw = req.url || (req.headers && req.headers[':path']) || '/';
    const url = String(raw).split('?')[0];
    if (url !== '/' && url !== '/index.html') {
      res.writeHead(404);
      res.end();
      return;
    }
    res.setHeader('content-type', 'text/html; charset=utf-8');
    res.setHeader('accept-ranges', 'bytes');
    const range = req.headers.range;
    if (typeof range === 'string' && /^bytes=(\d*)-(\d*)$/.test(range)) {
      const m = /^bytes=(\d*)-(\d*)$/.exec(range);
      const start = m[1] === '' ? 0 : parseInt(m[1], 10);
      let end = m[2] === '' ? body.length - 1 : parseInt(m[2], 10);
      if (!Number.isFinite(start) || !Number.isFinite(end) || start >= body.length || start > end) {
        res.writeHead(416);
        res.end();
        return;
      }
      end = Math.min(end, body.length - 1);
      const slice = body.subarray(start, end + 1);
      res.writeHead(206, {
        'content-range': `bytes ${start}-${end}/${body.length}`,
        'content-length': slice.length,
      });
      res.end(slice);
      return;
    }
    res.writeHead(200, { 'content-length': body.length });
    res.end(body);
  }
);

server.on('error', (err) => {
  console.error('node http2 lab server error:', err);
  process.exit(1);
});

// Listen on :443 inside the container. The host publish is 127.0.0.1 only
// (see docker-compose.yml / lab-up-targets.sh). Do not publish 0.0.0.0.
server.listen(443, () => {
  console.log('node http2 lab on :443 body=%d allowHTTP1=true', body.length);
});
