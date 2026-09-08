// simcast-template-version: 2
/**
 * simcast auth gate.
 *
 * serve-sim ships no authentication, so exposing port 3200 through a public
 * tunnel would hand simulator control to anyone who guessed the URL. This is a
 * dependency-free reverse proxy that requires `?k=<token>` once, trades it for
 * an HttpOnly cookie, and forwards everything (including the MJPEG stream and
 * the control WebSocket) to serve-sim on localhost.
 */
const http = require('node:http');
const net = require('node:net');

const TOKEN = process.env.SIMCAST_GATE_TOKEN || '';
const TARGET_PORT = Number(process.env.SIMCAST_TARGET_PORT || 3200);
const TARGET_HOST = '127.0.0.1';
const PORT = Number(process.env.SIMCAST_GATE_PORT || 3199);
const COOKIE = 'simcast_k';

if (!TOKEN) {
  console.error('SIMCAST_GATE_TOKEN is required — refusing to proxy an unauthenticated simulator');
  process.exit(1);
}

function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function cookieToken(req) {
  const raw = req.headers.cookie || '';
  for (const part of raw.split(';')) {
    const [name, ...rest] = part.trim().split('=');
    if (name === COOKIE) return rest.join('=');
  }
  return null;
}

/** Returns 'cookie' when already authorised, 'query' when the token was just presented, or false. */
function authorize(req) {
  if (timingSafeEqual(cookieToken(req), TOKEN)) return 'cookie';
  const url = new URL(req.url, 'http://localhost');
  if (timingSafeEqual(url.searchParams.get('k'), TOKEN)) return 'query';
  return false;
}

const DENIED = `<!doctype html><meta charset=utf-8><title>simcast</title>
<style>body{font:14px/1.6 -apple-system,system-ui,sans-serif;margin:15vh auto;max-width:34rem;padding:0 1.5rem;color:#111}
@media(prefers-color-scheme:dark){body{background:#111;color:#eee}}code{background:#8882;padding:.15em .4em;border-radius:4px}</style>
<h1>🔒 simcast</h1>
<p>This simulator stream needs the access key from the link the CLI printed.</p>
<p>Ask whoever started the session for the full URL — the one ending in <code>?k=…</code>.</p>`;

const server = http.createServer((req, res) => {
  if (req.url.startsWith('/__simcast/healthz')) {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: true, target: TARGET_PORT }));
    return;
  }

  const auth = authorize(req);
  if (!auth) {
    res.writeHead(403, { 'content-type': 'text/html; charset=utf-8' });
    res.end(DENIED);
    return;
  }

  // Trade the query token for a cookie so the key stops travelling in URLs
  // (and so the preview's own fetches and WebSocket upgrades carry it).
  if (auth === 'query') {
    const url = new URL(req.url, 'http://localhost');
    url.searchParams.delete('k');
    res.writeHead(302, {
      'set-cookie': `${COOKIE}=${TOKEN}; Path=/; HttpOnly; SameSite=Lax; Max-Age=43200`,
      location: url.pathname + url.search,
    });
    res.end();
    return;
  }

  const upstream = http.request(
    {
      host: TARGET_HOST,
      port: TARGET_PORT,
      method: req.method,
      path: req.url,
      headers: { ...req.headers, host: `${TARGET_HOST}:${TARGET_PORT}` },
    },
    (upRes) => {
      res.writeHead(upRes.statusCode || 502, upRes.headers);
      upRes.pipe(res);
    },
  );

  upstream.on('error', (err) => {
    if (!res.headersSent) res.writeHead(502, { 'content-type': 'text/plain' });
    res.end(`upstream error: ${err.message}`);
  });

  req.pipe(upstream);
});

// WebSockets carry simulator input, so the upgrade path has to be proxied too.
server.on('upgrade', (req, socket, head) => {
  if (!authorize(req)) {
    socket.end('HTTP/1.1 403 Forbidden\r\n\r\n');
    return;
  }

  const upstream = net.connect(TARGET_PORT, TARGET_HOST, () => {
    const headers = Object.entries(req.headers)
      .map(([k, v]) => (Array.isArray(v) ? v.map((x) => `${k}: ${x}`).join('\r\n') : `${k}: ${v}`))
      .join('\r\n');
    upstream.write(`${req.method} ${req.url} HTTP/1.1\r\n${headers}\r\n\r\n`);
    if (head && head.length) upstream.write(head);
    upstream.pipe(socket);
    socket.pipe(upstream);
  });

  const drop = () => {
    socket.destroy();
    upstream.destroy();
  };
  upstream.on('error', drop);
  socket.on('error', drop);
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`simcast gate on :${PORT} -> :${TARGET_PORT}`);
});
