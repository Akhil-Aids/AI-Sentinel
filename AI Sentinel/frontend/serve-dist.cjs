const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, 'dist');
const types = { '.css': 'text/css', '.html': 'text/html', '.js': 'text/javascript', '.svg': 'image/svg+xml' };

http.createServer((request, response) => {
  const requested = request.url.split('?')[0];
  const file = requested === '/' ? 'index.html' : requested.replace(/^\//, '');
  const target = path.resolve(root, file);
  const safeTarget = target.startsWith(root) ? target : path.join(root, 'index.html');
  const fallback = path.join(root, 'index.html');
  fs.readFile(safeTarget, (error, body) => {
    if (error) fs.readFile(fallback, (fallbackError, fallbackBody) => {
      if (fallbackError) return response.writeHead(500).end('Unable to load dashboard');
      response.writeHead(200, { 'Content-Type': 'text/html' }).end(fallbackBody);
    });
    else response.writeHead(200, { 'Content-Type': types[path.extname(safeTarget)] || 'application/octet-stream' }).end(body);
  });
}).listen(5173, '127.0.0.1', () => console.log('Dashboard: http://127.0.0.1:5173'));
