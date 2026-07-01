/**
 * tunnel-manager.js — Persistent SSH Tunnel Manager
 *
 * Spawns the localhost.run SSH tunnel, detects the public URL,
 * publishes it to KV Store for auto-discovery, and auto-restarts
 * if the tunnel dies. Runs as a PM2-managed process.
 */

'use strict';

const { spawn } = require('child_process');
const https = require('https');
const fs = require('fs');
const path = require('path');

const LOG_FILE = path.join(__dirname, 'lhr3.log');
const KV_APP_KEY = 'b1v0t309';

let tunnelProcess = null;
let currentUrl = null;
let publishTimer = null;

// ── Logging ──────────────────────────────────────────────────────────────────
function log(msg) {
  const ts = new Date().toISOString().replace('T', ' ').slice(0, 19);
  console.log(`[${ts}] [Tunnel] ${msg}`);
}

// ── Extract lhr.life URL from text ──────────────────────────────────────────
function extractUrl(text) {
  const m = text.match(/https:\/\/[a-f0-9]+\.lhr\.life/);
  return m ? m[0] : null;
}

// ── Publish URL to KV Store ──────────────────────────────────────────────────
async function publishUrl(url) {
  if (!url) return;
  try {
    const b64 = Buffer.from(url).toString('base64')
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const kvPath = `/api/KeyVal/UpdateValue/${KV_APP_KEY}/server_url/${b64}`;

    await new Promise((resolve, reject) => {
      const req = https.request({
        hostname: 'keyvalue.immanuel.co',
        port: 443,
        path: kvPath,
        method: 'POST',
        headers: { 'Content-Length': '0' },
        timeout: 10000,
      }, (res) => {
        res.on('data', () => {});
        res.on('end', () => {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            log(`✅ Published URL to KV Store: ${url}`);
            currentUrl = url;
            resolve();
          } else {
            reject(new Error(`KV HTTP ${res.statusCode}`));
          }
        });
      });
      req.on('error', reject);
      req.on('timeout', () => req.destroy(new Error('timeout')));
      req.end();
    });
  } catch (err) {
    log(`⚠️  KV Store publish failed: ${err.message}`);
  }
}

// ── Re-publish every 4 minutes to keep KV store fresh ───────────────────────
function startPublishInterval() {
  if (publishTimer) clearInterval(publishTimer);
  publishTimer = setInterval(() => {
    if (currentUrl) publishUrl(currentUrl);
  }, 4 * 60 * 1000);
}

// ── Start the SSH Tunnel ─────────────────────────────────────────────────────
function startTunnel() {
  // Clean up old log
  try { fs.unlinkSync(LOG_FILE); } catch (_) {}

  log('Starting SSH tunnel to localhost.run...');

  tunnelProcess = spawn('ssh', [
    '-o', 'StrictHostKeyChecking=no',
    '-o', 'ServerAliveInterval=30',
    '-o', 'ServerAliveCountMax=3',
    '-o', 'ExitOnForwardFailure=yes',
    '-R', '80:127.0.0.1:3000',
    'nokey@localhost.run',
  ], {
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  let outputBuffer = '';

  function handleOutput(data) {
    const text = data.toString();
    outputBuffer += text;

    // Write to log file for server.js detection
    try { fs.appendFileSync(LOG_FILE, text); } catch (_) {}

    // Extract URL from output
    const url = extractUrl(outputBuffer);
    if (url && url !== currentUrl) {
      log(`🌐 Tunnel URL: ${url}`);
      publishUrl(url);
      startPublishInterval();
    }

    // Log non-empty lines
    text.split('\n').filter(l => l.trim()).forEach(l => console.log(l));
  }

  tunnelProcess.stdout.on('data', handleOutput);
  tunnelProcess.stderr.on('data', handleOutput);

  tunnelProcess.on('exit', (code, signal) => {
    log(`⚠️  Tunnel exited (code=${code}, signal=${signal}). Restarting in 15s...`);
    currentUrl = null;
    tunnelProcess = null;
    setTimeout(startTunnel, 15000);
  });

  tunnelProcess.on('error', (err) => {
    log(`❌ Tunnel process error: ${err.message}`);
  });
}

// ── Wait for server to be ready before starting tunnel ──────────────────────
async function waitForServer(maxWaitMs = 60000) {
  const start = Date.now();
  log('Waiting for Node.js server on port 3000...');
  while (Date.now() - start < maxWaitMs) {
    try {
      await new Promise((resolve, reject) => {
        const req = require('http').get('http://localhost:3000/api/health', (res) => {
          if (res.statusCode === 200) resolve();
          else reject(new Error(`HTTP ${res.statusCode}`));
        });
        req.on('error', reject);
        req.setTimeout(2000, () => req.destroy(new Error('timeout')));
      });
      log('✅ Server is ready!');
      return true;
    } catch (_) {
      await new Promise(r => setTimeout(r, 3000));
    }
  }
  log('⚠️  Server not ready after 60s — starting tunnel anyway');
  return false;
}

// ── Main ─────────────────────────────────────────────────────────────────────
(async () => {
  log('Tunnel Manager starting...');
  await waitForServer(30000);
  startTunnel();
})();

// Graceful shutdown
process.on('SIGINT',  () => { if (tunnelProcess) tunnelProcess.kill(); process.exit(0); });
process.on('SIGTERM', () => { if (tunnelProcess) tunnelProcess.kill(); process.exit(0); });
