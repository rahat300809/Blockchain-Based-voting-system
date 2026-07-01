/**
 * ecosystem.config.js — PM2 Process Manager Configuration
 *
 * Manages two always-running processes:
 *   1. blockvote-server  — Node.js API + WebSocket server
 *   2. blockvote-tunnel  — SSH tunnel to localhost.run (public HTTPS URL)
 *
 * Usage:
 *   pm2 start ecosystem.config.js   ← start everything
 *   pm2 save                         ← save process list
 *   pm2 list                         ← see status
 *   pm2 logs                         ← see live logs
 *   pm2 restart all                  ← restart everything
 */

const path = require('path');

module.exports = {
  apps: [
    // ── 1. Node.js API Server ──────────────────────────────────────────
    {
      name: 'blockvote-server',
      script: 'server.js',
      cwd: path.join(__dirname, 'api-server'),
      watch: false,
      autorestart: true,
      restart_delay: 3000,
      max_restarts: 50,
      env: {
        NODE_ENV: 'production',
        PORT: 3000,
      },
      log_file: path.join(__dirname, 'logs', 'server-combined.log'),
      out_file: path.join(__dirname, 'logs', 'server-out.log'),
      error_file: path.join(__dirname, 'logs', 'server-error.log'),
      log_date_format: 'YYYY-MM-DD HH:mm:ss',
      merge_logs: true,
    },

    // ── 2. SSH Tunnel (localhost.run) ──────────────────────────────────
    {
      name: 'blockvote-tunnel',
      script: 'tunnel-manager.js',
      cwd: __dirname,
      watch: false,
      autorestart: true,
      restart_delay: 10000,  // Wait 10s before restarting tunnel
      max_restarts: 100,
      log_file: path.join(__dirname, 'logs', 'tunnel-combined.log'),
      out_file: path.join(__dirname, 'logs', 'tunnel-out.log'),
      error_file: path.join(__dirname, 'logs', 'tunnel-error.log'),
      log_date_format: 'YYYY-MM-DD HH:mm:ss',
      merge_logs: true,
    },
  ],
};
