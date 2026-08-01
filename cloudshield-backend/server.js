/**
 * CloudShield — Express Backend (server.js)
 * ==========================================
 * Express + SQLite3 (WAL mode) backend for the CloudShield HIDS dashboard.
 *
 * Endpoints:
 *   POST /api/alert      — Ingest batched threat alerts from actuator.py
 *   GET  /api/status     — Return system status + recent logs for dashboard polling
 *   GET  /api/health     — Liveness probe
 *   POST /api/reset      — Flush Firewall & Clear Active Threats
 *
 * Database: SQLite3 in WAL journal mode for concurrent read/write safety.
 * Table   : ThreatLogs (id, timestamp, threat_type, severity, details, action_taken)
 */

const express    = require('express');
const cors       = require('cors');
const sqlite3    = require('sqlite3').verbose();
const path       = require('path');

// ── Configuration ────────────────────────────────────────────
const PORT        = 3000;
const DB_PATH     = path.join(__dirname, 'cloudshield.db');
const DEFAULT_LIMIT = 20;   // Max rows returned by /api/status

const app = express();
app.use(cors());
app.use(express.json({ limit: '1mb' }));

// ═══════════════════════════════════════════════════════════════
// 1. Database Initialization (SQLite3 + WAL)
// ═══════════════════════════════════════════════════════════════
const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) {
    console.error('[DB] FATAL: Cannot open database:', err.message);
    process.exit(1);
  }
  console.log('[DB] Database opened:', DB_PATH);
});

// Enable WAL mode for safe concurrent reads during writes
db.run('PRAGMA journal_mode = WAL;', (err) => {
  if (err) console.error('[DB] WAL mode failed:', err.message);
  else      console.log('[DB] WAL mode enabled');
});

// Create ThreatLogs table if it doesn't exist
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS ThreatLogs (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp     TEXT    NOT NULL,
      threat_type   TEXT    NOT NULL,
      severity      TEXT    NOT NULL,
      details       TEXT    DEFAULT '',
      action_taken  TEXT    DEFAULT 'logged'
    );
  `);
  db.run(`
    CREATE INDEX IF NOT EXISTS idx_threatlogs_timestamp
    ON ThreatLogs (timestamp DESC);
  `);
  console.log('[DB] ThreatLogs table ready');
});

// ═══════════════════════════════════════════════════════════════
// 2. Severity Normalization Utilities
// ═══════════════════════════════════════════════════════════════

function normalizeSeverity(raw) {
  const s = (raw || '').toString().toUpperCase().trim();
  if (s === 'CRITICAL') return 'CRITICAL';
  if (s === 'HIGH'     || s === 'WARN' || s === 'WARNING') return 'HIGH';
  return 'SAFE';  // "MEDIUM", "LOW", or anything else
}

function worstSeverity(severities) {
  if (severities.includes('CRITICAL')) return 'CRITICAL';
  if (severities.includes('HIGH'))     return 'HIGH';
  return 'SAFE';
}

function severityToLevel(severity) {
  if (severity === 'CRITICAL') return 'critical';
  if (severity === 'HIGH')     return 'warn';
  return 'info';
}

function deriveAction(severity, source_ip) {
  if (severity === 'CRITICAL' && source_ip) return 'Firewall DROP rule applied';
  if (severity === 'HIGH'     && source_ip) return 'Firewall DROP rule applied';
  return 'Logged — monitoring';
}

// ═══════════════════════════════════════════════════════════════
// 3. POST /api/alert — Batch Alert Ingestion
// ═══════════════════════════════════════════════════════════════
app.post('/api/alert', (req, res) => {
  const body = req.body;
  const alerts = body.alerts;

  if (!Array.isArray(alerts) || alerts.length === 0) {
    return res.status(400).json({ error: 'Expected { "alerts": [...] } with at least one alert' });
  }

  const stmt = db.prepare(`
    INSERT INTO ThreatLogs (timestamp, threat_type, severity, details, action_taken)
    VALUES (?, ?, ?, ?, ?)
  `);

  let inserted = 0;
  db.serialize(() => {
    db.run('BEGIN TRANSACTION');

    for (const alert of alerts) {
      const detailsStr = typeof alert.details === 'object'
        ? JSON.stringify(alert.details)
        : String(alert.details || '');

      const severity   = normalizeSeverity(alert.severity);
      const actionTaken = deriveAction(severity, alert.source_ip);

      stmt.run(
        alert.timestamp   || new Date().toISOString(),
        alert.threat_type || 'unknown',
        severity,
        detailsStr,
        actionTaken
      );
      inserted++;
    }

    db.run('COMMIT', (err) => {
      if (err) {
        console.error('[POST /api/alert] COMMIT failed:', err.message);
        return res.status(500).json({ error: 'Database write failed' });
      }
      console.log(`[POST /api/alert] Ingested ${inserted} alert(s)`);
      res.status(201).json({ ingested: inserted, status: 'ok' });
    });
  });
});

// ═══════════════════════════════════════════════════════════════
// 4. GET /api/status — Dashboard Polling Endpoint
// ═══════════════════════════════════════════════════════════════
app.get('/api/status', (req, res) => {
  const limit = Math.min(Math.max(parseInt(req.query.limit) || DEFAULT_LIMIT, 1), 100);

  let baseSql = `
    SELECT id, timestamp, threat_type, severity, details, action_taken
    FROM ThreatLogs
  `;
  const params = [];

  if (req.query.since) {
    baseSql += ' WHERE timestamp > ?';
    params.push(req.query.since);
  }

  baseSql += ' ORDER BY id DESC LIMIT ?';
  params.push(limit);

  db.all(baseSql, params, (err, rows) => {
    if (err) {
      console.error('[GET /api/status] Query error:', err.message);
      return res.status(500).json({ error: 'Database read failed' });
    }

    db.get('SELECT COUNT(*) as cnt FROM ThreatLogs', (err2, countRow) => {
      if (err2) {
        console.error('[GET /api/status] Count error:', err2.message);
        return res.status(500).json({ error: 'Database count failed' });
      }

      const totalRecords = countRow ? countRow.cnt : 0;

      db.all(
        'SELECT severity, threat_type, details, action_taken, timestamp FROM ThreatLogs ORDER BY id DESC LIMIT 50',
        [],
        (err3, recentRows) => {
          if (err3) {
            console.error('[GET /api/status] Recent scan error:', err3.message);
            return res.status(500).json({ error: 'Database recent scan failed' });
          }

          // ── EVALUATE SYSTEM SEVERITY ──
          let systemSeverity = 'SAFE';
          let latestThreat = null;

          // Scan from newest to oldest
          for (const row of recentRows) {
            if (row.threat_type === 'System Reset') {
              // If we hit a reset log before any threat, the system is clear!
              break; 
            }
            if (row.severity === 'CRITICAL' || row.severity === 'HIGH') {
              // We found an active threat that hasn't been reset yet
              systemSeverity = row.severity;
              latestThreat = row;
              break; 
            }
          }

          const logs = rows.reverse().map(row => {
            let detailText = row.details || '';
            try {
              const parsed = JSON.parse(detailText);
              const parts = [];
              if (parsed.attacker_ip)  parts.push(`Attacker: ${parsed.attacker_ip}`);
              if (parsed.attacker_mac) parts.push(`MAC: ${parsed.attacker_mac}`);
              if (parsed.victim_ip)    parts.push(`Victim: ${parsed.victim_ip}`);
              if (parsed.ssid)         parts.push(`SSID: ${parsed.ssid}`);
              if (parsed.bssid)        parts.push(`BSSID: ${parsed.bssid}`);
              if (parsed.channel)      parts.push(`Ch: ${parsed.channel}`);
              if (parsed.reason)       parts.push(parsed.reason);
              if (parts.length > 0) detailText = parts.join(' · ');
            } catch (_) {
              // details was already a plain string, keep it as-is
            }

            if (row.action_taken && row.action_taken !== 'Logged — monitoring') {
              detailText += ` [${row.action_taken}]`;
            }

            let timeStr = '';
            try {
              const d = new Date(row.timestamp);
              timeStr = d.toLocaleTimeString('en-US', {
                hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false
              });
            } catch (_) {
              timeStr = row.timestamp;
            }

            return {
              time:   timeStr,
              title:  row.threat_type || 'Unknown Event',
              detail: detailText,
              level:  severityToLevel(row.severity)
            };
          });

          // ── Build top-level detail string for latest threat ──
          let topLevelDetail = null;
          if (latestThreat) {
            try {
              const parsed = JSON.parse(latestThreat.details || '{}');
              const parts = [];
              if (parsed.attacker_ip)  parts.push(`Source IP: ${parsed.attacker_ip}`);
              if (parsed.attacker_mac) parts.push(`MAC: ${parsed.attacker_mac}`);
              if (parsed.ssid)         parts.push(`SSID: ${parsed.ssid}`);
              if (parsed.bssid)        parts.push(`BSSID: ${parsed.bssid}`);
              if (parsed.spoofed_domain) parts.push(`Target: ${parsed.spoofed_domain}`);
              if (parsed.reason)       parts.push(parsed.reason);
              
              if (parts.length > 0) topLevelDetail = parts.join(' · ');
              else topLevelDetail = latestThreat.details;
            } catch (_) {
              topLevelDetail = latestThreat.details;
            }
          }

          const response = {
            status:              systemSeverity,
            severity:            systemSeverity,
            threat_type:         latestThreat ? latestThreat.threat_type : null,
            details:             topLevelDetail,
            total_records:       totalRecords,
            has_active_threats:  systemSeverity !== 'SAFE',
            logs:                logs
          };

          res.json(response);
        }
      );
    });
  });
});

// ═══════════════════════════════════════════════════════════════
// 5. GET /api/health — Liveness Probe
// ═══════════════════════════════════════════════════════════════
app.get('/api/health', (req, res) => {
  db.get('SELECT 1 as ok', (err, row) => {
    if (err) {
      return res.status(503).json({ status: 'unhealthy', error: err.message });
    }
    res.json({
      status: 'healthy',
      db:     'connected',
      uptime: process.uptime()
    });
  });
});

// ═══════════════════════════════════════════════════════════════
// NEW POST /api/reset — Flush Firewall & Clear Active Threats
// ═══════════════════════════════════════════════════════════════
app.post('/api/reset', (req, res) => {
  const { exec } = require('child_process');

  // Run the flush command on the OS
  exec('sudo iptables -F', (error, stdout, stderr) => {
    if (error) {
      console.error(`[FIREWALL ERROR] ${error.message}`);
      return res.status(500).json({ error: 'Failed to flush firewall' });
    }

    // Insert a "SAFE" log to instantly turn the dashboard green again
    db.run(`
      INSERT INTO ThreatLogs (timestamp, threat_type, severity, details, action_taken)
      VALUES (?, 'System Reset', 'SAFE', 'Admin flushed firewall and restored connectivity.', 'Firewall flushed')
    `, [new Date().toISOString()], (dbErr) => {
      console.log('[FIREWALL] Successfully flushed iptables. System SAFE.');
      res.json({ status: 'ok', message: 'Network restored' });
    });
  });
});

// ═══════════════════════════════════════════════════════════════
// 6. Static File Serving (serve index.html from public/)
// ═══════════════════════════════════════════════════════════════
app.use(express.static(path.join(__dirname, 'public')));

// ═══════════════════════════════════════════════════════════════
// 7. Start Server
// ═══════════════════════════════════════════════════════════════
app.listen(PORT, () => {
  console.log('═══════════════════════════════════════════════════');
  console.log(`  CloudShield Backend running`);
  console.log(`  API:    http://localhost:${PORT}/api/status`);
  console.log(`  Health: http://localhost:${PORT}/api/health`);
  console.log(`  Alert:  POST http://localhost:${PORT}/api/alert`);
  console.log(`  Reset:  POST http://localhost:${PORT}/api/reset`);
  console.log('═══════════════════════════════════════════════════');
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\n[SERVER] Shutting down...');
  db.close((err) => {
    if (err) console.error('[DB] Close error:', err.message);
    process.exit(err ? 1 : 0);
  });
});