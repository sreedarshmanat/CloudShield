/**
 * ============================================================================
 *  CloudShield HIDS — Backend Alert Server (server.js)
 * ============================================================================
 *
 *  A production-ready Express.js + SQLite backend that:
 *    1. Receives batched threat alerts from the Python daemon (POST /api/alert)
 *    2. Serves the latest threat logs to the dashboard  (GET  /api/status)
 *    3. Provides a lightweight liveness probe             (GET  /api/health)
 *
 *  All alert inserts are wrapped in a single SQLite transaction for atomic,
 *  high-throughput writes — even during network-flood scenarios.
 *
 *  Dependencies (single-line install):
 *    npm install express cors sqlite3
 *
 *  Run:
 *    node server.js            # production
 *    npm run dev               # auto-restart on file changes (Node 18+)
 * ============================================================================
 */

// ---------------------------------------------------------------------------
//  1. MODULE IMPORTS
// ---------------------------------------------------------------------------
// Express — the HTTP framework that routes incoming requests to handler functions.
const express = require('express');

// cors — middleware that adds Access-Control-Allow-* headers so the frontend
//         dashboard (served from a different origin/port) can call our API
//         without being blocked by the browser's Same-Origin Policy.
const cors = require('cors');

// sqlite3 — asynchronous, event-driven SQLite3 bindings for Node.js.
//           We use the default "callback" API (not the newer promise wrapper)
//           because it integrates cleanly with SQLite's native transaction
//           semantics (BEGIN / COMMIT / ROLLBACK).
const sqlite3 = require('sqlite3').verbose();

// path — built-in Node.js module for resolving file paths in a
//         cross-platform way (Windows backslashes vs. POSIX forward slashes).
const path = require('path');


// ---------------------------------------------------------------------------
//  2. EXPRESS APPLICATION INITIALIZATION
// ---------------------------------------------------------------------------
// create an Express application instance.  This is the central object that
// holds all middleware, route definitions, and settings.
const app = express();

// Define the port the server will listen on.  We read from an environment
// variable first (standard for containerized / cloud deployments) and fall
// back to 3000 for local development.
const PORT = process.env.PORT || 3000;

// The path to the SQLite database file.  It will be created automatically
// by sqlite3 if it does not exist.  Using an absolute path rooted to the
// server's working directory avoids ambiguity.
const DB_PATH = path.join(__dirname, 'cloudshield.db');


// ---------------------------------------------------------------------------
//  3. MIDDLEWARE REGISTRATION
// ---------------------------------------------------------------------------
// express.json() parses incoming requests with Content-Type: application/json
// and populates req.body with the parsed JavaScript object.  The 'limit'
// option caps the request body size to 5 MB to prevent denial-of-service
// attacks that send absurdly large payloads to exhaust server memory.
app.use(express.json({ limit: '5mb' }));

// Enable Cross-Origin Resource Sharing (CORS) for ALL origins.
// In a production hardened deployment you would restrict this to the
// specific origin of your frontend dashboard, e.g.:
//   cors({ origin: 'https://dashboard.cloudshield.local' })
// But for development and flexible deployment we allow any origin.
app.use(cors());


// ---------------------------------------------------------------------------
//  4. SQLITE DATABASE INITIALIZATION
// ---------------------------------------------------------------------------
// We open the database connection once at startup and reuse it for the
// entire lifetime of the process.  sqlite3 uses a single-threaded native
// bindings model, so one connection per process is the correct pattern.
//
// The 'verbose()' mode on the require() above enables long-stack-trace
// logging for easier debugging of asynchronous callback chains.

const db = new sqlite3.Database(DB_PATH, (err) => {
    if (err) {
        // If the database file cannot be opened (permissions, disk full,
        // corrupted file, etc.) we log the error and exit immediately
        // because the server cannot function without persistent storage.
        console.error('[FATAL] Could not connect to SQLite database:');
        console.error(err.message);
        process.exit(1);
    }
    console.log(`[DB] Connected to SQLite database at: ${DB_PATH}`);
});

// SQLite operates in "auto-commit" mode by default — every statement is
// wrapped in its own implicit transaction.  Enabling WAL (Write-Ahead
// Logging) mode provides two major benefits for our use case:
//
//   1. CONCURRENT READS:  Readers never block writers and vice-versa.
//      This means GET /api/status (dashboard polling) will not be blocked
//      by a long-running POST /api/alert transaction that is inserting
//      hundreds of batched alerts.
//
//   2. BETTER WRITE PERFORMANCE:  In WAL mode, writes are appended to a
//      separate log file rather than modifying the database file in-place,
//      which reduces disk I/O contention.
//
// PRAGMA synchronous = NORMAL tells SQLite to not flush to disk on every
// single write, which is safe with WAL mode (the WAL replay covers crash
// recovery) and significantly faster than the default FULL mode.
//
// PRAGMA journal_mode = DELETE would be the default (rollback journal).
// We override it to WAL for the reasons above.
//
// PRAGMA busy_timeout = 5000 tells SQLite to retry for up to 5 seconds
// if the database file is locked by another connection, instead of
// immediately returning SQLITE_BUSY.  This is a safety net for edge
// cases where concurrent readers and writers momentarily conflict.
db.serialize(() => {
    db.run('PRAGMA journal_mode = WAL;');
    db.run('PRAGMA synchronous = NORMAL;');
    db.run('PRAGMA busy_timeout = 5000;');

    // -----------------------------------------------------------------------
    //  CREATE TABLE: ThreatLogs
    // -----------------------------------------------------------------------
    // IF NOT EXISTS makes this idempotent — safe to run on every server
    // startup without risking data loss if the table already exists.
    //
    // Schema decisions:
    //   - id:         AUTOINCREMENT ensures monotonically increasing
    //                 integer keys even if rows are deleted.
    //   - timestamp:  Stored as TEXT in ISO 8601 format (e.g.
    //                 "2026-07-31T21:42:00.000").  SQLite has native
    //                 date/time functions that can parse and compare
    //                 these strings lexicographically.
    //   - severity:   Stored as uppercase text.  We intentionally use
    //                 TEXT instead of an ENUM because SQLite does not
    //                 natively support ENUM — CHECK constraints are the
    //                 alternative, but for a HIDS with evolving threat
    //                 taxonomy, TEXT with application-layer validation
    //                 is more flexible.
    //   - details:    Free-text field for the Python daemon to pass
    //                 rich context (IPs, MACs, packet summaries).
    //   - action_taken: Computed server-side based on severity so the
    //                 frontend can display it without re-deriving logic.
    db.run(`
        CREATE TABLE IF NOT EXISTS ThreatLogs (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp     TEXT    NOT NULL,
            threat_type   TEXT    NOT NULL,
            severity      TEXT    NOT NULL,
            details       TEXT    NOT NULL,
            action_taken  TEXT    NOT NULL
        );
    `, (err) => {
        if (err) {
            console.error('[FATAL] Failed to create ThreatLogs table:');
            console.error(err.message);
            process.exit(1);
        }
        console.log('[DB] ThreatLogs table is ready.');
    });
});

// db.serialize() ensures the PRAGMAs and CREATE TABLE run sequentially.
// After this block, the database is fully initialized and ready for
// concurrent request handling.


// ---------------------------------------------------------------------------
//  5. HELPER: Determine action_taken from severity
// ---------------------------------------------------------------------------
/**
 * Returns the appropriate action_taken string based on the alert severity.
 *
 * The Python daemon may already be executing OS-level firewall commands
 * (netsh / iptables) for HIGH and CRITICAL threats via the Actuator module.
 * This function mirrors that logic on the backend side so that the
 * dashboard can display what was done without querying the agent.
 *
 * @param {string} severity - Uppercase severity level
 *   "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
 * @returns {string} Human-readable action description
 */
function resolveAction(severity) {
    // Normalize to uppercase in case the Python daemon sends mixed case.
    const level = (severity || '').toUpperCase();

    if (level === 'CRITICAL' || level === 'HIGH') {
        return 'Logged & Mitigated via OS Firewall';
    }

    // MEDIUM and LOW severity threats are informational — they are
    // recorded for visibility on the dashboard but do not trigger
    // automated firewall rules.
    return 'Logged to Dashboard';
}


// ---------------------------------------------------------------------------
//  6. ROUTE: POST /api/alert  —  Batch Alert Ingestion
// ---------------------------------------------------------------------------
/**
 * POST /api/alert
 *
 * The Python daemon sends an array of threat alerts every ~10 seconds
 * (the "Threaded Batch Queue" interval).  This endpoint:
 *
 *   1. Validates the request structure (must have a non-empty "alerts" array).
 *   2. Wraps ALL inserts inside a single SQLite transaction (BEGIN → INSERT → COMMIT).
 *      — This is the #1 performance optimization for write-heavy workloads.
 *      — Without a transaction, each INSERT is its own auto-committed
 *        operation, which forces SQLite to flush to disk after every
 *        single row — catastrophically slow during network floods.
 *      — With a transaction, SQLite writes all rows to the WAL in one
 *        fsync() call on COMMIT, which is orders of magnitude faster.
 *   3. Uses a Prepared Statement (the ? placeholders) for two reasons:
 *      a) SQL INJECTION PREVENTION — user-supplied values are never
 *         interpolated into the SQL string; they are bound as parameters.
 *      b) PERFORMANCE — SQLite compiles the SQL once and reuses the
 *         compiled byte-code for each row in the batch.
 *
 * Request Body:
 * {
 *   "alerts": [
 *     {
 *       "timestamp":   "2026-07-31T21:42:00.000",
 *       "threat_type": "ARP Spoofing / Man-in-the-Middle",
 *       "severity":    "CRITICAL",
 *       "details":     "Rogue MAC address detected."
 *     },
 *     ...
 *   ]
 * }
 *
 * Success Response (201):
 * { "success": true, "message": "...", "processed": 5 }
 */
app.post('/api/alert', (req, res) => {
    // --- Input Validation ---
    // Check that req.body.alerts exists, is an array, and is not empty.
    // We use Array.isArray() because typeof [] === 'object' in JavaScript
    // (arrays are objects), so a simple truthiness check would accept {}.
    if (
        !req.body ||
        !Array.isArray(req.body.alerts) ||
        req.body.alerts.length === 0
    ) {
        // 400 Bad Request — the client sent a malformed payload.
        // We return early to avoid entering a transaction unnecessarily.
        return res.status(400).json({
            success: false,
            error: 'Request body must contain a non-empty "alerts" array.'
        });
    }

    const alerts = req.body.alerts;

    // --- Begin Transaction ---
    // db.run('BEGIN') starts an explicit transaction.  From this point
    // until COMMIT or ROLLBACK, all writes are held in memory and only
    // flushed to disk on COMMIT.  If the process crashes mid-transaction,
    // SQLite's WAL replay will automatically roll it back on next open.
    db.run('BEGIN TRANSACTION', (beginErr) => {
        if (beginErr) {
            console.error('[TX] Failed to BEGIN transaction:', beginErr.message);
            return res.status(500).json({
                success: false,
                error: 'Database transaction error.'
            });
        }

        // --- Prepare the INSERT Statement ---
        // db.prepare() returns a Statement object.  We call .run() on it
        // for each alert, binding the values via the ? placeholders.
        // This is a PREPARED STATEMENT — the SQL is compiled once by
        // SQLite's query planner and the compiled byte-code is reused
        // for every .run() call.  This is significantly faster than
        // db.run('INSERT ...', a, b, c) inside a loop because the
        // latter re-parses and re-compiles the SQL string each time.
        const stmt = db.prepare(`
            INSERT INTO ThreatLogs (timestamp, threat_type, severity, details, action_taken)
            VALUES (?, ?, ?, ?, ?)
        `);

        // Track how many rows were successfully inserted so we can
        // report it back in the response.
        let insertedCount = 0;
        // Track whether any individual insert failed so we can ROLLBACK
        // the entire batch — partial writes are unacceptable because
        // they would leave the database in an inconsistent state.
        let hasError = false;

        // --- Iterate Over Each Alert in the Batch ---
        for (let i = 0; i < alerts.length; i++) {
            const alert = alerts[i];

            // Defensive field extraction with fallback defaults.
            // Even though the Python daemon should always send well-formed
            // data, we guard against missing fields to prevent cryptic
            // SQLite NULL constraint errors.
            const timestamp   = alert.timestamp   || new Date().toISOString();
            const threatType = alert.threat_type  || 'Unknown Threat';
            const severity   = String(alert.severity || 'LOW').toUpperCase();
            const details    = alert.details     || 'No additional details.';

            // Dynamically compute action_taken based on severity.
            // This mirrors the Python Actuator's decision logic so the
            // dashboard can display what action was taken without
            // having to re-derive it from severity.
            const actionTaken = resolveAction(severity);

            // Execute the prepared statement with bound parameters.
            // Because we are inside a transaction, this write is buffered
            // and will not hit the disk until COMMIT.
            stmt.run(timestamp, threatType, severity, details, actionTaken, (insertErr) => {
                if (insertErr) {
                    // Log the specific row that failed (with index) for
                    // easier debugging, but do NOT throw — we want to
                    // ROLLBACK the entire batch instead of committing a
                    // partial result.
                    hasError = true;
                    console.error(
                        `[TX] Insert failed at index ${i}:`, insertErr.message
                    );
                    console.error('[TX] Problematic alert payload:', JSON.stringify(alert));
                } else {
                    insertedCount++;
                }

                // --- Check if this was the LAST alert in the batch ---
                // Because SQLite's callback model is asynchronous, we cannot
                // use a simple for-loop with await.  Instead, we check after
                // each callback whether we've processed all alerts.
                //
                // IMPORTANT:  In the sqlite3 callback API, all callbacks
                // from a single serialize() block run on the same tick of
                // the event loop, but the .run() callbacks from a prepared
                // statement in a loop DO fire sequentially.  However, the
                // exact ordering is guaranteed because SQLite serializes
                // all database operations through a single internal mutex.
                if (insertedCount + (hasError ? 1 : 0) >= alerts.length) {
                    // All alerts have been processed.  Now decide: COMMIT or ROLLBACK?
                    if (hasError) {
                        // ROLLBACK discards ALL writes from this transaction,
                        // restoring the database to its pre-BEGIN state.
                        // This ensures atomicity — the database never
                        // contains a partial batch.
                        db.run('ROLLBACK', (rollbackErr) => {
                            if (rollbackErr) {
                                console.error('[TX] ROLLBACK also failed:', rollbackErr.message);
                            }
                            // Finalize the prepared statement to free the
                            // compiled SQL byte-code memory allocated by
                            // SQLite's virtual machine.
                            stmt.finalize();

                            console.warn(`[ALERT] Batch ROLLED BACK — ${alerts.length} alerts rejected due to insert errors.`);
                            return res.status(500).json({
                                success: false,
                                error: 'One or more alerts failed to insert. Entire batch rolled back.',
                                processed: 0
                            });
                        });
                    } else {
                        // COMMIT persists all writes to the WAL file and
                        // flushes to disk.  This is the only fsync() call
                        // for the entire batch — this is why transactions
                        // are so much faster than individual auto-committed
                        // INSERT statements.
                        db.run('COMMIT', (commitErr) => {
                            // Always finalize the statement to prevent
                            // memory leaks, regardless of commit success.
                            stmt.finalize();

                            if (commitErr) {
                                console.error('[TX] COMMIT failed:', commitErr.message);
                                return res.status(500).json({
                                    success: false,
                                    error: 'Failed to commit alert batch.'
                                });
                            }

                            // 201 Created — the standard HTTP status code for
                            // "a new resource was successfully created".
                            console.log(`[ALERT] Batch committed: ${insertedCount} alerts ingested.`);
                            return res.status(201).json({
                                success: true,
                                message: `${insertedCount} alert(s) processed and stored successfully.`,
                                processed: insertedCount
                            });
                        });
                    }
                }
            });
        }
    });
});


// ---------------------------------------------------------------------------
//  7. ROUTE: GET /api/status  —  Dashboard Real-Time Polling
// ---------------------------------------------------------------------------
/**
 * GET /api/status
 *
 * The frontend dashboard polls this endpoint (e.g., every 3-5 seconds)
 * to retrieve the most recent threat logs for real-time display.
 *
 * Query Parameters (optional):
 *   ?limit=N   — Number of recent logs to fetch (default: 10, max: 100)
 *
 * Performance Notes:
 *   - Because we enabled WAL mode, this SELECT will NOT be blocked by
 *     a concurrent POST /api/alert that is in the middle of a transaction.
 *     WAL allows readers to see a consistent snapshot of the database
 *     as it existed before the current write transaction began.
 *   - The ORDER BY id DESC with LIMIT is efficient because id is the
 *     INTEGER PRIMARY KEY, which in SQLite is an alias for the rowid.
 *     The B-Tree index scan can satisfy the query by reading only the
 *     last N leaf pages — no full table scan is needed.
 *
 * Success Response (200):
 * {
 *   "status": "operational",
 *   "total_records": 142,
 *   "recent_alerts": [ ... ]
 * }
 */
app.get('/api/status', (req, res) => {
    // Parse the optional ?limit= query parameter with clamping.
    // parseInt with radix 10 prevents octal interpretation ("010" → 10, not 8).
    // We clamp to a maximum of 100 to prevent unbounded result sets
    // that could exhaust memory on the server or the frontend.
    let limit = parseInt(req.query.limit, 10) || 10;
    limit = Math.max(1, Math.min(limit, 100));

    // First, get the total record count.  This is a lightweight O(1)
    // operation in SQLite because MAX(id) uses the rowid B-Tree index.
    db.get('SELECT MAX(id) AS total FROM ThreatLogs', (countErr, countRow) => {
        if (countErr) {
            console.error('[STATUS] Failed to count records:', countErr.message);
            return res.status(500).json({
                success: false,
                error: 'Failed to query database status.'
            });
        }

        const totalRecords = countRow.total || 0;

        // Fetch the most recent N alerts ordered by id DESCENDING
        // (newest first).  db.all() returns all matching rows as an array.
        //
        // The prepared statement with ? placeholder prevents SQL injection
        // in the LIMIT clause (even though parseInt makes it safe, this
        // is defense-in-depth).
        db.all(
            'SELECT id, timestamp, threat_type, severity, details, action_taken FROM ThreatLogs ORDER BY id DESC LIMIT ?',
            [limit],
            (queryErr, rows) => {
                if (queryErr) {
                    console.error('[STATUS] Failed to fetch recent alerts:', queryErr.message);
                    return res.status(500).json({
                        success: false,
                        error: 'Failed to retrieve threat logs.'
                    });
                }

                // Determine if there are any HIGH/CRITICAL threats in the
                // recent results so the frontend can change its UI state
                // (e.g., flashing red border, alarm sound, etc.).
                const hasActiveThreats = rows.some(
                    (row) => row.severity === 'HIGH' || row.severity === 'CRITICAL'
                );

                return res.status(200).json({
                    status: 'operational',
                    total_records: totalRecords,
                    recent_alerts: rows,
                    has_active_threats: hasActiveThreats
                });
            }
        );
    });
});


// ---------------------------------------------------------------------------
//  8. ROUTE: GET /api/health  —  Liveness / Readiness Probe
// ---------------------------------------------------------------------------
/**
 * GET /api/health
 *
 * A lightweight endpoint used by:
 *   - Container orchestrators (Kubernetes liveness/readiness probes)
 *   - Load balancers (health checks before routing traffic)
 *   - Monitoring systems (Prometheus / Uptime Kuma heartbeat checks)
 *   - Developers (quick manual verification that the server is alive)
 *
 * It performs a minimal database round-trip (SELECT 1) to verify that
 * the SQLite connection is not stale or corrupted, in addition to
 * confirming that the Express server is accepting connections.
 *
 * Success Response (200):
 * { "status": "healthy", "uptime": 3600, "database": "connected" }
 */
app.get('/api/health', (req, res) => {
    // process.uptime() returns the number of seconds the Node.js process
    // has been running.  Useful for operators to detect recent restarts.
    const uptimeSeconds = process.uptime();

    // A quick database round-trip to confirm the connection is alive.
    // SELECT 1 is the cheapest possible SQL query — it touches no tables
    // and returns a single constant value.
    db.get('SELECT 1 AS ping', (err) => {
        if (err) {
            // If even SELECT 1 fails, the database connection is broken.
            console.error('[HEALTH] Database health check failed:', err.message);
            return res.status(503).json({
                // 503 Service Unavailable — the server is running but its
                // dependency (database) is unhealthy.
                status: 'unhealthy',
                uptime: uptimeSeconds,
                database: 'disconnected',
                error: 'Database connection lost.'
            });
        }

        return res.status(200).json({
            status: 'healthy',
            uptime: uptimeSeconds,
            database: 'connected'
        });
    });
});


// ---------------------------------------------------------------------------
//  9. GLOBAL ERROR-HANDLING MIDDLEWARE
// ---------------------------------------------------------------------------
// Express treats middleware with 4 parameters (err, req, res, next) as an
// error-handling middleware.  It is invoked whenever:
//   a) next(err) is called inside a route or middleware, OR
//   b) An unhandled synchronous exception is thrown inside a route handler.
//
// This is the LAST line of defense — if an error reaches here, it means
// no route caught it.  We log the full stack trace for debugging and
// return a generic 500 response to the client (never expose internals).
//
// IMPORTANT:  This must be registered AFTER all routes.  Express matches
// middleware in the order it is registered, so putting this last ensures
// it only catches errors that no route handled.
//
// NOTE:  Asynchronous errors (rejected promises) are NOT caught by this
// middleware in Express 4.x.  If you convert routes to async/await,
// you must wrap them with try/catch or use a library like
// express-async-errors.  Our current callback-based routes do not
// have this issue because errors are passed via the (err, ...) callback.
app.use((err, req, res, _next) => {
    // Log the full error for server-side debugging.
    // In production, you would replace console.error with a structured
    // logging library (winston, pino) that writes to files / syslog.
    console.error(`[ERROR] ${req.method} ${req.path} — ${err.message}`);
    console.error(err.stack);

    // Determine the appropriate HTTP status code.
    // If the error has a statusCode property (set by some middleware
    // or by our own code), use it; otherwise default to 500.
    const statusCode = err.statusCode || 500;

    // Never send the full error message or stack trace to the client.
    // Attackers can use detailed error messages to fingerprint your
    // technology stack and find vulnerabilities.
    res.status(statusCode).json({
        success: false,
        error: statusCode === 500
            ? 'Internal server error. Please try again later.'
            : err.message
    });
});


// ---------------------------------------------------------------------------
//  10. START THE SERVER
// ---------------------------------------------------------------------------
// app.listen() binds the Express app to the specified port and starts
// accepting incoming HTTP connections.  The callback fires once the
// server is ready (not when every request is processed).
//
// We MUST capture the return value (the http.Server instance) into a
// variable so we can call .close() on it during graceful shutdown.
// This is the ONLY app.listen() call in the file.


// ---------------------------------------------------------------------------
//  11. GRACEFUL SHUTDOWN HANDLING
// ---------------------------------------------------------------------------
// When the process receives SIGINT (Ctrl+C in terminal) or SIGTERM
// (sent by `kill <pid>` or container orchestrators during shutdown),
// we need to:
//
//   1. Stop accepting new connections (close the HTTP server).
//   2. Close the SQLite database connection cleanly.  If we don't do
//      this, the WAL file may not be checkpointed and the last
//      transaction could be lost on crash.
//   3. Exit with code 0 (success) after cleanup is complete.
//
// Why not just let the process die?
//   - SQLite's WAL mode requires a clean shutdown to checkpoint the
//     WAL file back into the main database file.  An unclean shutdown
//     leaves the WAL file, which is replayed on next open — this works,
//     but a clean shutdown is faster and avoids recovery overhead.
//   - The HTTP server's keep-alive connections would be abruptly torn
//     down, potentially causing the frontend dashboard to show connection
//     errors instead of a clean "server shutting down" message.

/**
 * Performs a clean shutdown of both the HTTP server and SQLite database.
 *
 * @param {string} signal - The OS signal that triggered the shutdown
 *   ("SIGINT" or "SIGTERM"), used for logging purposes.
 */
function gracefulShutdown(signal) {
    console.log(`
[SHUTDOWN] Received ${signal}. Closing server and database...`);

    // Close the HTTP server first.  This stops Express from accepting
    // NEW connections, but it does NOT terminate existing in-flight
    // requests — those are allowed to complete naturally.
    //
    // The callback fires once the server is fully closed.
    // We set a 5-second timeout to force-close if cleanup hangs
    // (e.g., a long-running transaction is stuck).
    const forceExitTimeout = setTimeout(() => {
        console.error('[SHUTDOWN] Forced exit — cleanup did not complete in time.');
        process.exit(1);
    }, 5000);

    server.close(() => {
        // The HTTP server is now closed.  No more requests can arrive.
        // Now close the SQLite database connection.
        //
        // db.close() runs any pending WAL checkpoint and releases all
        // file handles and memory associated with the database connection.
        db.close((closeErr) => {
            if (closeErr) {
                console.error('[SHUTDOWN] Error closing database:', closeErr.message);
            } else {
                console.log('[SHUTDOWN] Database connection closed cleanly.');
            }

            // Clear the force-exit timeout since we shut down cleanly.
            clearTimeout(forceExitTimeout);

            console.log('[SHUTDOWN] CloudShield server stopped. Goodbye.');
            process.exit(0);
        });
    });
}

// Start the server and capture the http.Server instance for
// graceful shutdown.  We also print the startup banner here.
const server = app.listen(PORT, () => {
    console.log('============================================================');
    console.log('  CloudShield HIDS — Backend Alert Server');
    console.log(`  Listening on:  http://localhost:${PORT}`);
    console.log(`  Database:      ${DB_PATH}`);
    console.log('============================================================');
    console.log('  Endpoints:');
    console.log(`    POST  /api/alert   — Ingest batched threat alerts`);
    console.log(`    GET   /api/status  — Fetch recent threat logs`);
    console.log(`    GET   /api/health  — Server liveness probe`);
    console.log('============================================================');
});

// Register the same handler for both signals.
// SIGINT  = Ctrl+C in the terminal (user-initiated).
// SIGTERM = `kill <pid>` or orchestrator-initiated graceful shutdown.
process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));

// Catch unhandled promise rejections (defense in depth).
// In Node.js 15+, unhandled rejections terminate the process by default.
// We intercept them to log a meaningful message before exit.
process.on('unhandledRejection', (reason, promise) => {
    console.error('[FATAL] Unhandled Promise Rejection at:', promise);
    console.error('[FATAL] Reason:', reason);
    // Do not call process.exit() here — let the process crash naturally
    // so the OS / container orchestrator can detect the failure and
    // restart the service.
});
