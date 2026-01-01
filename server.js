/**
 * GoXPrint Driver Manager - Full Server with Auth, SQLite, R2
 * 
 * Features:
 * - JWT Authentication
 * - SQLite Database (better-sqlite3)
 * - R2 Storage integration
 * - Settings management
 * - INF File Parsing for printer models
 */

import express from 'express';
import multer from 'multer';
import cors from 'cors';
import crypto from 'crypto';
import http from 'http';
import { WebSocketServer } from 'ws';
import { readFileSync, writeFileSync, existsSync, mkdirSync, unlinkSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { randomUUID } from 'crypto';
import { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand, ListObjectsV2Command, HeadBucketCommand } from '@aws-sdk/client-s3';
import AdmZip from 'adm-zip';
import Database from 'better-sqlite3';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 3001;

// ==================== WEBSOCKET INFRASTRUCTURE ====================
const MESSAGE_QUEUE = new Map(); // deviceId -> [{message, timestamp, retries}]
const PENDING_COMMANDS = new Map(); // commandId -> {deviceId, timeout, callback}
const HEARTBEAT_INTERVAL = 30000; // 30 seconds
const COMMAND_TIMEOUT = 60000; // 60 seconds
const MAX_RETRIES = 3;
const RECONNECT_GRACE_PERIOD = 120000; // 2 minutes

// Message queue for offline devices
function queueMessage(deviceId, message) {
    if (!MESSAGE_QUEUE.has(deviceId)) {
        MESSAGE_QUEUE.set(deviceId, []);
    }
    MESSAGE_QUEUE.get(deviceId).push({
        message,
        timestamp: Date.now(),
        retries: 0
    });

    // Clean old messages (> 10 minutes)
    const queue = MESSAGE_QUEUE.get(deviceId);
    MESSAGE_QUEUE.set(deviceId, queue.filter(m => Date.now() - m.timestamp < 600000));
}

// Send queued messages when device comes online
function flushMessageQueue(deviceId, ws) {
    const queue = MESSAGE_QUEUE.get(deviceId);
    if (!queue || queue.length === 0) return;

    console.log(`[WS] Flushing ${queue.length} queued messages for device ${deviceId}`);
    queue.forEach(item => {
        if (ws.readyState === 1) {
            ws.send(JSON.stringify(item.message));
        }
    });
    MESSAGE_QUEUE.delete(deviceId);
}

// Heartbeat system
function startHeartbeat(ws, identifier) {
    const interval = setInterval(() => {
        if (ws.readyState === 1) {
            ws.ping();
        } else {
            clearInterval(interval);
        }
    }, HEARTBEAT_INTERVAL);

    ws.on('pong', () => {
        ws.lastPong = Date.now();
    });

    return interval;
}

// Command acknowledgment tracking
function trackCommand(commandId, deviceId, callback) {
    const timeout = setTimeout(() => {
        PENDING_COMMANDS.delete(commandId);
        callback({ success: false, error: 'Command timeout after 60s' });
    }, COMMAND_TIMEOUT);

    PENDING_COMMANDS.set(commandId, {
        deviceId,
        timeout,
        callback
    });
}

function acknowledgeCommand(commandId, result) {
    const pending = PENDING_COMMANDS.get(commandId);
    if (pending) {
        clearTimeout(pending.timeout);
        pending.callback(result);
        PENDING_COMMANDS.delete(commandId);
    }
}


// ==================== SQLite DATABASE ====================
const DATA_DIR = join(__dirname, 'data');
const DB_FILE = join(DATA_DIR, 'goxprint.db');
const DRIVERS_DIR = join(DATA_DIR, 'drivers');
const OLD_JSON_FILE = join(DATA_DIR, 'database.json');

// Ensure directories exist
if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true });
if (!existsSync(DRIVERS_DIR)) mkdirSync(DRIVERS_DIR, { recursive: true });

// Initialize SQLite database
const sqlite = new Database(DB_FILE);
sqlite.pragma('journal_mode = WAL');

// Create tables
sqlite.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        display_name TEXT,
        role TEXT DEFAULT 'user',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    
    CREATE TABLE IF NOT EXISTS drivers (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        model TEXT,
        manufacturer TEXT,
        version TEXT,
        size TEXT,
        size_bytes INTEGER,
        file_name TEXT,
        download_url TEXT,
        download_count INTEGER DEFAULT 0,
        models TEXT,
        default_model TEXT,
        inf_count INTEGER DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
    );
    
    CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        user_id TEXT,
        username TEXT,
        display_name TEXT,
        role TEXT,
        expires_at INTEGER
    );
`);

// Migrate from JSON if exists
function migrateFromJSON() {
    if (existsSync(OLD_JSON_FILE)) {
        try {
            const oldData = JSON.parse(readFileSync(OLD_JSON_FILE, 'utf-8'));
            console.log('Migrating from JSON database...');

            // Migrate users
            const insertUser = sqlite.prepare('INSERT OR IGNORE INTO users (id, username, password, display_name, role, created_at) VALUES (?, ?, ?, ?, ?, ?)');
            for (const user of oldData.users || []) {
                insertUser.run(user.id, user.username, user.password, user.displayName, user.role, user.createdAt);
            }

            // Migrate drivers
            const insertDriver = sqlite.prepare('INSERT OR IGNORE INTO drivers (id, name, model, manufacturer, version, size, size_bytes, file_name, download_url, download_count, models, default_model, inf_count, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
            for (const driver of oldData.drivers || []) {
                insertDriver.run(driver.id, driver.name, driver.model, driver.manufacturer, driver.version, driver.size, driver.sizeBytes, driver.fileName, driver.downloadUrl, driver.downloadCount, JSON.stringify(driver.models || []), driver.defaultModel, driver.infCount, driver.createdAt);
            }

            // Migrate settings
            const insertSetting = sqlite.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)');
            for (const [key, value] of Object.entries(oldData.settings || {})) {
                insertSetting.run(key, String(value));
            }

            console.log('Migration complete!');
            // Rename old file to backup
            const backupFile = OLD_JSON_FILE + '.backup';
            if (!existsSync(backupFile)) {
                writeFileSync(backupFile, readFileSync(OLD_JSON_FILE));
            }
        } catch (err) {
            console.error('Migration error:', err.message);
        }
    }
}

// Initialize default data
function initDB() {
    // Check if admin user exists
    const adminExists = sqlite.prepare('SELECT 1 FROM users WHERE username = ?').get('admin');
    if (!adminExists) {
        sqlite.prepare('INSERT INTO users (id, username, password, display_name, role) VALUES (?, ?, ?, ?, ?)').run('admin-001', 'admin', 'admin123', 'Administrator', 'admin');
    }

    // Check if jwt_secret exists
    const jwtSecret = sqlite.prepare('SELECT value FROM settings WHERE key = ?').get('jwt_secret');
    if (!jwtSecret) {
        const defaultSettings = {
            r2_endpoint: '',
            r2_access_key: '',
            r2_secret_key: '',
            r2_bucket: 'goxprint-drivers',
            r2_public_url: 'https://download.goxprint.com',
            r2_enabled: 'false',
            jwt_secret: randomUUID()
        };
        const insertSetting = sqlite.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)');
        for (const [key, value] of Object.entries(defaultSettings)) {
            insertSetting.run(key, value);
        }
    }
}

migrateFromJSON();
initDB();

// Database helper functions
const db = {
    get users() {
        return sqlite.prepare('SELECT id, username, password, display_name as displayName, role, created_at as createdAt FROM users').all();
    },
    get drivers() {
        return sqlite.prepare('SELECT * FROM drivers').all().map(d => ({
            id: d.id,
            name: d.name,
            model: d.model,
            manufacturer: d.manufacturer,
            version: d.version,
            size: d.size,
            sizeBytes: d.size_bytes,
            fileName: d.file_name,
            downloadUrl: d.download_url,
            downloadCount: d.download_count,
            defaultModel: d.default_model,
            infCount: d.inf_count,
            createdAt: d.created_at,
            models: JSON.parse(d.models || '[]')
        }));
    },
    get settings() {
        const rows = sqlite.prepare('SELECT key, value FROM settings').all();
        return rows.reduce((acc, row) => ({ ...acc, [row.key]: row.value }), {});
    },
    get sessions() {
        const rows = sqlite.prepare('SELECT token, user_id, username, display_name, role, expires_at FROM sessions WHERE expires_at > ?').all(Date.now());
        return rows.reduce((acc, row) => ({
            ...acc,
            [row.token]: { userId: row.user_id, username: row.username, displayName: row.display_name, role: row.role, expiresAt: row.expires_at }
        }), {});
    },

    // User methods
    findUser(username, password) {
        return sqlite.prepare('SELECT id, username, password, display_name as displayName, role FROM users WHERE username = ? AND password = ?').get(username, password);
    },

    // Driver methods
    findDriver(id) {
        const d = sqlite.prepare('SELECT * FROM drivers WHERE id = ?').get(id);
        if (!d) return null;
        return {
            id: d.id,
            name: d.name,
            model: d.model,
            manufacturer: d.manufacturer,
            version: d.version,
            size: d.size,
            sizeBytes: d.size_bytes,
            fileName: d.file_name,
            downloadUrl: d.download_url,
            downloadCount: d.download_count,
            defaultModel: d.default_model,
            infCount: d.inf_count,
            createdAt: d.created_at,
            models: JSON.parse(d.models || '[]')
        };
    },
    addDriver(driver) {
        sqlite.prepare('INSERT INTO drivers (id, name, model, manufacturer, version, size, size_bytes, file_name, download_url, download_count, models, default_model, inf_count, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').run(driver.id, driver.name, driver.model, driver.manufacturer, driver.version, driver.size, driver.sizeBytes, driver.fileName, driver.downloadUrl, driver.downloadCount, JSON.stringify(driver.models || []), driver.defaultModel, driver.infCount, driver.createdAt);
    },
    updateDriver(id, updates) {
        const fields = [];
        const values = [];
        if (updates.name) { fields.push('name = ?'); values.push(updates.name); }
        if (updates.model) { fields.push('model = ?'); values.push(updates.model); }
        if (updates.manufacturer) { fields.push('manufacturer = ?'); values.push(updates.manufacturer); }
        if (updates.version) { fields.push('version = ?'); values.push(updates.version); }
        if (updates.models) { fields.push('models = ?'); values.push(JSON.stringify(updates.models)); }
        if (updates.defaultModel) { fields.push('default_model = ?'); values.push(updates.defaultModel); }
        if (updates.downloadCount !== undefined) { fields.push('download_count = ?'); values.push(updates.downloadCount); }
        if (fields.length > 0) {
            values.push(id);
            sqlite.prepare(`UPDATE drivers SET ${fields.join(', ')} WHERE id = ?`).run(...values);
        }
    },
    deleteDriver(id) {
        sqlite.prepare('DELETE FROM drivers WHERE id = ?').run(id);
    },

    // Session methods
    addSession(token, session) {
        sqlite.prepare('INSERT OR REPLACE INTO sessions (token, user_id, username, display_name, role, expires_at) VALUES (?, ?, ?, ?, ?, ?)').run(token, session.userId, session.username, session.displayName, session.role, session.expiresAt);
    },
    deleteSession(token) {
        sqlite.prepare('DELETE FROM sessions WHERE token = ?').run(token);
    },

    // Settings methods
    updateSettings(updates) {
        const stmt = sqlite.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)');
        for (const [key, value] of Object.entries(updates)) {
            if (key !== 'jwt_secret') stmt.run(key, String(value));
        }
    }
};

// For backward compatibility (used by some functions)
function saveDB() {
    // No-op for SQLite, data is saved immediately
}

// ==================== INF PARSER ====================
// Improved parser that correctly extracts printer model names
function parseINFFile(infContent) {
    const models = [];
    const lines = infContent.split('\n');
    const stringDefs = new Map(); // Store [Strings] section values

    let inModelsSection = false;
    let inStringsSection = false;
    let manufacturer = '';
    let driverName = '';

    // First pass: collect string definitions
    for (let line of lines) {
        line = line.trim();
        if (line.startsWith(';') || line === '') continue;

        if (line.startsWith('[') && line.endsWith(']')) {
            const section = line.slice(1, -1).toLowerCase();
            inStringsSection = section === 'strings';
            continue;
        }

        if (inStringsSection && line.includes('=')) {
            const parts = line.split('=');
            if (parts.length >= 2) {
                const key = parts[0].trim();
                const value = parts[1].trim().replace(/^"|"$/g, '');
                if (key && value) {
                    stringDefs.set(key.toLowerCase(), value);
                }
            }
        }
    }

    // Second pass: find models
    for (let line of lines) {
        line = line.trim();
        if (line.startsWith(';') || line === '') continue;

        // Check for section headers
        if (line.startsWith('[') && line.endsWith(']')) {
            const section = line.slice(1, -1).toLowerCase();

            // Models section: manufacturer.nt* but NOT strings, version, install, etc.
            if (section.includes('.nt') &&
                !section.includes('install') &&
                !section.includes('service') &&
                !section.includes('copyfiles') &&
                !section.includes('registrydata')) {
                inModelsSection = true;
            } else {
                inModelsSection = false;
            }
            continue;
        }

        // Parse manufacturer name
        if (line.toLowerCase().includes('manufacturer=')) {
            const match = line.match(/Manufacturer\s*=\s*"?([^",%]+)/i);
            if (match) manufacturer = match[1].trim();
        }

        // Parse driver name from DriverPackageDisplayName
        if (line.toLowerCase().includes('driverpackagedisplayname')) {
            const match = line.match(/=\s*"?([^"]+)/i);
            if (match) {
                driverName = match[1].trim();
                // Resolve string reference
                if (driverName.startsWith('%') && driverName.endsWith('%')) {
                    const key = driverName.slice(1, -1).toLowerCase();
                    driverName = stringDefs.get(key) || driverName;
                }
            }
        }

        // Parse model entries in models section
        // Format: "Model Name" = install_section, hwid1, hwid2, ...
        if (inModelsSection && line.includes('=')) {
            let modelName = '';

            // Try quoted format first: "Model Name" = section
            const modelMatch = line.match(/^"([^"]+)"/);
            if (modelMatch) {
                modelName = modelMatch[1].trim();
            } else {
                // Try unquoted format: ModelName = section
                const unquotedMatch = line.match(/^([^=]+)=/);
                if (unquotedMatch) {
                    modelName = unquotedMatch[1].trim();
                }
            }

            // Resolve string reference like %ModelName%
            if (modelName.startsWith('%') && modelName.endsWith('%')) {
                const key = modelName.slice(1, -1).toLowerCase();
                modelName = stringDefs.get(key) || '';
            }

            // Filter out invalid model names
            const invalidNames = [
                'addservice', 'install', 'copyfiles', 'ntamd64', 'ntx86',
                'ntarm', 'ntarm64', 'ntia64', 'coinstaller', 'registry',
                'manufacturer', 'version', 'strings', 'sourcefiles',
                'destinationdir', 'defaultinstall', 'wdf', 'class'
            ];

            const nameLower = modelName.toLowerCase();
            const isValid = modelName &&
                modelName.length > 5 &&  // Model names are usually longer
                !invalidNames.some(inv => nameLower.includes(inv)) &&
                !nameLower.match(/^\d+$/) &&  // Not just numbers
                !nameLower.startsWith('_') &&
                (
                    // Should contain printer-related keywords or brand names
                    nameLower.includes('pcl') ||
                    nameLower.includes('ps') ||
                    nameLower.includes('print') ||
                    nameLower.includes('laser') ||
                    nameLower.includes('jet') ||
                    nameLower.includes('fax') ||
                    nameLower.includes('mfp') ||
                    nameLower.includes('ricoh') ||
                    nameLower.includes('hp') ||
                    nameLower.includes('canon') ||
                    nameLower.includes('epson') ||
                    nameLower.includes('brother') ||
                    nameLower.includes('xerox') ||
                    nameLower.includes('konica') ||
                    nameLower.includes('kyocera') ||
                    nameLower.includes('sharp') ||
                    nameLower.includes('samsung') ||
                    nameLower.includes('lexmark') ||
                    nameLower.includes('oki') ||
                    nameLower.includes('driver') ||
                    nameLower.includes('universal')
                );

            if (isValid) {
                models.push(modelName);
            }
        }
    }

    // If no models found, try to use driverName
    if (models.length === 0 && driverName) {
        models.push(driverName);
    }

    // Remove duplicates and sort
    const uniqueModels = [...new Set(models)].sort();

    return {
        manufacturer,
        driverName,
        models: uniqueModels
    };
}

function extractModelsFromZip(zipFilePath) {
    try {
        const zip = new AdmZip(zipFilePath);
        const zipEntries = zip.getEntries();

        let allModels = [];
        let manufacturer = '';
        let driverName = '';
        let infFiles = [];

        // Find all .inf files
        for (const entry of zipEntries) {
            if (entry.entryName.toLowerCase().endsWith('.inf')) {
                infFiles.push(entry);
            }
        }

        console.log(`Found ${infFiles.length} INF files in ZIP`);

        // Parse each INF file
        for (const infEntry of infFiles) {
            try {
                const infContent = infEntry.getData().toString('utf-8');
                const parsed = parseINFFile(infContent);

                if (parsed.manufacturer && !manufacturer) {
                    manufacturer = parsed.manufacturer;
                }
                if (parsed.driverName && !driverName) {
                    driverName = parsed.driverName;
                }
                if (parsed.models.length > 0) {
                    allModels = allModels.concat(parsed.models);
                }

                console.log(`Parsed ${infEntry.entryName}: ${parsed.models.length} models`);
            } catch (parseError) {
                console.error(`Error parsing ${infEntry.entryName}:`, parseError.message);
            }
        }

        // Remove duplicates and sort
        const uniqueModels = [...new Set(allModels)].sort();

        return {
            manufacturer,
            driverName,
            models: uniqueModels,
            infCount: infFiles.length
        };
    } catch (error) {
        console.error('Error extracting models from ZIP:', error.message);
        return { manufacturer: '', driverName: '', models: [], infCount: 0 };
    }
}

// ==================== AUTH HELPERS ====================
function generateToken() {
    return crypto.randomBytes(32).toString('hex');
}

function hashPassword(password) {
    return crypto.createHash('sha256').update(password + db.settings.jwt_secret).digest('hex');
}

function verifyToken(token) {
    return db.sessions[token];
}

// Auth middleware
function authMiddleware(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    const token = authHeader.split(' ')[1];
    const session = verifyToken(token);

    if (!session) {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }

    req.user = session;
    next();
}

// ==================== R2 CLIENT ====================
let s3Client = null;

function initR2Client() {
    const settings = db.settings;
    if (settings.r2_enabled === 'true' && settings.r2_endpoint && settings.r2_access_key && settings.r2_secret_key) {
        s3Client = new S3Client({
            region: 'auto',
            endpoint: settings.r2_endpoint,
            credentials: {
                accessKeyId: settings.r2_access_key,
                secretAccessKey: settings.r2_secret_key,
            },
        });
        return true;
    }
    return false;
}

// ==================== MULTER ====================
const storage = multer.diskStorage({
    destination: DRIVERS_DIR,
    filename: (req, file, cb) => {
        const id = randomUUID();
        const safeName = file.originalname.replace(/[^a-zA-Z0-9.-]/g, '_');
        cb(null, `${id}_${safeName}`);
    }
});
const upload = multer({ storage, limits: { fileSize: 500 * 1024 * 1024 } });

// ==================== HELPERS ====================
function formatSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

// ==================== EXPRESS APP ====================
const app = express();
app.use(cors());
app.use(express.json());

// Serve driver files
app.use('/drivers', express.static(DRIVERS_DIR));

// Helper function to fix download URLs (replace localhost with actual server)
const fixDownloadUrl = (driver, req) => {
    if (!driver) return driver;
    const serverUrl = `${req.protocol}://${req.get('host')}`;
    const fixed = { ...driver };
    if (fixed.downloadUrl && fixed.downloadUrl.includes('localhost')) {
        fixed.downloadUrl = fixed.downloadUrl.replace(/http:\/\/localhost:\d+/, serverUrl);
    }
    if (fixed.download_url && fixed.download_url.includes('localhost')) {
        fixed.download_url = fixed.download_url.replace(/http:\/\/localhost:\d+/, serverUrl);
    }
    return fixed;
};

// ==================== PUBLIC API (no auth required) ====================

// Health check
app.get('/api/health', (req, res) => {
    res.json({
        status: 'ok',
        version: '1.0.0',
        r2Enabled: db.settings.r2_enabled === 'true',
        timestamp: new Date().toISOString()
    });
});

// Get tool download URL (public for goxprint-remote)
app.get('/api/tool-download', (req, res) => {
    const downloadUrl = db.settings.tool_download_url || '';
    const toolName = db.settings.tool_name || 'GoXTool';
    const toolVersion = db.settings.tool_version || '1.0.0';

    res.json({
        downloadUrl,
        toolName,
        toolVersion,
        hasDownload: !!downloadUrl
    });
});

// Generate daily PIN - 4 digit code that changes every day
function generateDailyPin() {
    // Use Vietnam timezone (UTC+7)
    const today = new Date();
    const vietnamTime = new Date(today.toLocaleString('en-US', { timeZone: 'Asia/Ho_Chi_Minh' }));
    const dateStr = `${vietnamTime.getFullYear()}-${vietnamTime.getMonth() + 1}-${vietnamTime.getDate()}`;
    const secret = 'goxprint-daily-pin-secret-2026';
    const hash = crypto.createHash('sha256').update(dateStr + secret).digest('hex');
    // Take first 4 digits from hash (convert hex to number, mod 10000, pad to 4 digits)
    const pin = (parseInt(hash.substring(0, 8), 16) % 10000).toString().padStart(4, '0');
    return pin;
}

// Get daily PIN (public for goxprint-remote to display)
app.get('/api/daily-pin', (req, res) => {
    const pin = generateDailyPin();
    const today = new Date();
    const tomorrow = new Date(today);
    tomorrow.setDate(tomorrow.getDate() + 1);
    tomorrow.setHours(0, 0, 0, 0);

    res.json({
        pin,
        date: today.toISOString().split('T')[0],
        expiresAt: tomorrow.toISOString(),
        message: 'Mã PIN thay đổi mỗi ngày lúc 00:00'
    });
});

// Verify PIN (for GoXTool to validate on startup)
app.post('/api/verify-pin', (req, res) => {
    const { pin } = req.body;
    const correctPin = generateDailyPin();

    if (pin === correctPin) {
        res.json({ valid: true, message: 'PIN hợp lệ!' });
    } else {
        res.json({ valid: false, message: 'PIN không đúng!' });
    }
});

// List drivers (public for GoXPrint Tool) - with optional pagination
app.get('/api/drivers', (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const perPage = Math.min(parseInt(req.query.per_page) || 100, 100);

    // If no pagination params, return all drivers (backward compatible)
    if (!req.query.page && !req.query.per_page) {
        return res.json(db.drivers.map(d => fixDownloadUrl(d, req)));
    }

    // Paginated response
    const total = db.drivers.length;
    const lastPage = Math.ceil(total / perPage);
    const from = (page - 1) * perPage;
    const to = Math.min(from + perPage, total);
    const data = db.drivers.slice(from, to).map(d => fixDownloadUrl(d, req));

    res.json({
        data,
        pagination: {
            current_page: page,
            per_page: perPage,
            total,
            last_page: lastPage,
            from: from + 1,
            to
        }
    });
});

// Search drivers (public for GoXPrint Tool)
app.get('/api/drivers/search', (req, res) => {
    const query = (req.query.q || '').toLowerCase().trim();
    const page = parseInt(req.query.page) || 1;
    const perPage = Math.min(parseInt(req.query.per_page) || 15, 100);

    if (!query) {
        return res.status(400).json({ error: 'Search query is required' });
    }

    // Search in name, model, manufacturer, and models array
    const filtered = db.drivers.filter(driver => {
        const searchFields = [
            driver.name || '',
            driver.model || '',
            driver.manufacturer || '',
            driver.defaultModel || '',
            ...(driver.models || [])
        ].map(f => f.toLowerCase());

        return searchFields.some(field => field.includes(query));
    });

    // Paginate results
    const total = filtered.length;
    const lastPage = Math.ceil(total / perPage);
    const from = (page - 1) * perPage;
    const to = Math.min(from + perPage, total);
    const data = filtered.slice(from, to).map(d => fixDownloadUrl(d, req));

    res.json({
        data,
        pagination: {
            current_page: page,
            per_page: perPage,
            total,
            last_page: lastPage,
            from: from + 1,
            to
        },
        search_query: query
    });
});

// Get single driver
app.get('/api/drivers/:id', (req, res) => {
    const driver = db.drivers.find(d => d.id === req.params.id);
    if (!driver) return res.status(404).json({ error: 'Driver not found' });
    res.json(fixDownloadUrl(driver, req));
});

// Download driver
app.get('/api/drivers/:id/download', (req, res) => {
    const driver = db.findDriver(req.params.id);
    if (!driver) return res.status(404).json({ error: 'Driver not found' });

    db.updateDriver(req.params.id, { downloadCount: (driver.downloadCount || 0) + 1 });

    res.redirect(driver.downloadUrl);
});

// ==================== AUTH API ====================

// Login
app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password required' });
    }

    const user = db.findUser(username, password);

    if (!user) {
        return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = generateToken();
    const session = {
        userId: user.id,
        username: user.username,
        displayName: user.displayName,
        role: user.role,
        expiresAt: Date.now() + 24 * 60 * 60 * 1000 // 24 hours
    };
    db.addSession(token, session);

    res.json({
        success: true,
        token,
        user: {
            id: user.id,
            username: user.username,
            displayName: user.displayName,
            role: user.role
        }
    });
});

// Logout
app.post('/api/auth/logout', authMiddleware, (req, res) => {
    const token = req.headers.authorization.split(' ')[1];
    db.deleteSession(token);
    res.json({ success: true });
});

// Get current user
app.get('/api/auth/me', authMiddleware, (req, res) => {
    res.json({ user: req.user });
});

// ==================== TEMPORARY DRIVER UPLOAD (for remote UI) ====================
// Upload temporary driver (auto-delete after 1 hour) - NO AUTH REQUIRED
app.post('/api/drivers/upload-temp', upload.single('driver'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        const filePath = join(DRIVERS_DIR, req.file.filename);
        const id = `temp_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        const downloadUrl = `http://localhost:${PORT}/drivers/${req.file.filename}`;

        // Parse models from ZIP
        let models = [];
        let defaultModel = req.file.originalname.replace('.zip', '');
        try {
            models = await extractModelsFromZip(filePath);
            if (models.length > 0) {
                defaultModel = models[0];
            }
        } catch (e) {
            console.log('Could not parse INF from temp driver:', e.message);
        }

        // Create temporary driver entry
        const tempDriver = {
            id,
            name: req.file.originalname.replace('.zip', ''),
            manufacturer: 'Custom Upload',
            models,
            defaultModel,
            version: '1.0',
            download_url: downloadUrl,
            file_size: formatSize(req.file.size),
            temporary: true,
            expires_at: Date.now() + (60 * 60 * 1000) // 1 hour
        };

        // Add to database temporarily
        sqlite.prepare(`
            INSERT INTO drivers (id, name, manufacturer, models, default_model, version, file_size, download_url, temporary, expires_at)
            VALUES (@id, @name, @manufacturer, @models, @defaultModel, @version, @file_size, @download_url, 1, @expires_at)
        `).run({
            id: tempDriver.id,
            name: tempDriver.name,
            manufacturer: tempDriver.manufacturer,
            models: JSON.stringify(models),
            defaultModel: tempDriver.defaultModel,
            version: tempDriver.version,
            file_size: tempDriver.file_size,
            download_url: tempDriver.download_url,
            expires_at: tempDriver.expires_at
        });

        // Schedule deletion after 1 hour
        setTimeout(() => {
            try {
                // Delete from database
                sqlite.prepare('DELETE FROM drivers WHERE id = ?').run(id);
                // Delete file
                if (existsSync(filePath)) {
                    unlinkSync(filePath);
                }
                console.log(`Temporary driver ${id} auto-deleted after 1 hour`);
            } catch (e) {
                console.error('Error deleting temp driver:', e);
            }
        }, 60 * 60 * 1000); // 1 hour

        console.log(`Temporary driver uploaded: ${id}, will auto-delete in 1 hour`);

        res.json({
            success: true,
            id: tempDriver.id,
            name: tempDriver.name,
            models,
            defaultModel,
            download_url: downloadUrl,
            expires_in: '1 hour'
        });

    } catch (error) {
        console.error('Temp driver upload error:', error);
        res.status(500).json({ error: 'Upload failed: ' + error.message });
    }
});

// ==================== ADMIN API (auth required) ====================

// Upload driver - Manual model input (no INF parsing)
app.post('/api/admin/drivers', authMiddleware, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        let { name, model, manufacturer, version, models } = req.body;

        // Parse models from string if provided (comma-separated or JSON array)
        let modelsList = [];
        if (models) {
            if (typeof models === 'string') {
                try {
                    modelsList = JSON.parse(models);
                } catch {
                    // Treat as comma-separated
                    modelsList = models.split(',').map(m => m.trim()).filter(m => m);
                }
            } else if (Array.isArray(models)) {
                modelsList = models;
            }
        }

        if (!name || !manufacturer) {
            return res.status(400).json({ error: 'Missing required fields: name, manufacturer' });
        }

        const filePath = join(DRIVERS_DIR, req.file.filename);
        const id = req.file.filename.split('_')[0];
        let downloadUrl = `http://localhost:${PORT}/drivers/${req.file.filename}`;

        // If R2 is enabled, upload to R2
        if (db.settings.r2_enabled === 'true' && s3Client) {
            try {
                const fileContent = readFileSync(filePath);
                const fileKey = `drivers/${req.file.filename}`;

                await s3Client.send(new PutObjectCommand({
                    Bucket: db.settings.r2_bucket,
                    Key: fileKey,
                    Body: fileContent,
                    ContentType: 'application/zip',
                }));

                downloadUrl = `${db.settings.r2_public_url}/${fileKey}`;
            } catch (r2Error) {
                console.error('R2 upload failed, using local storage:', r2Error.message);
            }
        }

        const driver = {
            id,
            name,
            model: model || name,
            manufacturer,
            version: version || '1.0',
            size: formatSize(req.file.size),
            sizeBytes: req.file.size,
            fileName: req.file.filename,
            downloadUrl,
            downloadCount: 0,
            createdAt: new Date().toISOString(),
            // Models from manual input, use name as default if empty
            models: modelsList.length > 0 ? modelsList : [name],
            infCount: 0,
            defaultModel: modelsList.length > 0 ? modelsList[0] : name
        };

        db.addDriver(driver);

        res.status(201).json({
            success: true,
            driver,
            message: `Driver uploaded successfully with ${driver.models.length} model(s).`
        });
    } catch (error) {
        console.error('Upload error:', error);
        res.status(500).json({ error: 'Upload failed: ' + error.message });
    }
});

// Delete driver
app.delete('/api/admin/drivers/:id', authMiddleware, async (req, res) => {
    const driver = db.findDriver(req.params.id);
    if (!driver) return res.status(404).json({ error: 'Driver not found' });

    // Delete local file
    const filePath = join(DRIVERS_DIR, driver.fileName);
    if (existsSync(filePath)) {
        unlinkSync(filePath);
    }

    // Delete from R2 if enabled
    if (db.settings.r2_enabled === 'true' && s3Client) {
        try {
            await s3Client.send(new DeleteObjectCommand({
                Bucket: db.settings.r2_bucket,
                Key: `drivers/${driver.fileName}`
            }));
        } catch (r2Error) {
            console.error('R2 delete failed:', r2Error.message);
        }
    }

    db.deleteDriver(req.params.id);

    res.json({ success: true, message: 'Driver deleted' });
});

// Parse INF from uploaded file (preview before committing)
app.post('/api/admin/parse-inf', authMiddleware, upload.single('file'), async (req, res) => {
    let filePath = null;
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        filePath = join(DRIVERS_DIR, req.file.filename);

        // Parse INF files from ZIP
        const infData = extractModelsFromZip(filePath);

        // Send response first
        res.json({
            success: true,
            manufacturer: infData.manufacturer || '',
            driverName: infData.driverName || '',
            models: infData.models,
            infCount: infData.infCount
        });

        // Delete the temp file after a short delay (to avoid EBUSY)
        setTimeout(() => {
            try {
                if (existsSync(filePath)) {
                    unlinkSync(filePath);
                    console.log('Cleaned up temp file:', filePath);
                }
            } catch (err) {
                console.warn('Could not delete temp file:', err.message);
            }
        }, 1000);

    } catch (error) {
        console.error('Parse INF error:', error);
        // Try to clean up on error too
        if (filePath) {
            setTimeout(() => {
                try { if (existsSync(filePath)) unlinkSync(filePath); } catch { }
            }, 1000);
        }
        res.status(500).json({ error: 'Parse failed: ' + error.message });
    }
});

// Update driver (edit models, defaultModel, name, etc.)
app.put('/api/admin/drivers/:id', authMiddleware, (req, res) => {
    const driver = db.findDriver(req.params.id);
    if (!driver) return res.status(404).json({ error: 'Driver not found' });

    const { name, model, manufacturer, version, models, defaultModel } = req.body;

    db.updateDriver(req.params.id, { name, model, manufacturer, version, models, defaultModel });

    const updatedDriver = db.findDriver(req.params.id);
    res.json({ success: true, driver: updatedDriver, message: 'Driver updated' });
});

// ==================== SETTINGS API ====================

// Get settings
app.get('/api/admin/settings', authMiddleware, (req, res) => {
    // Don't expose secret key
    const settings = { ...db.settings };
    if (settings.r2_secret_key) {
        settings.r2_secret_key = settings.r2_secret_key.substring(0, 8) + '****';
    }
    res.json(settings);
});

// Update settings
app.put('/api/admin/settings', authMiddleware, (req, res) => {
    const updates = req.body;

    db.updateSettings(updates);

    // Reinitialize R2 client if settings changed
    if (updates.r2_endpoint || updates.r2_access_key || updates.r2_secret_key) {
        initR2Client();
    }

    res.json({ success: true, message: 'Settings updated' });
});

// Test R2 connection
app.post('/api/admin/settings/test-r2', authMiddleware, async (req, res) => {
    const { endpoint, accessKey, secretKey, bucket } = req.body;

    if (!endpoint || !accessKey || !secretKey || !bucket) {
        return res.status(400).json({ error: 'All R2 credentials required' });
    }

    try {
        const testClient = new S3Client({
            region: 'auto',
            endpoint: endpoint,
            credentials: {
                accessKeyId: accessKey,
                secretAccessKey: secretKey,
            },
        });

        // Test by checking if bucket exists
        await testClient.send(new HeadBucketCommand({ Bucket: bucket }));

        res.json({ success: true, message: 'R2 connection successful!' });
    } catch (error) {
        console.error('R2 test failed:', error);
        res.json({
            success: false,
            message: `R2 connection failed: ${error.Code || error.message}`
        });
    }
});

// ==================== WEBSOCKET FOR REMOTE CONTROL ====================
const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws' });

// Connected devices: deviceId -> { ws, connectionCode, deviceInfo }
const connectedDevices = new Map();
// Connection groups: connectionCode -> Set of deviceIds
const connectionGroups = new Map();
// Admin clients
const adminClients = new Set();

// Connection code cache: gateway+subnet -> {code, expiresAt}
const connectionCodeCache = new Map();

// Generate 6-digit connection code from gateway + subnet with 30s rotation
function generateConnectionCode(gateway, subnet) {
    const now = Date.now();
    const cacheKey = `${gateway}-${subnet}`;

    // Check cache with 30s expiry
    const cached = connectionCodeCache.get(cacheKey);
    if (cached && cached.expiresAt > now) {
        return cached.code;
    }

    // Generate new code based on 60-minute time window
    const timeWindow = Math.floor(now / 3600000); // 60 minutes
    const baseStr = `${gateway}-${subnet}-${timeWindow}`;

    let hash = 0;
    for (let i = 0; i < baseStr.length; i++) {
        hash = ((hash << 5) - hash) + baseStr.charCodeAt(i);
        hash = hash & hash;
    }
    const code = (Math.abs(hash % 900000) + 100000).toString();

    // Cache for 30 seconds
    connectionCodeCache.set(cacheKey, {
        code,
        expiresAt: now + 30000
    });

    console.log(`[WS] Generated code ${code} for gateway ${gateway} (expires in 30s)`);
    return code;
}

// Broadcast to admin clients (only if device is in their LAN)
function broadcastToAdmins(data, deviceConnectionCode) {
    adminClients.forEach(ws => {
        if (ws.readyState === 1) {
            // Only send if admin is in same LAN or no connection code filter
            if (!deviceConnectionCode || ws.adminConnectionCode === deviceConnectionCode) {
                ws.send(JSON.stringify(data));
            }
        }
    });
}

// Get all devices status
function getAllDevicesStatus() {
    const devices = [];
    connectedDevices.forEach((client, deviceId) => {
        if (client.deviceInfo) {
            devices.push({
                id: deviceId,
                connectionCode: client.connectionCode,
                ...client.deviceInfo,
                isOnline: client.ws.readyState === 1
            });
        }
    });
    return devices;
}

wss.on('connection', (ws, req) => {
    const clientIP = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || '127.0.0.1';
    let deviceId = null;
    let isAdmin = false;
    let heartbeatInterval = null;

    console.log(`[WS] New connection from ${clientIP}`);

    ws.on('message', (message) => {
        try {
            const data = JSON.parse(message.toString());

            switch (data.type) {
                case 'register': {
                    deviceId = data.deviceId || randomUUID();
                    const gateway = data.gateway || '';
                    const subnet = data.subnet || '';
                    const connectionCode = generateConnectionCode(gateway, subnet);

                    // Store device with enhanced info
                    connectedDevices.set(deviceId, {
                        ws,
                        connectionCode,
                        gateway,
                        subnet,
                        lastSeen: Date.now(),
                        deviceInfo: {
                            hostname: data.hostname || 'Unknown',
                            os: data.os || 'Windows',
                            printers: data.printers || [],
                            ip: clientIP,
                            subnet: subnet,
                            gateway: gateway,
                            connectedAt: new Date().toISOString()
                        }
                    });

                    // Add to connection group
                    if (!connectionGroups.has(connectionCode)) {
                        connectionGroups.set(connectionCode, new Set());
                    }
                    connectionGroups.get(connectionCode).add(deviceId);

                    // Start heartbeat
                    heartbeatInterval = startHeartbeat(ws, deviceId);

                    // Send registration confirmation
                    ws.send(JSON.stringify({
                        type: 'registered',
                        deviceId,
                        connectionCode,
                        expiresIn: 3600,
                        serverTime: Date.now(),
                        message: 'Đã kết nối thành công!'
                    }));

                    // Flush queued messages
                    flushMessageQueue(deviceId, ws);

                    // Broadcast to admins
                    broadcastToAdmins({
                        type: 'device_online',
                        device: {
                            id: deviceId,
                            connectionCode,
                            ...connectedDevices.get(deviceId).deviceInfo,
                            isOnline: true
                        }
                    }, connectionCode);

                    console.log(`[WS] Device registered: ${deviceId} on LAN ${connectionCode}`);
                    break;
                }

                case 'admin_connect': {
                    isAdmin = true;
                    adminClients.add(ws);

                    const adminConnectionCode = data.connectionCode || '';
                    ws.adminConnectionCode = adminConnectionCode;

                    // Start heartbeat for admin
                    heartbeatInterval = startHeartbeat(ws, 'admin');

                    // Send current device list
                    const matchingDevices = getAllDevicesStatus().filter(
                        d => d.connectionCode === adminConnectionCode
                    );
                    ws.send(JSON.stringify({
                        type: 'devices_list',
                        devices: matchingDevices,
                        serverTime: Date.now()
                    }));

                    console.log(`[WS] Admin connected for code ${adminConnectionCode}`);
                    break;
                }

                case 'admin_connect': {
                    isAdmin = true;
                    adminClients.add(ws);

                    // Admin sends the connection code they want to monitor
                    const adminConnectionCode = data.connectionCode || '';
                    ws.adminConnectionCode = adminConnectionCode;

                    // Send devices matching the entered connection code
                    const matchingDevices = getAllDevicesStatus().filter(d => d.connectionCode === adminConnectionCode);
                    ws.send(JSON.stringify({ type: 'devices_list', devices: matchingDevices }));
                    break;
                }

                case 'command': {
                    const { targetDeviceId, command, params } = data;
                    const commandId = data.commandId || randomUUID();
                    const target = connectedDevices.get(targetDeviceId);

                    if (target && target.ws.readyState === 1) {
                        // Send command with ID for tracking
                        target.ws.send(JSON.stringify({
                            type: 'command',
                            command,
                            params,
                            commandId
                        }));

                        // Track command for acknowledgment
                        trackCommand(commandId, targetDeviceId, (result) => {
                            if (ws.readyState === 1) {
                                ws.send(JSON.stringify({
                                    type: 'command_result',
                                    commandId,
                                    targetDeviceId,
                                    ...result
                                }));
                            }
                        });

                        ws.send(JSON.stringify({
                            type: 'command_sent',
                            targetDeviceId,
                            commandId,
                            command,
                            status: 'sent'
                        }));
                    } else {
                        // Queue message for offline device
                        queueMessage(targetDeviceId, {
                            type: 'command',
                            command,
                            params,
                            commandId
                        });

                        ws.send(JSON.stringify({
                            type: 'command_queued',
                            targetDeviceId,
                            commandId,
                            message: 'Device offline, command queued'
                        }));
                    }
                    break;
                }

                case 'command_ack': {
                    // Device acknowledges command
                    acknowledgeCommand(data.commandId, {
                        success: data.success,
                        result: data.result,
                        deviceName: data.deviceName
                    });
                    break;
                }

                case 'batch_command': {
                    const { connectionCode: targetCode, command: batchCmd, params: batchParams } = data;
                    const group = connectionGroups.get(targetCode);
                    if (group) {
                        let sentCount = 0;
                        group.forEach(dId => {
                            const device = connectedDevices.get(dId);
                            if (device && device.ws.readyState === 1) {
                                device.ws.send(JSON.stringify({ type: 'command', command: batchCmd, params: batchParams, commandId: randomUUID() }));
                                sentCount++;
                            }
                        });
                        ws.send(JSON.stringify({ type: 'batch_command_sent', connectionCode: targetCode, sentCount }));
                    }
                    break;
                }

                case 'command_result': {
                    const deviceClient = connectedDevices.get(deviceId);
                    broadcastToAdmins({
                        type: 'command_result',
                        deviceId,
                        deviceName: data.deviceName,
                        ...data
                    }, deviceClient?.connectionCode);
                    break;
                }

                case 'status_update':
                    if (deviceId && connectedDevices.has(deviceId)) {
                        const client = connectedDevices.get(deviceId);
                        client.deviceInfo = { ...client.deviceInfo, ...data.deviceInfo };
                        client.lastSeen = Date.now();
                        broadcastToAdmins({
                            type: 'device_update',
                            device: {
                                id: deviceId,
                                connectionCode: client.connectionCode,
                                ...client.deviceInfo,
                                isOnline: true
                            }
                        }, client.connectionCode);
                    }
                    break;

                case 'progress': {
                    const progressClient = connectedDevices.get(deviceId);
                    broadcastToAdmins({
                        type: 'progress',
                        deviceId,
                        deviceName: data.deviceName,
                        status: data.status,
                        progress: data.progress
                    }, progressClient?.connectionCode);
                    break;
                }

                case 'heartbeat': {
                    // Update last seen
                    if (deviceId && connectedDevices.has(deviceId)) {
                        connectedDevices.get(deviceId).lastSeen = Date.now();
                    }
                    ws.send(JSON.stringify({ type: 'heartbeat_ack', serverTime: Date.now() }));
                    break;
                }
            }
        } catch (err) {
            console.error('[WS] Error processing message:', err.message);
            ws.send(JSON.stringify({
                type: 'error',
                message: 'Invalid message format',
                error: err.message
            }));
        }
    });

    ws.on('close', () => {
        if (heartbeatInterval) clearInterval(heartbeatInterval);

        if (isAdmin) {
            adminClients.delete(ws);
            console.log('[WS] Admin disconnected');
        } else if (deviceId) {
            const client = connectedDevices.get(deviceId);
            if (client) {
                // Mark as offline but keep for grace period
                console.log(`[WS] Device ${deviceId} disconnected, grace period: 2min`);
                setTimeout(() => {
                    const stillExists = connectedDevices.get(deviceId);
                    if (stillExists && stillExists.ws.readyState !== 1) {
                        // Remove after grace period if not reconnected
                        const group = connectionGroups.get(client.connectionCode);
                        if (group) {
                            group.delete(deviceId);
                            if (group.size === 0) {
                                connectionGroups.delete(client.connectionCode);
                            }
                        }
                        broadcastToAdmins({
                            type: 'device_offline',
                            deviceId
                        }, client.connectionCode);
                        connectedDevices.delete(deviceId);
                        console.log(`[WS] Device removed: ${deviceId}`);
                    } else {
                        console.log(`[WS] Device ${deviceId} reconnected within grace period`);
                    }
                }, RECONNECT_GRACE_PERIOD);
            }
        }
    });

    ws.on('error', (error) => {
        console.error('[WS] WebSocket error:', error.message);
    });
});

// ==================== CODE ROTATION & CLEANUP ====================

// Check for code rotation every 5 seconds
setInterval(() => {
    connectedDevices.forEach((client, deviceId) => {
        if (client.ws.readyState === 1 && client.gateway && client.subnet) {
            const newCode = generateConnectionCode(client.gateway, client.subnet);
            if (newCode !== client.connectionCode) {
                console.log(`[WS] Code rotated for device ${deviceId}: ${client.connectionCode} -> ${newCode}`);
                client.connectionCode = newCode;

                // Update connection groups
                connectionGroups.forEach((group, code) => {
                    group.delete(deviceId);
                });
                if (!connectionGroups.has(newCode)) {
                    connectionGroups.set(newCode, new Set());
                }
                connectionGroups.get(newCode).add(deviceId);

                // Notify device
                client.ws.send(JSON.stringify({
                    type: 'code_rotated',
                    newCode,
                    expiresIn: 3600
                }));
            }
        }
    });
}, 5000);

// Clean dead connections every minute
setInterval(() => {
    const now = Date.now();
    connectedDevices.forEach((client, deviceId) => {
        if (client.lastSeen && now - client.lastSeen > 120000) { // 2 minutes
            console.log(`[WS] Removing stale device: ${deviceId} (last seen: ${Math.floor((now - client.lastSeen) / 1000)}s ago)`);

            const group = connectionGroups.get(client.connectionCode);
            if (group) {
                group.delete(deviceId);
                if (group.size === 0) {
                    connectionGroups.delete(client.connectionCode);
                }
            }
            connectedDevices.delete(deviceId);
        }
    });
}, 60000);


// Remote API endpoints
app.get('/api/remote/status', (req, res) => {
    res.json({ connectedDevices: connectedDevices.size, connectionGroups: connectionGroups.size, adminClients: adminClients.size });
});

app.get('/api/remote/devices', (req, res) => {
    res.json(getAllDevicesStatus());
});

// ==================== START SERVER ====================
initR2Client();

server.listen(PORT, () => {
    console.log(`
🖨️  GoXPrint Driver Manager  
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📡 API:       http://localhost:${PORT}/api
🌐 WebSocket: ws://localhost:${PORT}/ws
📁 Admin:     http://localhost:3000 (Vite)
🔐 Auth:      Username: admin / Password: admin123
☁️  R2:        ${db.settings.r2_enabled === 'true' ? 'Enabled' : 'Disabled'}
📦 Features:  INF Parsing + Remote Control
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  `);
});
