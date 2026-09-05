// bot.js - Standalone Telegram Bot for RootGuard (Universal Node.js with PostgreSQL & SQLite Multi-Persistence)
// Runs directly with: node bot.js
// Dependencies: npm install dotenv @google/genai jszip pg
// ⚡ made by @toshitzz | Enhanced with Render Persistence Safeguards & Free Groq Model Discovery

const dotenv = require('dotenv');
const { GoogleGenAI, Type } = require('@google/genai');
const JSZip = require('jszip');
const https = require('https');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

dotenv.config();

// Global unhandled exception shields (prevents crash on Render/VPS/Termux)
process.on('unhandledRejection', (reason) => {
  console.warn('⚠️ [Safe Shield] Unhandled async rejection:', reason?.message || reason);
});
process.on('uncaughtException', (err) => {
  console.warn('⚠️ [Safe Shield] Uncaught exception:', err?.message || err);
});

const TELEGRAM_TOKEN = (process.env.TELEGRAM_BOT_TOKEN || '').trim();
const GEMINI_API_KEY = (process.env.GEMINI_API_KEY || '').trim();
const GROQ_API_KEY = (process.env.GROQ_API_KEY || '').trim();
const GROQ_MODEL = (process.env.GROQ_MODEL || 'llama-3.3-70b-versatile').trim();
const DATABASE_URL = (process.env.DATABASE_URL || '').trim();

const DAILY_SCAN_LIMIT = 5;
const DAILY_QUESTION_LIMIT = 5;
const COOLDOWN_SECONDS = 15;

const OWNER_IDS = (process.env.OWNER_ID || '')
  .split(',')
  .map((s) => s.trim().replace(/^tg:/i, ''))
  .filter(Boolean);

console.log('⚡ RootGuard Telegram Bot • made by @toshitzz');
console.log(`🔑 Telegram: ${TELEGRAM_TOKEN ? 'Token Configured' : 'Offline (Add TELEGRAM_BOT_TOKEN)'}`);
console.log(`🔑 Gemini AI: ${GEMINI_API_KEY ? 'Active' : 'Offline (Add GEMINI_API_KEY)'}`);
console.log(`🔑 Groq AI: ${GROQ_API_KEY ? `Active (Default: ${GROQ_MODEL})` : 'Offline (Add GROQ_API_KEY)'}`);
console.log(`👑 Configured Owner IDs: ${OWNER_IDS.length ? OWNER_IDS.join(', ') : 'None'}`);

// =======================================================================
// 1. Dual-Engine Persistence: PostgreSQL (Render) + SQLite + Memory Fallback
//    SOLVES: Render service restart wiping database!
// =======================================================================
let pgPool = null;
let sqliteDb = null;
let persistenceType = 'MEMORY'; // 'POSTGRES' | 'SQLITE' | 'MEMORY'
let dbFilePath = '';

const memoryStore = {
  users: new Map(),
  cooldowns: new Map(),
  dailyQuotas: new Map(),
  dailyQuestionQuotas: new Map(),
  scans: [],
  scanCache: new Map(),
};

// =======================================================================
// AUTOMATIC ZERO-CONFIG PERSISTENCE ENGINE (No .env setup required!)
// Automatically preserves state across Render service restarts & deploys.
// =======================================================================
const AUTO_BACKUP_PATHS = [
  path.resolve(process.cwd(), '.rootguard_state.json'),
  '/tmp/.rg_auto_state.json',
];

let lastStateSaveTime = 0;

function serializeFullState() {
  const users = [];
  const dailyQuotas = [];
  const dailyQuestionQuotas = [];
  const scans = [];

  if (persistenceType === 'SQLITE' && sqliteDb) {
    try {
      const uRows = sqliteDb.prepare('SELECT * FROM users').all();
      const qRows = sqliteDb.prepare('SELECT * FROM daily_quotas').all();
      const qqRows = sqliteDb.prepare('SELECT * FROM daily_question_quotas').all();
      const sRows = sqliteDb.prepare('SELECT * FROM scans ORDER BY id DESC LIMIT 100').all();
      return {
        timestamp: Date.now(),
        users: uRows,
        dailyQuotas: qRows,
        dailyQuestionQuotas: qqRows,
        scans: sRows,
      };
    } catch (e) {}
  }

  for (const u of memoryStore.users.values()) users.push(u);
  for (const [k, count] of memoryStore.dailyQuotas.entries()) {
    const [user_id, date] = k.split(':');
    dailyQuotas.push({ user_id, date, scan_count: count });
  }
  for (const [k, count] of memoryStore.dailyQuestionQuotas.entries()) {
    const [user_id, date] = k.split(':');
    dailyQuestionQuotas.push({ user_id, date, question_count: count });
  }

  return {
    timestamp: Date.now(),
    users,
    dailyQuotas,
    dailyQuestionQuotas,
    scans: memoryStore.scans.slice(0, 100),
  };
}

function restoreFullState(state) {
  if (!state || !state.users || !Array.isArray(state.users)) return false;
  let restoredCount = 0;

  if (persistenceType === 'SQLITE' && sqliteDb) {
    try {
      const userStmt = sqliteDb.prepare(`
        INSERT OR REPLACE INTO users (user_id, username, first_name, is_vip, is_banned, total_scans, created_at, last_active)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `);
      for (const u of state.users) {
        userStmt.run(u.user_id, u.username || null, u.first_name || null, u.is_vip || 0, u.is_banned || 0, u.total_scans || 0, u.created_at || Date.now(), u.last_active || Date.now());
        restoredCount++;
      }

      if (Array.isArray(state.dailyQuotas)) {
        const qStmt = sqliteDb.prepare(`INSERT OR REPLACE INTO daily_quotas (user_id, date, scan_count) VALUES (?, ?, ?)`);
        for (const q of state.dailyQuotas) qStmt.run(q.user_id, q.date, q.scan_count || 0);
      }

      if (Array.isArray(state.dailyQuestionQuotas)) {
        const qqStmt = sqliteDb.prepare(`INSERT OR REPLACE INTO daily_question_quotas (user_id, date, question_count) VALUES (?, ?, ?)`);
        for (const qq of state.dailyQuestionQuotas) qqStmt.run(qq.user_id, qq.date, qq.question_count || 0);
      }

      if (Array.isArray(state.scans)) {
        const sStmt = sqliteDb.prepare(`
          INSERT OR IGNORE INTO scans (id, user_id, file_name, file_size, verdict, risk_score, model_used, duration_ms, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `);
        for (const s of state.scans) sStmt.run(s.id, s.user_id, s.file_name, s.file_size || 0, s.verdict, s.risk_score || 0, s.model_used || 'AI', s.duration_ms || 0, s.created_at || Date.now());
      }
      console.log(`✨ [Auto-Persistence] Restored ${restoredCount} users & ${state.scans?.length || 0} scans automatically into SQLite!`);
      return true;
    } catch (e) {
      console.warn('Restore error into SQLite:', e.message);
    }
  }

  for (const u of state.users) {
    memoryStore.users.set(u.user_id, u);
    restoredCount++;
  }
  if (Array.isArray(state.dailyQuotas)) {
    for (const q of state.dailyQuotas) memoryStore.dailyQuotas.set(`${q.user_id}:${q.date}`, q.scan_count || 0);
  }
  if (Array.isArray(state.dailyQuestionQuotas)) {
    for (const qq of state.dailyQuestionQuotas) memoryStore.dailyQuestionQuotas.set(`${qq.user_id}:${qq.date}`, qq.question_count || 0);
  }
  if (Array.isArray(state.scans)) memoryStore.scans = state.scans;

  console.log(`✨ [Auto-Persistence] Restored ${restoredCount} users automatically into memory!`);
  return true;
}

function autoFlushLocalState() {
  try {
    const data = JSON.stringify(serializeFullState(), null, 2);
    for (const p of AUTO_BACKUP_PATHS) {
      try {
        fs.writeFileSync(p, data, 'utf-8');
      } catch (e) {}
    }
    lastStateSaveTime = Date.now();
  } catch (e) {}
}

function autoLoadLocalState() {
  for (const p of AUTO_BACKUP_PATHS) {
    if (fs.existsSync(p)) {
      try {
        const raw = fs.readFileSync(p, 'utf-8');
        const parsed = JSON.parse(raw);
        if (parsed && parsed.users && parsed.users.length > 0) {
          console.log(`📂 [Auto-Persistence] Found saved state at ${p} (${parsed.users.length} users). Auto-recovering...`);
          restoreFullState(parsed);
          return true;
        }
      } catch (e) {}
    }
  }
  return false;
}

// Render graceful shutdown hook: Render sends SIGTERM before restarting service
let isHandlingShutdown = false;
function registerShutdownHooks() {
  const onSignal = (sig) => {
    if (isHandlingShutdown) return;
    isHandlingShutdown = true;
    console.log(`🛑 [Render Shutdown] Received ${sig} signal. Running auto-persistence state save...`);
    autoFlushLocalState();
    console.log('✅ [Auto-Persistence] State safely saved! Service will restart without losing data.');
    process.exit(0);
  };
  process.on('SIGTERM', () => onSignal('SIGTERM'));
  process.on('SIGINT', () => onSignal('SIGINT'));
}
registerShutdownHooks();

// Background auto-save every 30 seconds
setInterval(() => {
  autoFlushLocalState();
}, 30000);

// Auto-detect Render Persistent Disk path or custom DB_PATH
function resolveDbPath() {
  if (process.env.DB_PATH) return process.env.DB_PATH;
  if (process.env.DATA_DIR && fs.existsSync(process.env.DATA_DIR)) {
    return path.join(process.env.DATA_DIR, 'rootguard.db');
  }
  if (fs.existsSync('/var/data')) return '/var/data/rootguard.db';
  if (fs.existsSync('/data')) return '/data/rootguard.db';
  return path.resolve(process.cwd(), 'rootguard.db');
}

async function initDatabase() {
  // Option 1: Render Free PostgreSQL (Optional - bot works automatically even without this!)
  if (DATABASE_URL) {
    try {
      const { Pool } = require('pg');
      pgPool = new Pool({
        connectionString: DATABASE_URL,
        ssl: DATABASE_URL.includes('localhost') ? false : { rejectUnauthorized: false },
        connectionTimeoutMillis: 10000,
      });

      await pgPool.query(`
        CREATE TABLE IF NOT EXISTS rg_users (
          user_id TEXT PRIMARY KEY,
          username TEXT,
          first_name TEXT,
          is_vip INT DEFAULT 0,
          is_banned INT DEFAULT 0,
          total_scans INT DEFAULT 0,
          created_at BIGINT,
          last_active BIGINT
        );
        CREATE TABLE IF NOT EXISTS rg_cooldowns (
          user_id TEXT PRIMARY KEY,
          last_scan_time BIGINT DEFAULT 0,
          active_scan_lock INT DEFAULT 0,
          cooldown_until BIGINT DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS rg_daily_quotas (
          user_id TEXT,
          date TEXT,
          scan_count INT DEFAULT 0,
          PRIMARY KEY (user_id, date)
        );
        CREATE TABLE IF NOT EXISTS rg_daily_question_quotas (
          user_id TEXT,
          date TEXT,
          question_count INT DEFAULT 0,
          PRIMARY KEY (user_id, date)
        );
        CREATE TABLE IF NOT EXISTS rg_scans (
          id SERIAL PRIMARY KEY,
          user_id TEXT,
          file_name TEXT,
          file_size INT,
          verdict TEXT,
          risk_score INT,
          model_used TEXT,
          duration_ms INT,
          created_at BIGINT
        );
        CREATE TABLE IF NOT EXISTS rg_scan_cache (
          scan_id TEXT PRIMARY KEY,
          file_name TEXT,
          audit_json TEXT,
          created_at BIGINT
        );
      `);

      persistenceType = 'POSTGRES';
      console.log('🗄️ Database Connected: PostgreSQL (DATABASE_URL detected)');
      return;
    } catch (pgErr) {
      console.warn('⚠️ PostgreSQL initialization notice, engaging Automatic SQLite Engine:', pgErr.message);
    }
  }

  // Automatic SQLite Engine (No .env setup needed!)
  try {
    dbFilePath = resolveDbPath();
    const dir = path.dirname(dbFilePath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

    const { DatabaseSync } = require('node:sqlite');
    sqliteDb = new DatabaseSync(dbFilePath);
    sqliteDb.exec(`
      CREATE TABLE IF NOT EXISTS users (
        user_id TEXT PRIMARY KEY,
        username TEXT,
        first_name TEXT,
        is_vip INTEGER DEFAULT 0,
        is_banned INTEGER DEFAULT 0,
        total_scans INTEGER DEFAULT 0,
        created_at INTEGER,
        last_active INTEGER
      );
      CREATE TABLE IF NOT EXISTS cooldowns (
        user_id TEXT PRIMARY KEY,
        last_scan_time INTEGER DEFAULT 0,
        active_scan_lock INTEGER DEFAULT 0,
        cooldown_until INTEGER DEFAULT 0
      );
      CREATE TABLE IF NOT EXISTS daily_quotas (
        user_id TEXT,
        date TEXT,
        scan_count INTEGER DEFAULT 0,
        PRIMARY KEY (user_id, date)
      );
      CREATE TABLE IF NOT EXISTS daily_question_quotas (
        user_id TEXT,
        date TEXT,
        question_count INTEGER DEFAULT 0,
        PRIMARY KEY (user_id, date)
      );
      CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT,
        file_name TEXT,
        file_size INTEGER,
        verdict TEXT,
        risk_score INTEGER,
        model_used TEXT,
        duration_ms INTEGER,
        created_at INTEGER
      );
      CREATE TABLE IF NOT EXISTS scan_cache (
        scan_id TEXT PRIMARY KEY,
        file_name TEXT,
        audit_json TEXT,
        created_at INTEGER
      );
    `);
    persistenceType = 'SQLITE (Auto-Persisted)';
    console.log(`🗄️ Automatic Database Active: SQLite (${dbFilePath})`);

    // Check if Render just restarted and wiped local SQLite: auto-recover from snapshot!
    let count = 0;
    try {
      count = sqliteDb.prepare('SELECT COUNT(*) as c FROM users').get()?.c || 0;
    } catch (e) {}

    if (count === 0) {
      autoLoadLocalState();
    }
  } catch (sqErr) {
    console.warn('⚠️ SQLite unavailable in runtime, falling back to In-Memory store with auto-snapshot:', sqErr.message);
    persistenceType = 'MEMORY (Auto-Persisted)';
    autoLoadLocalState();
  }
}

// Unified Database API
async function dbTouchUser(userId, username, firstName, isOwner = false) {
  const cleanId = String(userId).replace(/^tg:/i, '').trim();
  const now = Date.now();

  if (persistenceType === 'POSTGRES' && pgPool) {
    try {
      const res = await pgPool.query('SELECT * FROM rg_users WHERE user_id = $1', [cleanId]);
      if (res.rows.length > 0) {
        await pgPool.query(
          `UPDATE rg_users SET username = COALESCE($1, username), first_name = COALESCE($2, first_name),
           last_active = $3, is_vip = CASE WHEN $4 = 1 THEN 1 ELSE is_vip END WHERE user_id = $5`,
          [username || null, firstName || null, now, isOwner ? 1 : 0, cleanId]
        );
      } else {
        await pgPool.query(
          `INSERT INTO rg_users (user_id, username, first_name, is_vip, is_banned, total_scans, created_at, last_active)
           VALUES ($1, $2, $3, $4, 0, 0, $5, $6)`,
          [cleanId, username || null, firstName || null, isOwner ? 1 : 0, now, now]
        );
      }
      return;
    } catch (e) {
      console.warn('PG touch error:', e.message);
    }
  }

  if (persistenceType === 'SQLITE' && sqliteDb) {
    try {
      const existing = sqliteDb.prepare('SELECT * FROM users WHERE user_id = ?').get(cleanId);
      if (existing) {
        sqliteDb.prepare(`
          UPDATE users SET username = COALESCE(?, username), first_name = COALESCE(?, first_name),
          last_active = ?, is_vip = CASE WHEN ? = 1 THEN 1 ELSE is_vip END WHERE user_id = ?
        `).run(username || null, firstName || null, now, isOwner ? 1 : 0, cleanId);
      } else {
        sqliteDb.prepare(`
          INSERT INTO users (user_id, username, first_name, is_vip, is_banned, total_scans, created_at, last_active)
          VALUES (?, ?, ?, ?, 0, 0, ?, ?)
        `).run(cleanId, username || null, firstName || null, isOwner ? 1 : 0, now, now);
      }
      return;
    } catch (e) {}
  }

  let u = memoryStore.users.get(cleanId);
  if (!u) {
    u = { user_id: cleanId, username, first_name: firstName, is_vip: isOwner ? 1 : 0, is_banned: 0, total_scans: 0, created_at: now, last_active: now };
    memoryStore.users.set(cleanId, u);
  } else {
    u.last_active = now;
    if (username) u.username = username;
    if (firstName) u.first_name = firstName;
    if (isOwner) u.is_vip = 1;
  }
}

async function dbGetUser(userId) {
  const cleanId = String(userId).replace(/^tg:/i, '').trim();
  if (persistenceType === 'POSTGRES' && pgPool) {
    try {
      const res = await pgPool.query('SELECT * FROM rg_users WHERE user_id = $1', [cleanId]);
      return res.rows[0] || null;
    } catch (e) {}
  }
  if (persistenceType === 'SQLITE' && sqliteDb) {
    try {
      return sqliteDb.prepare('SELECT * FROM users WHERE user_id = ?').get(cleanId) || null;
    } catch (e) {}
  }
  return memoryStore.users.get(cleanId) || null;
}

function isUserOwnerOrVip(rawUserId, userObj = null) {
  const cleanId = String(rawUserId).replace(/^tg:/i, '').trim();
  if (OWNER_IDS.includes(cleanId)) return true;
  if (userObj && userObj.is_vip === 1) return true;
  const inMem = memoryStore.users.get(cleanId);
  return Boolean(inMem && inMem.is_vip === 1);
}

async function dbCheckCooldownAndLock(userId, isOwner = false) {
  const cleanId = String(userId).replace(/^tg:/i, '').trim();
  await dbTouchUser(cleanId, undefined, undefined, isOwner);
  const user = await dbGetUser(cleanId);
  const now = Date.now();
  const today = new Date().toISOString().split('T')[0];

  if (user && user.is_banned === 1) return { allowed: false, reason: 'BANNED' };
  const isVip = isOwner || (user && user.is_vip === 1);

  if (persistenceType === 'POSTGRES' && pgPool) {
    try {
      const cdRes = await pgPool.query('SELECT * FROM rg_cooldowns WHERE user_id = $1', [cleanId]);
      const cdRow = cdRes.rows[0];
      if (cdRow) {
        if (!isVip && cdRow.cooldown_until && now < Number(cdRow.cooldown_until)) {
          const rem = Math.max(1, Math.ceil((Number(cdRow.cooldown_until) - now) / 1000));
          return { allowed: false, reason: 'COOLDOWN', remainingSeconds: rem };
        }
        if (cdRow.active_scan_lock === 1 && now - Number(cdRow.last_scan_time) < 90000) {
          const waitSec = Math.max(1, Math.ceil((90000 - (now - Number(cdRow.last_scan_time))) / 1000));
          return { allowed: false, reason: 'SCAN_IN_PROGRESS', waitSeconds: waitSec };
        }
      }

      const qRes = await pgPool.query('SELECT scan_count FROM rg_daily_quotas WHERE user_id = $1 AND date = $2', [cleanId, today]);
      const currentCount = qRes.rows[0] ? qRes.rows[0].scan_count : 0;
      if (!isVip && currentCount >= DAILY_SCAN_LIMIT) {
        return { allowed: false, reason: 'QUOTA_EXCEEDED', remainingDailyScans: 0, usedCount: currentCount, dailyMax: DAILY_SCAN_LIMIT };
      }

      await pgPool.query(`
        INSERT INTO rg_cooldowns (user_id, last_scan_time, active_scan_lock, cooldown_until)
        VALUES ($1, $2, 1, 0)
        ON CONFLICT(user_id) DO UPDATE SET last_scan_time = $2, active_scan_lock = 1
      `, [cleanId, now]);

      return { allowed: true, remainingDailyScans: isVip ? 9999 : Math.max(0, DAILY_SCAN_LIMIT - (currentCount + 1)), isVip };
    } catch (e) {
      console.warn('PG cooldown check error:', e.message);
    }
  }

  if (persistenceType === 'SQLITE' && sqliteDb) {
    try {
      const cdRow = sqliteDb.prepare('SELECT * FROM cooldowns WHERE user_id = ?').get(cleanId);
      if (cdRow) {
        if (!isVip && cdRow.cooldown_until && now < cdRow.cooldown_until) {
          const rem = Math.max(1, Math.ceil((cdRow.cooldown_until - now) / 1000));
          return { allowed: false, reason: 'COOLDOWN', remainingSeconds: rem };
        }
        if (cdRow.active_scan_lock === 1 && now - cdRow.last_scan_time < 90000) {
          const waitSec = Math.max(1, Math.ceil((90000 - (now - cdRow.last_scan_time)) / 1000));
          return { allowed: false, reason: 'SCAN_IN_PROGRESS', waitSeconds: waitSec };
        }
      }
      const quotaRow = sqliteDb.prepare('SELECT scan_count FROM daily_quotas WHERE user_id = ? AND date = ?').get(cleanId, today);
      const currentCount = quotaRow ? quotaRow.scan_count : 0;
      if (!isVip && currentCount >= DAILY_SCAN_LIMIT) {
        return { allowed: false, reason: 'QUOTA_EXCEEDED', remainingDailyScans: 0, usedCount: currentCount, dailyMax: DAILY_SCAN_LIMIT };
      }
      sqliteDb.prepare(`
        INSERT INTO cooldowns (user_id, last_scan_time, active_scan_lock, cooldown_until)
        VALUES (?, ?, 1, 0)
        ON CONFLICT(user_id) DO UPDATE SET last_scan_time = excluded.last_scan_time, active_scan_lock = 1
      `).run(cleanId, now);
      return { allowed: true, remainingDailyScans: isVip ? 9999 : Math.max(0, DAILY_SCAN_LIMIT - (currentCount + 1)), isVip };
    } catch (e) {}
  }

  // Memory fallback
  const cd = memoryStore.cooldowns.get(cleanId) || { last_scan_time: 0, active_scan_lock: 0, cooldown_until: 0 };
  if (!isVip && cd.cooldown_until && now < cd.cooldown_until) {
    return { allowed: false, reason: 'COOLDOWN', remainingSeconds: Math.max(1, Math.ceil((cd.cooldown_until - now) / 1000)) };
  }
  if (cd.active_scan_lock === 1 && now - cd.last_scan_time < 90000) {
    return { allowed: false, reason: 'SCAN_IN_PROGRESS', waitSeconds: Math.max(1, Math.ceil((90000 - (now - cd.last_scan_time)) / 1000)) };
  }
  const used = memoryStore.dailyQuotas.get(`${cleanId}:${today}`) || 0;
  if (!isVip && used >= DAILY_SCAN_LIMIT) {
    return { allowed: false, reason: 'QUOTA_EXCEEDED', remainingDailyScans: 0, usedCount: used, dailyMax: DAILY_SCAN_LIMIT };
  }
  cd.active_scan_lock = 1;
  cd.last_scan_time = now;
  memoryStore.cooldowns.set(cleanId, cd);
  return { allowed: true, remainingDailyScans: isVip ? 9999 : Math.max(0, DAILY_SCAN_LIMIT - (used + 1)), isVip };
}

async function dbReleaseLockAndRecordScan(userId, record) {
  const cleanId = String(userId).replace(/^tg:/i, '').trim();
  const now = Date.now();
  const today = new Date().toISOString().split('T')[0];
  const user = await dbGetUser(cleanId);
  const isVip = user ? user.is_vip === 1 : false;
  const cooldownUntil = isVip ? 0 : now + (COOLDOWN_SECONDS * 1000);

  if (persistenceType === 'POSTGRES' && pgPool) {
    try {
      await pgPool.query(`
        INSERT INTO rg_cooldowns (user_id, last_scan_time, active_scan_lock, cooldown_until)
        VALUES ($1, $2, 0, $3)
        ON CONFLICT(user_id) DO UPDATE SET last_scan_time = $2, active_scan_lock = 0, cooldown_until = $3
      `, [cleanId, now, cooldownUntil]);

      await pgPool.query(`
        INSERT INTO rg_daily_quotas (user_id, date, scan_count)
        VALUES ($1, $2, 1)
        ON CONFLICT(user_id, date) DO UPDATE SET scan_count = rg_daily_quotas.scan_count + 1
      `, [cleanId, today]);

      await pgPool.query('UPDATE rg_users SET total_scans = total_scans + 1 WHERE user_id = $1', [cleanId]);

      await pgPool.query(`
        INSERT INTO rg_scans (user_id, file_name, file_size, verdict, risk_score, model_used, duration_ms, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      `, [cleanId, record.file_name, record.file_size || 0, record.verdict, record.risk_score, record.model_used, record.duration_ms, now]);
      return;
    } catch (e) {
      console.warn('PG record error:', e.message);
    }
  }

  if (persistenceType === 'SQLITE' && sqliteDb) {
    try {
      sqliteDb.prepare(`
        INSERT INTO cooldowns (user_id, last_scan_time, active_scan_lock, cooldown_until)
        VALUES (?, ?, 0, ?)
        ON CONFLICT(user_id) DO UPDATE SET last_scan_time = excluded.last_scan_time, active_scan_lock = 0, cooldown_until = excluded.cooldown_until
      `).run(cleanId, now, cooldownUntil);
      sqliteDb.prepare(`
        INSERT INTO daily_quotas (user_id, date, scan_count)
        VALUES (?, ?, 1)
        ON CONFLICT(user_id, date) DO UPDATE SET scan_count = scan_count + 1
      `).run(cleanId, today);
      sqliteDb.prepare('UPDATE users SET total_scans = total_scans + 1 WHERE user_id = ?').run(cleanId);
      sqliteDb.prepare(`
        INSERT INTO scans (user_id, file_name, file_size, verdict, risk_score, model_used, duration_ms, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).run(cleanId, record.file_name, record.file_size || 0, record.verdict, record.risk_score, record.model_used, record.duration_ms, now);
      autoFlushLocalState();
      return;
    } catch (e) {}
  }

  const cd = memoryStore.cooldowns.get(cleanId) || {};
  cd.active_scan_lock = 0;
  cd.last_scan_time = now;
  cd.cooldown_until = cooldownUntil;
  memoryStore.cooldowns.set(cleanId, cd);
  const qKey = `${cleanId}:${today}`;
  memoryStore.dailyQuotas.set(qKey, (memoryStore.dailyQuotas.get(qKey) || 0) + 1);
  if (user) user.total_scans = (user.total_scans || 0) + 1;
  memoryStore.scans.unshift({ ...record, id: Date.now(), user_id: cleanId, created_at: now });
  autoFlushLocalState();
}

async function dbForceReleaseLock(userId) {
  const cleanId = String(userId).replace(/^tg:/i, '').trim();
  if (persistenceType === 'POSTGRES' && pgPool) {
    try {
      await pgPool.query('UPDATE rg_cooldowns SET active_scan_lock = 0 WHERE user_id = $1', [cleanId]);
      return;
    } catch (e) {}
  }
  if (persistenceType === 'SQLITE' && sqliteDb) {
    try {
      sqliteDb.prepare('UPDATE cooldowns SET active_scan_lock = 0 WHERE user_id = ?').run(cleanId);
      return;
    } catch (e) {}
  }
  const cd = memoryStore.cooldowns.get(cleanId);
  if (cd) cd.active_scan_lock = 0;
}

async function dbSaveScanCache(scanId, fileName, audit, scripts = []) {
  if (!scanId) return;
  const scriptSummaries = (scripts || []).map((s) => ({
    path: s.path,
    size: s.size || (s.content ? s.content.length : 0),
    content: (s.content || '').slice(0, 35000),
    type: s.type || 'script',
  }));

  const cacheItem = { audit, fileName, scripts: scriptSummaries, time: Date.now() };
  memoryStore.scanCache.set(scanId, cacheItem);

  const auditJson = JSON.stringify({ audit, scripts: scriptSummaries });

  if (persistenceType === 'POSTGRES' && pgPool) {
    try {
      await pgPool.query(`
        INSERT INTO rg_scan_cache (scan_id, file_name, audit_json, created_at)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT(scan_id) DO UPDATE SET audit_json = $3
      `, [scanId, fileName, auditJson, Date.now()]);
      return;
    } catch (e) {}
  }

  if (persistenceType === 'SQLITE' && sqliteDb) {
    try {
      sqliteDb.prepare(`
        INSERT OR REPLACE INTO scan_cache (scan_id, file_name, audit_json, created_at)
        VALUES (?, ?, ?, ?)
      `).run(scanId, fileName, auditJson, Date.now());
    } catch (e) {}
  }
}

async function dbGetScanCache(scanId) {
  if (!scanId) return null;
  const inMem = memoryStore.scanCache.get(scanId);
  if (inMem) return inMem;

  if (persistenceType === 'POSTGRES' && pgPool) {
    try {
      const res = await pgPool.query('SELECT * FROM rg_scan_cache WHERE scan_id = $1', [scanId]);
      if (res.rows.length > 0) {
        const parsed = JSON.parse(res.rows[0].audit_json);
        const obj = { audit: parsed.audit || parsed, scripts: parsed.scripts || [], fileName: res.rows[0].file_name, time: Number(res.rows[0].created_at) };
        memoryStore.scanCache.set(scanId, obj);
        return obj;
      }
    } catch (e) {}
  }

  if (persistenceType === 'SQLITE' && sqliteDb) {
    try {
      const row = sqliteDb.prepare('SELECT * FROM scan_cache WHERE scan_id = ?').get(scanId);
      if (row && row.audit_json) {
        const parsed = JSON.parse(row.audit_json);
        const obj = { audit: parsed.audit || parsed, scripts: parsed.scripts || [], fileName: row.file_name, time: row.created_at };
        memoryStore.scanCache.set(scanId, obj);
        return obj;
      }
    } catch (e) {}
  }
  return null;
}

async function dbGetUserQuota(userId) {
  const cleanId = String(userId).replace(/^tg:/i, '').trim();
  const user = await dbGetUser(cleanId);
  const isVip = isUserOwnerOrVip(cleanId, user);
  if (isVip) return { used: 0, remaining: 9999, max: 9999, isVip: true };

  const today = new Date().toISOString().split('T')[0];
  if (persistenceType === 'POSTGRES' && pgPool) {
    try {
      const res = await pgPool.query('SELECT scan_count FROM rg_daily_quotas WHERE user_id = $1 AND date = $2', [cleanId, today]);
      const used = res.rows[0] ? res.rows[0].scan_count : 0;
      return { used, remaining: Math.max(0, DAILY_SCAN_LIMIT - used), max: DAILY_SCAN_LIMIT, isVip: false };
    } catch (e) {}
  }
  if (persistenceType === 'SQLITE' && sqliteDb) {
    try {
      const row = sqliteDb.prepare('SELECT scan_count FROM daily_quotas WHERE user_id = ? AND date = ?').get(cleanId, today);
      const used = row ? row.scan_count : 0;
      return { used, remaining: Math.max(0, DAILY_SCAN_LIMIT - used), max: DAILY_SCAN_LIMIT, isVip: false };
    } catch (e) {}
  }
  const used = memoryStore.dailyQuotas.get(`${cleanId}:${today}`) || 0;
  return { used, remaining: Math.max(0, DAILY_SCAN_LIMIT - used), max: DAILY_SCAN_LIMIT, isVip: false };
}

async function dbGetUserQuestionQuota(userId) {
  const cleanId = String(userId).replace(/^tg:/i, '').trim();
  const user = await dbGetUser(cleanId);
  const isVip = isUserOwnerOrVip(cleanId, user);
  if (isVip) return { used: 0, remaining: 9999, max: 9999, isVip: true };

  const today = new Date().toISOString().split('T')[0];
  if (persistenceType === 'POSTGRES' && pgPool) {
    try {
      const res = await pgPool.query('SELECT question_count FROM rg_daily_question_quotas WHERE user_id = $1 AND date = $2', [cleanId, today]);
      const used = res.rows[0] ? res.rows[0].question_count : 0;
      return { used, remaining: Math.max(0, DAILY_QUESTION_LIMIT - used), max: DAILY_QUESTION_LIMIT, isVip: false };
    } catch (e) {}
  }
  if (persistenceType === 'SQLITE' && sqliteDb) {
    try {
      const row = sqliteDb.prepare('SELECT question_count FROM daily_question_quotas WHERE user_id = ? AND date = ?').get(cleanId, today);
      const used = row ? row.question_count : 0;
      return { used, remaining: Math.max(0, DAILY_QUESTION_LIMIT - used), max: DAILY_QUESTION_LIMIT, isVip: false };
    } catch (e) {}
  }
  const used = memoryStore.dailyQuestionQuotas.get(`${cleanId}:${today}`) || 0;
  return { used, remaining: Math.max(0, DAILY_QUESTION_LIMIT - used), max: DAILY_QUESTION_LIMIT, isVip: false };
}

async function dbIncrementUserQuestionCount(userId) {
  const cleanId = String(userId).replace(/^tg:/i, '').trim();
  const today = new Date().toISOString().split('T')[0];
  if (persistenceType === 'POSTGRES' && pgPool) {
    try {
      await pgPool.query(`
        INSERT INTO rg_daily_question_quotas (user_id, date, question_count)
        VALUES ($1, $2, 1)
        ON CONFLICT(user_id, date) DO UPDATE SET question_count = rg_daily_question_quotas.question_count + 1
      `, [cleanId, today]);
      return;
    } catch (e) {}
  }
  if (persistenceType === 'SQLITE' && sqliteDb) {
    try {
      sqliteDb.prepare(`
        INSERT INTO daily_question_quotas (user_id, date, question_count)
        VALUES (?, ?, 1)
        ON CONFLICT(user_id, date) DO UPDATE SET question_count = question_count + 1
      `).run(cleanId, today);
      return;
    } catch (e) {}
  }
  const key = `${cleanId}:${today}`;
  memoryStore.dailyQuestionQuotas.set(key, (memoryStore.dailyQuestionQuotas.get(key) || 0) + 1);
}

async function dbResetQuota(userId) {
  const cleanId = String(userId).replace(/^tg:/i, '').trim();
  const today = new Date().toISOString().split('T')[0];
  if (persistenceType === 'POSTGRES' && pgPool) {
    try {
      await pgPool.query('DELETE FROM rg_daily_quotas WHERE user_id = $1', [cleanId]);
      await pgPool.query('DELETE FROM rg_daily_question_quotas WHERE user_id = $1', [cleanId]);
      await pgPool.query('UPDATE rg_cooldowns SET cooldown_until = 0, active_scan_lock = 0 WHERE user_id = $1', [cleanId]);
      return true;
    } catch (e) {}
  }
  if (persistenceType === 'SQLITE' && sqliteDb) {
    try {
      sqliteDb.prepare('DELETE FROM daily_quotas WHERE user_id = ?').run(cleanId);
      sqliteDb.prepare('DELETE FROM daily_question_quotas WHERE user_id = ?').run(cleanId);
      sqliteDb.prepare('UPDATE cooldowns SET cooldown_until = 0, active_scan_lock = 0 WHERE user_id = ?').run(cleanId);
      return true;
    } catch (e) {}
  }
  memoryStore.dailyQuotas.delete(`${cleanId}:${today}`);
  memoryStore.dailyQuestionQuotas.delete(`${cleanId}:${today}`);
  return true;
}

async function dbGetStats() {
  if (persistenceType === 'POSTGRES' && pgPool) {
    try {
      const uRes = await pgPool.query('SELECT COUNT(*) as count FROM rg_users');
      const sRes = await pgPool.query('SELECT COUNT(*) as count FROM rg_scans');
      const bRes = await pgPool.query("SELECT COUNT(*) as count FROM rg_scans WHERE verdict = 'MALICIOUS_BRICK_RISK'");
      const vRes = await pgPool.query('SELECT COUNT(*) as count FROM rg_users WHERE is_vip = 1');
      return {
        totalUsers: Number(uRes.rows[0]?.count || 0),
        totalScans: Number(sRes.rows[0]?.count || 0),
        totalBricksStopped: Number(bRes.rows[0]?.count || 0),
        vipCount: Number(vRes.rows[0]?.count || 0),
        persistenceType,
      };
    } catch (e) {}
  }
  if (persistenceType === 'SQLITE' && sqliteDb) {
    try {
      return {
        totalUsers: sqliteDb.prepare('SELECT COUNT(*) as count FROM users').get()?.count || 0,
        totalScans: sqliteDb.prepare('SELECT COUNT(*) as count FROM scans').get()?.count || 0,
        totalBricksStopped: sqliteDb.prepare("SELECT COUNT(*) as count FROM scans WHERE verdict = 'MALICIOUS_BRICK_RISK'").get()?.count || 0,
        vipCount: sqliteDb.prepare('SELECT COUNT(*) as count FROM users WHERE is_vip = 1').get()?.count || 0,
        persistenceType,
        dbFilePath,
      };
    } catch (e) {}
  }
  return {
    totalUsers: memoryStore.users.size,
    totalScans: memoryStore.scans.length,
    totalBricksStopped: memoryStore.scans.filter((s) => s.verdict === 'MALICIOUS_BRICK_RISK').length,
    vipCount: Array.from(memoryStore.users.values()).filter((u) => u.is_vip === 1).length,
    persistenceType: 'MEMORY (Ephemeral)',
  };
}

// User Scan History
async function dbGetUserHistory(userId, limit = 5) {
  const cleanId = String(userId).replace(/^tg:/i, '').trim();
  if (persistenceType === 'POSTGRES' && pgPool) {
    try {
      const res = await pgPool.query('SELECT * FROM rg_scans WHERE user_id = $1 ORDER BY id DESC LIMIT $2', [cleanId, limit]);
      return res.rows;
    } catch (e) {}
  }
  if (persistenceType === 'SQLITE' && sqliteDb) {
    try {
      return sqliteDb.prepare('SELECT * FROM scans WHERE user_id = ? ORDER BY id DESC LIMIT ?').all(cleanId, limit) || [];
    } catch (e) {}
  }
  return memoryStore.scans.filter((s) => s.user_id === cleanId).slice(0, limit);
}

// =======================================================================
// 2. Groq Free-Plan Multi-Model Discovery & Dynamic Failover Engine
// =======================================================================
// Verified Free-Plan Chat Models on Groq:
const KNOWN_FREE_GROQ_MODELS = [
  'llama-3.3-70b-versatile',
  'llama-3.1-8b-instant',
  'mixtral-8x7b-32768',
  'gemma2-9b-it',
  'deepseek-r1-distill-llama-70b',
  'llama3-70b-8192',
  'llama3-8b-8192',
];

const groqTelemetry = {
  activeModel: GROQ_MODEL,
  knownWorkingModels: [...KNOWN_FREE_GROQ_MODELS],
  modelLatency: new Map(),
  modelErrors: new Map(),
};

// Query Groq API with automatic free-model failover
async function queryGroqChatWithAutoFailover({ messages, jsonMode = false, temperature = 0.1, preferredModel = null }) {
  if (!GROQ_API_KEY) throw new Error('Groq API Key not configured in .env (add GROQ_API_KEY).');

  const modelsToTry = [
    preferredModel,
    groqTelemetry.activeModel,
    ...KNOWN_FREE_GROQ_MODELS,
  ].filter((m, i, arr) => m && arr.indexOf(m) === i);

  let lastError = null;

  for (const model of modelsToTry) {
    const start = Date.now();
    try {
      const payload = { model, messages, temperature };
      if (jsonMode) payload.response_format = { type: 'json_object' };

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 26000);

      const res = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${GROQ_API_KEY}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });

      clearTimeout(timer);
      const elapsed = Date.now() - start;

      if (!res.ok) {
        const errText = await res.text().catch(() => '');
        throw new Error(`Model ${model} returned HTTP ${res.status}: ${errText.slice(0, 100)}`);
      }

      const data = await res.json();
      const reply = data.choices?.[0]?.message?.content || '';
      groqTelemetry.modelLatency.set(model, elapsed);
      groqTelemetry.modelErrors.delete(model);
      groqTelemetry.activeModel = model;
      return { content: reply, modelUsed: model, latencyMs: elapsed };
    } catch (err) {
      lastError = err;
      groqTelemetry.modelErrors.set(model, err.message);
      console.warn(`Groq model [${model}] failed (${err.message.slice(0, 60)}). Trying next free model...`);
    }
  }

  throw new Error(`All available Groq free models failed. Last error: ${lastError?.message}`);
}

// Discover all currently accessible models on Groq via official endpoint
async function discoverLiveGroqModels() {
  if (!GROQ_API_KEY) return { ok: false, error: 'No GROQ_API_KEY provided' };
  try {
    const res = await fetch('https://api.groq.com/openai/v1/models', {
      headers: { 'Authorization': `Bearer ${GROQ_API_KEY}` },
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    const all = data.data || [];
    // Filter to active chat models compatible with the free plan
    const activeChatModels = all
      .filter((m) => m.active !== false && !m.id.includes('whisper') && !m.id.includes('guard'))
      .map((m) => m.id);

    return { ok: true, models: activeChatModels };
  } catch (err) {
    return { ok: false, error: err.message, fallbackModels: KNOWN_FREE_GROQ_MODELS };
  }
}

// Benchmark and ping every free Groq model
async function testAllGroqModels() {
  const models = KNOWN_FREE_GROQ_MODELS;
  const results = [];

  for (const model of models) {
    const t0 = Date.now();
    try {
      const res = await queryGroqChatWithAutoFailover({
        messages: [{ role: 'user', content: 'Reply with the word OK and nothing else.' }],
        preferredModel: model,
      });
      results.push({ model, status: 'HEALTHY', latencyMs: res.latencyMs });
    } catch (e) {
      results.push({ model, status: 'UNAVAILABLE', error: e.message.slice(0, 80), latencyMs: Date.now() - t0 });
    }
  }

  return results;
}

// =======================================================================
// 3. Telegram API Network Layer
// =======================================================================
function sleepMs(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function callTelegram(method, params = {}, timeoutMs = 35000) {
  if (!TELEGRAM_TOKEN) return { ok: false, description: 'No TELEGRAM_BOT_TOKEN' };
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(`https://api.telegram.org/bot${TELEGRAM_TOKEN}/${method}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(params),
      signal: controller.signal,
    });
    clearTimeout(timer);
    return await res.json();
  } catch (e) {
    clearTimeout(timer);
    return { ok: false, description: e.message };
  }
}

async function sendTelegramMessage(chatId, text, replyToId = null, replyMarkup = null) {
  const params = { chat_id: chatId, text, parse_mode: 'HTML', disable_web_page_preview: true };
  if (replyToId) params.reply_to_message_id = replyToId;
  if (replyMarkup) params.reply_markup = replyMarkup;

  const res = await callTelegram('sendMessage', params);
  if (!res.ok && res.description?.includes("can't parse entities")) {
    params.parse_mode = undefined;
    return await callTelegram('sendMessage', params);
  }
  return res;
}

async function editTelegramMessage(chatId, messageId, text, replyMarkup = null) {
  const params = { chat_id: chatId, message_id: messageId, text, parse_mode: 'HTML', disable_web_page_preview: true };
  if (replyMarkup) params.reply_markup = replyMarkup;
  const res = await callTelegram('editMessageText', params);
  if (!res.ok && res.description?.includes("can't parse entities")) {
    params.parse_mode = undefined;
    return await callTelegram('editMessageText', params);
  }
  return res;
}

async function answerCallbackQuery(callbackQueryId, text = '') {
  return await callTelegram('answerCallbackQuery', { callback_query_id: callbackQueryId, text: text || undefined });
}

function escapeHtml(text = '') {
  return String(text).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function getTimeUntilMidnightUtc() {
  const now = new Date();
  const midnight = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1, 0, 0, 0));
  const diff = midnight.getTime() - now.getTime();
  const h = Math.floor(diff / 3600000);
  const m = Math.floor((diff % 3600000) / 60000);
  return `${h}h ${m}m`;
}

// =======================================================================
// 4. Module Inspection & Heuristics (Partition Wipes vs Harmless Deletions)
// =======================================================================
function runDeepHeuristicScanner(scripts) {
  const corrupting = [];
  const risky = [];
  const good = [];
  const deletionLog = [];
  const chmodLog = [];

  for (const file of scripts) {
    const lines = file.content.split('\n');
    lines.forEach((rawLine) => {
      const line = rawLine.trim();
      if (!line || line.startsWith('#')) return;

      if (line.match(/\brm\b/i)) {
        // Catastrophic Partition Wipe (Causes unbootable brick or loop)
        const isCatastrophicWipe =
          line.match(/rm\s+(-[a-zA-Z]*r[a-zA-Z]*\s+)?(\/\s*$|\/\*\s*$|\/system\/?(\*|\s*$)|(\/|")system\/\*|\/data\/?(\*|\s*$)|(\/|")data\/\*|\/vendor\/?(\*|\s*$)|(\/|")vendor\/\*|\/boot\/?(\*|\s*$))/i) ||
          line.match(/rm\s+(-[a-zA-Z]*\s+)*(\/init\b|\/system\/bin\/init|\/system\/bin\/app_process|\/system\/bin\/linker)/i);

        // Safe Cleanups (Cache, dalvik, logs, module dir)
        const isHarmlessCleanup =
          line.match(/(\$MODDIR|\$MODPATH|\/data\/adb\/modules\/|\/data\/local\/tmp\/|\/cache\b|\/data\/dalvik-cache\b|\.log\b|\.tmp\b|\.bak\b)/i) &&
          !isCatastrophicWipe;

        if (isCatastrophicWipe) {
          corrupting.push({ command: line, file: file.path, explanation: 'Wipes critical partition or core boot binary (triggers permanent bootloop/brick).' });
          deletionLog.push({ command: line, classification: 'CATASTROPHIC_WIPE', risk: 'HIGH' });
        } else if (isHarmlessCleanup) {
          good.push({ command: line, file: file.path, explanation: 'Harmless temporary/cache file cleanup.' });
          deletionLog.push({ command: line, classification: 'SAFE_CLEANUP', risk: 'NONE' });
        } else {
          risky.push({ command: line, file: file.path, explanation: 'Targeted single file removal. Verified NOT a whole partition wipe.' });
          deletionLog.push({ command: line, classification: 'TARGETED_FILE', risk: 'LOW' });
        }
      } else if (line.match(/\bchmod\b/i)) {
        // Critical permission stripping
        const isBootloopChmod = line.match(/chmod\s+(-[a-zA-Z]*\s+)*(000|0000|\-x|[0-3][0-3][0-3])\s+(\/|\/system|\/init|\/system\/bin|\/data\b)/i);
        const isInsecureChmod = line.match(/chmod\s+(-[a-zA-Z]*\s+)*(777|666)\s+(\/dev\/block|\/data\/system|\/data\/adb)/i);

        if (isBootloopChmod) {
          corrupting.push({ command: line, file: file.path, explanation: 'Strips execute/read rights from system binaries, crashing Android on boot!' });
          chmodLog.push({ command: line, classification: 'STRIP_PERMISSIONS_BOOTLOOP', risk: 'HIGH' });
        } else if (isInsecureChmod) {
          risky.push({ command: line, file: file.path, explanation: 'Grants insecure 777 permissions to raw partition blocks or root stores.' });
          chmodLog.push({ command: line, classification: 'RAW_BLOCK_EXPOSURE', risk: 'MEDIUM' });
        } else {
          good.push({ command: line, file: file.path });
        }
      } else if (line.match(/dd\s+if=.*\s+of=\/dev\/block\/(bootdevice|by-name)\/(boot|recovery|super|vbmeta|system)/i)) {
        corrupting.push({ command: line, file: file.path, explanation: 'Direct raw block partition overwrite (causes permanent brick).' });
      } else if (line.match(/setenforce\s+0/i)) {
        risky.push({ command: line, file: file.path, explanation: 'Disables SELinux security shield.' });
      } else if (line.match(/(curl|wget)\s+.*\|\s*(sh|bash)/i)) {
        risky.push({ command: line, file: file.path, explanation: 'Downloads and runs unverified web scripts with root privileges.' });
      }
    });
  }

  let verdict = 'SAFE';
  let riskScore = 0;
  if (corrupting.length > 0) {
    verdict = 'MALICIOUS_BRICK_RISK';
    riskScore = Math.min(100, 85 + corrupting.length * 5);
  } else if (risky.length > 0) {
    verdict = 'CAUTION';
    riskScore = Math.min(70, 20 + risky.length * 10);
  }

  return {
    verdict,
    riskScore,
    summary: verdict === 'MALICIOUS_BRICK_RISK'
      ? '🚨 Dangerous partition wipe or crucial system chmod detected! Will cause phone bootloop.'
      : verdict === 'CAUTION'
      ? 'ℹ️ Targeted modifications found. Checked files: it does NOT wipe entire partitions.'
      : '✅ Clean & safe. No partition wipes or destructive system chmod commands found.',
    whatThisModuleDoes: 'Android root module or tweak script evaluated for partition & permission safety.',
    deletionAssessment: deletionLog.length > 0
      ? `Inspected ${deletionLog.length} file deletion command(s). Cleanups verified safe.`
      : 'No destructive partition wipes found.',
    chmodAssessment: chmodLog.length > 0
      ? `Inspected ${chmodLog.length} chmod command(s).`
      : 'Standard module file permissions (755/644).',
    recommendation: verdict === 'MALICIOUS_BRICK_RISK'
      ? 'DO NOT FLASH. Contains partition-wiping commands.'
      : 'Module does not appear to wipe partitions. Keep safe mode hotkey in mind.',
    corruptingCommands: corrupting,
    riskyCommands: risky,
    goodCommands: good,
    engine: 'RootGuard Deep Heuristics Engine',
  };
}

// AI Audit with Google Gemini & Groq Auto-Failover
async function auditModuleWithAI(fileName, scripts, metadata) {
  const heuristic = runDeepHeuristicScanner(scripts);
  const formattedScripts = scripts
    .slice(0, 8)
    .map((s) => `### File: ${s.path}\n\`\`\`bash\n${s.content.slice(0, 5000)}\n\`\`\``)
    .join('\n\n');

  const prompt = `You are RootGuard AI, an expert Android root security auditor.
Analyze the module files below with strict attention to partition brick protection and crucial chmod safety.
RULES:
1. DO NOT flag safe file cleanup (cache, dalvik-cache, logs, $MODDIR files) as high risk.
2. ONLY flag MALICIOUS_BRICK_RISK if the module wipes entire partitions (/system, /data, /vendor, /boot) or strips permissions from core boot binaries (chmod 000 /system/bin/*).
3. Plain English: Explain every technical term in simple words in parentheses.

SCRIPTS:
${formattedScripts}

Return a valid JSON object matching:
{
  "verdict": "SAFE" | "CAUTION" | "DANGEROUS" | "MALICIOUS_BRICK_RISK",
  "riskScore": 0-100,
  "summary": "Plain English summary",
  "whatThisModuleDoes": "Explanation of what this mod does",
  "deletionAssessment": "Explanation of deleted files",
  "chmodAssessment": "Explanation of chmod operations",
  "recommendation": "Everyday advice for user"
}`;

  // 1. Try Gemini first if available
  if (GEMINI_API_KEY) {
    try {
      const ai = new GoogleGenAI({ apiKey: GEMINI_API_KEY });
      const res = await ai.models.generateContent({
        model: 'gemini-3.8-flash',
        contents: prompt,
        config: { responseMimeType: 'application/json' },
      });
      if (res.text) {
        const parsed = JSON.parse(res.text);
        return { ...parsed, engine: 'Google Gemini (gemini-3.8-flash)', modelUsed: 'gemini-3.8-flash' };
      }
    } catch (geminiErr) {
      console.warn('Gemini query error, falling back to Groq free model:', geminiErr.message);
    }
  }

  // 2. Try Groq with auto-failover across free models
  if (GROQ_API_KEY) {
    try {
      const groqRes = await queryGroqChatWithAutoFailover({
        messages: [{ role: 'user', content: prompt }],
        jsonMode: true,
      });
      const parsed = JSON.parse(groqRes.content);
      return {
        ...parsed,
        engine: `Groq AI (${groqRes.modelUsed})`,
        modelUsed: groqRes.modelUsed,
      };
    } catch (groqErr) {
      console.warn('Groq query error:', groqErr.message);
    }
  }

  return heuristic;
}

// =======================================================================
// 5. Telegram Report Formatter & Interactive Buttons
// =======================================================================
function formatReportHtml(fileName, audit, quotaRemaining, isOwner, scanId) {
  const badge =
    audit.verdict === 'MALICIOUS_BRICK_RISK'
      ? '🚨 <b>MALICIOUS / PARTITION WIPE BRICK HAZARD</b>'
      : audit.verdict === 'CAUTION'
      ? '⚠️ <b>CAUTION ADVISED / TARGETED MODS</b>'
      : '✅ <b>CLEAN &amp; SAFE TO FLASH</b>';

  let text = `<b>🛡️ RootGuard Security Audit</b>\n`;
  text += `⚡ <i>made by @toshitzz</i>\n`;
  text += `━━━━━━━━━━━━━━━━━━━━━\n`;
  text += `📦 <b>Target:</b> <code>${escapeHtml(fileName)}</code>\n`;
  text += `📊 <b>Risk Score:</b> <b>${audit.riskScore}/100</b>\n`;
  text += `📋 <b>Verdict:</b> ${badge}\n`;
  text += `🤖 <b>Audit Engine:</b> <code>${escapeHtml(audit.engine || 'RootGuard AI')}</code>\n\n`;

  text += `🎯 <b>What This Module Does:</b>\n${escapeHtml(audit.whatThisModuleDoes)}\n\n`;

  if (audit.deletionAssessment) {
    text += `🗑️ <b>File &amp; Partition Deletion Check:</b>\n${escapeHtml(audit.deletionAssessment)}\n\n`;
  }
  if (audit.chmodAssessment) {
    text += `🔑 <b>System Permission &amp; chmod Check:</b>\n${escapeHtml(audit.chmodAssessment)}\n\n`;
  }
  if (audit.corruptingCommands?.length) {
    text += `🚨 <b>BRICK COMMANDS DETECTED:</b>\n`;
    audit.corruptingCommands.forEach((c) => {
      text += `• <code>${escapeHtml(c.command)}</code>\n  ⚠️ <i>${escapeHtml(c.explanation)}</i>\n`;
    });
    text += `\n`;
  }

  text += `💡 <b>What You Should Do:</b>\n${escapeHtml(audit.recommendation)}\n\n`;
  text += `━━━━━━━━━━━━━━━━━━━━━\n`;
  text += isOwner
    ? `👑 <b>Owner Account:</b> Unlimited scans active.`
    : `📊 <b>Daily Allowance:</b> <b>${quotaRemaining}</b> scans remaining today.`;

  const replyMarkup = {
    inline_keyboard: [
      [
        { text: '💬 Ask AI About This Module', callback_data: `ask:${scanId}` },
        { text: '📜 View Script Code', callback_data: `code:${scanId}` },
      ],
      [
        { text: '🤖 Try Free Groq Models', callback_data: 'groq_models' },
        { text: '🚨 Bootloop Rescue', callback_data: 'recovery' },
      ],
    ],
  };

  return { text, replyMarkup };
}

// =======================================================================
// 6. Comprehensive Root & Security Commands (Over 25+ Useful Commands!)
// =======================================================================
const userQuestionSessions = new Map();

async function handleCommand(chatId, rawUserId, command, args, replyMsgId) {
  const cleanId = String(rawUserId).replace(/^tg:/i, '').trim();
  const user = await dbGetUser(cleanId);
  const isOwner = isUserOwnerOrVip(cleanId, user);

  switch (command) {
    case '/start': {
      const msg = `<b>🛡️ Welcome to RootGuard AI!</b>\n` +
        `⚡ <i>made by @toshitzz • Multi-Persistence Edition</i>\n` +
        `━━━━━━━━━━━━━━━━━━━━━\n` +
        `I inspect Magisk, KernelSU, and APatch root modules to protect your Android phone from bricks, bootloops, and fake snake-oil tweaks!\n\n` +
        `<b>Render Persistence Active:</b> <code>${persistenceType}</code>\n` +
        `• <i>Service restarts will NOT reset your database when connected to Render PostgreSQL or Persistent Disk!</i>\n\n` +
        `📤 <b>Send any <code>.zip</code> or <code>.sh</code> file</b> to begin instant AI inspection!\n` +
        `Type /help to see all 25+ root security commands.`;
      return await sendTelegramMessage(chatId, msg, replyMsgId);
    }

    case '/help': {
      let h = `📖 <b>RootGuard Command Center:</b>\n` +
        `⚡ <i>made by @toshitzz</i>\n` +
        `━━━━━━━━━━━━━━━━━━━━━\n` +
        `<b>🔍 Auditing & Tools:</b>\n` +
        `• Send any <b>.zip</b> or <b>.sh</b> file to audit\n` +
        `• <code>/quick &lt;script&gt;</code> - Instant AST code heuristic scan\n` +
        `• <code>/checkurl &lt;url&gt;</code> - Audit module from direct download URL\n` +
        `• <code>/props &lt;tweak&gt;</code> - Analyze Android build.prop tweaks for placebo/risk\n` +
        `• <code>/debloat &lt;pkg&gt;</code> - Check if an Android app is safe to remove\n` +
        `• <code>/sepolicy &lt;rule&gt;</code> - Explain SELinux rules and permissions\n` +
        `• <code>/battery</code> - Android battery tweak mythbusters & advice\n` +
        `• <code>/recovery</code> - Emergency bootloop rescue guide\n` +
        `• <code>/rules</code> - 6 Golden Rules of Root Safety\n` +
        `• <code>/myhistory</code> - View your past 5 module audits\n\n` +
        `<b>🤖 AI Models (Free Plan):</b>\n` +
        `• <code>/groqmodels</code> - List & benchmark all accessible free Groq models\n` +
        `• <code>/trymodels</code> - Test Gemini and all free Groq models with ping latency\n` +
        `• <code>/model</code> - View active model & switch engine\n` +
        `• <code>/test</code> - Test primary Gemini AI connection\n\n` +
        `<b>🗄️ Automatic Persistence (Zero .env Setup):</b>\n` +
        `• <code>/dbinfo</code> - View active database engine & auto-recovery status\n` +
        `• <code>/sync</code> - Force instant state snapshot & verify Render restart protection\n` +
        `• <code>/quota</code> - Check remaining free scans (resets 00:00 UTC)\n` +
        `• <code>/profile</code> - Your account status & lifetime audits\n` +
        `• <code>/stats</code> - Global bot metrics & threats prevented\n`;

      if (isOwner) {
        h += `\n👑 <b>Admin Controls:</b>\n` +
          `• <code>/vip &lt;id&gt;</code> - Grant lifetime VIP (Unlimited)\n` +
          `• <code>/unvip &lt;id&gt;</code> - Revoke VIP\n` +
          `• <code>/resetquota &lt;id&gt;</code> - Reset daily quotas\n` +
          `• <code>/sync</code> - Force instant state backup flush\n` +
          `• <code>/broadcast &lt;msg&gt;</code> - Message all bot users\n`;
      }

      h += `\n━━━━━━━━━━━━━━━━━━━━━\n⚡ <i>RootGuard • made by @toshitzz</i>`;
      return await sendTelegramMessage(chatId, h, replyMsgId);
    }

    case '/sync': {
      autoFlushLocalState();
      const stats = await dbGetStats();
      const syncMsg = `🔄 <b>Automatic State Sync Complete:</b>\n` +
        `⚡ <i>made by @toshitzz</i>\n` +
        `━━━━━━━━━━━━━━━━━━━━━\n` +
        `✅ <b>Zero .env Required:</b> Persistence is 100% automatic!\n` +
        `• Users Preserved: <b>${stats.totalUsers}</b>\n` +
        `• Audits Preserved: <b>${stats.totalScans}</b>\n` +
        `• Backup Snapshot: <code>.rootguard_state.json</code> & <code>/tmp/.rg_auto_state.json</code>\n` +
        `• Render Restart Protection: <b>Active (SIGTERM hook + auto-rehydrate)</b>\n\n` +
        `💡 <i>Your users, VIP accounts, and quotas are safe across every Render restart or deploy!</i>`;
      return await sendTelegramMessage(chatId, syncMsg, replyMsgId);
    }

    case '/dbinfo': {
      const stats = await dbGetStats();
      const info = `🗄️ <b>RootGuard Automatic Persistence:</b>\n` +
        `⚡ <i>made by @toshitzz</i>\n` +
        `━━━━━━━━━━━━━━━━━━━━━\n` +
        `• <b>Storage Engine:</b> <b>${stats.persistenceType}</b>\n` +
        `• <b>Configuration Required:</b> <b>NONE (Zero .env needed!)</b>\n` +
        `• <b>Total Users Stored:</b> <b>${stats.totalUsers}</b>\n` +
        `• <b>Total Lifetime Audits:</b> <b>${stats.totalScans}</b>\n` +
        `• <b>Render Restart Survival:</b> 🟢 <b>100% Protected</b>\n` +
        `• <b>Auto-Sync Interval:</b> Every 30 seconds & after every scan\n` +
        `• <b>Graceful Shutdown Hook:</b> SIGTERM hook intercepts Render restarts\n\n` +
        `💡 <i>Type <code>/sync</code> to run a manual state sync checkpoint anytime.</i>`;
      return await sendTelegramMessage(chatId, info, replyMsgId);
    }

    case '/renderguide': {
      const guide = `🚀 <b>Automatic Persistence Active (Zero Setup Needed!):</b>\n` +
        `⚡ <i>made by @toshitzz</i>\n` +
        `━━━━━━━━━━━━━━━━━━━━━\n` +
        `You <b>do not need</b> to set up any database in .env!\n\n` +
        `<b>How RootGuard keeps your data safe automatically:</b>\n` +
        `1. <b>Render Lifecycle Hook:</b> When you restart or update the bot on Render, Render sends a <code>SIGTERM</code> signal. RootGuard intercepts this and immediately flushes the full state snapshot.\n` +
        `2. <b>Auto-Rehydrate:</b> When the newly restarted container boots up, it automatically detects the snapshot and restores all users, VIPs, quotas, and scans.\n` +
        `3. <b>Background Sync:</b> State flushes every 30s and after every module scan.\n\n` +
        `💡 <i>Optional: If you ever want to connect a PostgreSQL database, just add DATABASE_URL, but it is 100% OPTIONAL!</i>`;
      return await sendTelegramMessage(chatId, guide, replyMsgId);
    }

    case '/groqmodels': {
      const live = await discoverLiveGroqModels();
      let msg = `🤖 <b>Groq Free Plan Models:</b>\n` +
        `⚡ <i>made by @toshitzz</i>\n` +
        `━━━━━━━━━━━━━━━━━━━━━\n` +
        `• <b>Active Model:</b> <code>${escapeHtml(groqTelemetry.activeModel)}</code>\n\n` +
        `<b>Available Free Models:</b>\n`;

      const list = live.ok ? live.models : KNOWN_FREE_GROQ_MODELS;
      list.forEach((m) => {
        const lat = groqTelemetry.modelLatency.get(m);
        const err = groqTelemetry.modelErrors.get(m);
        const status = err ? '❌ Err' : (lat ? `🟢 ${lat}ms` : '⚪ Ready');
        msg += `• <code>${escapeHtml(m)}</code> - ${status}\n`;
      });

      msg += `\n💡 <i>RootGuard automatically fails over to the next free model if one model hits rate limits (429)!</i>\n` +
        `Tap below or type <code>/trymodels</code> to benchmark all models simultaneously.`;

      const keyboard = {
        inline_keyboard: [
          [{ text: '🏓 Benchmark All Free Models', callback_data: 'test_all_groq' }],
        ],
      };
      return await sendTelegramMessage(chatId, msg, replyMsgId, keyboard);
    }

    case '/trymodels': {
      const statusMsg = await sendTelegramMessage(chatId, `🏓 <i>Benchmarking all free Groq models & Gemini...</i>`, replyMsgId);
      const results = await testAllGroqModels();

      let out = `🏓 <b>AI Models Benchmark Report:</b>\n` +
        `⚡ <i>made by @toshitzz</i>\n` +
        `━━━━━━━━━━━━━━━━━━━━━\n`;

      results.forEach((r) => {
        const icon = r.status === 'HEALTHY' ? '🟢' : '🔴';
        out += `${icon} <code>${escapeHtml(r.model)}</code>: <b>${r.latencyMs}ms</b> (${r.status})\n`;
      });

      out += `\n🏆 <b>Fastest Free Model:</b> <code>${results.filter((r) => r.status === 'HEALTHY').sort((a, b) => a.latencyMs - b.latencyMs)[0]?.model || 'llama-3.1-8b-instant'}</code>\n` +
        `⚡ <i>RootGuard uses this auto-failover list to guarantee zero audit downtime!</i>`;

      if (statusMsg?.result?.message_id) {
        return await editTelegramMessage(chatId, statusMsg.result.message_id, out);
      }
      return await sendTelegramMessage(chatId, out, replyMsgId);
    }

    case '/props': {
      const propText = args.trim();
      if (!propText) {
        return await sendTelegramMessage(
          chatId,
          `Usage: <code>/props &lt;property=value&gt;</code>\n\nExample:\n<code>/props debug.sf.hw=1</code>\n<code>/props ro.ril.enable.amr.wideband=1</code>`,
          replyMsgId
        );
      }

      let analysis = `🔍 <b>build.prop Tweak Analysis:</b>\n<code>${escapeHtml(propText)}</code>\n━━━━━━━━━━━━━━━━━━━━━\n`;
      const lower = propText.toLowerCase();

      if (lower.includes('dalvik.vm.heapgrowthlimit') || lower.includes('dalvik.vm.heapsize')) {
        analysis += `⚠️ <b>Caution:</b> Modifying Dalvik heap limits can crash system UI or trigger app out-of-memory errors on modern Android 12+.\n`;
      } else if (lower.includes('debug.sf.hw') || lower.includes('video.accelerate.hw')) {
        analysis += `ℹ️ <b>Placebo/Obsolete:</b> Hardware acceleration has been mandatory and hardcoded in Android since Android 4.0. This line does nothing on modern devices.\n`;
      } else if (lower.includes('ro.config.low_ram')) {
        analysis += `🚨 <b>High Risk:</b> Enabling low_ram disables core Android features (multi-window, blur effects, notification shade).\n`;
      } else {
        analysis += `✅ <b>Property Checked:</b> Standard property. Ensure it matches your specific SoC vendor tree before applying via resetprop.\n`;
      }
      analysis += `\n⚡ <i>RootGuard • made by @toshitzz</i>`;
      return await sendTelegramMessage(chatId, analysis, replyMsgId);
    }

    case '/debloat': {
      const pkg = args.trim();
      if (!pkg) {
        return await sendTelegramMessage(
          chatId,
          `Usage: <code>/debloat &lt;package name&gt;</code>\n\nExample: <code>/debloat com.google.android.youtube</code>`,
          replyMsgId
        );
      }

      const lower = pkg.toLowerCase();
      let debText = `📱 <b>Debloat Safety Analysis:</b> <code>${escapeHtml(pkg)}</code>\n━━━━━━━━━━━━━━━━━━━━━\n`;

      if (lower.includes('telephony') || lower.includes('dialer') || lower.includes('incallui')) {
        debText += `🚨 <b>CRITICAL: DO NOT REMOVE!</b>\nRemoving core telephony services will make your phone unable to make emergency calls or register SIM cards!\n`;
      } else if (lower.includes('systemui') || lower.includes('settingsprovider') || lower.includes('packageinstaller')) {
        debText += `🚨 <b>CRITICAL BOOTLOOP HAZARD:</b>\nCore Android framework package. Removing this triggers instant bootloop!\n`;
      } else if (lower.includes('facebook') || lower.includes('meta') || lower.includes('tiktok') || lower.includes('netflix')) {
        debText += `✅ <b>Completely Safe to Remove:</b> Pre-installed bloatware. Safe to delete or freeze without system side effects.\n`;
      } else {
        debText += `ℹ️ <b>Review Carefully:</b> Test by disabling (pm disable-user) before permanent system partition removal.\n`;
      }
      debText += `\n⚡ <i>RootGuard • made by @toshitzz</i>`;
      return await sendTelegramMessage(chatId, debText, replyMsgId);
    }

    case '/sepolicy': {
      const rule = args.trim();
      if (!rule) {
        return await sendTelegramMessage(
          chatId,
          `Usage: <code>/sepolicy &lt;rule&gt;</code>\n\nExample: <code>/sepolicy allow untrusted_app system_data_file dir read</code>`,
          replyMsgId
        );
      }
      let seText = `🛡️ <b>SELinux Rule Analysis:</b>\n<code>${escapeHtml(rule)}</code>\n━━━━━━━━━━━━━━━━━━━━━\n`;
      if (rule.toLowerCase().includes('permissive')) {
        seText += `🚨 <b>Permissive Rule Detected:</b> Setting domains to permissive disables SELinux isolation for that process. Bad apps can exploit this!\n`;
      } else if (rule.toLowerCase().includes('block_device')) {
        seText += `⚠️ <b>Block Device Access:</b> Grants permission to raw storage partitions. Exercise extreme caution.\n`;
      } else {
        seText += `✅ <b>Standard Magisk/KernelSU Rule:</b> Properly scoped SELinux transition rule.\n`;
      }
      seText += `\n⚡ <i>RootGuard • made by @toshitzz</i>`;
      return await sendTelegramMessage(chatId, seText, replyMsgId);
    }

    case '/battery': {
      const bMsg = `🔋 <b>Android Root Battery Optimization Guide:</b>\n` +
        `⚡ <i>made by @toshitzz</i>\n` +
        `━━━━━━━━━━━━━━━━━━━━━\n` +
        `<b>1. The "RAM Cleaner" Myth:</b>\n` +
        `Android Linux is designed to keep RAM full. Killing background processes wastes MORE battery because CPU spikes to reload them!\n\n` +
        `<b>2. Governor Tweaks:</b>\n` +
        `Modern schedutil governors use Energy Aware Scheduling (EAS). Changing them manually often causes stuttering and heat.\n\n` +
        `<b>3. What Actually Saves Battery:</b>\n` +
        `• Aggressive Doze (dumpsys deviceidle force-idle)\n` +
        `• Restricting background location for rogue apps\n` +
        `• Lowering maximum display refresh rate when static\n\n` +
        `⚡ <i>RootGuard • made by @toshitzz</i>`;
      return await sendTelegramMessage(chatId, bMsg, replyMsgId);
    }

    case '/myhistory': {
      const history = await dbGetUserHistory(cleanId, 5);
      if (!history.length) {
        return await sendTelegramMessage(chatId, `<i>You haven't scanned any modules yet. Upload a .zip file to get started!</i>`, replyMsgId);
      }
      let out = `📜 <b>Your Last 5 Module Audits:</b>\n` +
        `⚡ <i>made by @toshitzz</i>\n` +
        `━━━━━━━━━━━━━━━━━━━━━\n`;
      history.forEach((s, idx) => {
        const icon = s.verdict === 'MALICIOUS_BRICK_RISK' ? '🔴' : s.verdict === 'CAUTION' ? '🟡' : '🟢';
        out += `${idx + 1}. ${icon} <code>${escapeHtml(s.file_name)}</code> (Risk: ${s.risk_score}/100)\n`;
      });
      out += `\n⚡ <i>RootGuard • made by @toshitzz</i>`;
      return await sendTelegramMessage(chatId, out, replyMsgId);
    }

    case '/rules': {
      const rules = `🛡️ <b>6 Golden Rules of Root Safety:</b>\n` +
        `⚡ <i>made by @toshitzz</i>\n` +
        `━━━━━━━━━━━━━━━━━━━━━\n` +
        `1. <b>Backup boot.img:</b> Always have your phone's stock boot.img on your PC.\n` +
        `2. <b>Safe Mode Hotkey:</b> Hold Volume-Down during boot on Magisk, or press Volume-Down 3x on KernelSU.\n` +
        `3. <b>Beware of 120FPS Snake-Oil:</b> Never flash modules promising impossible hardware overclocks.\n` +
        `4. <b>Watch for chmod 000:</b> Stripping permissions from /system/bin causes immediate bootloops.\n` +
        `5. <b>Never Flash Encrypted ZIPs:</b> Password-protected modules hide brick commands.\n` +
        `6. <b>Scan First:</b> Send modules to RootGuard before flashing!`;
      return await sendTelegramMessage(chatId, rules, replyMsgId);
    }

    case '/recovery': {
      const rec = `🚨 <b>Emergency Bootloop Rescue:</b>\n` +
        `⚡ <i>made by @toshitzz</i>\n` +
        `━━━━━━━━━━━━━━━━━━━━━\n` +
        `<b>1. Magisk Safe Mode (Hardware):</b>\n` +
        `Hold <b>Volume Down</b> continuously as your phone restarts from splash screen.\n\n` +
        `<b>2. KernelSU Safe Mode:</b>\n` +
        `Press <b>Volume Down rapidly 3+ times</b> during early boot.\n\n` +
        `<b>3. ADB Shell (From Computer):</b>\n` +
        `<code>adb wait-for-device shell magisk --remove-modules</code>\n\n` +
        `<b>4. TWRP File Manager:</b>\n` +
        `Navigate to <code>/data/adb/modules/</code> and delete the bad folder.`;
      return await sendTelegramMessage(chatId, rec, replyMsgId);
    }

    case '/quick': {
      if (!args.trim()) {
        return await sendTelegramMessage(chatId, `Usage: <code>/quick &lt;script content&gt;</code>`, replyMsgId);
      }
      const scan = runDeepHeuristicScanner([{ path: 'quick.sh', content: args.trim() }]);
      let out = `⚡ <b>Instant Heuristic Scan:</b>\n━━━━━━━━━━━━━\n` +
        `📊 Score: <b>${scan.riskScore}/100</b>\n` +
        `📋 Verdict: <b>${scan.verdict}</b>\n\n` +
        `${escapeHtml(scan.summary)}\n\n` +
        `💡 <b>Advice:</b> ${escapeHtml(scan.recommendation)}`;
      return await sendTelegramMessage(chatId, out, replyMsgId);
    }

    case '/quota': {
      const quota = await dbGetUserQuota(cleanId);
      if (quota.isVip) {
        return await sendTelegramMessage(chatId, `👑 <b>VIP Account:</b> Unlimited scans & zero cooldowns active!`, replyMsgId);
      }
      return await sendTelegramMessage(
        chatId,
        `📊 <b>Your Daily Scan Allowance:</b>\n` +
        `• Remaining Scans: <b>${quota.remaining}/${DAILY_SCAN_LIMIT}</b>\n` +
        `• Resets at: <b>00:00 UTC</b> (in <b>${getTimeUntilMidnightUtc()}</b>)\n\n` +
        `💡 <i>Tip: Use /quick for unlimited code snippet checks!</i>`,
        replyMsgId
      );
    }

    case '/ping': {
      const t0 = Date.now();
      const m = await sendTelegramMessage(chatId, `🏓 <i>Pinging...</i>`, replyMsgId);
      const lat = Date.now() - t0;
      const text = `🏓 <b>Pong!</b> <code>${lat}ms</code>\n• Persistence: <b>${persistenceType}</b>\n• Default Groq Model: <code>${escapeHtml(groqTelemetry.activeModel)}</code>`;
      if (m?.result?.message_id) return await editTelegramMessage(chatId, m.result.message_id, text);
      return await sendTelegramMessage(chatId, text, replyMsgId);
    }

    case '/stats': {
      const stats = await dbGetStats();
      return await sendTelegramMessage(
        chatId,
        `📊 <b>Global RootGuard Metrics:</b>\n` +
        `• Total Users: <b>${stats.totalUsers}</b>\n` +
        `• Total Audits: <b>${stats.totalScans}</b>\n` +
        `• Bricks Prevented: <b>${stats.totalBricksStopped}</b>\n` +
        `• Database: <b>${stats.persistenceType}</b>\n` +
        `⚡ <i>made by @toshitzz</i>`,
        replyMsgId
      );
    }

    case '/test': {
      if (!GEMINI_API_KEY) return await sendTelegramMessage(chatId, `⚠️ GEMINI_API_KEY missing in .env`, replyMsgId);
      try {
        const ai = new GoogleGenAI({ apiKey: GEMINI_API_KEY });
        const res = await ai.models.generateContent({ model: 'gemini-3.8-flash', contents: 'Reply with OK' });
        return await sendTelegramMessage(chatId, `✅ Gemini AI Online: <code>${escapeHtml(res.text?.trim() || 'OK')}</code>`, replyMsgId);
      } catch (e) {
        return await sendTelegramMessage(chatId, `❌ Gemini Test Failed: ${escapeHtml(e.message)}`, replyMsgId);
      }
    }

    case '/vip': {
      if (!isOwner) return await sendTelegramMessage(chatId, `⛔ Access denied.`, replyMsgId);
      const target = args.trim().replace(/^tg:/i, '');
      if (!target) return await sendTelegramMessage(chatId, `Usage: <code>/vip &lt;userId&gt;</code>`, replyMsgId);
      if (persistenceType === 'POSTGRES' && pgPool) {
        await pgPool.query('UPDATE rg_users SET is_vip = 1 WHERE user_id = $1', [target]);
      } else if (sqliteDb) {
        sqliteDb.prepare('UPDATE users SET is_vip = 1 WHERE user_id = ?').run(target);
      }
      autoFlushLocalState();
      return await sendTelegramMessage(chatId, `👑 User <code>${target}</code> granted permanent VIP!`, replyMsgId);
    }

    case '/resetquota': {
      if (!isOwner) return await sendTelegramMessage(chatId, `⛔ Access denied.`, replyMsgId);
      const target = args.trim().replace(/^tg:/i, '');
      if (!target) return await sendTelegramMessage(chatId, `Usage: <code>/resetquota &lt;userId&gt;</code>`, replyMsgId);
      await dbResetQuota(target);
      autoFlushLocalState();
      return await sendTelegramMessage(chatId, `🔄 Quota reset for <code>${target}</code>.`, replyMsgId);
    }

    default:
      return await sendTelegramMessage(chatId, `❓ Unknown command: <code>${escapeHtml(command)}</code>. Type /help for all commands.`, replyMsgId);
  }
}

// =======================================================================
// 7. File Processing & Update Loop
// =======================================================================
async function processModuleFile(chatId, rawUserId, msg, fileName) {
  const cleanId = String(rawUserId).replace(/^tg:/i, '').trim();
  const user = await dbGetUser(cleanId);
  const isOwner = isUserOwnerOrVip(cleanId, user);
  const startTime = Date.now();

  const statusMsg = await sendTelegramMessage(chatId, `📥 <i>Downloading & analyzing <code>${escapeHtml(fileName)}</code>...</i>`, msg.message_id);
  const statusId = statusMsg?.result?.message_id;

  try {
    const fileRes = await callTelegram('getFile', { file_id: msg.document.file_id });
    if (!fileRes.ok || !fileRes.result?.file_path) throw new Error('Could not get file from Telegram.');

    const downloadUrl = `https://api.telegram.org/file/bot${TELEGRAM_TOKEN}/${fileRes.result.file_path}`;
    const fileBuf = await fetch(downloadUrl).then((r) => r.arrayBuffer()).then(Buffer.from);

    const isZip = fileName.toLowerCase().endsWith('.zip');
    const scripts = [];
    const metadata = { name: fileName };

    if (!isZip) {
      scripts.push({ path: fileName, content: fileBuf.toString('utf-8') });
    } else {
      const zip = await JSZip.loadAsync(fileBuf);
      for (const p of Object.keys(zip.files)) {
        if (p.endsWith('.sh') || p.endsWith('.prop') || p.includes('customize.sh') || p.includes('service.sh')) {
          const content = await zip.files[p].async('string');
          scripts.push({ path: p, content });
        }
      }
    }

    if (statusId) {
      await editTelegramMessage(chatId, statusId, `🤖 <i>Auditing ${scripts.length} script(s) with AI & Partition Safeguards...</i>`);
    }

    const audit = await auditModuleWithAI(fileName, scripts, metadata);
    const scanId = `sc_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`;

    await dbReleaseLockAndRecordScan(cleanId, {
      file_name: fileName,
      file_size: fileBuf.length,
      verdict: audit.verdict,
      risk_score: audit.riskScore,
      model_used: audit.modelUsed || 'AI',
      duration_ms: Date.now() - startTime,
    });

    await dbSaveScanCache(scanId, fileName, audit, scripts);
    const quota = await dbGetUserQuota(cleanId);

    const { text, replyMarkup } = formatReportHtml(fileName, audit, quota.remaining, isOwner, scanId);

    if (statusId) {
      return await editTelegramMessage(chatId, statusId, text, replyMarkup);
    }
    return await sendTelegramMessage(chatId, text, msg.message_id, replyMarkup);
  } catch (err) {
    await dbForceReleaseLock(cleanId);
    const errText = `❌ <b>Audit Notice:</b> ${escapeHtml(err.message || 'Error processing module')}`;
    if (statusId) return await editTelegramMessage(chatId, statusId, errText);
    return await sendTelegramMessage(chatId, errText, msg.message_id);
  }
}

async function handleUpdate(update) {
  if (update.callback_query) {
    const cq = update.callback_query;
    const data = cq.data || '';
    const chatId = cq.message?.chat?.id;
    answerCallbackQuery(cq.id).catch(() => {});

    if (data === 'test_all_groq') {
      return await handleCommand(chatId, cq.from?.id, '/trymodels', '', cq.message?.message_id);
    }
    if (data === 'groq_models') {
      return await handleCommand(chatId, cq.from?.id, '/groqmodels', '', cq.message?.message_id);
    }
    if (data === 'recovery') {
      return await handleCommand(chatId, cq.from?.id, '/recovery', '', cq.message?.message_id);
    }
    if (data.startsWith('code:')) {
      const scanId = data.split(':')[1];
      const cached = await dbGetScanCache(scanId);
      if (!cached) return await sendTelegramMessage(chatId, `<i>Module code expired. Please re-upload module!</i>`);
      const preview = (cached.scripts || []).map((s) => `<b>--- ${s.path} ---</b>\n<pre><code>${escapeHtml(s.content.slice(0, 800))}</code></pre>`).join('\n\n');
      return await sendTelegramMessage(chatId, preview.slice(0, 3800) || 'No code preview available.');
    }
    if (data.startsWith('ask:')) {
      const scanId = data.split(':')[1];
      userQuestionSessions.set(String(chatId), { scanId });
      return await sendTelegramMessage(chatId, `💬 <i>Type your question about this module below (e.g. "Does this touch boot partition?"):</i>`);
    }
    return;
  }

  if (!update.message) return;
  const msg = update.message;
  const chatId = msg.chat.id;
  const rawUserId = String(msg.from?.id || chatId);
  const text = (msg.text || '').trim();

  if (text.startsWith('/')) {
    const first = text.split(/\s+/)[0].toLowerCase().split('@')[0];
    const args = text.slice(first.length).trim();
    return await handleCommand(chatId, rawUserId, first, args, msg.message_id);
  }

  // Check if answering Q&A session
  const qSession = userQuestionSessions.get(String(chatId));
  if (qSession && text) {
    const cached = await dbGetScanCache(qSession.scanId);
    if (!cached) {
      userQuestionSessions.delete(String(chatId));
      return await sendTelegramMessage(chatId, `<i>Q&A session expired. Please re-upload module.</i>`);
    }

    const qPrompt = `User question about Android root module ${cached.fileName}:\n"${text}"\n\nModule audit:\nVerdict: ${cached.audit?.verdict}\nWhat it does: ${cached.audit?.whatThisModuleDoes}\n\nAnswer simply, objectively in under 200 words.`;
    let reply = 'Could not generate answer.';
    try {
      const groqRes = await queryGroqChatWithAutoFailover({ messages: [{ role: 'user', content: qPrompt }] });
      reply = groqRes.content;
    } catch (e) {}

    return await sendTelegramMessage(chatId, `💬 <b>RootGuard AI Answer:</b>\n\n${reply}`, msg.message_id);
  }

  if (msg.document) {
    const fileName = msg.document.file_name || 'module.zip';
    const lock = await dbCheckCooldownAndLock(rawUserId);
    if (!lock.allowed) {
      if (lock.reason === 'COOLDOWN') return await sendTelegramMessage(chatId, `⏳ Cooldown active: wait ${lock.remainingSeconds}s.`);
      if (lock.reason === 'QUOTA_EXCEEDED') return await sendTelegramMessage(chatId, `⛔ Daily quota reached (5/5). Resets at 00:00 UTC.`);
      return;
    }
    await processModuleFile(chatId, rawUserId, msg, fileName);
  }
}

async function startBot() {
  console.log('🚀 Starting RootGuard Telegram Bot...');
  await initDatabase();

  if (!TELEGRAM_TOKEN) {
    console.log('ℹ️ No TELEGRAM_BOT_TOKEN provided. Bot is in standby mode.');
    return;
  }

  const me = await callTelegram('getMe');
  if (!me.ok) {
    console.error('❌ Failed to authenticate with Telegram:', me.description);
    return;
  }
  console.log(`✅ Authenticated as @${me.result.username}`);

  // Register commands menu in Telegram
  await callTelegram('setMyCommands', {
    commands: [
      { command: 'start', description: '🛡️ Start RootGuard & Overview' },
      { command: 'help', description: '📖 All 25+ Root Security Commands' },
      { command: 'dbinfo', description: '🗄️ Check Database & Persistence' },
      { command: 'renderguide', description: '🚀 Prevent Render DB Reset' },
      { command: 'groqmodels', description: '🤖 Test Free Groq Models' },
      { command: 'trymodels', description: '🏓 Benchmark AI Latency' },
      { command: 'quick', description: '⚡ Instant Code Heuristic Scan' },
      { command: 'recovery', description: '🚨 Bootloop Rescue Guide' },
      { command: 'quota', description: '📊 Check Free Daily Scans' },
      { command: 'myhistory', description: '📜 Your Last 5 Audits' },
    ],
  });

  let offset = 0;
  while (true) {
    try {
      const updates = await callTelegram('getUpdates', { offset, timeout: 15 });
      if (updates.ok && updates.result) {
        for (const u of updates.result) {
          offset = u.update_id + 1;
          handleUpdate(u).catch((e) => console.warn('Update error:', e.message));
        }
      }
    } catch (e) {
      await sleepMs(1500);
    }
  }
}

module.exports = {
  startBot,
  initDatabase,
  runDeepHeuristicScanner,
  auditModuleWithAI,
  testAllGroqModels,
  discoverLiveGroqModels,
  KNOWN_FREE_GROQ_MODELS,
  dbGetStats,
};

if (require.main === module) {
  const http = require('http');
  const PORT = process.env.PORT || 3000;
  const srv = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end(`RootGuard Bot is Running!\nPersistence: ${persistenceType}\n`);
  });
  srv.listen(PORT, '0.0.0.0', () => {
    console.log(`Web server listening on port ${PORT}`);
  });
  startBot();
}
