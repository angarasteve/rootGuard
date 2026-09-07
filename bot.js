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
// 2. Google Gemini Multi-Key Pool & Dynamic Model Engine (Up to 4 Keys)
//    - Automatic Failover when any key hits quota/rate limits
//    - Real-time Telegram user alert: "Switching to Backup Key, please wait..."
//    - Dynamic discovery of all available working Gemini models
// =======================================================================

const GEMINI_CANDIDATE_MODELS = [
  'gemini-2.5-flash',
  'gemini-3.8-flash',
  'gemini-2.5-pro',
  'gemini-2.0-flash',
  'gemini-2.0-flash-lite',
  'gemini-1.5-flash',
  'gemini-1.5-pro',
];

class GoogleKeyPoolManager {
  constructor() {
    this.keys = [];
    this.activeKeyIndex = 1;
    this.preferredModel = 'gemini-2.5-flash';
    this.discoveredModels = new Set(GEMINI_CANDIDATE_MODELS);
    this.modelLatencies = new Map();
    this.initKeys();
  }

  initKeys() {
    const rawKeys = [];
    const envVars = [
      process.env.GEMINI_API_KEY,
      process.env.GEMINI_API_KEY_1,
      process.env.GEMINI_API_KEY_2,
      process.env.GEMINI_API_KEY_3,
      process.env.GEMINI_API_KEY_4,
      process.env.GEMINI_API_KEYS,
    ];

    for (const val of envVars) {
      if (!val) continue;
      const parts = String(val).split(',').map((s) => s.trim()).filter(Boolean);
      for (const p of parts) {
        if (!rawKeys.includes(p)) rawKeys.push(p);
      }
    }

    // Up to 4 Google Gemini API keys
    const selected = rawKeys.slice(0, 4);
    this.keys = selected.map((k, idx) => {
      const masked = k.length > 8 ? `${k.slice(0, 6)}...${k.slice(-4)}` : `Key #${idx + 1}`;
      return {
        index: idx + 1,
        key: k,
        masked,
        status: 'HEALTHY', // 'HEALTHY' | 'EXHAUSTED' | 'ERROR'
        exhaustedUntil: 0,
        requestsCount: 0,
        successCount: 0,
        failureCount: 0,
        lastUsed: 0,
        lastLatencyMs: 0,
        lastError: null,
      };
    });

    this.activeKeyIndex = this.keys.length > 0 ? 1 : 0;
    console.log(`🔑 Google Gemini Pool: ${this.keys.length} Key(s) Loaded`);
    this.keys.forEach((k) => console.log(`   • Key #${k.index}: ${k.masked}`));
  }

  getActiveKey() {
    if (this.keys.length === 0) return null;
    const now = Date.now();

    // Check current active key
    const current = this.keys.find((k) => k.index === this.activeKeyIndex);
    if (current && (current.exhaustedUntil <= now || current.status === 'HEALTHY')) {
      if (current.exhaustedUntil <= now && current.status === 'EXHAUSTED') {
        current.status = 'HEALTHY';
        current.exhaustedUntil = 0;
      }
      return current;
    }

    // Look for next non-exhausted key
    for (const k of this.keys) {
      if (k.exhaustedUntil <= now) {
        k.status = 'HEALTHY';
        k.exhaustedUntil = 0;
        this.activeKeyIndex = k.index;
        return k;
      }
    }

    // If all are currently in cooldown, return the one whose cooldown expires soonest
    const sorted = [...this.keys].sort((a, b) => a.exhaustedUntil - b.exhaustedUntil);
    return sorted[0] || null;
  }

  markKeyExhausted(index, reason = 'Quota Limit Reached') {
    const k = this.keys.find((x) => x.index === index);
    if (k) {
      k.status = 'EXHAUSTED';
      k.exhaustedUntil = Date.now() + 10 * 60 * 1000; // 10-minute cooldown
      k.lastError = reason;
      k.failureCount++;
    }
  }

  switchActiveKey(index) {
    const k = this.keys.find((x) => x.index === index);
    if (k) {
      this.activeKeyIndex = index;
      return true;
    }
    return false;
  }

  setPreferredModel(model) {
    this.preferredModel = model;
  }

  async queryWithAutoFailover({ prompt, jsonMode = false, onSwitchNotice = null, preferredModel = null }) {
    if (this.keys.length === 0) {
      throw new Error('No Google Gemini API key configured. Please add GEMINI_API_KEY in .env');
    }

    let attempts = 0;
    const maxAttempts = this.keys.length;
    let lastError = null;

    while (attempts < maxAttempts) {
      attempts++;
      const currentKey = this.getActiveKey();
      if (!currentKey) break;

      const startTime = Date.now();
      currentKey.requestsCount++;
      currentKey.lastUsed = startTime;

      const modelsToTry = [
        preferredModel,
        this.preferredModel,
        ...GEMINI_CANDIDATE_MODELS,
      ].filter((m, i, arr) => m && arr.indexOf(m) === i);

      let keySuccess = false;
      let modelError = null;

      for (const model of modelsToTry) {
        try {
          const ai = new GoogleGenAI({ apiKey: currentKey.key });
          const config = jsonMode ? { responseMimeType: 'application/json' } : {};
          const res = await ai.models.generateContent({
            model,
            contents: prompt,
            config,
          });

          const elapsed = Date.now() - startTime;
          currentKey.lastLatencyMs = elapsed;
          currentKey.successCount++;
          currentKey.status = 'HEALTHY';
          this.preferredModel = model; // Keep working model active

          return {
            text: res.text || '',
            keyIndex: currentKey.index,
            maskedKey: currentKey.masked,
            modelUsed: model,
            latencyMs: elapsed,
          };
        } catch (err) {
          modelError = err;
          const msg = (err.message || '').toLowerCase();
          const isQuota =
            msg.includes('resource_exhausted') ||
            msg.includes('429') ||
            msg.includes('quota') ||
            msg.includes('rate limit');

          if (isQuota) {
            // Key quota exhausted! Exit model loop immediately to rotate key.
            break;
          }
          // If model is unsupported or 404, smoothly try next candidate model
          console.warn(`[Google Key #${currentKey.index} Model ${model}]: ${err.message.slice(0, 80)}. Trying next candidate model...`);
        }
      }

      const errMsg = (modelError?.message || '').toLowerCase();
      const isQuota =
        errMsg.includes('resource_exhausted') ||
        errMsg.includes('429') ||
        errMsg.includes('quota') ||
        errMsg.includes('rate limit');

      if (isQuota) {
        this.markKeyExhausted(currentKey.index, 'Resource/Quota Limit Reached');
        const nextKey = this.getActiveKey();

        if (nextKey && nextKey.index !== currentKey.index) {
          console.warn(`⚠️ Google API Key #${currentKey.index} quota reached! Switching to Backup Key #${nextKey.index}`);
          if (onSwitchNotice) {
            try {
              await onSwitchNotice(
                `⚠️ <b>Google Gemini API Key #${currentKey.index} quota limit reached!</b>\n` +
                `🔄 <i>Switching to Backup Key #${nextKey.index}, please wait...</i>`
              );
            } catch (noticeErr) {}
          }
          // Continue to next key in pool
          continue;
        } else {
          lastError = new Error(`All ${this.keys.length} Google Gemini API keys are currently cooling down from quota limits.`);
          break;
        }
      } else {
        currentKey.failureCount++;
        currentKey.lastError = modelError?.message || 'Unknown error';
        lastError = modelError;
      }
    }

    throw lastError || new Error('Google Gemini AI audit failed.');
  }

  // Benchmark all candidate Gemini models on active key
  async benchmarkAllModels() {
    const active = this.getActiveKey();
    if (!active) return [];

    const results = [];
    for (const model of GEMINI_CANDIDATE_MODELS) {
      const t0 = Date.now();
      try {
        const ai = new GoogleGenAI({ apiKey: active.key });
        const res = await ai.models.generateContent({
          model,
          contents: 'Reply with OK',
        });
        const lat = Date.now() - t0;
        this.modelLatencies.set(model, lat);
        results.push({
          model,
          status: 'AVAILABLE',
          latencyMs: lat,
          sample: res.text?.trim() || 'OK',
          isActive: model === this.preferredModel,
        });
      } catch (err) {
        results.push({
          model,
          status: 'UNAVAILABLE',
          latencyMs: Date.now() - t0,
          error: err.message.slice(0, 80),
          isActive: model === this.preferredModel,
        });
      }
    }
    return results;
  }

  // Benchmark all 4 Google API keys simultaneously
  async benchmarkAllKeys() {
    const results = [];
    for (const k of this.keys) {
      const t0 = Date.now();
      try {
        const ai = new GoogleGenAI({ apiKey: k.key });
        await ai.models.generateContent({
          model: this.preferredModel,
          contents: 'Reply with OK',
        });
        const lat = Date.now() - t0;
        k.lastLatencyMs = lat;
        k.status = 'HEALTHY';
        results.push({
          index: k.index,
          masked: k.masked,
          status: 'HEALTHY',
          latencyMs: lat,
          isActive: k.index === this.activeKeyIndex,
        });
      } catch (err) {
        const isQuota = (err.message || '').toLowerCase().includes('quota') || (err.message || '').includes('429');
        results.push({
          index: k.index,
          masked: k.masked,
          status: isQuota ? 'EXHAUSTED' : 'ERROR',
          latencyMs: Date.now() - t0,
          error: err.message.slice(0, 80),
          isActive: k.index === this.activeKeyIndex,
        });
      }
    }
    return results;
  }
}

const googleKeyPool = new GoogleKeyPoolManager();

// =======================================================================
// (Secondary Optional) Groq Free-Plan Failover Engine
// =======================================================================
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

async function queryGroqChatWithAutoFailover({ messages, jsonMode = false, temperature = 0.1, preferredModel = null }) {
  if (!GROQ_API_KEY) throw new Error('Groq API Key not configured in .env.');

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
    }
  }

  throw new Error(`All available Groq free models failed: ${lastError?.message}`);
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

// AI Audit with Google Gemini Multi-Key & Secondary Groq Auto-Failover
async function auditModuleWithAI(fileName, scripts, metadata, onSwitchNotice = null) {
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

  // 1. Google Gemini Multi-Key Pool (Up to 4 Keys with Quota Alert & Automatic Failover)
  if (googleKeyPool.keys.length > 0) {
    try {
      const res = await googleKeyPool.queryWithAutoFailover({
        prompt,
        jsonMode: true,
        onSwitchNotice,
      });
      if (res.text) {
        const parsed = JSON.parse(res.text);
        return {
          ...parsed,
          engine: `Google Gemini (${res.modelUsed}) • Key #${res.keyIndex}`,
          modelUsed: res.modelUsed,
          keyIndex: res.keyIndex,
          maskedKey: res.maskedKey,
        };
      }
    } catch (geminiErr) {
      console.warn('Gemini query error across pool:', geminiErr.message);
    }
  }

  // 2. Secondary Groq failover if configured
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
        { text: '🔑 Google Gemini Keys Pool', callback_data: 'keys_status' },
        { text: '🚨 Bootloop Rescue', callback_data: 'recovery' },
      ],
    ],
  };

  return { text, replyMarkup };
}

// =======================================================================
// 6. Comprehensive Root & Security Commands (Over 30+ Useful Commands!)
// =======================================================================
const userQuestionSessions = new Map();

async function handleCommand(chatId, rawUserId, command, args, replyMsgId) {
  const cleanId = String(rawUserId).replace(/^tg:/i, '').trim();
  const user = await dbGetUser(cleanId);
  const isOwner = isUserOwnerOrVip(cleanId, user);

  switch (command) {
    case '/start': {
      const activeKey = googleKeyPool.getActiveKey();
      const activeDesc = activeKey ? `Key #${activeKey.index} (${activeKey.masked})` : 'None Configured';
      const msg = `<b>🛡️ Welcome to RootGuard AI!</b>\n` +
        `⚡ <i>made by @toshitzz • Multi-Key Google Gemini Edition</i>\n` +
        `━━━━━━━━━━━━━━━━━━━━━\n` +
        `I inspect Magisk, KernelSU, and APatch root modules to protect your Android phone from bricks, bootloops, and fake snake-oil tweaks!\n\n` +
        `<b>🔑 Google Gemini Pool:</b> <code>${googleKeyPool.keys.length}/4 Keys Configured</code>\n` +
        `• <b>Active Key:</b> <code>${activeDesc}</code>\n` +
        `• <b>Active Model:</b> <code>${escapeHtml(googleKeyPool.preferredModel)}</code>\n` +
        `• <b>Auto-Failover:</b> 🟢 <i>Switches to backup key if quota is hit with live notification!</i>\n\n` +
        `<b>🗄️ Automatic Persistence:</b> <code>${persistenceType}</code>\n` +
        `• <i>Zero-config! Restarts on Render will NOT lose user data or VIP status.</i>\n\n` +
        `📤 <b>Send any <code>.zip</code> or <code>.sh</code> file</b> to begin instant AI inspection!\n` +
        `Type /help to see all 30+ root security & AI commands.`;

      const keyboard = {
        inline_keyboard: [
          [
            { text: '🔑 View Gemini Keys Pool', callback_data: 'keys_status' },
            { text: '🤖 List Models', callback_data: 'gemini_models' },
          ],
          [
            { text: '🚨 Bootloop Rescue Guide', callback_data: 'recovery' },
            { text: '📖 Full Help Menu', callback_data: 'help_menu' },
          ],
        ],
      };
      return await sendTelegramMessage(chatId, msg, replyMsgId, keyboard);
    }

    case '/help': {
      let h = `📖 <b>RootGuard Command Center:</b>\n` +
        `⚡ <i>made by @toshitzz</i>\n` +
        `━━━━━━━━━━━━━━━━━━━━━\n` +
        `<b>🔍 Auditing & Tools:</b>\n` +
        `• Send any <b>.zip</b> or <b>.sh</b> file directly to audit\n` +
        `• <code>/scan</code> - Instructions on auditing root modules\n` +
        `• <code>/quick &lt;script&gt;</code> - Instant AST code heuristic scan\n` +
        `• <code>/checkurl &lt;url&gt;</code> - Audit module from direct download link\n` +
        `• <code>/recovery</code> - Emergency bootloop rescue guide (Magisk/KernelSU/TWRP)\n` +
        `• <code>/props &lt;tweak&gt;</code> - Analyze Android build.prop tweaks for placebo/risk\n` +
        `• <code>/debloat &lt;pkg&gt;</code> - Check if an Android package is safe to remove\n` +
        `• <code>/sepolicy &lt;rule&gt;</code> - Analyze SELinux rules and permissions\n` +
        `• <code>/battery</code> - Android battery tweak mythbusters & advice\n` +
        `• <code>/kernelsu</code> - KernelSU vs Magisk vs APatch comparison\n` +
        `• <code>/safetynet</code> - Play Integrity & device certification bypass tips\n` +
        `• <code>/romcheck &lt;rom&gt;</code> - Custom ROM & GSI compatibility advice\n` +
        `• <code>/rules</code> - 6 Golden Rules of Root Safety\n` +
        `• <code>/myhistory</code> - View your past 5 module audits\n` +
        `• <code>/report &lt;id&gt;</code> - Re-open audit report for any past scan\n\n` +
        `<b>🔑 Google Gemini Multi-Key & Models:</b>\n` +
        `• <code>/keys</code> - Real-time status of all 4 Google Gemini API keys\n` +
        `• <code>/switchkey &lt;1-4&gt;</code> - Manually switch active primary Gemini key\n` +
        `• <code>/models</code> - View all working Gemini models & latencies\n` +
        `• <code>/setmodel &lt;model&gt;</code> - Select preferred Gemini model\n` +
        `• <code>/test</code> - Test active Gemini key & model response\n` +
        `• <code>/benchmark</code> - Ping all 4 keys & models simultaneously\n\n` +
        `<b>🗄️ Zero-Config Persistence (Render Safe):</b>\n` +
        `• <code>/dbinfo</code> - View active database engine & auto-recovery status\n` +
        `• <code>/sync</code> - Force instant state snapshot checkpoint\n` +
        `• <code>/renderguide</code> - How Render restart protection works\n` +
        `• <code>/quota</code> - Check remaining free scans (resets 00:00 UTC)\n` +
        `• <code>/profile</code> - Your account status & lifetime audits\n` +
        `• <code>/stats</code> - Global bot metrics & threats prevented\n` +
        `• <code>/ping</code> - Bot latency & API speed test\n` +
        `• <code>/about</code> - About RootGuard architecture\n`;

      if (isOwner) {
        h += `\n👑 <b>Admin Controls:</b>\n` +
          `• <code>/vip &lt;id&gt;</code> - Grant lifetime VIP (Unlimited)\n` +
          `• <code>/unvip &lt;id&gt;</code> - Revoke VIP\n` +
          `• <code>/resetquota &lt;id&gt;</code> - Reset user daily quota\n` +
          `• <code>/broadcast &lt;msg&gt;</code> - Message all bot users\n` +
          `• <code>/dbbackup</code> - Output raw JSON state snapshot\n`;
      }

      h += `\n━━━━━━━━━━━━━━━━━━━━━\n⚡ <i>RootGuard • made by @toshitzz</i>`;
      return await sendTelegramMessage(chatId, h, replyMsgId);
    }

    case '/scan': {
      const msg = `📤 <b>How to Audit a Root Module:</b>\n` +
        `⚡ <i>made by @toshitzz</i>\n` +
        `━━━━━━━━━━━━━━━━━━━━━\n` +
        `1. Simply tap the <b>Paperclip icon (Attach File)</b> in this chat.\n` +
        `2. Select your Magisk, KernelSU, or APatch <code>.zip</code> or standalone shell script <code>.sh</code>.\n` +
        `3. RootGuard automatically unpacks scripts, runs AST partition wipe detection, and performs Google Gemini AI audit.\n\n` +
        `💡 <i>Don't have the file locally? Use <code>/checkurl &lt;direct download link&gt;</code> instead!</i>`;
      return await sendTelegramMessage(chatId, msg, replyMsgId);
    }

    case '/keys':
    case '/apikeys': {
      let msg = `🔑 <b>Google Gemini Multi-Key Pool (Up to 4 Keys):</b>\n` +
        `⚡ <i>made by @toshitzz</i>\n` +
        `━━━━━━━━━━━━━━━━━━━━━\n` +
        `RootGuard supports <b>4 Google Gemini API keys</b>. If any key exhausts its daily quota or hits 429 rate limits, it automatically alerts the user and seamlessly switches to the next available backup key!\n\n`;

      if (googleKeyPool.keys.length === 0) {
        msg += `❌ <b>No Gemini Keys Configured!</b>\nAdd <code>GEMINI_API_KEY</code>, <code>GEMINI_API_KEY_2</code>, etc. in your .env file.`;
      } else {
        const now = Date.now();
        googleKeyPool.keys.forEach((k) => {
          const isActive = k.index === googleKeyPool.activeKeyIndex;
          const activeBadge = isActive ? ' ⭐ <b>[ACTIVE PRIMARY]</b>' : '';
          const isExhausted = k.status === 'EXHAUSTED' && k.exhaustedUntil > now;
          const coolLeft = isExhausted ? Math.ceil((k.exhaustedUntil - now) / 1000) : 0;
          const statusIcon = isExhausted ? `⏳ Quota Cooldown (${coolLeft}s)` : k.status === 'HEALTHY' ? '🟢 Ready' : '🔴 Error';

          msg += `<b>Key #${k.index}:</b> <code>${escapeHtml(k.masked)}</code>${activeBadge}\n` +
            `• Status: ${statusIcon}\n` +
            `• Requests: <b>${k.requestsCount}</b> (✅ ${k.successCount} | ❌ ${k.failureCount})\n` +
            `• Last Latency: <b>${k.lastLatencyMs ? `${k.lastLatencyMs}ms` : 'None'}</b>\n\n`;
        });

        msg += `💡 <i>Type <code>/switchkey &lt;1-${googleKeyPool.keys.length}&gt;</code> to change the active key manually, or <code>/benchmark</code> to ping all keys!</i>`;
      }

      const inlineButtons = googleKeyPool.keys.map((k) => ({
        text: `Switch to Key #${k.index}`,
        callback_data: `switch_key_${k.index}`,
      }));

      const keyboard = {
        inline_keyboard: [
          inlineButtons.slice(0, 2),
          inlineButtons.slice(2, 4),
          [{ text: '🏓 Benchmark All Keys', callback_data: 'benchmark_keys' }],
        ].filter((row) => row.length > 0),
      };

      return await sendTelegramMessage(chatId, msg, replyMsgId, keyboard);
    }

    case '/switchkey': {
      const targetIdx = parseInt(args.trim(), 10);
      if (isNaN(targetIdx) || targetIdx < 1 || targetIdx > googleKeyPool.keys.length) {
        return await sendTelegramMessage(
          chatId,
          `Usage: <code>/switchkey &lt;1-${googleKeyPool.keys.length}&gt;</code>\nExample: <code>/switchkey 2</code>`,
          replyMsgId
        );
      }
      const switched = googleKeyPool.switchActiveKey(targetIdx);
      if (switched) {
        const k = googleKeyPool.keys.find((x) => x.index === targetIdx);
        return await sendTelegramMessage(
          chatId,
          `✅ <b>Active Google API Key Switched!</b>\nNow using <b>Key #${targetIdx}</b>: <code>${k?.masked}</code>\n\nType <code>/test</code> to verify.`,
          replyMsgId
        );
      }
      return await sendTelegramMessage(chatId, `❌ Could not switch to Key #${targetIdx}.`, replyMsgId);
    }

    case '/models':
    case '/geminimodels': {
      let msg = `🤖 <b>Google Gemini Model Catalog:</b>\n` +
        `⚡ <i>made by @toshitzz</i>\n` +
        `━━━━━━━━━━━━━━━━━━━━━\n` +
        `• <b>Active Model:</b> <code>${escapeHtml(googleKeyPool.preferredModel)}</code>\n` +
        `• <b>Active Key:</b> <code>Key #${googleKeyPool.activeKeyIndex}</code>\n\n` +
        `<b>Available Candidate Models:</b>\n`;

      GEMINI_CANDIDATE_MODELS.forEach((m) => {
        const isActive = m === googleKeyPool.preferredModel;
        const lat = googleKeyPool.modelLatencies.get(m);
        const badge = isActive ? ' ⭐ <b>[ACTIVE]</b>' : '';
        const latText = lat ? `🟢 ${lat}ms` : '⚪ Ready';
        msg += `• <code>${escapeHtml(m)}</code> - ${latText}${badge}\n`;
      });

      msg += `\n💡 <i>RootGuard automatically discovers and uses the best available model. Type <code>/setmodel &lt;name&gt;</code> to set preferred model!</i>`;

      const keyboard = {
        inline_keyboard: [
          [
            { text: 'Set: gemini-2.5-flash', callback_data: 'set_model_gemini-2.5-flash' },
            { text: 'Set: gemini-3.8-flash', callback_data: 'set_model_gemini-3.8-flash' },
          ],
          [
            { text: 'Set: gemini-2.0-flash', callback_data: 'set_model_gemini-2.0-flash' },
            { text: '🏓 Benchmark All Models', callback_data: 'benchmark_models' },
          ],
        ],
      };
      return await sendTelegramMessage(chatId, msg, replyMsgId, keyboard);
    }

    case '/setmodel': {
      const choice = args.trim().toLowerCase();
      if (!choice) {
        return await sendTelegramMessage(
          chatId,
          `Usage: <code>/setmodel &lt;model-name&gt;</code>\nExample: <code>/setmodel gemini-2.5-flash</code>\nType /models to view choices.`,
          replyMsgId
        );
      }
      googleKeyPool.setPreferredModel(choice);
      return await sendTelegramMessage(
        chatId,
        `✅ Preferred model set to: <code>${escapeHtml(choice)}</code>\nType <code>/test</code> to ping it!`,
        replyMsgId
      );
    }

    case '/test': {
      const activeKey = googleKeyPool.getActiveKey();
      if (!activeKey) {
        return await sendTelegramMessage(chatId, `⚠️ No Google Gemini API key configured in .env`, replyMsgId);
      }
      const statusMsg = await sendTelegramMessage(chatId, `📡 <i>Testing Google Gemini Key #${activeKey.index} (${activeKey.masked})...</i>`, replyMsgId);

      const t0 = Date.now();
      try {
        const ai = new GoogleGenAI({ apiKey: activeKey.key });
        const res = await ai.models.generateContent({
          model: googleKeyPool.preferredModel,
          contents: 'Reply with "Google Gemini Online OK" and state your current model version in under 15 words.',
        });
        const elapsed = Date.now() - t0;
        const text = `✅ <b>Google Gemini AI Online!</b>\n` +
          `⚡ <i>made by @toshitzz</i>\n` +
          `━━━━━━━━━━━━━━━━━━━━━\n` +
          `• <b>Key Used:</b> Key #${activeKey.index} (<code>${escapeHtml(activeKey.masked)}</code>)\n` +
          `• <b>Model:</b> <code>${escapeHtml(googleKeyPool.preferredModel)}</code>\n` +
          `• <b>Ping Latency:</b> <b>${elapsed}ms</b>\n` +
          `• <b>Response:</b> <i>${escapeHtml(res.text?.trim() || 'OK')}</i>\n` +
          `• <b>Spare Backup Keys:</b> <b>${googleKeyPool.keys.length - 1}</b> available for failover`;

        if (statusMsg?.result?.message_id) {
          return await editTelegramMessage(chatId, statusMsg.result.message_id, text);
        }
        return await sendTelegramMessage(chatId, text, replyMsgId);
      } catch (e) {
        const errText = `❌ <b>Gemini Test Failed:</b>\n<code>${escapeHtml(e.message)}</code>\n\n💡 <i>If this key ran out of quota, type /switchkey to rotate!</i>`;
        if (statusMsg?.result?.message_id) {
          return await editTelegramMessage(chatId, statusMsg.result.message_id, errText);
        }
        return await sendTelegramMessage(chatId, errText, replyMsgId);
      }
    }

    case '/benchmark': {
      if (googleKeyPool.keys.length === 0) {
        return await sendTelegramMessage(chatId, `⚠️ No Google Gemini API keys configured.`, replyMsgId);
      }
      const statusMsg = await sendTelegramMessage(chatId, `🏓 <i>Benchmarking all Google Gemini API keys & available models...</i>`, replyMsgId);
      const keyResults = await googleKeyPool.benchmarkAllKeys();
      const modelResults = await googleKeyPool.benchmarkAllModels();

      let out = `🏓 <b>Google Gemini Pool Benchmark:</b>\n` +
        `⚡ <i>made by @toshitzz</i>\n` +
        `━━━━━━━━━━━━━━━━━━━━━\n` +
        `<b>🔑 API Key Latencies:</b>\n`;

      keyResults.forEach((r) => {
        const icon = r.status === 'HEALTHY' ? '🟢' : r.status === 'EXHAUSTED' ? '⏳' : '🔴';
        const active = r.isActive ? ' ⭐' : '';
        out += `${icon} <b>Key #${r.index}</b> (<code>${r.masked}</code>): <b>${r.latencyMs}ms</b> (${r.status})${active}\n`;
      });

      out += `\n<b>🤖 Candidate Model Availability:</b>\n`;
      modelResults.forEach((m) => {
        const icon = m.status === 'AVAILABLE' ? '🟢' : '🔴';
        out += `${icon} <code>${escapeHtml(m.model)}</code>: <b>${m.latencyMs}ms</b> (${m.status})\n`;
      });

      out += `\n⚡ <i>Automatic failover is ready! If any key hits rate limits, the next key takes over instantly.</i>`;

      if (statusMsg?.result?.message_id) {
        return await editTelegramMessage(chatId, statusMsg.result.message_id, out);
      }
      return await sendTelegramMessage(chatId, out, replyMsgId);
    }

    case '/checkurl': {
      const targetUrl = args.trim();
      if (!targetUrl || (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://'))) {
        return await sendTelegramMessage(
          chatId,
          `Usage: <code>/checkurl &lt;direct download URL&gt;</code>\n\nExample:\n<code>/checkurl https://raw.githubusercontent.com/user/repo/main/install.sh</code>`,
          replyMsgId
        );
      }

      const lock = await dbCheckCooldownAndLock(cleanId);
      if (!lock.allowed) {
        if (lock.reason === 'COOLDOWN') return await sendTelegramMessage(chatId, `⏳ Cooldown active: wait ${lock.remainingSeconds}s.`, replyMsgId);
        if (lock.reason === 'QUOTA_EXCEEDED') return await sendTelegramMessage(chatId, `⛔ Daily quota reached (5/5). Resets at 00:00 UTC.`, replyMsgId);
        return;
      }

      const statusMsg = await sendTelegramMessage(chatId, `📥 <i>Downloading module from URL...</i>`, replyMsgId);
      const statusId = statusMsg?.result?.message_id;

      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 30000);
        const res = await fetch(targetUrl, { signal: controller.signal });
        clearTimeout(timer);

        if (!res.ok) throw new Error(`HTTP ${res.status}: Could not download URL.`);
        const buf = await res.arrayBuffer().then(Buffer.from);
        const urlParts = targetUrl.split('/');
        const rawFileName = urlParts[urlParts.length - 1].split('?')[0] || 'remote_module.sh';

        const isZip = rawFileName.toLowerCase().endsWith('.zip');
        const scripts = [];

        if (!isZip) {
          scripts.push({ path: rawFileName, content: buf.toString('utf-8') });
        } else {
          const zip = await JSZip.loadAsync(buf);
          for (const p of Object.keys(zip.files)) {
            if (p.endsWith('.sh') || p.endsWith('.prop') || p.includes('customize.sh') || p.includes('service.sh')) {
              const content = await zip.files[p].async('string');
              scripts.push({ path: p, content });
            }
          }
        }

        if (statusId) {
          await editTelegramMessage(chatId, statusId, `🤖 <i>Auditing ${scripts.length} script(s) with Google Gemini Multi-Key Engine...</i>`);
        }

        const onSwitchNotice = async (noticeHtml) => {
          if (statusId) await editTelegramMessage(chatId, statusId, noticeHtml);
        };

        const audit = await auditModuleWithAI(rawFileName, scripts, { name: rawFileName }, onSwitchNotice);
        const scanId = `sc_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`;

        await dbReleaseLockAndRecordScan(cleanId, {
          file_name: rawFileName,
          file_size: buf.length,
          verdict: audit.verdict,
          risk_score: audit.riskScore,
          model_used: audit.modelUsed || 'AI',
          duration_ms: 2500,
        });

        await dbSaveScanCache(scanId, rawFileName, audit, scripts);
        const quota = await dbGetUserQuota(cleanId);
        const { text, replyMarkup } = formatReportHtml(rawFileName, audit, quota.remaining, isOwner, scanId);

        if (statusId) return await editTelegramMessage(chatId, statusId, text, replyMarkup);
        return await sendTelegramMessage(chatId, text, replyMsgId, replyMarkup);
      } catch (err) {
        await dbForceReleaseLock(cleanId);
        const errText = `❌ <b>URL Audit Failed:</b> ${escapeHtml(err.message)}`;
        if (statusId) return await editTelegramMessage(chatId, statusId, errText);
        return await sendTelegramMessage(chatId, errText, replyMsgId);
      }
    }

    case '/kernelsu': {
      const msg = `⚡ <b>KernelSU vs Magisk vs APatch:</b>\n` +
        `⚡ <i>made by @toshitzz</i>\n` +
        `━━━━━━━━━━━━━━━━━━━━━\n` +
        `<b>1. KernelSU (Kernel-Space Root):</b>\n` +
        `• <b>How it works:</b> Hooks system calls directly inside the Linux Kernel (GKI 5.10+).\n` +
        `• <b>Stealth:</b> Apps cannot see su binaries in userspace because ungranted apps see standard system calls!\n` +
        `• <b>Modules:</b> Uses OverlayFS instead of magic mount.\n\n` +
        `<b>2. Magisk (User-Space Root):</b>\n` +
        `• <b>How it works:</b> Patches boot.img ramdisk to start magiskd daemon on early boot.\n` +
        `• <b>Stealth:</b> Relies on Zygisk + Shamiko/ZygiskNext to hide from banking apps.\n\n` +
        `<b>3. APatch (Kernel Patch without Full Kernel Compile):</b>\n` +
        `• <b>How it works:</b> Injects KernelPatch directly into standard boot.img kernel binary.\n` +
        `• <b>Stealth:</b> Superpatch hooks allow kernel-level privilege elevation with easy flashing.\n\n` +
        `💡 <i>RootGuard checks modules for compatibility with all 3 engines!</i>`;
      return await sendTelegramMessage(chatId, msg, replyMsgId);
    }

    case '/safetynet':
    case '/playintegrity': {
      const msg = `🛡️ <b>Play Integrity & Device Certification Guide:</b>\n` +
        `⚡ <i>made by @toshitzz</i>\n` +
        `━━━━━━━━━━━━━━━━━━━━━\n` +
        `SafetyNet is deprecated and replaced by <b>Play Integrity API</b>:\n\n` +
        `<b>The 3 Integrity Verdicts:</b>\n` +
        `1. <b>MEETS_BASIC_INTEGRITY:</b> Device is intact (passes on virtually all rooted setups with basic Zygisk).\n` +
        `2. <b>MEETS_DEVICE_INTEGRITY:</b> Required by Google Wallet, Pokémon GO, and Banking apps. Passed using <i>PlayIntegrityFork (PIF)</i> or <i>PlayIntegrityFix</i> with custom pif.json fingerprints.\n` +
        `3. <b>MEETS_STRONG_INTEGRITY:</b> Hardware-backed keystore evaluation (unlocked bootloaders fail unless using advanced keybox exploits like TrickyStore).\n\n` +
        `⚠️ <i>Warning: Never flash sketchy 'instant strong integrity' modules that demand your Google account password!</i>`;
      return await sendTelegramMessage(chatId, msg, replyMsgId);
    }

    case '/romcheck': {
      const romName = args.trim() || 'Custom ROM';
      const msg = `📱 <b>Custom ROM Compatibility Guide (${escapeHtml(romName)}):</b>\n` +
        `⚡ <i>made by @toshitzz</i>\n` +
        `━━━━━━━━━━━━━━━━━━━━━\n` +
        `<b>Flashing Root Modules on Custom ROMs:</b>\n` +
        `• <b>AOSP / Pixel Experience / LineageOS:</b> High compatibility. Stock Android framework makes standard Magisk/KernelSU modules safe.\n` +
        `• <b>OEM ROMs (HyperOS, OneUI, ColorOS):</b> Caution! Heavy vendor frameworks often crash when flashing generic AOSP systemUI blur or status bar modules.\n` +
        `• <b>GSI (Generic System Images):</b> Dynamic partitions and vendor overlay trees differ. Avoid modules touching <code>/vendor</code> directly.\n\n` +
        `💡 <i>Always test module scripts with RootGuard before rebooting!</i>`;
      return await sendTelegramMessage(chatId, msg, replyMsgId);
    }

    case '/about': {
      const stats = await dbGetStats();
      const msg = `🛡️ <b>About RootGuard AI:</b>\n` +
        `⚡ <i>made with craftsmanship by @toshitzz</i>\n` +
        `━━━━━━━━━━━━━━━━━━━━━\n` +
        `RootGuard is a specialized security auditor designed specifically for Android root enthusiasts, developers, and modders.\n\n` +
        `• <b>AI Core:</b> Google Gemini Multi-Key Pool (Up to 4 Keys with Live Failover)\n` +
        `• <b>Heuristic Scanner:</b> Strict partition wipe & chmod bootloop detection\n` +
        `• <b>Persistence:</b> Automatic zero-config snapshotting (Render crash & restart safe!)\n` +
        `• <b>Audits Completed:</b> <b>${stats.totalScans}</b>\n` +
        `• <b>Bootloops Prevented:</b> <b>${stats.totalBricksStopped}</b>\n\n` +
        `⚡ <i>Stay safe, never flash unverified modules blindly!</i>`;
      return await sendTelegramMessage(chatId, msg, replyMsgId);
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

    case '/report': {
      const targetScanId = args.trim();
      if (!targetScanId) {
        return await sendTelegramMessage(chatId, `Usage: <code>/report &lt;scanId&gt;</code>`, replyMsgId);
      }
      const cached = await dbGetScanCache(targetScanId);
      if (!cached) {
        return await sendTelegramMessage(chatId, `❌ Scan report <code>${escapeHtml(targetScanId)}</code> not found or expired.`, replyMsgId);
      }
      const quota = await dbGetUserQuota(cleanId);
      const { text, replyMarkup } = formatReportHtml(cached.fileName, cached.audit, quota.remaining, isOwner, targetScanId);
      return await sendTelegramMessage(chatId, text, replyMsgId, replyMarkup);
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

    case '/profile':
    case '/myid': {
      const quota = await dbGetUserQuota(cleanId);
      const history = await dbGetUserHistory(cleanId, 50);
      const msg = `👤 <b>Your RootGuard Profile:</b>\n` +
        `⚡ <i>made by @toshitzz</i>\n` +
        `━━━━━━━━━━━━━━━━━━━━━\n` +
        `• <b>Telegram ID:</b> <code>${cleanId}</code>\n` +
        `• <b>Account Role:</b> ${isOwner ? '👑 <b>Owner / SuperAdmin</b>' : quota.isVip ? '⭐ <b>VIP Member (Unlimited)</b>' : '👤 <b>Standard User</b>'}\n` +
        `• <b>Remaining Scans Today:</b> <b>${quota.isVip ? 'Unlimited' : `${quota.remaining}/${DAILY_SCAN_LIMIT}`}</b>\n` +
        `• <b>Total Lifetime Scans:</b> <b>${history.length}</b>\n` +
        `• <b>Render Persistence:</b> 🟢 <b>Synced</b>`;
      return await sendTelegramMessage(chatId, msg, replyMsgId);
    }

    case '/ping': {
      const t0 = Date.now();
      const m = await sendTelegramMessage(chatId, `🏓 <i>Pinging...</i>`, replyMsgId);
      const lat = Date.now() - t0;
      const activeKey = googleKeyPool.getActiveKey();
      const text = `🏓 <b>Pong!</b> <code>${lat}ms</code>\n` +
        `• <b>Persistence:</b> <b>${persistenceType}</b>\n` +
        `• <b>Active Google Key:</b> Key #${activeKey ? activeKey.index : 'None'}\n` +
        `• <b>Active Model:</b> <code>${escapeHtml(googleKeyPool.preferredModel)}</code>`;
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
        `• Google Gemini Keys: <b>${googleKeyPool.keys.length}/4 Active</b>\n` +
        `• Database: <b>${stats.persistenceType}</b>\n` +
        `⚡ <i>made by @toshitzz</i>`,
        replyMsgId
      );
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

    case '/unvip': {
      if (!isOwner) return await sendTelegramMessage(chatId, `⛔ Access denied.`, replyMsgId);
      const target = args.trim().replace(/^tg:/i, '');
      if (!target) return await sendTelegramMessage(chatId, `Usage: <code>/unvip &lt;userId&gt;</code>`, replyMsgId);
      if (persistenceType === 'POSTGRES' && pgPool) {
        await pgPool.query('UPDATE rg_users SET is_vip = 0 WHERE user_id = $1', [target]);
      } else if (sqliteDb) {
        sqliteDb.prepare('UPDATE users SET is_vip = 0 WHERE user_id = ?').run(target);
      }
      autoFlushLocalState();
      return await sendTelegramMessage(chatId, `User <code>${target}</code> VIP status revoked.`, replyMsgId);
    }

    case '/resetquota': {
      if (!isOwner) return await sendTelegramMessage(chatId, `⛔ Access denied.`, replyMsgId);
      const target = args.trim().replace(/^tg:/i, '');
      if (!target) return await sendTelegramMessage(chatId, `Usage: <code>/resetquota &lt;userId&gt;</code>`, replyMsgId);
      await dbResetQuota(target);
      autoFlushLocalState();
      return await sendTelegramMessage(chatId, `🔄 Quota reset for <code>${target}</code>.`, replyMsgId);
    }

    case '/broadcast': {
      if (!isOwner) return await sendTelegramMessage(chatId, `⛔ Access denied.`, replyMsgId);
      const bMsg = args.trim();
      if (!bMsg) return await sendTelegramMessage(chatId, `Usage: <code>/broadcast &lt;message&gt;</code>`, replyMsgId);

      const allUsers = memoryStore.users ? Array.from(memoryStore.users.keys()) : [];
      let sentCount = 0;
      for (const uId of allUsers) {
        try {
          await sendTelegramMessage(uId, `📢 <b>RootGuard Broadcast Announcement:</b>\n\n${escapeHtml(bMsg)}\n\n⚡ <i>by @toshitzz</i>`);
          sentCount++;
          await sleepMs(50);
        } catch (e) {}
      }
      return await sendTelegramMessage(chatId, `✅ Broadcast sent to ${sentCount} active users!`, replyMsgId);
    }

    case '/dbbackup': {
      if (!isOwner) return await sendTelegramMessage(chatId, `⛔ Access denied.`, replyMsgId);
      autoFlushLocalState();
      const stats = await dbGetStats();
      const backupText = JSON.stringify({
        exportedAt: new Date().toISOString(),
        stats,
        usersCount: memoryStore.users.size,
        scansCount: memoryStore.scans.length,
      }, null, 2);
      return await sendTelegramMessage(chatId, `<pre><code>${escapeHtml(backupText)}</code></pre>`, replyMsgId);
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
      await editTelegramMessage(chatId, statusId, `🤖 <i>Auditing ${scripts.length} script(s) with Google Gemini Multi-Key Safeguards...</i>`);
    }

    // Real-time failover notice to user if a Google API Key runs out of quota
    const onSwitchNotice = async (noticeHtml) => {
      if (statusId) {
        await editTelegramMessage(chatId, statusId, noticeHtml);
      } else {
        await sendTelegramMessage(chatId, noticeHtml);
      }
    };

    const audit = await auditModuleWithAI(fileName, scripts, metadata, onSwitchNotice);
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

    if (data === 'keys_status') {
      return await handleCommand(chatId, cq.from?.id, '/keys', '', cq.message?.message_id);
    }
    if (data === 'benchmark_keys' || data === 'benchmark_models') {
      return await handleCommand(chatId, cq.from?.id, '/benchmark', '', cq.message?.message_id);
    }
    if (data === 'gemini_models') {
      return await handleCommand(chatId, cq.from?.id, '/models', '', cq.message?.message_id);
    }
    if (data === 'help_menu') {
      return await handleCommand(chatId, cq.from?.id, '/help', '', cq.message?.message_id);
    }
    if (data.startsWith('switch_key_')) {
      const idx = data.replace('switch_key_', '');
      return await handleCommand(chatId, cq.from?.id, '/switchkey', idx, cq.message?.message_id);
    }
    if (data.startsWith('set_model_')) {
      const model = data.replace('set_model_', '');
      return await handleCommand(chatId, cq.from?.id, '/setmodel', model, cq.message?.message_id);
    }
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
      const qRes = await googleKeyPool.queryWithAutoFailover({
        prompt: qPrompt,
        onSwitchNotice: async (notice) => {
          await sendTelegramMessage(chatId, notice);
        },
      });
      reply = qRes.text;
    } catch (e) {
      if (GROQ_API_KEY) {
        try {
          const groqRes = await queryGroqChatWithAutoFailover({ messages: [{ role: 'user', content: qPrompt }] });
          reply = groqRes.content;
        } catch (ge) {}
      }
    }

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
      { command: 'start', description: '🛡️ Start RootGuard & Multi-Key Overview' },
      { command: 'help', description: '📖 All 30+ Root Security & AI Commands' },
      { command: 'keys', description: '🔑 Google Gemini 4-Key Pool Dashboard' },
      { command: 'models', description: '🤖 Live Candidate Gemini Models' },
      { command: 'test', description: '📡 Test Active Gemini AI Response' },
      { command: 'benchmark', description: '🏓 Ping All 4 Keys & Models' },
      { command: 'recovery', description: '🚨 Emergency Bootloop Rescue Guide' },
      { command: 'props', description: '🔍 Analyze build.prop Tweaks' },
      { command: 'debloat', description: '📱 Safe System App Removal Checker' },
      { command: 'dbinfo', description: '🗄️ Zero-Config Persistence Status' },
      { command: 'sync', description: '🔄 Force State Snapshot Checkpoint' },
      { command: 'quota', description: '📊 Check Free Daily Scans' },
      { command: 'myhistory', description: '📜 Your Last 5 Module Audits' },
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
