import fs from "fs";
import path from "path";
import sqlite3 from "sqlite3";
import bcrypt from "bcryptjs";

const dataDir = path.resolve(process.cwd(), "data");
const dbPath = path.join(dataDir, "database.sqlite");

if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const db = new sqlite3.Database(dbPath);
db.configure("busyTimeout", 5000);

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const withBusyRetry = async (executor, retries = 5) => {
  for (let attempt = 0; attempt <= retries; attempt += 1) {
    try {
      return await executor();
    } catch (error) {
      const isBusy = String(error?.message || "").includes("SQLITE_BUSY");
      if (!isBusy || attempt === retries) throw error;
      await sleep(150 * (attempt + 1));
    }
  }
  throw new Error("Unreachable retry branch");
};

const run = (sql, params = []) =>
  withBusyRetry(
    () =>
      new Promise((resolve, reject) => {
        db.run(sql, params, function onRun(err) {
          if (err) reject(err);
          else resolve(this);
        });
      }),
    6,
  );

const get = (sql, params = []) =>
  withBusyRetry(
    () =>
      new Promise((resolve, reject) => {
        db.get(sql, params, (err, row) => {
          if (err) reject(err);
          else resolve(row);
        });
      }),
    6,
  );

const all = (sql, params = []) =>
  withBusyRetry(
    () =>
      new Promise((resolve, reject) => {
        db.all(sql, params, (err, rows) => {
          if (err) reject(err);
          else resolve(rows);
        });
      }),
    6,
  );

const ensureColumn = async (tableName, columnName, definition) => {
  const columns = await all(`PRAGMA table_info(${tableName})`);
  const hasColumn = columns.some((column) => column.name === columnName);
  if (!hasColumn) {
    await run(`ALTER TABLE ${tableName} ADD COLUMN ${columnName} ${definition}`);
  }
};

const initDb = async () => {
  await run(`PRAGMA journal_mode = WAL;`);
  await run(`
    CREATE TABLE IF NOT EXISTS admin_users (
      id TEXT PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS records (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      category TEXT NOT NULL,
      holder TEXT NOT NULL,
      location TEXT,
      date TEXT,
      image TEXT,
      featured INTEGER NOT NULL DEFAULT 0
    );
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS applications (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      category TEXT,
      date TEXT,
      holder TEXT NOT NULL,
      location TEXT,
      status TEXT NOT NULL DEFAULT 'pending',
      image TEXT,
      submitteremail TEXT,
      created_at TEXT NOT NULL
    );
  `);
  await ensureColumn("applications", "submitteremail", "TEXT");
  await ensureColumn("applications", "video", "TEXT");
  await ensureColumn("applications", "rejection_reason", "TEXT");
  await ensureColumn("applications", "reviewed_at", "TEXT");

  await run(`
    CREATE TABLE IF NOT EXISTS issues (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      pdf_url TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'archive',
      updated_at TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS page_content (
      path TEXT PRIMARY KEY,
      html TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
  `);

  const adminEmail = process.env.ADMIN_EMAIL || "admin@example.com";
  const adminPassword = process.env.ADMIN_PASSWORD || "admin12345";
  const existingAdmin = await get(`SELECT id FROM admin_users WHERE email = ?`, [adminEmail]);

  if (!existingAdmin) {
    const passwordHash = await bcrypt.hash(adminPassword, 10);
    await run(
      `INSERT INTO admin_users (id, email, password_hash, created_at) VALUES (?, ?, ?, ?)`,
      [crypto.randomUUID(), adminEmail, passwordHash, new Date().toISOString()],
    );
    // eslint-disable-next-line no-console
    console.log(`[sqlite] Admin user created: ${adminEmail}`);
  }
};

export { db, dbPath, run, get, all, initDb };
