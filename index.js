import "dotenv/config";
import fs from "fs";
import path from "path";
import express from "express";
import cors from "cors";
import multer from "multer";
import bcrypt from "bcryptjs";
import nodemailer from "nodemailer";
import { all, get, initDb, run } from "./db.js";
import { createToken, parseToken, requireAuth } from "./auth.js";

const app = express();
const PORT = Number(process.env.PORT || 3001);
const maxImageUploadMb = Number(process.env.MAX_IMAGE_UPLOAD_MB || 10);
const maxVideoUploadMb = Number(process.env.MAX_VIDEO_UPLOAD_MB || 250);
const maxPdfUploadMb = Number(process.env.MAX_PDF_UPLOAD_MB || 200);
const publicDir = path.resolve(process.cwd(), "public");
const uploadsDir = path.join(publicDir, "uploads");
const uploadsApplicationsDir = path.join(uploadsDir, "applications");
const uploadsIssuesDir = path.join(uploadsDir, "issues");

for (const dir of [uploadsDir, uploadsApplicationsDir, uploadsIssuesDir]) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

app.use(cors({ origin: true }));
app.use(express.json({ limit: "10mb" }));
app.use("/uploads", express.static(uploadsDir));

const imageUpload = multer({
  limits: { fileSize: Math.max(maxImageUploadMb, maxVideoUploadMb) * 1024 * 1024 },
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, uploadsApplicationsDir),
    filename: (_req, file, cb) => cb(null, `${Date.now()}-${file.originalname.replace(/\s+/g, "-")}`),
  }),
});
const applicationUpload = imageUpload.fields([
  { name: "image", maxCount: 1 },
  { name: "video", maxCount: 1 },
]);

const pdfUpload = multer({
  limits: { fileSize: maxPdfUploadMb * 1024 * 1024 },
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, uploadsIssuesDir),
    filename: (_req, file, cb) => cb(null, `${Date.now()}-${file.originalname.replace(/\s+/g, "-")}`),
  }),
});

const parseRecordRow = (row) => ({
  ...row,
  title: JSON.parse(row.title),
  description: JSON.parse(row.description),
  featured: Boolean(row.featured),
});

const createMailTransport = () => {
  const host = process.env.SMTP_HOST;
  const port = Number(process.env.SMTP_PORT || 587);
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;

  if (!host || !user || !pass) return null;

  return nodemailer.createTransport({
    host,
    port,
    secure: Boolean(Number(process.env.SMTP_SECURE || 0)),
    auth: { user, pass },
  });
};

const mailTransport = createMailTransport();
const mailFrom = process.env.MAIL_FROM || process.env.SMTP_USER || "noreply@kines.local";

const sendApplicationEmail = async ({ to, subject, html }) => {
  if (!to || !mailTransport) return;
  try {
    await mailTransport.sendMail({ from: mailFrom, to, subject, html });
  } catch (error) {
    // eslint-disable-next-line no-console
    console.warn("[mail] Failed to send application email:", error?.message || error);
  }
};

app.get("/api/health", (_req, res) => {
  res.json({ ok: true });
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }

  const user = await get(`SELECT * FROM admin_users WHERE email = ?`, [email]);
  if (!user) {
    return res.status(401).json({ error: "Invalid login credentials" });
  }

  const validPassword = await bcrypt.compare(password, user.password_hash);
  if (!validPassword) {
    return res.status(401).json({ error: "Invalid login credentials" });
  }

  const token = createToken(user);
  return res.json({ token, user: { id: user.id, email: user.email } });
});

app.get("/api/auth/session", (req, res) => {
  const payload = parseToken(req);
  if (!payload) return res.status(401).json({ error: "Unauthorized" });
  return res.json({ user: { id: payload.userId, email: payload.email } });
});

app.get("/api/admin-users", requireAuth, async (_req, res) => {
  const users = await all(
    `SELECT id, email, created_at FROM admin_users ORDER BY created_at DESC, rowid DESC`,
  );
  return res.json(users);
});

app.post("/api/admin-users", requireAuth, async (req, res) => {
  const { email, password } = req.body || {};
  const login = String(email || "").trim().toLowerCase();
  const rawPassword = String(password || "");

  if (!login || !rawPassword) {
    return res.status(400).json({ error: "Email and password are required" });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(login)) {
    return res.status(400).json({ error: "Invalid email format" });
  }
  if (rawPassword.length < 8) {
    return res.status(400).json({ error: "Password must be at least 8 characters" });
  }

  const existing = await get(`SELECT id FROM admin_users WHERE email = ?`, [login]);
  if (existing) {
    return res.status(409).json({ error: "User with this email already exists" });
  }

  const id = crypto.randomUUID();
  const passwordHash = await bcrypt.hash(rawPassword, 10);
  const createdAt = new Date().toISOString();
  await run(
    `INSERT INTO admin_users (id, email, password_hash, created_at) VALUES (?, ?, ?, ?)`,
    [id, login, passwordHash, createdAt],
  );

  return res.status(201).json({ id, email: login, created_at: createdAt });
});

app.delete("/api/admin-users/:id", requireAuth, async (req, res) => {
  const userId = String(req.params.id || "");
  if (!userId) return res.status(400).json({ error: "User id is required" });
  if (req.auth?.userId === userId) {
    return res.status(400).json({ error: "You cannot delete your own account" });
  }

  const target = await get(`SELECT id FROM admin_users WHERE id = ?`, [userId]);
  if (!target) {
    return res.status(404).json({ error: "User not found" });
  }

  await run(`DELETE FROM admin_users WHERE id = ?`, [userId]);
  return res.json({ ok: true });
});

app.get("/api/records", async (req, res) => {
  const limit = req.query.limit ? Number(req.query.limit) : null;
  const sql = limit
    ? `SELECT * FROM records ORDER BY date DESC, rowid DESC LIMIT ?`
    : `SELECT * FROM records ORDER BY date DESC, rowid DESC`;
  const rows = await all(sql, limit ? [limit] : []);
  return res.json(rows.map(parseRecordRow));
});

app.post("/api/records", requireAuth, async (req, res) => {
  const record = req.body || {};
  const id = record.id || crypto.randomUUID();
  await run(
    `
      INSERT INTO records (id, title, description, category, holder, location, date, image, featured)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        title = excluded.title,
        description = excluded.description,
        category = excluded.category,
        holder = excluded.holder,
        location = excluded.location,
        date = excluded.date,
        image = excluded.image,
        featured = excluded.featured
    `,
    [
      id,
      JSON.stringify(record.title || {}),
      JSON.stringify(record.description || {}),
      record.category || "",
      record.holder || "",
      record.location || "",
      record.date || "",
      record.image || "",
      record.featured ? 1 : 0,
    ],
  );
  const saved = await get(`SELECT * FROM records WHERE id = ?`, [id]);
  return res.json(parseRecordRow(saved));
});

app.delete("/api/records/:id", requireAuth, async (req, res) => {
  await run(`DELETE FROM records WHERE id = ?`, [req.params.id]);
  return res.json({ ok: true });
});

app.get("/api/applications", requireAuth, async (req, res) => {
  const status = String(req.query.status || "pending");
  const rows = await all(
    `SELECT * FROM applications WHERE status = ? ORDER BY created_at DESC, rowid DESC`,
    [status],
  );
  return res.json(rows);
});

app.post("/api/applications", applicationUpload, async (req, res) => {
  const now = new Date().toISOString();
  const imageFile = req.files?.image?.[0];
  const videoFile = req.files?.video?.[0];
  const image = imageFile ? `/uploads/applications/${imageFile.filename}` : "";
  const video = videoFile ? `/uploads/applications/${videoFile.filename}` : "";
  const payload = req.body || {};
  const requiredFields = ["title", "description", "category", "date", "holder", "location", "submitteremail"];
  const missingField = requiredFields.find((fieldName) => !String(payload[fieldName] || "").trim());
  if (missingField || !image || !video) {
    return res.status(400).json({
      error: "All fields are required, including email, image and video",
    });
  }
  if (imageFile.size > maxImageUploadMb * 1024 * 1024) {
    return res.status(400).json({ error: `Image exceeds ${maxImageUploadMb}MB limit` });
  }
  if (videoFile.size > maxVideoUploadMb * 1024 * 1024) {
    return res.status(400).json({ error: `Video exceeds ${maxVideoUploadMb}MB limit` });
  }

  const id = crypto.randomUUID();
  await run(
    `
      INSERT INTO applications (id, title, description, category, date, holder, location, status, image, video, submitteremail, rejection_reason, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, '', ?)
    `,
    [
      id,
      payload.title || "",
      payload.description || "",
      payload.category || "",
      payload.date || "",
      payload.holder || "",
      payload.location || "",
      image,
      video,
      payload.submitteremail || "",
      now,
    ],
  );
  const created = await get(`SELECT * FROM applications WHERE id = ?`, [id]);
  await sendApplicationEmail({
    to: created.submitteremail,
    subject: "Ваша заявка принята на модерацию",
    html: `
      <p>Здравствуйте!</p>
      <p>Ваша заявка "<strong>${created.title}</strong>" успешно принята и отправлена на модерацию.</p>
      <p>Мы сообщим вам о результате сразу после рассмотрения.</p>
    `,
  });
  return res.status(201).json(created);
});

app.patch("/api/applications/:id", requireAuth, async (req, res) => {
  const { status, rejectionReason } = req.body || {};
  const nextStatus = status || "pending";
  const reviewedAt = ["approved", "rejected"].includes(nextStatus) ? new Date().toISOString() : null;
  await run(
    `UPDATE applications
     SET status = ?, rejection_reason = ?, reviewed_at = COALESCE(?, reviewed_at)
     WHERE id = ?`,
    [nextStatus, rejectionReason || "", reviewedAt, req.params.id],
  );
  const updated = await get(`SELECT * FROM applications WHERE id = ?`, [req.params.id]);
  if (updated?.submitteremail && nextStatus === "approved") {
    await sendApplicationEmail({
      to: updated.submitteremail,
      subject: "Заявка одобрена",
      html: `
        <p>Поздравляем!</p>
        <p>Ваша заявка "<strong>${updated.title}</strong>" была одобрена модератором.</p>
      `,
    });
  }
  if (updated?.submitteremail && nextStatus === "rejected") {
    const reason = updated.rejection_reason || "Причина не указана";
    await sendApplicationEmail({
      to: updated.submitteremail,
      subject: "Заявка отклонена",
      html: `
        <p>Здравствуйте!</p>
        <p>К сожалению, заявка "<strong>${updated.title}</strong>" была отклонена модератором.</p>
        <p><strong>Причина:</strong> ${reason}</p>
      `,
    });
  }
  return res.json(updated);
});

app.delete("/api/applications/:id", requireAuth, async (req, res) => {
  await run(`DELETE FROM applications WHERE id = ?`, [req.params.id]);
  return res.json({ ok: true });
});

app.get("/api/issues", async (req, res) => {
  const status = req.query.status ? String(req.query.status) : null;
  const rows = status
    ? await all(`SELECT * FROM issues WHERE status = ? ORDER BY updated_at DESC, rowid DESC`, [status])
    : await all(`SELECT * FROM issues ORDER BY updated_at DESC, rowid DESC`);
  return res.json(rows);
});

app.post("/api/issues", requireAuth, pdfUpload.single("pdf"), async (req, res) => {
  const now = new Date().toISOString();
  const payload = req.body || {};
  const id = crypto.randomUUID();
  const pdfUrl = req.file ? `/uploads/issues/${req.file.filename}` : payload.pdf_url || "";

  if (!payload.title || !pdfUrl) {
    return res.status(400).json({ error: "title and pdf_url/pdf file are required" });
  }

  await run(
    `
      INSERT INTO issues (id, title, pdf_url, status, updated_at, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `,
    [id, payload.title, pdfUrl, payload.status || "archive", now, now],
  );
  const created = await get(`SELECT * FROM issues WHERE id = ?`, [id]);
  return res.status(201).json(created);
});

app.patch("/api/issues/:id/status", requireAuth, async (req, res) => {
  const { status } = req.body || {};
  const now = new Date().toISOString();
  if (!["current", "archive"].includes(status)) {
    return res.status(400).json({ error: "Invalid status" });
  }
  if (status === "current") {
    await run(`UPDATE issues SET status = 'archive', updated_at = ? WHERE status = 'current'`, [now]);
  }
  await run(`UPDATE issues SET status = ?, updated_at = ? WHERE id = ?`, [status, now, req.params.id]);
  const updated = await get(`SELECT * FROM issues WHERE id = ?`, [req.params.id]);
  return res.json(updated);
});

app.delete("/api/issues/:id", requireAuth, async (req, res) => {
  await run(`DELETE FROM issues WHERE id = ?`, [req.params.id]);
  return res.json({ ok: true });
});

app.get("/api/page-content", async (req, res) => {
  const pagePath = String(req.query.path || "/");
  const row = await get(`SELECT * FROM page_content WHERE path = ?`, [pagePath]);
  return res.json(row || null);
});

app.put("/api/page-content", requireAuth, async (req, res) => {
  const { path: pagePath, html } = req.body || {};
  const updatedAt = new Date().toISOString();
  await run(
    `
      INSERT INTO page_content (path, html, updated_at)
      VALUES (?, ?, ?)
      ON CONFLICT(path) DO UPDATE SET
        html = excluded.html,
        updated_at = excluded.updated_at
    `,
    [pagePath, html, updatedAt],
  );
  const saved = await get(`SELECT * FROM page_content WHERE path = ?`, [pagePath]);
  return res.json(saved);
});

app.post("/api/assistant/chat", async (req, res) => {
  const { message = "", language = "ru" } = req.body || {};
  const rows = await all(`SELECT id, title, holder, category FROM records ORDER BY rowid DESC LIMIT 15`);
  const records = rows.map((row) => ({ ...row, title: JSON.parse(row.title) }));
  const lowerMessage = String(message).toLowerCase();
  const relevant = records.filter((record) => {
    const titleRu = record.title?.ru || "";
    return titleRu.toLowerCase().includes(lowerMessage) || (record.holder || "").toLowerCase().includes(lowerMessage);
  });
  const links = (relevant.length > 0 ? relevant : records.slice(0, 3)).map((record) => ({
    id: record.id,
    title: record.title?.ru || record.title?.en || "Record",
  }));

  const reply =
    language === "ru"
      ? "Нашел несколько релевантных записей. Ниже ссылки, можно открыть и посмотреть детали."
      : "Бірнеше сәйкес жазбаны таптым. Төмендегі сілтемелерді ашып, толық ақпаратты қарай аласыз.";

  return res.json({ reply, relevantLinks: links });
});

app.use((error, _req, res, _next) => {
  if (error instanceof multer.MulterError && error.code === "LIMIT_FILE_SIZE") {
    return res.status(413).json({
      error: "File is too large",
      details: "Check MAX_IMAGE_UPLOAD_MB / MAX_VIDEO_UPLOAD_MB / MAX_PDF_UPLOAD_MB in .env",
    });
  }
  // eslint-disable-next-line no-console
  console.error(error);
  res.status(500).json({ error: error.message || "Internal server error" });
});

await initDb();
app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`[api] http://localhost:${PORT}`);
});
