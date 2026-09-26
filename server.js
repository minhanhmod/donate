const express = require("express");
const crypto = require("crypto");
const { Pool } = require("pg");
const fs = require("fs");
const path = require("path");

const app = express();
app.use(express.json({ limit: "100kb" }));

const PORT = process.env.PORT || 3000;
const PAYOS_CLIENT_ID = process.env.PAYOS_CLIENT_ID;
const PAYOS_API_KEY = process.env.PAYOS_API_KEY;
const PAYOS_CHECKSUM_KEY = process.env.PAYOS_CHECKSUM_KEY;
const FRONTEND_URL = process.env.FRONTEND_URL || "https://minhanhmod.github.io/donate/";
const DATABASE_URL = process.env.DATABASE_URL;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const ADMIN_TOKEN_SECRET = process.env.ADMIN_TOKEN_SECRET || PAYOS_CHECKSUM_KEY;

if (!PAYOS_CLIENT_ID || !PAYOS_API_KEY || !PAYOS_CHECKSUM_KEY) {
  console.warn("Missing PAYOS_CLIENT_ID / PAYOS_API_KEY / PAYOS_CHECKSUM_KEY");
}
if (!DATABASE_URL) {
  console.error("Missing DATABASE_URL");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS payment_orders (
      id BIGSERIAL PRIMARY KEY,
      order_code BIGINT UNIQUE NOT NULL,
      amount BIGINT NOT NULL CHECK (amount > 0),
      donor_name VARCHAR(40) NOT NULL DEFAULT 'Ẩn danh',
      donor_message VARCHAR(500) NOT NULL DEFAULT '',
      status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
      checkout_url TEXT,
      reference VARCHAR(120),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      paid_at TIMESTAMPTZ,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      deleted_at TIMESTAMPTZ
    );

    ALTER TABLE payment_orders ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;

    CREATE INDEX IF NOT EXISTS idx_payment_orders_status_paid_at
      ON payment_orders(status, paid_at DESC);

    CREATE TABLE IF NOT EXISTS manual_donations (
      id BIGSERIAL PRIMARY KEY,
      amount BIGINT NOT NULL CHECK (amount > 0),
      donor_name VARCHAR(40) NOT NULL DEFAULT 'Ẩn danh',
      donor_message VARCHAR(500) NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      deleted_at TIMESTAMPTZ
    );

    CREATE INDEX IF NOT EXISTS idx_manual_donations_created_at
      ON manual_donations(created_at DESC);

    CREATE TABLE IF NOT EXISTS chat_messages (
      id UUID PRIMARY KEY,
      name VARCHAR(30) NOT NULL,
      message VARCHAR(500) NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_chat_messages_created_at
      ON chat_messages(created_at DESC);
  `);
  console.log("PostgreSQL database ready");
}

function signPaymentRequest({ amount, cancelUrl, description, orderCode, returnUrl }) {
  const data = [
    ["amount", amount],
    ["cancelUrl", cancelUrl],
    ["description", description],
    ["orderCode", orderCode],
    ["returnUrl", returnUrl],
  ].sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}=${v}`)
    .join("&");

  return crypto.createHmac("sha256", PAYOS_CHECKSUM_KEY).update(data).digest("hex");
}

function signWebhookData(data) {
  const entries = Object.entries(data).sort(([a], [b]) => a.localeCompare(b));
  const text = entries.map(([key, value]) => {
    if (value === null || value === undefined || value === "null" || value === "undefined") value = "";
    if (Array.isArray(value)) {
      value = JSON.stringify(value.map(x => {
        if (x && typeof x === "object" && !Array.isArray(x)) {
          return Object.fromEntries(Object.entries(x).sort(([a], [b]) => a.localeCompare(b)));
        }
        return x;
      }));
    } else if (typeof value === "object") {
      value = JSON.stringify(value);
    }
    return `${key}=${value}`;
  }).join("&");

  return crypto.createHmac("sha256", PAYOS_CHECKSUM_KEY).update(text).digest("hex");
}

function safeEqualHex(a, b) {
  try {
    const aa = Buffer.from(String(a).toLowerCase(), "hex");
    const bb = Buffer.from(String(b).toLowerCase(), "hex");
    return aa.length === bb.length && aa.length > 0 && crypto.timingSafeEqual(aa, bb);
  } catch {
    return false;
  }
}

function cors(req, res, next) {
  const allowedOrigin = new URL(FRONTEND_URL).origin;
  res.setHeader("Access-Control-Allow-Origin", allowedOrigin);
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,PATCH,DELETE,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Access-Control-Max-Age", "86400");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
}
app.use(cors);


function makeAdminToken() {
  const exp = Date.now() + 12 * 60 * 60 * 1000;
  const payload = String(exp);
  const sig = crypto.createHmac("sha256", ADMIN_TOKEN_SECRET).update(payload).digest("hex");
  return `${payload}.${sig}`;
}
function verifyAdmin(req) {
  const auth = String(req.headers.authorization || "");
  if (!auth.startsWith("Bearer ")) return false;
  const token = auth.slice(7);
  const [exp, sig] = token.split(".");
  if (!exp || !sig || Number(exp) < Date.now()) return false;
  const expected = crypto.createHmac("sha256", ADMIN_TOKEN_SECRET).update(exp).digest("hex");
  return safeEqualHex(expected, sig);
}
function requireAdmin(req, res, next) {
  if (!ADMIN_PASSWORD) return res.status(503).json({ success:false, message:"Chưa cấu hình ADMIN_PASSWORD trên Render." });
  if (!verifyAdmin(req)) return res.status(401).json({ success:false, message:"Phiên Admin không hợp lệ hoặc đã hết hạn." });
  next();
}

app.get("/admin", (req, res) => {
  res.sendFile(path.join(__dirname, "admin.html"));
});

app.post("/api/admin/login", (req, res) => {
  if (!ADMIN_PASSWORD) return res.status(503).json({ success:false, message:"Chưa cấu hình ADMIN_PASSWORD trên Render." });
  const password = String(req.body.password || "");
  const a = Buffer.from(password);
  const b = Buffer.from(ADMIN_PASSWORD);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return res.status(401).json({ success:false, message:"Sai mật khẩu Admin." });
  }
  res.json({ success:true, token:makeAdminToken(), expiresIn:43200 });
});

app.get("/api/admin/orders", requireAdmin, async (req, res) => {
  try {
    const total = await pool.query("SELECT COALESCE(SUM(amount),0)::bigint AS total FROM payment_orders WHERE status='PAID' AND deleted_at IS NULL");
    const counts = await pool.query("SELECT COUNT(*) FILTER (WHERE status='PAID' AND deleted_at IS NULL)::int AS paid_count, COUNT(*) FILTER (WHERE status='PENDING' AND deleted_at IS NULL)::int AS pending_count FROM payment_orders");
    const rows = await pool.query(`SELECT id, order_code AS "orderCode", amount, donor_name AS name, donor_message AS message, status, reference, created_at AS "createdAt", paid_at AS "paidAt", deleted_at AS "deletedAt", (deleted_at IS NOT NULL) AS deleted FROM payment_orders ORDER BY created_at DESC`);
    res.json({ total:Number(total.rows[0].total||0), paidCount:counts.rows[0].paid_count, pendingCount:counts.rows[0].pending_count, orders:rows.rows });
  } catch(e) { console.error(e); res.status(500).json({success:false,message:"Không tải được giao dịch."}); }
});

app.patch("/api/admin/orders/:id", requireAdmin, async (req,res)=>{
  try {
    const name=String(req.body.name||"Ẩn danh").trim().slice(0,40)||"Ẩn danh";
    const message=String(req.body.message||"").trim().slice(0,500);
    const r=await pool.query("UPDATE payment_orders SET donor_name=$1, donor_message=$2, updated_at=NOW() WHERE id=$3 RETURNING id",[name,message,req.params.id]);
    if(!r.rowCount)return res.status(404).json({success:false,message:"Không tìm thấy giao dịch."});
    res.json({success:true});
  } catch(e){console.error(e);res.status(500).json({success:false,message:"Không lưu được giao dịch."});}
});

app.delete("/api/admin/orders/:id", requireAdmin, async (req,res)=>{
  try {
    const r=await pool.query("UPDATE payment_orders SET deleted_at=NOW(), updated_at=NOW() WHERE id=$1 AND deleted_at IS NULL RETURNING id",[req.params.id]);
    if(!r.rowCount)return res.status(404).json({success:false,message:"Không tìm thấy giao dịch hoặc đã ẩn."});
    res.json({success:true});
  } catch(e){console.error(e);res.status(500).json({success:false,message:"Không ẩn được giao dịch."});}
});

app.post("/api/admin/orders/:id/restore", requireAdmin, async (req,res)=>{
  try {
    const r=await pool.query("UPDATE payment_orders SET deleted_at=NULL, updated_at=NOW() WHERE id=$1 AND deleted_at IS NOT NULL RETURNING id",[req.params.id]);
    if(!r.rowCount)return res.status(404).json({success:false,message:"Không tìm thấy giao dịch đã ẩn."});
    res.json({success:true});
  } catch(e){console.error(e);res.status(500).json({success:false,message:"Không khôi phục được giao dịch."});}
});

app.post("/api/admin/manual-donations", requireAdmin, async (req,res)=>{
  try {
    const amount=Number(req.body.amount);
    if(!Number.isInteger(amount)||amount<1||amount>500000000){return res.status(400).json({success:false,message:"Số tiền không hợp lệ."});}
    const name=String(req.body.name||"Ẩn danh").trim().slice(0,40)||"Ẩn danh";
    const message=String(req.body.message||"").trim().slice(0,500);
    const r=await pool.query(`INSERT INTO manual_donations(amount,donor_name,donor_message) VALUES($1,$2,$3) RETURNING id`,[amount,name,message]);
    res.json({success:true,id:r.rows[0].id});
  } catch(e){console.error(e);res.status(500).json({success:false,message:"Không thêm được khoản donate."});}
});
app.get("/api/admin/manual-donations", requireAdmin, async (req,res)=>{
  try{const r=await pool.query(`SELECT id,amount,donor_name AS name,donor_message AS message,created_at AS "createdAt",deleted_at AS "deletedAt",(deleted_at IS NOT NULL) AS deleted FROM manual_donations ORDER BY created_at DESC`);res.json({donations:r.rows});}
  catch(e){console.error(e);res.status(500).json({success:false,message:"Không tải được khoản cộng tay."});}
});
app.delete("/api/admin/manual-donations/:id", requireAdmin, async (req,res)=>{
  try{const r=await pool.query("UPDATE manual_donations SET deleted_at=NOW() WHERE id=$1 AND deleted_at IS NULL RETURNING id",[req.params.id]);if(!r.rowCount)return res.status(404).json({success:false,message:"Không tìm thấy khoản cộng tay."});res.json({success:true});}
  catch(e){console.error(e);res.status(500).json({success:false,message:"Không ẩn được khoản cộng tay."});}
});
app.post("/api/admin/manual-donations/:id/restore", requireAdmin, async (req,res)=>{
  try{const r=await pool.query("UPDATE manual_donations SET deleted_at=NULL WHERE id=$1 AND deleted_at IS NOT NULL RETURNING id",[req.params.id]);if(!r.rowCount)return res.status(404).json({success:false,message:"Không tìm thấy khoản đã ẩn."});res.json({success:true});}
  catch(e){console.error(e);res.status(500).json({success:false,message:"Không khôi phục được khoản cộng tay."});}
});

app.get("/api/admin/chat", requireAdmin, async (req,res)=>{
  try{const r=await pool.query(`SELECT id,name,message,created_at AS "createdAt" FROM chat_messages ORDER BY created_at DESC LIMIT 500`);res.json({messages:r.rows});}
  catch(e){console.error(e);res.status(500).json({success:false,message:"Không tải được chat."});}
});
app.patch("/api/admin/chat/:id", requireAdmin, async (req,res)=>{
  try{const name=String(req.body.name||"Ẩn danh").trim().slice(0,30)||"Ẩn danh";const message=String(req.body.message||"").trim().slice(0,500);if(!message)return res.status(400).json({success:false,message:"Tin nhắn không được để trống."});const r=await pool.query("UPDATE chat_messages SET name=$1,message=$2 WHERE id=$3 RETURNING id",[name,message,req.params.id]);if(!r.rowCount)return res.status(404).json({success:false,message:"Không tìm thấy tin nhắn."});res.json({success:true});}
  catch(e){console.error(e);res.status(500).json({success:false,message:"Không sửa được tin nhắn."});}
});
app.delete("/api/admin/chat/:id", requireAdmin, async (req,res)=>{
  try{const r=await pool.query("DELETE FROM chat_messages WHERE id=$1 RETURNING id",[req.params.id]);if(!r.rowCount)return res.status(404).json({success:false,message:"Không tìm thấy tin nhắn."});res.json({success:true});}
  catch(e){console.error(e);res.status(500).json({success:false,message:"Không xóa được tin nhắn."});}
});

app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true, database: "connected" });
  } catch (e) {
    console.error(e);
    res.status(503).json({ ok: false, database: "disconnected" });
  }
});

app.post("/api/create-payment", async (req, res) => {
  try {
    const amount = Number(req.body.amount);
    if (!Number.isInteger(amount) || amount < 2000 || amount > 50000000) {
      return res.status(400).json({ success: false, message: "Số tiền không hợp lệ" });
    }

    const orderCode = Date.now();
    const description = `DONATE ${orderCode}`;
    const returnUrl = FRONTEND_URL;
    const cancelUrl = FRONTEND_URL;
    const name = String(req.body.name || "Ẩn danh").trim().slice(0, 40) || "Ẩn danh";
    const message = String(req.body.message || "").trim().slice(0, 500);

    const signature = signPaymentRequest({ amount, cancelUrl, description, orderCode, returnUrl });

    const response = await fetch("https://api-merchant.payos.vn/v2/payment-requests", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-client-id": PAYOS_CLIENT_ID,
        "x-api-key": PAYOS_API_KEY
      },
      body: JSON.stringify({ orderCode, amount, description, cancelUrl, returnUrl, signature })
    });

    const data = await response.json();
    if (!response.ok || data.code !== "00") {
      return res.status(response.status || 500).json({
        success: false,
        message: data.desc || "payOS error",
        raw: data
      });
    }

    await pool.query(
      `INSERT INTO payment_orders
        (order_code, amount, donor_name, donor_message, status, checkout_url)
       VALUES ($1, $2, $3, $4, 'PENDING', $5)`,
      [orderCode, amount, name, message, data.data.checkoutUrl]
    );

    res.json({
      success: true,
      orderCode,
      checkoutUrl: data.data.checkoutUrl,
      qrCode: data.data.qrCode
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success: false, message: "Không thể tạo thanh toán" });
  }
});

app.get("/api/payment/:orderCode", async (req, res) => {
  try {
    const orderCode = String(req.params.orderCode);
    const local = await pool.query(
      "SELECT status FROM payment_orders WHERE order_code = $1 LIMIT 1",
      [orderCode]
    );

    if (local.rows[0]?.status === "PAID") return res.json({ status: "PAID" });

    const r = await fetch(`https://api-merchant.payos.vn/v2/payment-requests/${encodeURIComponent(orderCode)}`, {
      headers: { "x-client-id": PAYOS_CLIENT_ID, "x-api-key": PAYOS_API_KEY }
    });
    const data = await r.json();
    if (!r.ok || data.code !== "00") {
      return res.status(r.status || 500).json({ status: "UNKNOWN", message: data.desc });
    }

    const status = data.data.status;
    await pool.query(
      "UPDATE payment_orders SET status = $1, updated_at = NOW() WHERE order_code = $2 AND status <> 'PAID'",
      [status, orderCode]
    );
    res.json({ status });
  } catch (e) {
    console.error(e);
    res.status(500).json({ status: "UNKNOWN" });
  }
});

app.post("/webhook/payos", async (req, res) => {
  const client = await pool.connect();
  try {
    const body = req.body;
    if (!body?.data || !body?.signature) return res.status(400).json({ success: false });

    const expected = signWebhookData(body.data);
    if (!safeEqualHex(expected, body.signature)) {
      return res.status(400).json({ success: false, message: "Invalid signature" });
    }

    const d = body.data;
    if (body.code !== "00" || d.code !== "00") {
      return res.json({ success: true });
    }

    await client.query("BEGIN");

    const result = await client.query(
      `SELECT * FROM payment_orders WHERE order_code = $1 FOR UPDATE`,
      [String(d.orderCode)]
    );

    if (result.rows.length === 0) {
      await client.query("ROLLBACK");
      // Return 200 so payOS does not endlessly retry an order that this server never created.
      return res.json({ success: true, ignored: true });
    }

    const order = result.rows[0];

    if (order.status !== "PAID") {
      await client.query(
        `UPDATE payment_orders
         SET status = 'PAID', reference = $1, paid_at = NOW(), updated_at = NOW()
         WHERE order_code = $2`,
        [d.reference || null, String(d.orderCode)]
      );
    }

    await client.query("COMMIT");
    res.json({ success: true });
  } catch (e) {
    await client.query("ROLLBACK").catch(() => {});
    console.error(e);
    res.status(500).json({ success: false });
  } finally {
    client.release();
  }
});

app.get("/api/stats", async (req, res) => {
  try {
    const totalResult = await pool.query(`
      SELECT COALESCE(SUM(amount), 0)::bigint AS total FROM (
        SELECT amount FROM payment_orders WHERE status = 'PAID' AND deleted_at IS NULL
        UNION ALL
        SELECT amount FROM manual_donations WHERE deleted_at IS NULL
      ) x`);
    const donorsResult = await pool.query(`
      SELECT * FROM (
        SELECT order_code::text AS "orderCode", amount, donor_name AS name, donor_message AS message, reference, paid_at AS "paidAt", id
        FROM payment_orders WHERE status = 'PAID' AND deleted_at IS NULL
        UNION ALL
        SELECT ('MANUAL-' || id)::text AS "orderCode", amount, donor_name AS name, donor_message AS message, NULL AS reference, created_at AS "paidAt", (1000000000000000 + id) AS id
        FROM manual_donations WHERE deleted_at IS NULL
      ) d ORDER BY "paidAt" DESC NULLS LAST, id DESC LIMIT 30`);

    res.json({ total: Number(totalResult.rows[0].total || 0), donors: donorsResult.rows });
  } catch (e) {
    console.error(e);
    res.status(500).json({ total: 0, donors: [] });
  }
});

app.get("/api/chat", async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, name, message, created_at AS "createdAt"
       FROM chat_messages
       ORDER BY created_at DESC
       LIMIT 100`
    );
    res.json({ messages: result.rows.reverse() });
  } catch (e) {
    console.error(e);
    res.status(500).json({ messages: [] });
  }
});

const chatRate = new Map();
app.post("/api/chat", async (req, res) => {
  try {
    const ip = String(req.headers["x-forwarded-for"] || req.socket.remoteAddress || "unknown")
      .split(",")[0].trim();
    const now = Date.now();
    const last = chatRate.get(ip) || 0;
    if (now - last < 1500) {
      return res.status(429).json({ success: false, message: "Bạn gửi quá nhanh, hãy chờ một chút." });
    }

    const name = String(req.body.name || "Ẩn danh").trim().slice(0, 30) || "Ẩn danh";
    const message = String(req.body.message || "").trim().slice(0, 500);
    if (!message) return res.status(400).json({ success: false, message: "Tin nhắn không được để trống." });

    chatRate.set(ip, now);
    const id = crypto.randomUUID();

    await pool.query(
      `INSERT INTO chat_messages(id, name, message) VALUES ($1, $2, $3)`,
      [id, name, message]
    );

    // Keep only the latest 500 chat messages to prevent unlimited database growth.
    await pool.query(`
      DELETE FROM chat_messages
      WHERE id IN (
        SELECT id FROM chat_messages
        ORDER BY created_at DESC
        OFFSET 500
      )
    `);

    const result = await pool.query(
      `SELECT id, name, message, created_at AS "createdAt"
       FROM chat_messages ORDER BY created_at ASC LIMIT 100`
    );

    res.json({ success: true, messages: result.rows });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success: false, message: "Không gửi được tin nhắn." });
  }
});

initDb()
  .then(() => app.listen(PORT, () => console.log(`Donate backend listening on ${PORT}`)))
  .catch(err => {
    console.error("Database initialization failed", err);
    process.exit(1);
  });

process.on("SIGTERM", async () => {
  await pool.end();
  process.exit(0);
});
