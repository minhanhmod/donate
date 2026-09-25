const express = require("express");
const crypto = require("crypto");

const app = express();
app.use(express.json({ limit: "100kb" }));

const PORT = process.env.PORT || 3000;
const PAYOS_CLIENT_ID = process.env.PAYOS_CLIENT_ID;
const PAYOS_API_KEY = process.env.PAYOS_API_KEY;
const PAYOS_CHECKSUM_KEY = process.env.PAYOS_CHECKSUM_KEY;
const FRONTEND_URL = process.env.FRONTEND_URL || "https://minhanhmod.github.io/donate/";

if (!PAYOS_CLIENT_ID || !PAYOS_API_KEY || !PAYOS_CHECKSUM_KEY) {
  console.warn("Missing PAYOS_CLIENT_ID / PAYOS_API_KEY / PAYOS_CHECKSUM_KEY");
}

// Demo in-memory storage. For production, replace this with a database.
const orders = new Map();
let total = 0;
const donors = [];

function signPaymentRequest({ amount, cancelUrl, description, orderCode, returnUrl }) {
  const data = [
    ["amount", amount],
    ["cancelUrl", cancelUrl],
    ["description", description],
    ["orderCode", orderCode],
    ["returnUrl", returnUrl],
  ].sort(([a],[b]) => a.localeCompare(b))
   .map(([k,v]) => `${k}=${v}`)
   .join("&");

  return crypto.createHmac("sha256", PAYOS_CHECKSUM_KEY).update(data).digest("hex");
}

function signWebhookData(data) {
  const entries = Object.entries(data).sort(([a],[b]) => a.localeCompare(b));
  const text = entries.map(([key, value]) => {
    if (value === null || value === undefined || value === "null" || value === "undefined") value = "";
    if (Array.isArray(value)) {
      value = JSON.stringify(value.map(x => {
        if (x && typeof x === "object" && !Array.isArray(x)) {
          return Object.fromEntries(Object.entries(x).sort(([a],[b]) => a.localeCompare(b)));
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

function safeEqualHex(a,b) {
  try {
    const aa=Buffer.from(String(a).toLowerCase(),"hex");
    const bb=Buffer.from(String(b).toLowerCase(),"hex");
    return aa.length===bb.length && crypto.timingSafeEqual(aa,bb);
  } catch { return false; }
}

function cors(req, res, next) {
  const allowedOrigin = "https://minhanhmod.github.io";

  res.setHeader("Access-Control-Allow-Origin", allowedOrigin);
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Access-Control-Max-Age", "86400");

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
}
app.use(cors);

app.get("/api/health",(req,res)=>res.json({ok:true}));

app.post("/api/create-payment", async (req,res)=>{
  try {
    const amount = Number(req.body.amount);
    if (!Number.isInteger(amount) || amount < 2000 || amount > 50000000)
      return res.status(400).json({success:false,message:"Số tiền không hợp lệ"});

    // Must be unique and within payOS orderCode requirements.
    const orderCode = Date.now();
    const description = `DONATE ${orderCode}`;
    const returnUrl = FRONTEND_URL;
    const cancelUrl = FRONTEND_URL;

    const signature = signPaymentRequest({amount,cancelUrl,description,orderCode,returnUrl});

    const response = await fetch("https://api-merchant.payos.vn/v2/payment-requests",{
      method:"POST",
      headers:{
        "Content-Type":"application/json",
        "x-client-id":PAYOS_CLIENT_ID,
        "x-api-key":PAYOS_API_KEY
      },
      body:JSON.stringify({
        orderCode, amount, description, cancelUrl, returnUrl, signature
      })
    });

    const data = await response.json();
    if(!response.ok || data.code !== "00")
      return res.status(response.status || 500).json({success:false,message:data.desc || "payOS error",raw:data});

    orders.set(String(orderCode), {
      orderCode, amount,
      name: String(req.body.name||"Ẩn danh").slice(0,40),
      message: String(req.body.message||"").slice(0,200),
      status:"PENDING",
      createdAt:Date.now(),
      checkoutUrl:data.data.checkoutUrl
    });

    res.json({
      success:true,
      orderCode,
      checkoutUrl:data.data.checkoutUrl,
      qrCode:data.data.qrCode
    });
  } catch(e) {
    console.error(e);
    res.status(500).json({success:false,message:"Không thể tạo thanh toán"});
  }
});

app.get("/api/payment/:orderCode", async (req,res)=>{
  try {
    const orderCode = String(req.params.orderCode);
    const local = orders.get(orderCode);
    if(local?.status === "PAID") return res.json({status:"PAID"});

    const r = await fetch(`https://api-merchant.payos.vn/v2/payment-requests/${encodeURIComponent(orderCode)}`,{
      headers:{"x-client-id":PAYOS_CLIENT_ID,"x-api-key":PAYOS_API_KEY}
    });
    const data=await r.json();
    if(!r.ok || data.code!=="00")
      return res.status(r.status||500).json({status:"UNKNOWN",message:data.desc});

    const status=data.data.status;
    if(local) local.status=status;
    res.json({status});
  } catch(e) {
    res.status(500).json({status:"UNKNOWN"});
  }
});

app.post("/webhook/payos",(req,res)=>{
  try {
    const body=req.body;
    if(!body?.data || !body?.signature) return res.status(400).json({success:false});

    const expected=signWebhookData(body.data);
    if(!safeEqualHex(expected,body.signature))
      return res.status(400).json({success:false,message:"Invalid signature"});

    const d=body.data;
    const order=orders.get(String(d.orderCode));

    if(body.code==="00" && d.code==="00" && order && order.status!=="PAID"){
      order.status="PAID";
      order.paidAt=Date.now();
      order.reference=d.reference || null;

      // Idempotency: payOS may retry a webhook. Only count once.
      total += Number(d.amount||0);
      donors.unshift({
        orderCode:d.orderCode,
        amount:Number(d.amount||0),
        name:order.name || "Ẩn danh",
        message:order.message || "",
        reference:d.reference || null,
        paidAt:order.paidAt
      });
    }

    res.json({success:true});
  } catch(e) {
    console.error(e);
    res.status(500).json({success:false});
  }
});

app.get("/api/stats",(req,res)=>{
  res.json({
    total,
    donors: donors.slice(0,30)
  });
});

app.listen(PORT,()=>console.log(`Donate backend listening on ${PORT}`));
