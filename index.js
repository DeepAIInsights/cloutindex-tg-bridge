const http = require("http");
const crypto = require("crypto");
const { TelegramClient, Api } = require("telegram");
const { StringSession } = require("telegram/sessions");

const PORT = process.env.PORT || 3000;
const API_ID = Number(process.env.TELEGRAM_API_ID || "39833482");
const API_HASH = String(process.env.TELEGRAM_API_HASH || "20cf1ac69254a37ea86e65575d27d3f2");
const BRIDGE_SECRET = String(process.env.BRIDGE_SECRET || "CI_TG_BRIDGE_2026");

// In-memory pending auth sessions (TTL 10 minutes)
const pendingSessions = new Map();

setInterval(() => {
  const now = Date.now();
  for (const [sid, item] of pendingSessions.entries()) {
    if (now - item.createdAt > 600000) {
      try { item.client.disconnect(); } catch (e) {}
      pendingSessions.delete(sid);
    }
  }
}, 60000);

function sendJson(res, status, data) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-Bridge-Secret"
  });
  res.end(JSON.stringify(data));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let raw = "";
    req.on("data", (chunk) => {
      raw += chunk;
      if (raw.length > 1048576) reject(new Error("Payload too large"));
    });
    req.on("end", () => {
      try {
        resolve(raw ? JSON.parse(raw) : {});
      } catch (e) {
        reject(new Error("Invalid JSON"));
      }
    });
    req.on("error", reject);
  });
}

async function extractAdminChannels(client) {
  const dialogs = await client.getDialogs({ limit: 200 });
  const channels = [];

  for (const d of dialogs) {
    const ent = d.entity;
    if (!ent) continue;
    const isBroadcastChannel = ent.className === "Channel" && Boolean(ent.broadcast);
    const hasRights = Boolean(ent.creator) || Boolean(ent.adminRights);
    if (!isBroadcastChannel || !hasRights) continue;

    const uname = ent.username ? `@${ent.username}` : "";
    if (!uname) continue;

    let subsCount = Number(ent.participantsCount) || 0;
    try {
      const full = await client.invoke(new Api.channels.GetFullChannel({ channel: ent }));
      if (full && full.fullChat && full.fullChat.participantsCount) {
        subsCount = Number(full.fullChat.participantsCount) || subsCount;
      }
    } catch (e) {}

    channels.push({
      external_id: String(ent.id),
      platform: "telegram",
      oauth_provider: "Telegram MTProto Verified",
      channel_handle: uname,
      channel_title: ent.title || uname,
      channel_avatar: "",
      followers: subsCount,
      posts_count: 0,
      views_30d: 0,
      extra_metric: 0
    });
  }

  return channels;
}

const server = http.createServer(async (req, res) => {
  if (req.method === "OPTIONS") {
    return sendJson(res, 200, { ok: true });
  }

  const url = new URL(req.url, `http://${req.headers.host}`);

  if (url.pathname === "/" && req.method === "GET") {
    return sendJson(res, 200, { status: "CLOUTINDEX Telegram MTProto Bridge Online" });
  }

  const secretHeader = req.headers["x-bridge-secret"] || "";
  if (secretHeader !== BRIDGE_SECRET) {
    return sendJson(res, 401, { success: false, error: "Unauthorized bridge request" });
  }

  try {
    // STEP 1: SEND CODE TO PHONE NUMBER
    if (url.pathname === "/tg/send-code" && req.method === "POST") {
      const { phone } = await readBody(req);
      const cleanPhone = String(phone || "").trim();
      if (!cleanPhone || cleanPhone.replace(/\D/g, "").length < 7) {
        return sendJson(res, 400, { success: false, error: "Введите корректный номер телефона с кодом страны" });
      }

      const client = new TelegramClient(new StringSession(""), API_ID, API_HASH, {
        connectionRetries: 4
      });
      await client.connect();

      const sendResult = await client.sendCode(
        { apiId: API_ID, apiHash: API_HASH },
        cleanPhone
      );

      const sessionId = crypto.randomBytes(16).toString("hex");
      pendingSessions.set(sessionId, {
        client,
        phone: cleanPhone,
        phoneCodeHash: sendResult.phoneCodeHash,
        createdAt: Date.now()
      });

      return sendJson(res, 200, {
        success: true,
        tg_session_id: sessionId,
        message: "Код отправлен в приложение Telegram"
      });
    }

    // STEP 2: VERIFY 5-DIGIT CODE (OR REQUEST CLOUD 2FA PASSWORD)
    if (url.pathname === "/tg/verify-code" && req.method === "POST") {
      const { tg_session_id, code } = await readBody(req);
      const entry = pendingSessions.get(String(tg_session_id || ""));
      if (!entry) {
        return sendJson(res, 404, { success: false, error: "Сессия входа истекла. Запросите код заново." });
      }

      try {
        await entry.client.invoke(
          new Api.auth.SignIn({
            phoneNumber: entry.phone,
            phoneCodeHash: entry.phoneCodeHash,
            phoneCode: String(code || "").trim()
          })
        );
      } catch (err) {
        const msg = String(err.errorMessage || err.message || "");
        if (msg.includes("SESSION_PASSWORD_NEEDED")) {
          return sendJson(res, 200, {
            success: true,
            requires_password: true,
            tg_session_id
          });
        }
        return sendJson(res, 400, { success: false, error: "Неверный код Telegram: " + msg });
      }

      const channels = await extractAdminChannels(entry.client);
      try { await entry.client.disconnect(); } catch (e) {}
      pendingSessions.delete(String(tg_session_id));

      return sendJson(res, 200, { success: true, channels });
    }

    // STEP 3: VERIFY CLOUD 2FA PASSWORD IF ENABLED
    if (url.pathname === "/tg/verify-password" && req.method === "POST") {
      const { tg_session_id, password } = await readBody(req);
      const entry = pendingSessions.get(String(tg_session_id || ""));
      if (!entry) {
        return sendJson(res, 404, { success: false, error: "Сессия входа истекла. Запросите код заново." });
      }

      try {
        await entry.client.signInWithPassword(
          { apiId: API_ID, apiHash: API_HASH },
          {
            password: async () => String(password || ""),
            onError: (err) => { throw err; }
          }
        );
      } catch (err) {
        return sendJson(res, 400, {
          success: false,
          error: "Неверный облачный пароль: " + (err.errorMessage || err.message || "Error")
        });
      }

      const channels = await extractAdminChannels(entry.client);
      try { await entry.client.disconnect(); } catch (e) {}
      pendingSessions.delete(String(tg_session_id));

      return sendJson(res, 200, { success: true, channels });
    }

    return sendJson(res, 404, { success: false, error: "Not found" });
  } catch (e) {
    return sendJson(res, 500, { success: false, error: e.message });
  }
});

server.listen(PORT, () => {
  console.log(`CLOUTINDEX Telegram MTProto Bridge listening on port ${PORT}`);
});
