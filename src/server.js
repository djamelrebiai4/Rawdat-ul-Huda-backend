import cors from "cors";
import { rateLimit } from "express-rate-limit";
import express from "express";
import helmet from "helmet";
import jwt from "jsonwebtoken";
import { createClient } from "@supabase/supabase-js";

const {
  PORT = "4000",
  FRONTEND_ORIGINS = "http://localhost:3000",
  SUPABASE_URL,
  SUPABASE_ANON_KEY,
  SUPABASE_SERVICE_ROLE_KEY,
  SESSION_SECRET,
} = process.env;

if (!SUPABASE_URL || !SUPABASE_ANON_KEY || !SUPABASE_SERVICE_ROLE_KEY) {
  throw new Error("SUPABASE_URL, SUPABASE_ANON_KEY, and SUPABASE_SERVICE_ROLE_KEY are required.");
}

if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
  throw new Error("SESSION_SECRET must contain at least 32 characters.");
}

const publicClient = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
  auth: { autoRefreshToken: false, persistSession: false },
});
const serviceClient = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { autoRefreshToken: false, persistSession: false },
});
const allowedOrigins = FRONTEND_ORIGINS.split(",").map((origin) => origin.trim()).filter(Boolean);
const editableSettings = new Set(["name", "whatsappNumber", "whatsappDisplay", "email", "facebook", "twitter"]);
const app = express();

if (process.env.TRUST_PROXY) {
  const trustedProxy = process.env.TRUST_PROXY;
  app.set("trust proxy", /^\d+$/.test(trustedProxy) ? Number(trustedProxy) : trustedProxy);
}

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-8",
  legacyHeaders: false,
});

const publicLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 120,
  standardHeaders: "draft-8",
  legacyHeaders: false,
});

app.disable("x-powered-by");
app.use(helmet());
app.use(cors({ origin: allowedOrigins, methods: ["GET", "POST", "PUT", "OPTIONS"], allowedHeaders: ["Content-Type", "Authorization"] }));
app.use(express.json({ limit: "256kb" }));

function validLocale(locale) {
  return locale === "en" || locale === "ar";
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function bearerToken(request) {
  const authorization = request.get("authorization") ?? "";
  return authorization.startsWith("Bearer ") ? authorization.slice(7) : "";
}

async function requireOwner(request, response, next) {
  try {
    const token = bearerToken(request);
    const claims = jwt.verify(token, SESSION_SECRET, {
      algorithms: ["HS256"],
      issuer: "rawdat-ul-huda-api",
      audience: "site-owner",
    });
    const userId = typeof claims === "object" ? claims.sub : undefined;

    if (typeof userId !== "string") {
      return response.status(401).json({ error: "unauthorized" });
    }

    const { data: membership, error } = await serviceClient
      .from("site_admins")
      .select("user_id")
      .eq("user_id", userId)
      .maybeSingle();

    if (error || !membership) {
      return response.status(403).json({ error: "owner_access_required" });
    }

    request.owner = { id: userId, email: claims.email };
    return next();
  } catch {
    return response.status(401).json({ error: "unauthorized" });
  }
}

async function readSiteContent(locale) {
  return serviceClient.from("site_content").select("messages").eq("locale", locale).maybeSingle();
}

async function readPublicSiteContent(locale) {
  return publicClient.from("site_content").select("messages").eq("locale", locale).maybeSingle();
}

async function readPublicSiteSettings() {
  return publicClient.from("site_settings").select("settings").eq("id", "main").maybeSingle();
}

app.get("/health", (_request, response) => response.json({ status: "ok" }));

app.get("/api/site/content/:locale", publicLimiter, async (request, response) => {
  const { locale } = request.params;
  if (!validLocale(locale)) return response.status(400).json({ error: "invalid_locale" });

  const { data, error } = await readPublicSiteContent(locale);
  if (error) return response.status(500).json({ error: "content_unavailable" });
  return response.json({ messages: data?.messages ?? null });
});

app.get("/api/site/settings", publicLimiter, async (_request, response) => {
  const { data, error } = await readPublicSiteSettings();

  if (error) return response.status(500).json({ error: "settings_unavailable" });
  return response.json({ settings: data?.settings ?? null });
});

app.post("/api/admin/auth/login", loginLimiter, async (request, response) => {
  const email = typeof request.body?.email === "string" ? request.body.email.trim() : "";
  const password = typeof request.body?.password === "string" ? request.body.password : "";
  if (!email || !password) return response.status(400).json({ error: "credentials_required" });

  const { data, error } = await publicClient.auth.signInWithPassword({ email, password });
  if (error || !data.user) return response.status(401).json({ error: "invalid_credentials" });

  const { data: membership, error: membershipError } = await serviceClient
    .from("site_admins")
    .select("user_id")
    .eq("user_id", data.user.id)
    .maybeSingle();

  if (membershipError || !membership) return response.status(403).json({ error: "owner_access_required" });

  const token = jwt.sign(
    { email: data.user.email },
    SESSION_SECRET,
    { subject: data.user.id, issuer: "rawdat-ul-huda-api", audience: "site-owner", expiresIn: "8h" },
  );

  return response.json({ token, user: { email: data.user.email } });
});

app.get("/api/admin/me", requireOwner, (request, response) => {
  response.json({ user: { id: request.owner.id, email: request.owner.email } });
});

app.get("/api/admin/content/:locale", requireOwner, async (request, response) => {
  const { locale } = request.params;
  if (!validLocale(locale)) return response.status(400).json({ error: "invalid_locale" });

  const { data, error } = await readSiteContent(locale);
  if (error) return response.status(500).json({ error: "content_unavailable" });
  return response.json({ messages: data?.messages ?? null });
});

app.put("/api/admin/content/:locale", requireOwner, async (request, response) => {
  const { locale } = request.params;
  const { section, content } = request.body ?? {};
  if (!validLocale(locale) || typeof section !== "string" || !/^[A-Za-z][\w-]{0,79}$/.test(section) || section === "site") {
    return response.status(400).json({ error: "invalid_content_target" });
  }

  const { data: existing, error: readError } = await readSiteContent(locale);
  if (readError) return response.status(500).json({ error: "content_unavailable" });
  const messages = isRecord(existing?.messages) ? existing.messages : {};
  const nextMessages = { ...messages, [section]: content };
  const { error } = await serviceClient
    .from("site_content")
    .upsert({ locale, messages: nextMessages, updated_at: new Date().toISOString() });

  if (error) return response.status(500).json({ error: "content_save_failed" });
  return response.json({ ok: true });
});

app.put("/api/admin/settings", requireOwner, async (request, response) => {
  const { settings } = request.body ?? {};
  if (!isRecord(settings) || Object.keys(settings).some((key) => !editableSettings.has(key))) {
    return response.status(400).json({ error: "invalid_settings" });
  }

  const validSettings = Object.values(settings).every((value) => typeof value === "string");
  if (!validSettings || [...editableSettings].some((key) => typeof settings[key] !== "string")) {
    return response.status(400).json({ error: "invalid_settings" });
  }

  const { error } = await serviceClient
    .from("site_settings")
    .upsert({ id: "main", settings, updated_at: new Date().toISOString() });

  if (error) return response.status(500).json({ error: "settings_save_failed" });
  return response.json({ ok: true });
});

app.use((error, _request, response, _next) => {
  if (error?.type === "entity.too.large") return response.status(413).json({ error: "request_too_large" });
  if (error?.type === "entity.parse.failed") return response.status(400).json({ error: "invalid_json" });
  if (error instanceof SyntaxError && "body" in error) return response.status(400).json({ error: "invalid_json" });
  console.error("Unhandled request error:", error);
  return response.status(500).json({ error: "internal_server_error" });
});

app.listen(Number(PORT), () => {
  console.log(`Rawdat ul-Huda API listening on port ${PORT}`);
});