const SESSION_DURATION = 7 * 24 * 60 * 60;
const PBKDF2_ITERATIONS = 310000;

const COOKIE_NAME = "__Host-videocash_session";

const SECURITY_HEADERS = {
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "same-origin",
  "X-Frame-Options": "DENY"
};

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...SECURITY_HEADERS,
      ...extraHeaders
    }
  });
}

function cookieHeaders(value, maxAge = SESSION_DURATION) {
  return {
    "Set-Cookie":
      `${COOKIE_NAME}=${value}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`
  };
}

function clearSessionCookie() {
  return {
    "Set-Cookie":
      `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`
  };
}

function randomToken(bytes = 32) {
  const data = crypto.getRandomValues(new Uint8Array(bytes));

  return Array.from(data)
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");
}

function toBase64(bytes) {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary);
}

function fromBase64(value) {
  const binary = atob(value);

  return Uint8Array.from(binary, char => char.charCodeAt(0));
}

async function hashPassword(password, saltBytes = null) {
  const salt = saltBytes || crypto.getRandomValues(new Uint8Array(16));

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256"
    },
    key,
    256
  );

  return {
    hash: toBase64(new Uint8Array(bits)),
    salt: toBase64(salt)
  };
}

async function verifyPassword(password, storedValue) {
  try {
    const parts = storedValue.split("$");

    if (
      parts.length !== 4 ||
      parts[0] !== "pbkdf2" ||
      parts[1] !== String(PBKDF2_ITERATIONS)
    ) {
      return false;
    }

    const salt = fromBase64(parts[2]);
    const result = await hashPassword(password, salt);

    const actual = fromBase64(result.hash);
    const expected = fromBase64(parts[3]);

    if (actual.length !== expected.length) {
      return false;
    }

    let difference = 0;

    for (let i = 0; i < actual.length; i++) {
      difference |= actual[i] ^ expected[i];
    }

    return difference === 0;
  } catch {
    return false;
  }
}

async function createPasswordRecord(password) {
  const result = await hashPassword(password);

  return `pbkdf2$${PBKDF2_ITERATIONS}$${result.salt}$${result.hash}`;
}

function getCookie(request, name) {
  const header = request.headers.get("Cookie") || "";

  for (const item of header.split(";")) {
    const separator = item.indexOf("=");

    if (separator === -1) continue;

    const key = item.slice(0, separator).trim();
    const value = item.slice(separator + 1).trim();

    if (key === name) {
      return value;
    }
  }

  return null;
}

function isValidUsername(username) {
  return /^[a-zA-Z0-9_]{3,24}$/.test(username);
}

function normalizeEmail(email) {
  return email.trim().toLowerCase();
}

function isValidEmail(email) {
  return (
    email.length <= 254 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
  );
}

function validPassword(password) {
  return (
    typeof password === "string" &&
    password.length >= 12 &&
    password.length <= 128
  );
}

function sameOrigin(request) {
  const origin = request.headers.get("Origin");

  if (!origin) {
    return false;
  }

  try {
    return new URL(origin).origin === new URL(request.url).origin;
  } catch {
    return false;
  }
}

async function readJson(request) {
  const contentType = request.headers.get("Content-Type") || "";

  if (!contentType.toLowerCase().includes("application/json")) {
    return null;
  }

  const length = Number(request.headers.get("Content-Length") || 0);

  if (length > 10000) {
    return null;
  }

  try {
    const text = await request.text();

    if (text.length > 10000) {
      return null;
    }

    return JSON.parse(text);
  } catch {
    return null;
  }
}

async function createSession(env, userId) {
  const token = randomToken();
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = now + SESSION_DURATION;

  // Only the hash of the session token is stored in the database.
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(token)
  );

  const sessionId = Array.from(new Uint8Array(digest))
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");

  await env.DB.prepare(
    `INSERT INTO sessions (id, user_id, expires_at)
     VALUES (?, ?, ?)`
  ).bind(sessionId, userId, expiresAt).run();

  return token;
}

async function getCurrentUser(request, env) {
  const token = getCookie(request, COOKIE_NAME);

  if (!token || !/^[a-f0-9]{64}$/.test(token)) {
    return null;
  }

  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(token)
  );

  const sessionId = Array.from(new Uint8Array(digest))
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");

  const now = Math.floor(Date.now() / 1000);

  const result = await env.DB.prepare(
    `SELECT
       users.id,
       users.username,
       users.email,
       users.balance,
       users.total_earned,
       users.plan
     FROM sessions
     INNER JOIN users ON users.id = sessions.user_id
     WHERE sessions.id = ?
       AND sessions.expires_at > ?`
  ).bind(sessionId, now).first();

  return result || null;
}

async function requirePost(request) {
  if (request.method !== "POST") {
    return json(
      { success: false, error: "Method not allowed" },
      405,
      { Allow: "POST" }
    );
  }

  if (!sameOrigin(request)) {
    return json(
      { success: false, error: "Invalid request origin" },
      403
    );
  }

  return null;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    try {
      // Serve the existing website.
      if (path === "/" && request.method === "GET") {
        return env.ASSETS.fetch(request);
      }

      // Health check.
      if (path === "/api/health" && request.method === "GET") {
        const result = await env.DB
          .prepare("SELECT 1 AS connected")
          .first();

        return json({
          success: true,
          project: "VideoCash-New",
          database: result?.connected === 1
            ? "connected"
            : "unknown"
        });
      }

      // Public configuration.
      if (path === "/api/config" && request.method === "GET") {
        return json({
          success: true,
          project: "VideoCash-New",
          languages: ["en", "ru"],
          platforms: [
            "Facebook",
            "Instagram",
            "WhatsApp",
            "X",
            "Telegram",
            "Snapchat",
            "Likee",
            "TikTok",
            "VK",
            "LinkedIn",
            "Threads",
            "Quora",
            "Pinterest",
            "YouTube"
          ],
          registrationEnabled: true,
          rewardsEnabled: false,
          withdrawalsEnabled: false
        });
      }

      // Register a new account.
      if (path === "/api/register") {
        const postError = await requirePost(request);

        if (postError) return postError;

        const body = await readJson(request);

        if (!body) {
          return json({
            success: false,
            error: "Invalid JSON request"
          }, 400);
        }

        const username = String(body.username || "").trim();
        const email = normalizeEmail(String(body.email || ""));
        const password = body.password;

        if (!isValidUsername(username)) {
          return json({
            success: false,
            error: "Username must be 3-24 characters using letters, numbers or underscores"
          }, 400);
        }

        if (!isValidEmail(email)) {
          return json({
            success: false,
            error: "Please enter a valid email address"
          }, 400);
        }

        if (!validPassword(password)) {
          return json({
            success: false,
            error: "Password must be 12-128 characters"
          }, 400);
        }

        const existing = await env.DB.prepare(
          "SELECT id FROM users WHERE username = ? COLLATE NOCASE OR email = ? LIMIT 1"
        ).bind(username, email).first();

        if (existing) {
          return json({
            success: false,
            error: "Username or email is already registered"
          }, 409);
        }

        const passwordRecord = await createPasswordRecord(password);

        const insert = await env.DB.prepare(
          `INSERT INTO users
            (username, email, password_hash, balance, total_earned, plan)
           VALUES (?, ?, ?, 0, 0, 'free')`
        ).bind(username, email, passwordRecord).run();

        const userId = insert.meta.last_row_id;
        const token = await createSession(env, userId);

        return json({
          success: true,
          message: "Account created successfully",
          user: {
            id: userId,
            username,
            email,
            balance: 0,
            total_earned: 0,
            plan: "free"
          }
        }, 201, cookieHeaders(token));
      }

      // Login.
      if (path === "/api/login") {
        const postError = await requirePost(request);

        if (postError) return postError;

        const body = await readJson(request);

        if (!body) {
          return json({
            success: false,
            error: "Invalid JSON request"
          }, 400);
        }

        const identifier = String(body.identifier || "")
          .trim()
          .toLowerCase();

        const password = body.password;

        if (
          !identifier ||
          typeof password !== "string" ||
          password.length > 128
        ) {
          return json({
            success: false,
            error: "Invalid email/username or password"
          }, 400);
        }

        const user = await env.DB.prepare(
          `SELECT id, username, email, password_hash,
                  balance, total_earned, plan
           FROM users
           WHERE lower(username) = ? OR email = ?
           LIMIT 1`
        ).bind(identifier, identifier).first();

        if (
          !user ||
          !(await verifyPassword(password, user.password_hash))
        ) {
          return json({
            success: false,
            error: "Invalid email/username or password"
          }, 401);
        }

        const token = await createSession(env, user.id);

        return json({
          success: true,
          message: "Login successful",
          user: {
            id: user.id,
            username: user.username,
            email: user.email,
            balance: user.balance,
            total_earned: user.total_earned,
            plan: user.plan
          }
        }, 200, cookieHeaders(token));
      }

      // Current authenticated account.
      if (path === "/api/me" && request.method === "GET") {
        const user = await getCurrentUser(request, env);

        if (!user) {
          return json({
            success: false,
            error: "Not authenticated"
          }, 401);
        }

        return json({
          success: true,
          user
        });
      }

      // Logout.
      if (path === "/api/logout") {
        const postError = await requirePost(request);

        if (postError) return postError;

        const token = getCookie(request, COOKIE_NAME);

        if (token && /^[a-f0-9]{64}$/.test(token)) {
          const digest = await crypto.subtle.digest(
            "SHA-256",
            new TextEncoder().encode(token)
          );

          const sessionId = Array.from(new Uint8Array(digest))
            .map(byte => byte.toString(16).padStart(2, "0"))
            .join("");

          await env.DB.prepare(
            "DELETE FROM sessions WHERE id = ?"
          ).bind(sessionId).run();
        }

        return json({
          success: true,
          message: "Logged out"
        }, 200, clearSessionCookie());
      }

      return json({
        success: false,
        error: "Not found"
      }, 404);

    } catch (error) {
      // Do not expose internal database errors or secrets to visitors.
      console.error("VideoCash-New request failed:", error?.message);

      return json({
        success: false,
        error: "Internal server error"
      }, 500);
    }
  }
};