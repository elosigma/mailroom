import type { Context, MiddlewareHandler } from "hono";
import { getCookie, setCookie, deleteCookie } from "hono/cookie";
import { createRemoteJWKSet, decodeJwt, errors, SignJWT, jwtVerify } from "jose";

export interface WebAccessEnv {
  WEB_ACCESS_TEAM_DOMAIN?: string;
  WEB_ACCESS_AUD?: string;
  RESEND_API_KEY?: string;
  DB?: D1Database;
}

export interface AccessIdentity {
  email: string;
  sub: string;
  role: "admin" | "user";
  mailboxId: number | null;
}

export type AccessFailureCode =
  | "access_not_configured"
  | "access_missing"
  | "access_invalid"
  | "access_forbidden"
  | "access_unavailable";

export interface AccessHint {
  team_domain: string;
  aud: string;
}

export type AccessResult =
  | { ok: true; identity: AccessIdentity }
  | { ok: false; status: 401 | 403 | 503; code: AccessFailureCode; error: string; hint?: AccessHint };

export const SESSION_COOKIE_NAME = "mailroom_session";

function sessionSecret(env: WebAccessEnv): Uint8Array {
  const seed =
    env.RESEND_API_KEY ||
    env.WEB_ACCESS_AUD ||
    "mailroom-antekch-uk-default-session-secret-2026";
  return new TextEncoder().encode(`mailroom-jwt-v1:${seed}`);
}

export async function signSessionToken(
  identity: AccessIdentity,
  env: WebAccessEnv,
): Promise<string> {
  return new SignJWT({
    email: identity.email,
    role: identity.role,
    mailboxId: identity.mailboxId,
  })
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(identity.sub)
    .setIssuedAt()
    .setExpirationTime("30d")
    .sign(sessionSecret(env));
}

export async function verifySessionToken(
  token: string | null | undefined,
  env: WebAccessEnv,
): Promise<AccessIdentity | null> {
  if (!token) return null;
  try {
    const { payload } = await jwtVerify(token, sessionSecret(env), {
      algorithms: ["HS256"],
    });
    if (typeof payload.email !== "string" || typeof payload.sub !== "string") {
      return null;
    }
    const role = payload.role === "admin" ? "admin" : "user";
    const mailboxId =
      typeof payload.mailboxId === "number" ? payload.mailboxId : null;
    return {
      email: payload.email,
      sub: payload.sub,
      role,
      mailboxId,
    };
  } catch {
    return null;
  }
}

export async function hashPassword(password: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(`mailroom-pw-v1:${password.trim()}`),
  );
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

let schemaReady = false;

export async function ensureAuthSchema(db: D1Database): Promise<void> {
  if (schemaReady) return;
  await db
    .prepare(
      `CREATE TABLE IF NOT EXISTS mailbox_passwords (
         address TEXT PRIMARY KEY COLLATE NOCASE,
         password_hash TEXT NOT NULL,
         plain_password TEXT NOT NULL,
         updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
       )`,
    )
    .run();
  const defaults: Array<[string, string]> = [
    ["admin@antekch.uk", "Antek2026!"],
    ["antek@antekch.uk", "Antek2026!"],
    ["ola@antekch.uk", "Ola2026!"],
    ["kasia@antekch.uk", "Kasia2026!"],
  ];
  for (const [address, plain] of defaults) {
    const hash = await hashPassword(plain);
    await db
      .prepare(
        `INSERT OR IGNORE INTO mailbox_passwords (address, password_hash, plain_password)
         VALUES (?, ?, ?)`,
      )
      .bind(address, hash, plain)
      .run();
  }
  schemaReady = true;
}

const keySets = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

/** Verify Access's signed assertion, or built-in session token. */
export async function verifyWebAccess(
  token: string | null | undefined,
  env: WebAccessEnv,
  cookieHeader?: string | null,
): Promise<AccessResult> {
  if (cookieHeader) {
    const match = cookieHeader.match(new RegExp(`(?:^|;\\s*)${SESSION_COOKIE_NAME}=([^;]+)`));
    if (match?.[1]) {
      const session = await verifySessionToken(decodeURIComponent(match[1]), env);
      if (session) return { ok: true, identity: session };
    }
  }
  const issuer = accessIssuer(env.WEB_ACCESS_TEAM_DOMAIN);
  const audience = env.WEB_ACCESS_AUD?.trim();
  if (!issuer || !audience) {
    return failure(401, "access_missing", "Zaloguj się do skrzynki pocztowej", token);
  }
  if (!token) return failure(401, "access_missing", "Zaloguj się do skrzynki pocztowej");

  let jwks = keySets.get(issuer);
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(`${issuer}/cdn-cgi/access/certs`));
    keySets.set(issuer, jwks);
  }
  try {
    const { payload } = await jwtVerify(token, jwks, {
      issuer,
      audience,
      algorithms: ["RS256"],
      requiredClaims: ["exp", "sub", "email", "type"],
    });
    if (
      payload.type !== "app" ||
      typeof payload.sub !== "string" || !payload.sub.trim() ||
      typeof payload.email !== "string" || !payload.email.trim()
    ) {
      return failure(403, "access_forbidden", "An Access user identity is required");
    }
    const cfEmail = payload.email.trim().toLowerCase();
    const isAdmin =
      cfEmail === "antek@antekch.uk" ||
      cfEmail === "admin@antekch.uk" ||
      cfEmail === "antekchlebek8@gmail.com";
    let mailboxId: number | null = null;
    if (!isAdmin && env.DB) {
      const mb = await env.DB.prepare("SELECT id FROM mailboxes WHERE LOWER(address) = ?")
        .bind(cfEmail)
        .first<{ id: number }>();
      mailboxId = mb?.id ?? -1;
    }
    return {
      ok: true,
      identity: {
        email: cfEmail,
        sub: payload.sub,
        role: isAdmin ? "admin" : "user",
        mailboxId,
      },
    };
  } catch (error) {
    if (error instanceof TypeError || error instanceof errors.JWKSTimeout ||
        (error instanceof errors.JOSEError && error.code === "ERR_JOSE_GENERIC")) {
      return failure(503, "access_unavailable", "Authentication service unavailable");
    }
    return failure(401, "access_invalid", "Invalid or expired Access assertion", token);
  }
}

export function getAuthIdentity(c: Context): AccessIdentity | null {
  return ((c as unknown as { get(key: string): AccessIdentity | undefined }).get("authIdentity")) ?? null;
}

export const requireWebAccess: MiddlewareHandler<{ Bindings: WebAccessEnv }> = async (c, next) => {
  c.header("Cache-Control", "private, no-store");
  const path = new URL(c.req.url).pathname;
  if (path === "/api/auth/login" || path === "/api/auth/logout") {
    await next();
    return;
  }

  const cookieToken = getCookie(c, SESSION_COOKIE_NAME);
  const session = await verifySessionToken(cookieToken, c.env);
  if (session) {
    (c as unknown as { set(key: string, value: AccessIdentity): void }).set("authIdentity", session);
    await next();
    return;
  }

  const cfToken = c.req.header("Cf-Access-Jwt-Assertion");
  if (cfToken) {
    const result = await verifyWebAccess(cfToken, c.env);
    if (result.ok) {
      (c as unknown as { set(key: string, value: AccessIdentity): void }).set("authIdentity", result.identity);
      await next();
      return;
    }
  }

  return c.json(
    {
      error: "Zaloguj się, aby uzyskać dostęp do poczty",
      code: "access_missing",
    },
    401,
  );
};

export { setCookie, deleteCookie };

function failure(
  status: 401 | 403 | 503,
  code: AccessFailureCode,
  error: string,
  token?: string | null,
): AccessResult {
  const hint = token ? accessHint(token) : undefined;
  return { ok: false, status, code, error, ...(hint ? { hint } : {}) };
}

function accessHint(token: string): AccessHint | undefined {
  try {
    const { iss, aud } = decodeJwt(token);
    const teamDomain = accessIssuer(iss);
    const audience = Array.isArray(aud) ? aud[0] : aud;
    if (!teamDomain || typeof audience !== "string" || !/^[a-f0-9]{64}$/.test(audience)) {
      return undefined;
    }
    return { team_domain: teamDomain, aud: audience };
  } catch {
    return undefined;
  }
}

function accessIssuer(value: string | undefined): string | null {
  if (!value) return null;
  try {
    const url = new URL(value);
    if (
      url.protocol !== "https:" ||
      !/^[a-z0-9-]+\.cloudflareaccess\.com$/.test(url.hostname) ||
      url.port || url.username || url.password || url.search || url.hash ||
      url.pathname !== "/"
    ) return null;
    return url.origin;
  } catch {
    return null;
  }
}
