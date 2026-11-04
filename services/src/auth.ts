// Sign-in: the app proves a character once and receives a key that stands for it from then on.
//
// The app runs the EVE sign-in itself (PKCE, an application with no scopes) and hands over the
// resulting access token. Tokens last about twenty minutes and scheduled posts run with nobody
// watching, so the token is checked, thrown away, and exchanged for a key. The key belongs to the
// app's database, not to one machine.

import type { MiddlewareHandler } from "hono";
import type { AppEnv } from "./env";
import { base64urlDecode, randomHex, sha256Hex } from "./crypto";
import { dayOf, ensureSchema, nowIso } from "./db";

const SSO_JWKS = "https://login.eveonline.com/oauth/jwks";
const SSO_ISSUERS = ["login.eveonline.com", "https://login.eveonline.com"];
const USER_AGENT = "eveconsole-services (+https://github.com/kernoeve/eveconsole-web)";

/** Signing in again adds a key; beyond this many the oldest stops working. */
const MAX_KEYS_PER_CHARACTER = 10;

interface Jwk { kid?: string; kty: string; alg?: string; n?: string; e?: string; crv?: string; x?: string; y?: string }
let jwksCache: { keys: Jwk[]; fetchedAt: number } | null = null;

async function jwks(): Promise<Jwk[]> {
  if (jwksCache && Date.now() - jwksCache.fetchedAt < 3_600_000) return jwksCache.keys;
  const r = await fetch(SSO_JWKS, { headers: { "User-Agent": USER_AGENT } });
  if (!r.ok) throw new Error(`JWKS ${r.status}`);
  const doc = await r.json<{ keys: Jwk[] }>();
  jwksCache = { keys: doc.keys, fetchedAt: Date.now() };
  return doc.keys;
}

export interface VerifiedCharacter {
  characterId: number;
  name: string;
  ownerHash: string;
}

export type TokenCheck = VerifiedCharacter | "invalid" | "has_scopes";

/**
 * Checks an EVE SSO access token: signature against EVE's published keys, issuer, expiry, and an
 * audience naming both our application and "EVE Online".
 *
 * ⚠️ The audience is what makes this a sign-in to US. Without it, any token any other EVE
 * application ever obtained for a character would sign that character in here.
 *
 * ⚠️ A token carrying scopes is refused. Those can read a character's wallet and mail, and nothing
 * here needs them; refusing means a mistake in a client can never send us one to hold.
 */
export async function checkToken(token: string, clientId: string): Promise<TokenCheck> {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return "invalid";
    const [h, p, s] = parts;
    const header = JSON.parse(new TextDecoder().decode(base64urlDecode(h))) as { alg: string; kid?: string };
    const keys = await jwks();
    const jwk = keys.find((k) => k.kid === header.kid);
    if (!jwk) return "invalid";

    const data = new TextEncoder().encode(`${h}.${p}`);
    const sig = base64urlDecode(s);
    let ok = false;
    if (header.alg === "RS256" && jwk.kty === "RSA") {
      const key = await crypto.subtle.importKey("jwk", jwk as JsonWebKey, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
      ok = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, sig, data);
    } else if (header.alg === "ES256" && jwk.kty === "EC") {
      const key = await crypto.subtle.importKey("jwk", jwk as JsonWebKey, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
      ok = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, sig, data);
    }
    if (!ok) return "invalid";

    const claims = JSON.parse(new TextDecoder().decode(base64urlDecode(p))) as {
      sub?: string; name?: string; owner?: string; iss?: string; aud?: string | string[]; exp?: number; scp?: string | string[];
    };
    if (!claims.exp || claims.exp * 1000 < Date.now()) return "invalid";
    if (!claims.iss || !SSO_ISSUERS.includes(claims.iss)) return "invalid";
    const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    if (!aud.includes(clientId) || !aud.includes("EVE Online")) return "invalid";

    const match = /^CHARACTER:EVE:(\d+)$/.exec(claims.sub ?? "");
    if (!match) return "invalid";

    if (claims.scp && claims.scp.length > 0) return "has_scopes";

    return { characterId: Number(match[1]), name: String(claims.name ?? ""), ownerHash: String(claims.owner ?? "") };
  } catch (e) {
    // EVE's keys could not be read: not the caller's fault, and not a verdict on the token.
    if (e instanceof Error && e.message.startsWith("JWKS")) throw e;
    return "invalid";
  }
}

export type SignIn = { key: string } | "banned";

/** The character is on file and holds a new key, or is refused. */
export async function signIn(db: D1Database, who: VerifiedCharacter): Promise<SignIn> {
  await ensureSchema(db);
  const now = nowIso();

  const banned = await db.prepare(`SELECT banned_at FROM characters WHERE character_id = ?1`)
    .bind(who.characterId).first<{ banned_at: string | null }>();
  if (banned?.banned_at) return "banned";

  const key = `ecs_${randomHex(32)}`;
  await db.batch([
    db.prepare(`INSERT INTO characters (character_id, name, owner_hash, first_seen, last_sign_in) VALUES (?1, ?2, ?3, ?4, ?4)
                ON CONFLICT (character_id) DO UPDATE SET name = ?2, owner_hash = ?3, last_sign_in = ?4`)
      .bind(who.characterId, who.name, who.ownerHash, now),
    db.prepare(`INSERT INTO api_keys (key_hash, character_id, created_at, last_used) VALUES (?1, ?2, ?3, ?3)`)
      .bind(await sha256Hex(key), who.characterId, now),
    db.prepare(`DELETE FROM api_keys WHERE character_id = ?1 AND key_hash NOT IN
                (SELECT key_hash FROM api_keys WHERE character_id = ?1 ORDER BY created_at DESC, key_hash LIMIT ?2)`)
      .bind(who.characterId, MAX_KEYS_PER_CHARACTER),
  ]);
  return { key };
}

/** Every call but sign-in: a key, and a character who is not banned. */
export const requireKey: MiddlewareHandler<AppEnv> = async (c, next) => {
  const header = c.req.header("Authorization") ?? "";
  const key = header.startsWith("Bearer ") ? header.slice(7).trim() : "";
  if (!key) return c.json({ error: "not_signed_in", message: "Sign in first." }, 401);

  await ensureSchema(c.env.DB);
  const keyHash = await sha256Hex(key);
  const row = await c.env.DB.prepare(
    `SELECT k.character_id, k.last_used, c.name, c.banned_at
     FROM api_keys k JOIN characters c ON c.character_id = k.character_id WHERE k.key_hash = ?1`,
  ).bind(keyHash).first<{ character_id: number; last_used: string; name: string; banned_at: string | null }>();

  if (!row) return c.json({ error: "not_signed_in", message: "This key is not valid. Sign in again." }, 401);
  if (row.banned_at) return c.json({ error: "banned", message: "This character may not use this service." }, 403);

  const now = nowIso();
  if (dayOf(row.last_used) !== dayOf(now)) {
    await c.env.DB.prepare(`UPDATE api_keys SET last_used = ?2 WHERE key_hash = ?1`).bind(keyHash, now).run();
  }

  c.set("caller", { characterId: row.character_id, characterName: row.name, keyHash });
  await next();
};
