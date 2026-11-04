// The calls the EVE Console app makes on eveconsole.com. README.md describes them.
//
// Two addresses, one Worker. api.* takes the app's calls and img.* only ever serves stored images,
// so nothing uploaded shares an address with anything that matters.

import { Hono, type Context } from "hono";
import { checkToken, requireKey, signIn } from "./auth";
import { timingSafeEqual } from "./crypto";
import { ensureSchema, usage } from "./db";
import { limits, type AppEnv, type Bindings } from "./env";
import { inspectImage } from "./image-format";
import {
  ban, deleteImages, fetchImage, imageUrl, listImages, ownerOf, purgeExpired, storeImage, takeDown, unban,
  type StoredImage,
} from "./images";

const app = new Hono<AppEnv>();

const IMAGE_ID = /^[0-9a-f]{32}$/;
const MAX_DELETE_IDS = 90;
const MAX_LIST_PAGE = 200;

const fail = (c: Context<AppEnv>, status: 400 | 401 | 403 | 404 | 409 | 413 | 415 | 429 | 502, error: string, message: string, extra: object = {}) =>
  c.json({ error, message, ...extra }, status);

const shown = (c: Context<AppEnv>, image: StoredImage) => ({ ...image, url: imageUrl(c.env.IMAGE_HOST, image.id, image.type) });

// ── The image address serves images and nothing else ─────────────────────────

app.use("*", async (c, next) => {
  if (new URL(c.req.url).hostname !== c.env.IMAGE_HOST) return next();

  const match = /^\/([0-9a-f]{32})\.(png|jpg)$/.exec(new URL(c.req.url).pathname);
  if (!match || (c.req.method !== "GET" && c.req.method !== "HEAD")) return c.notFound();

  const object = await fetchImage(c.env.IMAGES, match[1]);
  const type = object?.httpMetadata?.contentType;
  if (!object || (type === "image/png" ? "png" : "jpg") !== match[2]) return c.notFound();

  // ⚠️ The type is the one found in the bytes at upload, and nothing here lets a browser treat an
  // upload as anything but a picture.
  return new Response(c.req.method === "HEAD" ? null : object.body, {
    headers: {
      "Content-Type": type ?? "application/octet-stream",
      "Content-Length": String(object.size),
      "Cache-Control": "public, max-age=3600",
      "ETag": object.httpEtag,
      "X-Content-Type-Options": "nosniff",
      "Content-Security-Policy": "default-src 'none'; sandbox",
      "X-Robots-Tag": "noindex",
    },
  });
});

// ── Sign-in ──────────────────────────────────────────────────────────────────

app.get("/", (c) => c.json({ service: "eveconsole-services", version: c.env.SERVICE_VERSION }));

app.post("/v1/auth/eve", async (c) => {
  const body = await c.req.json<{ accessToken?: unknown }>().catch(() => null);
  if (typeof body?.accessToken !== "string" || body.accessToken.length > 16_384)
    return fail(c, 400, "bad_request", "Send the EVE access token as accessToken.");

  let who;
  try {
    who = await checkToken(body.accessToken, c.env.EVE_CLIENT_ID);
  } catch {
    return fail(c, 502, "eve_unavailable", "EVE's sign-in keys could not be read. Try again shortly.");
  }
  if (who === "has_scopes") return fail(c, 400, "token_has_scopes", "Sign-in needs a token with no scopes.");
  if (who === "invalid") return fail(c, 401, "invalid_token", "This EVE token could not be verified.");

  const result = await signIn(c.env.DB, who);
  if (result === "banned") return fail(c, 403, "banned", "This character may not use this service.");

  return c.json({
    key: result.key,
    character: { id: who.characterId, name: who.name },
    limits: limits(c.env),
    usage: await usage(c.env.DB, who.characterId),
  });
});

app.post("/v1/auth/sign-out", requireKey, async (c) => {
  await c.env.DB.prepare(`DELETE FROM api_keys WHERE key_hash = ?1`).bind(c.get("caller").keyHash).run();
  return c.json({ signedOut: true });
});

app.get("/v1/me", requireKey, async (c) => {
  const caller = c.get("caller");
  return c.json({
    character: { id: caller.characterId, name: caller.characterName },
    limits: limits(c.env),
    usage: await usage(c.env.DB, caller.characterId),
  });
});

// ── Images ───────────────────────────────────────────────────────────────────

app.post("/v1/images", requireKey, async (c) => {
  const caller = c.get("caller");
  const cap = limits(c.env);

  const asked = c.req.query("expiresInDays");
  const days = asked === undefined ? cap.maxExpiresInDays : Number(asked);
  if (!Number.isInteger(days) || days < 1 || days > cap.maxExpiresInDays)
    return fail(c, 400, "bad_expiry", `expiresInDays must be a whole number from 1 to ${cap.maxExpiresInDays}.`);

  const bytes = await readCapped(c.req.raw, cap.maxImageBytes);
  if (bytes === "too_large")
    return fail(c, 413, "image_too_large", `An image can be at most ${cap.maxImageBytes} bytes.`, { maxImageBytes: cap.maxImageBytes });
  if (bytes.length === 0) return fail(c, 400, "bad_request", "Send the image as the request body.");

  const info = inspectImage(bytes);
  if (!info) return fail(c, 415, "not_an_image", "Only PNG and JPEG images can be uploaded.");

  const stored = await storeImage(c.env.DB, c.env.IMAGES, caller.characterId, bytes, info, days, cap);
  if (stored === "daily_limit" || stored === "storage_limit") {
    const now = await usage(c.env.DB, caller.characterId);
    if (stored === "daily_limit") {
      c.header("Retry-After", String(secondsToNextUtcDay()));
      return fail(c, 429, "daily_limit", `At most ${cap.maxUploadsPerDay} uploads a day.`, { limits: cap, usage: now });
    }
    return fail(c, 409, "storage_limit", "This image would go over the storage limit. Delete some images first.", { limits: cap, usage: now });
  }

  return c.json({ ...shown(c, stored), usage: await usage(c.env.DB, caller.characterId) }, 201);
});

app.get("/v1/images", requireKey, async (c) => {
  const caller = c.get("caller");
  const asked = Number(c.req.query("limit") ?? 100);
  const limit = Number.isInteger(asked) && asked >= 1 ? Math.min(asked, MAX_LIST_PAGE) : 100;

  const page = await listImages(c.env.DB, caller.characterId, limit, c.req.query("cursor") ?? null);
  return c.json({
    images: page.images.map((i) => shown(c, i)),
    nextCursor: page.nextCursor,
    limits: limits(c.env),
    usage: await usage(c.env.DB, caller.characterId),
  });
});

app.post("/v1/images/delete", requireKey, async (c) => {
  const caller = c.get("caller");
  const body = await c.req.json<{ ids?: unknown }>().catch(() => null);
  const ids = body?.ids;
  if (!Array.isArray(ids) || ids.length === 0 || ids.length > MAX_DELETE_IDS || !ids.every((i) => typeof i === "string" && IMAGE_ID.test(i)))
    return fail(c, 400, "bad_request", `Send ids: from 1 to ${MAX_DELETE_IDS} image ids.`);

  const result = await deleteImages(c.env.DB, c.env.IMAGES, caller.characterId, ids as string[]);
  return c.json({ ...result, usage: await usage(c.env.DB, caller.characterId) });
});

// ── Takedowns and bans: no screen, just these ────────────────────────────────

const admin = new Hono<AppEnv>();

admin.use("*", async (c, next) => {
  const expected = c.env.ADMIN_TOKEN;
  const given = (c.req.header("Authorization") ?? "").replace(/^Bearer /, "");
  if (!expected || !timingSafeEqual(expected, given)) return c.notFound();
  await ensureSchema(c.env.DB);
  await next();
});

admin.get("/images/:id", async (c) => {
  const found = await ownerOf(c.env.DB, c.req.param("id"));
  return found ? c.json(found) : c.notFound();
});

admin.post("/images/:id/take-down", async (c) => {
  return (await takeDown(c.env.DB, c.env.IMAGES, c.req.param("id"))) ? c.json({ removed: true }) : c.notFound();
});

admin.post("/characters/:id/ban", async (c) => {
  const id = Number(c.req.param("id"));
  if (!Number.isInteger(id) || id <= 0) return fail(c, 400, "bad_request", "That is not a character id.");
  const body = await c.req.json<{ reason?: unknown }>().catch(() => null);
  const removed = await ban(c.env.DB, c.env.IMAGES, id, typeof body?.reason === "string" ? body.reason : "");
  return c.json({ banned: true, imagesRemoved: removed });
});

admin.post("/characters/:id/unban", async (c) => {
  const id = Number(c.req.param("id"));
  if (!Number.isInteger(id) || id <= 0) return fail(c, 400, "bad_request", "That is not a character id.");
  await unban(c.env.DB, id);
  return c.json({ banned: false });
});

app.route("/v1/admin", admin);

app.onError((err, c) => {
  console.error(err);
  return c.json({ error: "server_error", message: "Something went wrong on the site." }, 500);
});

app.notFound((c) => c.json({ error: "not_found", message: "Not found." }, 404));

// ── Helpers ──────────────────────────────────────────────────────────────────

/** The body, stopping as soon as it passes the limit rather than holding all of it first. */
async function readCapped(request: Request, max: number): Promise<Uint8Array | "too_large"> {
  if (Number(request.headers.get("Content-Length") ?? 0) > max) return "too_large";
  if (!request.body) return new Uint8Array();

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > max) {
      await reader.cancel();
      return "too_large";
    }
    chunks.push(value);
  }

  const bytes = new Uint8Array(total);
  let at = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, at);
    at += chunk.length;
  }
  return bytes;
}

function secondsToNextUtcDay(): number {
  const now = new Date();
  return Math.ceil((Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1) - now.getTime()) / 1000);
}

export default {
  fetch: app.fetch,
  async scheduled(_event: ScheduledController, env: Bindings, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil((async () => {
      await ensureSchema(env.DB);
      await purgeExpired(env.DB, env.IMAGES);
    })());
  },
};

export { app };
