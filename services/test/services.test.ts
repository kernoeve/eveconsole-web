import { beforeAll, describe, expect, it, vi } from "vitest";
import { createExecutionContext, env, waitOnExecutionContext } from "cloudflare:test";
import worker, { app } from "../src/index";
import { ensureSchema } from "../src/db";
import { inspectImage } from "../src/image-format";
import { purgeExpired } from "../src/images";

const API = "https://api.test";
const IMG = "https://img.test";
const ADMIN = { Authorization: "Bearer test-admin-token-do-not-use" };

// ── A real signature, checked the real way: only the fetch of EVE's keys is faked ──

let rsa: CryptoKeyPair;
let es: CryptoKeyPair;
let wrong: CryptoKeyPair;

const b64 = (s: string) => btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const b64b = (b: ArrayBuffer) => b64(String.fromCharCode(...new Uint8Array(b)));

async function jwt(claims: object, opts: { kid?: string; alg?: "RS256" | "ES256"; signer?: CryptoKey } = {}): Promise<string> {
  const alg = opts.alg ?? "RS256";
  const head = b64(JSON.stringify({ alg, kid: opts.kid ?? (alg === "RS256" ? "rsa-key" : "ec-key"), typ: "JWT" }));
  const body = b64(JSON.stringify(claims));
  const data = new TextEncoder().encode(`${head}.${body}`);
  const key = opts.signer ?? (alg === "RS256" ? rsa.privateKey : es.privateKey);
  const sig = alg === "RS256"
    ? await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, data)
    : await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, data);
  return `${head}.${body}.${b64b(sig)}`;
}

const claimsFor = (id: number, over: object = {}) => ({
  sub: `CHARACTER:EVE:${id}`,
  name: `Pilot ${id}`,
  owner: `owner-${id}`,
  iss: "https://login.eveonline.com",
  aud: ["test-client", "EVE Online"],
  exp: Math.floor(Date.now() / 1000) + 600,
  ...over,
});

beforeAll(async () => {
  rsa = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]) as CryptoKeyPair;
  es = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]) as CryptoKeyPair;
  wrong = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]) as CryptoKeyPair;
  const rsaJwk = await crypto.subtle.exportKey("jwk", rsa.publicKey) as JsonWebKey;
  const esJwk = await crypto.subtle.exportKey("jwk", es.publicKey) as JsonWebKey;

  const real = globalThis.fetch;
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (url === "https://login.eveonline.com/oauth/jwks")
      return Response.json({ keys: [{ ...rsaJwk, kid: "rsa-key", alg: "RS256" }, { ...esJwk, kid: "ec-key", alg: "ES256" }] });
    return real(input, init);
  });
});

// ── Pictures ──────────────────────────────────────────────────────────────────

function chunk(name: string, data: number[] = []): number[] {
  const n = data.length;
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255, ...[...name].map((c) => c.charCodeAt(0)), ...data, 0, 0, 0, 0];
}

function png(width = 2, height = 3, padding = 0): Uint8Array {
  const u32 = (v: number) => [(v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255];
  return new Uint8Array([
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
    ...chunk("IHDR", [...u32(width), ...u32(height), 8, 6, 0, 0, 0]),
    ...chunk("IDAT", new Array(padding + 4).fill(7)),
    ...chunk("IEND"),
  ]);
}

function jpeg(width = 640, height = 480): Uint8Array {
  return new Uint8Array([
    0xff, 0xd8,
    0xff, 0xe0, 0x00, 0x04, 0x4a, 0x46,                                // APP0
    0xff, 0xc0, 0x00, 0x08, 0x08, height >> 8, height & 255, width >> 8, width & 255, 0x03,  // frame
    0xff, 0xda, 0x00, 0x02, 0x11, 0x22, 0x33,                          // scan
    0xff, 0xd9,
  ]);
}

// ── Calls ─────────────────────────────────────────────────────────────────────

const call = (url: string, init: RequestInit = {}) => app.request(url, init, env);

async function signedIn(id: number): Promise<string> {
  const r = await call(`${API}/v1/auth/eve`, { method: "POST", body: JSON.stringify({ accessToken: await jwt(claimsFor(id)) }) });
  expect(r.status).toBe(200);
  return (await r.json<{ key: string }>()).key;
}

const bearer = (key: string) => ({ Authorization: `Bearer ${key}` });

const upload = (key: string, body: BodyInit, query = "") =>
  call(`${API}/v1/images${query}`, { method: "POST", headers: bearer(key), body });

const signInStatus = async (token: string) =>
  (await call(`${API}/v1/auth/eve`, { method: "POST", body: JSON.stringify({ accessToken: token }) })).status;

// ── Sign-in ───────────────────────────────────────────────────────────────────

describe("sign-in", () => {
  it("an RS256 or ES256 token with no scopes gets a key, a character, limits and usage", async () => {
    const r = await call(`${API}/v1/auth/eve`, { method: "POST", body: JSON.stringify({ accessToken: await jwt(claimsFor(1001)) }) });
    expect(r.status).toBe(200);
    const body = await r.json<any>();
    expect(body.key).toMatch(/^ecs_[0-9a-f]{64}$/);
    expect(body.character).toEqual({ id: 1001, name: "Pilot 1001" });
    expect(body.limits.maxStoredBytes).toBe(10240);
    expect(body.usage).toEqual({ storedBytes: 0, activeImages: 0, uploadsToday: 0 });

    expect(await signInStatus(await jwt(claimsFor(1002), { alg: "ES256" }))).toBe(200);
  });

  it("only the key's hash is stored", async () => {
    const key = await signedIn(1003);
    const rows = await env.DB.prepare(`SELECT key_hash FROM api_keys WHERE character_id = 1003`).all<{ key_hash: string }>();
    expect(rows.results.length).toBe(1);
    expect(rows.results[0].key_hash).not.toContain(key.slice(4));
  });

  it("refuses a token issued to another application, even one signed by EVE", async () => {
    expect(await signInStatus(await jwt(claimsFor(1004, { aud: ["another-app", "EVE Online"] })))).toBe(401);
    expect(await signInStatus(await jwt(claimsFor(1004, { aud: ["test-client"] })))).toBe(401);
  });

  it("refuses a token with scopes, so one can never be sent here by mistake", async () => {
    const r = await call(`${API}/v1/auth/eve`, { method: "POST", body: JSON.stringify({ accessToken: await jwt(claimsFor(1005, { scp: ["esi-wallet.read_character_wallet.v1"] })) }) });
    expect(r.status).toBe(400);
    expect((await r.json<any>()).error).toBe("token_has_scopes");
    expect(await signInStatus(await jwt(claimsFor(1005, { scp: "esi-mail.read_mail.v1" })))).toBe(400);
  });

  it("refuses an expired token, a wrong issuer, a forged signature, an unknown key and rubbish", async () => {
    expect(await signInStatus(await jwt(claimsFor(1006, { exp: Math.floor(Date.now() / 1000) - 5 })))).toBe(401);
    expect(await signInStatus(await jwt(claimsFor(1006, { iss: "https://evil.example" })))).toBe(401);
    expect(await signInStatus(await jwt(claimsFor(1006), { signer: wrong.privateKey }))).toBe(401);
    expect(await signInStatus(await jwt(claimsFor(1006), { kid: "no-such-key" }))).toBe(401);
    expect(await signInStatus(await jwt(claimsFor(1006, { sub: "CORPORATION:EVE:1006" })))).toBe(401);
    expect(await signInStatus("not.a.token")).toBe(401);
    expect(await signInStatus("rubbish")).toBe(401);
    // "alg": "none" with no signature must not pass.
    const none = `${b64(JSON.stringify({ alg: "none", kid: "rsa-key" }))}.${b64(JSON.stringify(claimsFor(1006)))}.`;
    expect(await signInStatus(none)).toBe(401);
    expect((await call(`${API}/v1/auth/eve`, { method: "POST", body: "{}" })).status).toBe(400);
  });

  it("every call needs a valid key", async () => {
    expect((await call(`${API}/v1/me`)).status).toBe(401);
    expect((await call(`${API}/v1/images`)).status).toBe(401);
    expect((await call(`${API}/v1/images`, { method: "POST", body: png() })).status).toBe(401);
    expect((await call(`${API}/v1/images/delete`, { method: "POST", body: "{}" })).status).toBe(401);
    expect((await call(`${API}/v1/me`, { headers: bearer("ecs_wrong") })).status).toBe(401);
  });

  it("sign-out ends that key and no other, and the images stay", async () => {
    const a = await signedIn(1007);
    const b = await signedIn(1007);
    const up = await upload(a, png());
    expect(up.status).toBe(201);

    expect((await call(`${API}/v1/auth/sign-out`, { method: "POST", headers: bearer(a) })).status).toBe(200);
    expect((await call(`${API}/v1/me`, { headers: bearer(a) })).status).toBe(401);

    const list = await (await call(`${API}/v1/images`, { headers: bearer(b) })).json<any>();
    expect(list.images.length).toBe(1);
  });
});

// ── Upload ────────────────────────────────────────────────────────────────────

describe("upload", () => {
  it("stores a PNG and a JPEG and answers with a URL that serves them", async () => {
    const key = await signedIn(2001);

    const r = await upload(key, png(2, 3));
    expect(r.status).toBe(201);
    const up = await r.json<any>();
    expect(up.url).toMatch(/^https:\/\/img\.test\/[0-9a-f]{32}\.png$/);
    expect(up).toMatchObject({ type: "image/png", width: 2, height: 3, size: png(2, 3).length });
    expect(up.usage).toMatchObject({ activeImages: 1, uploadsToday: 1, storedBytes: png(2, 3).length });

    const served = await call(up.url);
    expect(served.status).toBe(200);
    expect(served.headers.get("Content-Type")).toBe("image/png");
    expect(served.headers.get("X-Content-Type-Options")).toBe("nosniff");
    expect(served.headers.get("Content-Security-Policy")).toContain("sandbox");
    expect(new Uint8Array(await served.arrayBuffer())).toEqual(png(2, 3));

    const head = await call(up.url, { method: "HEAD" });
    expect(head.status).toBe(200);
    expect(head.headers.get("Content-Length")).toBe(String(png(2, 3).length));

    const j = await upload(key, jpeg(640, 480));
    expect(j.status).toBe(201);
    const jb = await j.json<any>();
    expect(jb).toMatchObject({ type: "image/jpeg", width: 640, height: 480 });
    expect(jb.url.endsWith(".jpg")).toBe(true);
    expect((await call(jb.url)).headers.get("Content-Type")).toBe("image/jpeg");
  });

  it("the type comes from the bytes, whatever the request says", async () => {
    const key = await signedIn(2002);
    const r = await call(`${API}/v1/images`, { method: "POST", headers: { ...bearer(key), "Content-Type": "text/html" }, body: png() });
    expect(r.status).toBe(201);
    expect((await r.json<any>()).type).toBe("image/png");
  });

  it("refuses anything that is not really a PNG or JPEG", async () => {
    const key = await signedIn(2003);
    const not = async (body: BodyInit) => (await upload(key, body)).status;

    expect(await not("<html><script>alert(1)</script></html>")).toBe(415);
    expect(await not(`<svg xmlns="http://www.w3.org/2000/svg"></svg>`)).toBe(415);
    expect(await not(new Uint8Array([0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 1, 0, 1, 0]))).toBe(415);  // GIF
    expect(await not(new Uint8Array([0x89, 0x50, 0x4e, 0x47]))).toBe(415);                        // a PNG's first bytes
    expect(await not(png().slice(0, -12))).toBe(415);                                            // no IEND

    const tailed = new Uint8Array([...png(), ...new TextEncoder().encode("<script>")]);
    expect(await not(tailed)).toBe(415);                                                         // something after the end
    expect(await not(png(0, 3))).toBe(415);                                                      // no width
    expect(await not(png(20_000, 3))).toBe(415);                                                 // absurdly wide
    expect(await not(jpeg().slice(0, -2))).toBe(415);                                            // no end of image
    expect((await upload(key, new Uint8Array())).status).toBe(400);
  });

  it("an image over the size limit is refused, whether it says so or not", async () => {
    const key = await signedIn(2004);
    expect((await upload(key, png(2, 3, 5000))).status).toBe(413);

    // A stream gives no Content-Length, so only reading it can tell.
    const stream = new ReadableStream({
      start(c) { c.enqueue(png(2, 3, 5000)); c.close(); },
    });
    const r = await upload(key, stream);
    expect(r.status).toBe(413);
    expect((await r.json<any>()).error).toBe("image_too_large");

    // Nothing was counted or stored.
    const me = await (await call(`${API}/v1/me`, { headers: bearer(key) })).json<any>();
    expect(me.usage).toEqual({ storedBytes: 0, activeImages: 0, uploadsToday: 0 });
  });

  it("expiresInDays: default the maximum, shorter allowed, longer and nonsense refused", async () => {
    const key = await signedIn(2005);
    const days = (iso: string) => Math.round((Date.parse(iso) - Date.now()) / 86_400_000);

    expect(days((await (await upload(key, png())).json<any>()).expiresAt)).toBe(365);
    expect(days((await (await upload(key, png(), "?expiresInDays=30")).json<any>()).expiresAt)).toBe(30);
    expect(days((await (await upload(key, png(), "?expiresInDays=1")).json<any>()).expiresAt)).toBe(1);

    for (const bad of ["0", "-1", "366", "1.5", "soon", ""]) {
      const r = await upload(key, png(), `?expiresInDays=${bad}`);
      expect(r.status, bad).toBe(400);
      expect((await r.json<any>()).error).toBe("bad_expiry");
    }
  });

  it("the storage limit counts what is held, and deleting frees it", async () => {
    const key = await signedIn(2006);
    const big = png(2, 3, 3000);                    // about 3 KB against a 10 KB limit
    const ids: string[] = [];
    for (let i = 0; i < 3; i++) {
      const r = await upload(key, big);
      expect(r.status).toBe(201);
      ids.push((await r.json<any>()).id);
    }

    const over = await upload(key, big);
    expect(over.status).toBe(409);
    const body = await over.json<any>();
    expect(body.error).toBe("storage_limit");
    expect(body.usage.activeImages).toBe(3);

    // A refused upload does not use up one of the day's.
    expect(body.usage.uploadsToday).toBe(3);

    const del = await call(`${API}/v1/images/delete`, { method: "POST", headers: bearer(key), body: JSON.stringify({ ids: [ids[0]] }) });
    expect(del.status).toBe(200);
    expect((await upload(key, big)).status).toBe(201);
  });

  it("the daily limit holds, even after deleting, and says when to come back", async () => {
    const key = await signedIn(2007);
    let last = "";
    for (let i = 0; i < 12; i++) {
      const r = await upload(key, png());
      expect(r.status).toBe(201);
      last = (await r.json<any>()).id;
    }
    const over = await upload(key, png());
    expect(over.status).toBe(429);
    expect((await over.json<any>()).error).toBe("daily_limit");
    expect(Number(over.headers.get("Retry-After"))).toBeGreaterThan(0);

    await call(`${API}/v1/images/delete`, { method: "POST", headers: bearer(key), body: JSON.stringify({ ids: [last] }) });
    expect((await upload(key, png())).status).toBe(429);
  });

  it("uploads at once cannot slip past the storage limit", async () => {
    const key = await signedIn(2008);
    const big = png(2, 3, 3000);
    const results = await Promise.all(Array.from({ length: 6 }, () => upload(key, big)));
    expect(results.filter((r) => r.status === 201).length).toBe(3);

    const me = await (await call(`${API}/v1/me`, { headers: bearer(key) })).json<any>();
    expect(me.usage.storedBytes).toBeLessThanOrEqual(10240);
    expect(me.usage.uploadsToday).toBe(3);
  });
});

// ── List and delete ───────────────────────────────────────────────────────────

describe("list and delete", () => {
  it("lists a character's active images, newest first, a page at a time", async () => {
    const key = await signedIn(3001);
    const ids: string[] = [];
    for (let i = 0; i < 5; i++) {
      ids.push((await (await upload(key, png())).json<any>()).id);
      await new Promise((r) => setTimeout(r, 3));
    }

    const first = await (await call(`${API}/v1/images?limit=2`, { headers: bearer(key) })).json<any>();
    expect(first.images.map((i: any) => i.id)).toEqual([ids[4], ids[3]]);
    expect(first.images[0].url).toContain(ids[4]);
    expect(first.images[0]).toHaveProperty("expiresAt");
    expect(first.usage.activeImages).toBe(5);
    expect(first.limits.maxUploadsPerDay).toBe(12);
    expect(first.nextCursor).toBeTruthy();

    const second = await (await call(`${API}/v1/images?limit=2&cursor=${encodeURIComponent(first.nextCursor)}`, { headers: bearer(key) })).json<any>();
    expect(second.images.map((i: any) => i.id)).toEqual([ids[2], ids[1]]);

    const third = await (await call(`${API}/v1/images?limit=2&cursor=${encodeURIComponent(second.nextCursor)}`, { headers: bearer(key) })).json<any>();
    expect(third.images.map((i: any) => i.id)).toEqual([ids[0]]);
    expect(third.nextCursor).toBeNull();
  });

  it("deleting a group removes the bytes, the rows and the usage, and reports the rest", async () => {
    const key = await signedIn(3002);
    const a = await (await upload(key, png())).json<any>();
    const b = await (await upload(key, png())).json<any>();
    const c = await (await upload(key, png())).json<any>();
    const missing = "f".repeat(32);

    const r = await call(`${API}/v1/images/delete`, { method: "POST", headers: bearer(key), body: JSON.stringify({ ids: [a.id, b.id, missing, a.id] }) });
    expect(r.status).toBe(200);
    const body = await r.json<any>();
    expect(body.deleted.sort()).toEqual([a.id, b.id].sort());
    expect(body.notFound).toEqual([missing]);
    expect(body.usage.activeImages).toBe(1);

    expect((await call(a.url)).status).toBe(404);
    expect((await call(c.url)).status).toBe(200);
  });

  it("one character can neither see nor delete another's images", async () => {
    const owner = await signedIn(3003);
    const other = await signedIn(3004);
    const image = await (await upload(owner, png())).json<any>();

    const list = await (await call(`${API}/v1/images`, { headers: bearer(other) })).json<any>();
    expect(list.images).toEqual([]);

    const r = await (await call(`${API}/v1/images/delete`, { method: "POST", headers: bearer(other), body: JSON.stringify({ ids: [image.id] }) })).json<any>();
    expect(r.deleted).toEqual([]);
    expect(r.notFound).toEqual([image.id]);
    expect((await call(image.url)).status).toBe(200);
  });

  it("refuses a bad delete", async () => {
    const key = await signedIn(3005);
    for (const body of ["nope", "{}", `{"ids":[]}`, `{"ids":["../x"]}`, JSON.stringify({ ids: Array(91).fill("a".repeat(32)) })])
      expect((await call(`${API}/v1/images/delete`, { method: "POST", headers: bearer(key), body })).status, body).toBe(400);
  });

  it("a full page of ids can be deleted at once", async () => {
    await ensureSchema(env.DB);
    const key = await signedIn(3006);
    const now = new Date().toISOString();
    const later = new Date(Date.now() + 86_400_000).toISOString();
    const ids = Array.from({ length: 90 }, (_, i) => i.toString(16).padStart(32, "a"));
    await env.DB.batch(ids.map((id) => env.DB.prepare(
      `INSERT INTO images (id, character_id, type, size, width, height, created_at, expires_at) VALUES (?1, 3006, 'image/png', 1, 1, 1, ?2, ?3)`,
    ).bind(id, now, later)));
    const r = await call(`${API}/v1/images/delete`, { method: "POST", headers: bearer(key), body: JSON.stringify({ ids }) });
    expect(r.status).toBe(200);
    expect((await r.json<any>()).deleted.length).toBe(90);
  });
});

// ── Expiry ────────────────────────────────────────────────────────────────────

describe("expiry", () => {
  const backdate = (id: string) => env.DB.prepare(`UPDATE images SET expires_at = ?2 WHERE id = ?1`)
    .bind(id, new Date(Date.now() - 1000).toISOString()).run();

  it("an expired image is not served, listed or counted, even before the purge", async () => {
    const key = await signedIn(4001);
    const up = await (await upload(key, png())).json<any>();

    // Expired in both places, as time passing would do.
    await backdate(up.id);
    await env.IMAGES.put(`i/${up.id}`, png(), {
      httpMetadata: { contentType: "image/png" },
      customMetadata: { expiresAt: new Date(Date.now() - 1000).toISOString(), characterId: "4001" },
    });

    expect((await call(up.url)).status).toBe(404);
    const list = await (await call(`${API}/v1/images`, { headers: bearer(key) })).json<any>();
    expect(list.images).toEqual([]);
    expect(list.usage.storedBytes).toBe(0);
  });

  it("the daily job purges what has expired and leaves the rest", async () => {
    const key = await signedIn(4002);
    const gone = await (await upload(key, png())).json<any>();
    const kept = await (await upload(key, png())).json<any>();
    await backdate(gone.id);
    await env.DB.prepare(`INSERT OR REPLACE INTO upload_days (character_id, day, count) VALUES (4002, '2020-01-01', 3)`).run();

    const ctx = createExecutionContext();
    await worker.scheduled({} as ScheduledController, env, ctx);
    await waitOnExecutionContext(ctx);

    expect(await env.IMAGES.head(`i/${gone.id}`)).toBeNull();
    expect(await env.DB.prepare(`SELECT id FROM images WHERE id = ?1`).bind(gone.id).first()).toBeNull();
    expect(await env.IMAGES.head(`i/${kept.id}`)).not.toBeNull();
    expect(await env.DB.prepare(`SELECT day FROM upload_days WHERE character_id = 4002 AND day = '2020-01-01'`).first()).toBeNull();
  });

  it("the purge works through more than one page", async () => {
    await ensureSchema(env.DB);
    const past = new Date(Date.now() - 1000).toISOString();
    const ids = Array.from({ length: 200 }, (_, i) => `e${i.toString(16).padStart(31, "0")}`);
    await env.DB.batch(ids.map((id) => env.DB.prepare(
      `INSERT INTO images (id, character_id, type, size, width, height, created_at, expires_at) VALUES (?1, 4003, 'image/png', 1, 1, 1, ?2, ?2)`,
    ).bind(id, past)));
    expect(await purgeExpired(env.DB, env.IMAGES)).toBeGreaterThanOrEqual(200);
    const left = await env.DB.prepare(`SELECT COUNT(*) AS n FROM images WHERE character_id = 4003`).first<{ n: number }>();
    expect(left?.n).toBe(0);
  });
});

// ── The two addresses ─────────────────────────────────────────────────────────

describe("addresses", () => {
  it("the image address serves images and nothing else", async () => {
    const key = await signedIn(5001);
    const up = await (await upload(key, png())).json<any>();
    const path = new URL(up.url).pathname;

    expect((await call(`${IMG}/`)).status).toBe(404);
    expect((await call(`${IMG}/v1/me`, { headers: bearer(key) })).status).toBe(404);
    expect((await call(`${IMG}/v1/images`, { method: "POST", headers: bearer(key), body: png() })).status).toBe(404);
    expect((await call(`${IMG}${path}`, { method: "POST" })).status).toBe(404);
    expect((await call(`${IMG}/${"0".repeat(32)}.png`)).status).toBe(404);
    expect((await call(`${IMG}/../i/${up.id}`)).status).toBe(404);
    // The right image under the wrong extension is not it.
    expect((await call(`${IMG}${path.replace(".png", ".jpg")}`)).status).toBe(404);
  });

  it("the API address does not serve images", async () => {
    const key = await signedIn(5002);
    const up = await (await upload(key, png())).json<any>();
    expect((await call(`${API}${new URL(up.url).pathname}`)).status).toBe(404);
  });
});

// ── Takedowns and bans ────────────────────────────────────────────────────────

describe("admin", () => {
  it("answers as if it were not there without the token", async () => {
    expect((await call(`${API}/v1/admin/images/${"0".repeat(32)}`)).status).toBe(404);
    const key = await signedIn(6001);
    const up = await (await upload(key, png())).json<any>();
    const r = await call(`${API}/v1/admin/images/${up.id}/take-down`, { method: "POST", headers: bearer(key) });
    expect(r.status).toBe(404);
    expect((await call(up.url)).status).toBe(200);
  });

  it("says who uploaded an image, and takes it down", async () => {
    const key = await signedIn(6002);
    const up = await (await upload(key, png())).json<any>();

    const who = await (await call(`${API}/v1/admin/images/${up.id}`, { headers: ADMIN })).json<any>();
    expect(who).toMatchObject({ characterId: 6002, characterName: "Pilot 6002" });

    expect((await call(`${API}/v1/admin/images/${up.id}/take-down`, { method: "POST", headers: ADMIN })).status).toBe(200);
    expect((await call(up.url)).status).toBe(404);
    expect((await call(`${API}/v1/admin/images/${up.id}/take-down`, { method: "POST", headers: ADMIN })).status).toBe(404);
  });

  it("a ban ends the keys, removes the images and refuses a new sign-in, until lifted", async () => {
    const key = await signedIn(6003);
    const up = await (await upload(key, png())).json<any>();

    const r = await call(`${API}/v1/admin/characters/6003/ban`, { method: "POST", headers: ADMIN, body: JSON.stringify({ reason: "test" }) });
    expect(await r.json<any>()).toEqual({ banned: true, imagesRemoved: 1 });

    expect((await call(`${API}/v1/me`, { headers: bearer(key) })).status).toBe(401);
    expect((await call(up.url)).status).toBe(404);

    const again = await call(`${API}/v1/auth/eve`, { method: "POST", body: JSON.stringify({ accessToken: await jwt(claimsFor(6003)) }) });
    expect(again.status).toBe(403);
    expect((await again.json<any>()).error).toBe("banned");

    await call(`${API}/v1/admin/characters/6003/unban`, { method: "POST", headers: ADMIN });
    expect(await signInStatus(await jwt(claimsFor(6003)))).toBe(200);
  });
});

// ── The format check on its own ───────────────────────────────────────────────

describe("inspectImage", () => {
  it("reads PNG and JPEG sizes", () => {
    expect(inspectImage(png(1200, 600))).toEqual({ type: "image/png", ext: "png", width: 1200, height: 600 });
    expect(inspectImage(jpeg(1920, 1080))).toEqual({ type: "image/jpeg", ext: "jpg", width: 1920, height: 1080 });
  });

  it("refuses a PNG that does not start with its header, or has no image data", () => {
    const signature = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
    expect(inspectImage(new Uint8Array([...signature, ...chunk("IEND")]))).toBeNull();
    expect(inspectImage(new Uint8Array([...signature, ...chunk("IHDR", new Array(13).fill(1)), ...chunk("IEND")]))).toBeNull();
    // A chunk claiming to run past the end of the file.
    expect(inspectImage(new Uint8Array([...signature, 0xff, 0xff, 0xff, 0xff, 0x49, 0x48, 0x44, 0x52]))).toBeNull();
  });
});
