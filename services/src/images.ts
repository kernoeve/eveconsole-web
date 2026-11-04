// Storing, listing, deleting and purging images.
//
// The row in D1 says whose an image is and counts it; the bytes are in R2, carrying their own expiry
// so an image can be served with no database read. An upload writes the row before the bytes: a
// failure between the two leaves a row its owner can see and delete, where the other order would
// leave a public file nothing knows about.

import { randomHex } from "./crypto";
import { dayOf, nowIso } from "./db";
import type { ImageInfo } from "./image-format";
import type { Limits } from "./env";

const objectKey = (id: string): string => `i/${id}`;
const extOf = (type: string): string => (type === "image/png" ? "png" : "jpg");

export const imageUrl = (host: string, id: string, type: string): string => `https://${host}/${id}.${extOf(type)}`;

export interface StoredImage {
  id: string;
  type: string;
  size: number;
  width: number;
  height: number;
  createdAt: string;
  expiresAt: string;
}

export type StoreResult = StoredImage | "daily_limit" | "storage_limit";

export async function storeImage(
  db: D1Database, bucket: R2Bucket, characterId: number, bytes: Uint8Array, info: ImageInfo,
  expiresInDays: number, cap: Limits,
): Promise<StoreResult> {
  const now = nowIso();
  const id = randomHex(16);
  const expiresAt = new Date(Date.now() + expiresInDays * 86_400_000).toISOString();

  // ⚠️ Both limits are one conditional statement each, so two uploads at once cannot both slip past.
  const counted = await db.prepare(
    `INSERT INTO upload_days (character_id, day, count) VALUES (?1, ?2, 1)
     ON CONFLICT (character_id, day) DO UPDATE SET count = count + 1 WHERE count < ?3`,
  ).bind(characterId, dayOf(now), cap.maxUploadsPerDay).run();
  if (counted.meta.changes === 0) return "daily_limit";

  const uncount = () => db.prepare(`UPDATE upload_days SET count = count - 1 WHERE character_id = ?1 AND day = ?2`)
    .bind(characterId, dayOf(now)).run();

  const inserted = await db.prepare(
    `INSERT INTO images (id, character_id, type, size, width, height, created_at, expires_at)
     SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8
     WHERE (SELECT COALESCE(SUM(size), 0) FROM images WHERE character_id = ?2 AND expires_at > ?7) + ?4 <= ?9`,
  ).bind(id, characterId, info.type, bytes.length, info.width, info.height, now, expiresAt, cap.maxStoredBytes).run();
  if (inserted.meta.changes === 0) {
    await uncount();
    return "storage_limit";
  }

  try {
    await bucket.put(objectKey(id), bytes, {
      httpMetadata: { contentType: info.type },
      customMetadata: { expiresAt, characterId: String(characterId) },
    });
  } catch (e) {
    await db.prepare(`DELETE FROM images WHERE id = ?1`).bind(id).run();
    await uncount();
    throw e;
  }

  return { id, type: info.type, size: bytes.length, width: info.width, height: info.height, createdAt: now, expiresAt };
}

interface ImageRow { id: string; type: string; size: number; width: number; height: number; created_at: string; expires_at: string }

const toImage = (r: ImageRow): StoredImage => ({
  id: r.id, type: r.type, size: r.size, width: r.width, height: r.height, createdAt: r.created_at, expiresAt: r.expires_at,
});

/** A character's active images, newest first, a page at a time. */
export async function listImages(
  db: D1Database, characterId: number, limit: number, cursor: string | null,
): Promise<{ images: StoredImage[]; nextCursor: string | null }> {
  const now = nowIso();
  const [createdAt, id] = cursor ? decodeCursor(cursor) : [null, null];
  const rows = await db.prepare(
    `SELECT id, type, size, width, height, created_at, expires_at FROM images
     WHERE character_id = ?1 AND expires_at > ?2 AND (?3 IS NULL OR (created_at, id) < (?3, ?4))
     ORDER BY created_at DESC, id DESC LIMIT ?5`,
  ).bind(characterId, now, createdAt, id, limit + 1).all<ImageRow>();

  const page = rows.results.slice(0, limit);
  const last = page[page.length - 1];
  return {
    images: page.map(toImage),
    nextCursor: rows.results.length > limit && last ? encodeCursor(last.created_at, last.id) : null,
  };
}

const encodeCursor = (createdAt: string, id: string): string => btoa(`${createdAt}|${id}`);

function decodeCursor(cursor: string): [string | null, string | null] {
  try {
    const [createdAt, id] = atob(cursor).split("|");
    return createdAt && id ? [createdAt, id] : [null, null];
  } catch {
    return [null, null];
  }
}

/** Deletes those of the ids that are this character's. Another's image reads as not found, so the
 *  answer never says whether an id exists. */
export async function deleteImages(
  db: D1Database, bucket: R2Bucket, characterId: number, ids: string[],
): Promise<{ deleted: string[]; notFound: string[] }> {
  const unique = [...new Set(ids)];
  const marks = unique.map((_, i) => `?${i + 2}`).join(",");
  const owned = await db.prepare(`SELECT id FROM images WHERE character_id = ?1 AND id IN (${marks})`)
    .bind(characterId, ...unique).all<{ id: string }>();
  const deleted = owned.results.map((r) => r.id);

  await removeImages(db, bucket, deleted);
  return { deleted, notFound: unique.filter((id) => !deleted.includes(id)) };
}

/** The bytes first: if this stops half way, the row is still there to try again from. */
async function removeImages(db: D1Database, bucket: R2Bucket, ids: string[]): Promise<void> {
  if (ids.length === 0) return;
  await bucket.delete(ids.map(objectKey));
  const marks = ids.map((_, i) => `?${i + 1}`).join(",");
  await db.prepare(`DELETE FROM images WHERE id IN (${marks})`).bind(...ids).run();
}

export async function ownerOf(db: D1Database, id: string): Promise<(StoredImage & { characterId: number; characterName: string }) | null> {
  const row = await db.prepare(
    `SELECT i.id, i.type, i.size, i.width, i.height, i.created_at, i.expires_at, i.character_id, c.name
     FROM images i JOIN characters c ON c.character_id = i.character_id WHERE i.id = ?1`,
  ).bind(id).first<ImageRow & { character_id: number; name: string }>();
  return row ? { ...toImage(row), characterId: row.character_id, characterName: row.name } : null;
}

export async function takeDown(db: D1Database, bucket: R2Bucket, id: string): Promise<boolean> {
  const row = await db.prepare(`SELECT id FROM images WHERE id = ?1`).bind(id).first();
  await removeImages(db, bucket, row ? [id] : []);
  return row !== null;
}

/** Bans a character: their keys stop working and everything they uploaded goes. */
export async function ban(db: D1Database, bucket: R2Bucket, characterId: number, reason: string): Promise<number> {
  const now = nowIso();
  await db.batch([
    db.prepare(`INSERT INTO characters (character_id, name, first_seen, last_sign_in, banned_at, ban_reason) VALUES (?1, '', ?2, ?2, ?2, ?3)
                ON CONFLICT (character_id) DO UPDATE SET banned_at = ?2, ban_reason = ?3`).bind(characterId, now, reason),
    db.prepare(`DELETE FROM api_keys WHERE character_id = ?1`).bind(characterId),
  ]);

  let removed = 0;
  for (;;) {
    const page = await db.prepare(`SELECT id FROM images WHERE character_id = ?1 LIMIT ?2`)
      .bind(characterId, PURGE_PAGE).all<{ id: string }>();
    if (page.results.length === 0) return removed;
    await removeImages(db, bucket, page.results.map((r) => r.id));
    removed += page.results.length;
  }
}

export async function unban(db: D1Database, characterId: number): Promise<void> {
  await db.prepare(`UPDATE characters SET banned_at = NULL, ban_reason = NULL WHERE character_id = ?1`).bind(characterId).run();
}

// D1 allows about a hundred bound values in one statement, so a page stays under that.
const PURGE_PAGE = 90;
const PURGE_PAGES_A_DAY = 200;

/** The daily purge: expired images, and upload counts from days that are over. */
export async function purgeExpired(db: D1Database, bucket: R2Bucket, now = nowIso()): Promise<number> {
  let purged = 0;
  for (let page = 0; page < PURGE_PAGES_A_DAY; page++) {
    const rows = await db.prepare(`SELECT id FROM images WHERE expires_at <= ?1 LIMIT ?2`)
      .bind(now, PURGE_PAGE).all<{ id: string }>();
    if (rows.results.length === 0) break;
    await removeImages(db, bucket, rows.results.map((r) => r.id));
    purged += rows.results.length;
  }
  await db.prepare(`DELETE FROM upload_days WHERE day < ?1`).bind(dayOf(now)).run();
  return purged;
}

/** An image to serve, unless it has expired: the purge may not have reached it yet. */
export async function fetchImage(bucket: R2Bucket, id: string): Promise<R2ObjectBody | null> {
  const object = await bucket.get(objectKey(id));
  if (!object) return null;
  const expiresAt = object.customMetadata?.expiresAt;
  return expiresAt && expiresAt > nowIso() ? object : null;
}
