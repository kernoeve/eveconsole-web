// The schema, and the figures every answer about a character's images is built from.
//
// ⚠️ D1 meters rows WRITTEN per account per day, and the store sites on the same account share the
// allowance. An upload writes three rows and everything else here writes as little as it can: a
// key's last-used time at most once a day, and nothing at all on a read.

let schemaReady = false;

export async function ensureSchema(db: D1Database): Promise<void> {
  if (schemaReady) return;
  await db.batch([
    db.prepare(`CREATE TABLE IF NOT EXISTS characters (
      character_id INTEGER PRIMARY KEY,
      name         TEXT NOT NULL,
      owner_hash   TEXT NOT NULL DEFAULT '',
      first_seen   TEXT NOT NULL,
      last_sign_in TEXT NOT NULL,
      banned_at    TEXT,
      ban_reason   TEXT
    )`),
    // Only the key's hash is kept: a copy of this table signs nobody in.
    db.prepare(`CREATE TABLE IF NOT EXISTS api_keys (
      key_hash     TEXT PRIMARY KEY,
      character_id INTEGER NOT NULL,
      created_at   TEXT NOT NULL,
      last_used    TEXT NOT NULL
    )`),
    db.prepare(`CREATE INDEX IF NOT EXISTS api_keys_character ON api_keys (character_id, created_at)`),
    db.prepare(`CREATE TABLE IF NOT EXISTS images (
      id           TEXT PRIMARY KEY,
      character_id INTEGER NOT NULL,
      type         TEXT NOT NULL,
      size         INTEGER NOT NULL,
      width        INTEGER NOT NULL,
      height       INTEGER NOT NULL,
      created_at   TEXT NOT NULL,
      expires_at   TEXT NOT NULL
    )`),
    db.prepare(`CREATE INDEX IF NOT EXISTS images_owner ON images (character_id, created_at, id)`),
    db.prepare(`CREATE INDEX IF NOT EXISTS images_expiry ON images (expires_at)`),
    db.prepare(`CREATE TABLE IF NOT EXISTS upload_days (
      character_id INTEGER NOT NULL,
      day          TEXT NOT NULL,
      count        INTEGER NOT NULL,
      PRIMARY KEY (character_id, day)
    )`),
  ]);
  schemaReady = true;
}

export const nowIso = (): string => new Date().toISOString();
export const dayOf = (iso: string): string => iso.slice(0, 10);

export interface Usage {
  storedBytes: number;
  activeImages: number;
  uploadsToday: number;
}

/** What a character holds now, and has uploaded today. An image past its expiry no longer counts,
 *  whether or not the daily purge has reached it yet. */
export async function usage(db: D1Database, characterId: number, now = nowIso()): Promise<Usage> {
  const [held, today] = await db.batch<{ bytes?: number; images?: number; count?: number }>([
    db.prepare(`SELECT COALESCE(SUM(size), 0) AS bytes, COUNT(*) AS images FROM images WHERE character_id = ?1 AND expires_at > ?2`)
      .bind(characterId, now),
    db.prepare(`SELECT count FROM upload_days WHERE character_id = ?1 AND day = ?2`).bind(characterId, dayOf(now)),
  ]);
  return {
    storedBytes: held.results[0]?.bytes ?? 0,
    activeImages: held.results[0]?.images ?? 0,
    uploadsToday: today.results[0]?.count ?? 0,
  };
}
