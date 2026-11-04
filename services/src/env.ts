export interface Bindings {
  DB: D1Database;
  IMAGES: R2Bucket;
  SERVICE_VERSION: string;
  API_HOST: string;
  IMAGE_HOST: string;
  /** The EVE application sign-in tokens must be issued to. Public, like the app's own. */
  EVE_CLIENT_ID: string;
  /** Takedowns and bans. Unset, the admin calls answer 404. */
  ADMIN_TOKEN?: string;
  MAX_IMAGE_BYTES: string;
  MAX_STORED_BYTES: string;
  MAX_UPLOADS_PER_DAY: string;
  MAX_EXPIRES_IN_DAYS: string;
}

export interface Caller {
  characterId: number;
  characterName: string;
  keyHash: string;
}

export interface AppEnv {
  Bindings: Bindings;
  Variables: { caller: Caller };
}

export interface Limits {
  maxImageBytes: number;
  maxStoredBytes: number;
  maxUploadsPerDay: number;
  maxExpiresInDays: number;
}

export function limits(env: Bindings): Limits {
  return {
    maxImageBytes: Number(env.MAX_IMAGE_BYTES),
    maxStoredBytes: Number(env.MAX_STORED_BYTES),
    maxUploadsPerDay: Number(env.MAX_UPLOADS_PER_DAY),
    maxExpiresInDays: Number(env.MAX_EXPIRES_IN_DAYS),
  };
}
