import { defineConfig } from "vitest/config";
import { cloudflareTest } from "@cloudflare/vitest-pool-workers";

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        compatibilityFlags: ["nodejs_compat"],
        bindings: {
          EVE_CLIENT_ID: "test-client",
          ADMIN_TOKEN: "test-admin-token-do-not-use",
          API_HOST: "api.test",
          IMAGE_HOST: "img.test",
          // Small enough for a test to reach.
          MAX_IMAGE_BYTES: "4096",
          MAX_STORED_BYTES: "10240",
          MAX_UPLOADS_PER_DAY: "12",
        },
      },
    }),
  ],
});
