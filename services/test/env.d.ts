import type { Bindings } from "../src/env";

// The bindings the tests' `env` carries: wrangler.toml's plus what vitest.config.ts sets.
declare global {
  namespace Cloudflare {
    interface Env extends Bindings {}
  }
}
export {};
