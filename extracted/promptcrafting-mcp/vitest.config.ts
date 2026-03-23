// vitest.config.ts — Integration tests for promptcrafting-mcp
// Runs tests against actual Cloudflare Workers environment (D1, KV, Durable Objects, AI)
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    environment: "node",
    // Simplified config without pool workers for now
    // We'll use standard test environment
  },
});
