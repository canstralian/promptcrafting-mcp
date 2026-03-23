// tests/setup/test-env.ts — Test environment setup with mocked Cloudflare bindings
import { beforeAll } from "vitest";

// Mock Cloudflare Workers global types
declare global {
  var PROMPT_TEMPLATES: KVNamespace;
  var AUDIT_DB: D1Database;
}

// In-memory KV namespace mock
class MockKV implements KVNamespace {
  private store: Map<string, { value: string; metadata?: Record<string, unknown> }> = new Map();

  async get(key: string, type?: "text" | "json" | "arrayBuffer" | "stream"): Promise<any> {
    const item = this.store.get(key);
    if (!item) return null;

    if (type === "json") {
      return JSON.parse(item.value);
    }
    return item.value;
  }

  async put(key: string, value: string | ArrayBuffer | ReadableStream, options?: any): Promise<void> {
    this.store.set(key, {
      value: typeof value === "string" ? value : "",
      metadata: options?.metadata,
    });
  }

  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }

  async list(options?: any): Promise<any> {
    const prefix = options?.prefix || "";
    const limit = options?.limit || 1000;
    const cursor = options?.cursor;

    const keys = Array.from(this.store.keys())
      .filter((k) => k.startsWith(prefix))
      .map((name) => ({
        name,
        metadata: this.store.get(name)?.metadata,
      }))
      .slice(0, limit);

    return {
      keys,
      list_complete: true,
      cursor: null,
    };
  }

  async getWithMetadata(key: string, type?: any): Promise<any> {
    const item = this.store.get(key);
    if (!item) return { value: null, metadata: null };
    return {
      value: type === "json" ? JSON.parse(item.value) : item.value,
      metadata: item.metadata,
    };
  }
}

// In-memory D1 database mock using better-sqlite3
let sqlite3: any;
try {
  sqlite3 = require("better-sqlite3");
} catch (e) {
  console.warn("better-sqlite3 not available, using minimal mock");
}

class MockD1 implements D1Database {
  private db: any;

  constructor() {
    if (sqlite3) {
      this.db = new sqlite3(":memory:");
    }
  }

  prepare(query: string): D1PreparedStatement {
    const db = this.db;
    return {
      bind(...values: any[]): D1PreparedStatement {
        return {
          ...this,
          first: async () => {
            if (!db) return null;
            try {
              const stmt = db.prepare(query);
              const result = stmt.get(...values);
              return result || null;
            } catch (e) {
              console.error("D1 query error:", e);
              return null;
            }
          },
          all: async () => {
            if (!db) return { results: [], success: true };
            try {
              const stmt = db.prepare(query);
              const results = stmt.all(...values);
              return { results: results || [], success: true };
            } catch (e) {
              console.error("D1 query error:", e);
              return { results: [], success: false };
            }
          },
          run: async () => {
            if (!db) return { success: true };
            try {
              const stmt = db.prepare(query);
              stmt.run(...values);
              return { success: true };
            } catch (e) {
              console.error("D1 query error:", e);
              return { success: false };
            }
          },
        } as any;
      },
      first: async () => {
        if (!db) return null;
        try {
          const stmt = db.prepare(query);
          return stmt.get() || null;
        } catch (e) {
          return null;
        }
      },
      all: async () => {
        if (!db) return { results: [], success: true };
        try {
          const stmt = db.prepare(query);
          const results = stmt.all();
          return { results: results || [], success: true };
        } catch (e) {
          return { results: [], success: false };
        }
      },
      run: async () => {
        if (!db) return { success: true };
        try {
          const stmt = db.prepare(query);
          stmt.run();
          return { success: true };
        } catch (e) {
          return { success: false };
        }
      },
    } as D1PreparedStatement;
  }

  async batch(statements: D1PreparedStatement[]): Promise<D1Response[]> {
    const results: D1Response[] = [];
    for (const stmt of statements) {
      const result = await stmt.run();
      results.push(result as D1Response);
    }
    return results;
  }

  async exec(query: string): Promise<D1ExecResult> {
    if (!this.db) {
      return { count: 0, duration: 0 };
    }
    try {
      this.db.exec(query);
      return { count: 1, duration: 0 };
    } catch (e) {
      console.error("D1 exec error:", e);
      throw e;
    }
  }

  async dump(): Promise<ArrayBuffer> {
    throw new Error("Not implemented");
  }
}

// Export test environment
export const testEnv = {
  PROMPT_TEMPLATES: new MockKV(),
  AUDIT_DB: new MockD1(),
  JWT_SECRET: "test-jwt-secret-32-characters-long",
  TEMPLATE_HMAC_KEY: "test-hmac-key-32-characters-long",
  ENVIRONMENT: "test",
  LOG_LEVEL: "error",
  HITL_TIMEOUT_MS: "5000",
  MAX_PROMPT_LENGTH: "50000",
};

// Setup globals
beforeAll(() => {
  global.PROMPT_TEMPLATES = testEnv.PROMPT_TEMPLATES;
  global.AUDIT_DB = testEnv.AUDIT_DB;
});
