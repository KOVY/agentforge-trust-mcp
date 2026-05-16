/**
 * Unit tests for MCP Sanitization Layer.
 * Sequential execution — tests share module-level state.
 *
 * Run: npx tsx src/sanitizer/__tests__/sanitizer.test.ts
 */

import assert from "node:assert/strict";
import {
  validateToolArgs,
  sanitizeFreeform,
  LIMITS,
  type ValidationRule,
} from "../input-validator.js";
import {
  guardedCall,
  checkRateLimit,
  resetGuards,
  getGuardStats,
  CallGuardError,
  type CallGuardConfig,
} from "../guards.js";
import {
  recordCall,
  recordRateLimit,
  recordTrustScoreDrop,
  configureAnomalyDetector,
  getAnomalyStats,
  resetAnomalyDetector,
} from "../anomaly-detector.js";

let passed = 0;
let failed = 0;

async function test(name: string, fn: () => void | Promise<void>): Promise<void> {
  try {
    await fn();
    passed++;
    console.log(`  ✅ ${name}`);
  } catch (err: unknown) {
    failed++;
    console.error(`  ❌ ${name}: ${(err as Error).message}`);
  }
}

async function runTests(): Promise<void> {
  console.log("\n🧪 MCP Sanitization Layer Tests\n");

  // ——— Input Validator ——————————————————————————————————
  console.log("📦 Input Validator");

  await test("rejects prototype pollution keys via JSON.parse", () => {
    const schema: Record<string, ValidationRule> = {
      name: { type: "string", required: true, maxLength: 100 },
    };
    const malicious = JSON.parse('{"name":"test","__proto__":{"polluted":true}}');
    const result = validateToolArgs(malicious, schema);
    assert.ok(!result.valid, `Expected invalid. Errors: ${JSON.stringify(result.errors)}`);
    assert.ok(result.errors.some((e) => e.code === "DANGEROUS_KEY"));
  });

  await test("rejects constructor injection", () => {
    const schema: Record<string, ValidationRule> = {
      data: { type: "object", additionalProperties: true },
    };
    const result = validateToolArgs(
      { data: { constructor: "evil" } } as Record<string, unknown>,
      schema
    );
    assert.ok(!result.valid);
    assert.ok(result.errors.some((e) => e.code === "DANGEROUS_KEY"));
  });

  await test("detects XSS script tags", () => {
    const schema: Record<string, ValidationRule> = {
      name: { type: "string", required: true, maxLength: 500 },
    };
    const result = validateToolArgs({ name: '<script>alert("xss")</script>' }, schema);
    assert.ok(!result.valid);
    assert.ok(result.errors.some((e) => e.code === "INJECTION_DETECTED"));
  });

  await test("detects template injection", () => {
    const schema: Record<string, ValidationRule> = {
      q: { type: "string", required: true, maxLength: 500 },
    };
    const result = validateToolArgs({ q: "${process.env.SECRET}" }, schema);
    assert.ok(!result.valid);
    assert.ok(result.errors.some((e) => e.code === "INJECTION_DETECTED"));
  });

  await test("detects path traversal", () => {
    const schema: Record<string, ValidationRule> = {
      path: { type: "string", required: true, maxLength: 500 },
    };
    const result = validateToolArgs({ path: "../../../etc/passwd" }, schema);
    assert.ok(!result.valid);
    assert.ok(result.errors.some((e) => e.code === "INJECTION_DETECTED"));
  });

  await test("detects null bytes", () => {
    const schema: Record<string, ValidationRule> = {
      name: { type: "string", required: true, maxLength: 500 },
    };
    const result = validateToolArgs({ name: "file\x00.txt" }, schema);
    assert.ok(!result.valid);
    assert.ok(result.errors.some((e) => e.code === "INJECTION_DETECTED"));
  });

  await test("validates required fields", () => {
    const schema: Record<string, ValidationRule> = {
      server: { type: "string", required: true },
    };
    const result = validateToolArgs({}, schema);
    assert.ok(!result.valid);
    assert.ok(result.errors.some((e) => e.code === "MISSING_REQUIRED"));
  });

  await test("validates maxLength", () => {
    const schema: Record<string, ValidationRule> = {
      name: { type: "string", required: true, maxLength: 5 },
    };
    const result = validateToolArgs({ name: "123456" }, schema);
    assert.ok(!result.valid);
    assert.ok(result.errors.some((e) => e.code === "MAX_LENGTH"));
  });

  await test("validates number range", () => {
    const schema: Record<string, ValidationRule> = {
      limit: { type: "number", minimum: 1, maximum: 100 },
    };
    const result = validateToolArgs({ limit: 200 }, schema);
    assert.ok(!result.valid);
    assert.ok(result.errors.some((e) => e.code === "MAX_VALUE"));
  });

  await test("validates enum values", () => {
    const schema: Record<string, ValidationRule> = {
      pricing: { type: "string", enum: ["free", "freemium", "paid"] },
    };
    const result = validateToolArgs({ pricing: "expensive" }, schema);
    assert.ok(!result.valid);
    assert.ok(result.errors.some((e) => e.code === "ENUM_MISMATCH"));
  });

  await test("coerces number strings to numbers", () => {
    const schema: Record<string, ValidationRule> = {
      limit: { type: "number", minimum: 1, maximum: 100 },
    };
    const result = validateToolArgs({ limit: "50" }, schema);
    assert.ok(result.valid);
    assert.equal(result.sanitized.limit, 50);
  });

  await test("passes valid arguments through", () => {
    const schema: Record<string, ValidationRule> = {
      server: { type: "string", required: true, maxLength: 128 },
      tool: { type: "string", required: true, maxLength: 128 },
    };
    const result = validateToolArgs(
      { server: "my-server", tool: "get_data" },
      schema
    );
    assert.ok(result.valid);
    assert.equal(result.sanitized.server, "my-server");
    assert.equal(result.sanitized.tool, "get_data");
  });

  await test("rejects oversized payloads", () => {
    const schema: Record<string, ValidationRule> = {
      data: { type: "string", maxLength: 200_000 },
    };
    const result = validateToolArgs({ data: "x".repeat(2_000_000) }, schema);
    assert.ok(!result.valid);
  });

  // ——— Sandbox ——————————————————————————————————————————
  console.log("\n📦 Call Guards");

  await test("blocks blocked servers", () => {
    resetGuards();
    const config = {
      blockedServers: ["evil-server"],
      trustedServers: [],
      maxCallsPerMinutePerServer: 100,
      maxConcurrentPerServer: 100,
      maxCallsPerSession: 100,
    } as CallGuardConfig;
    assert.throws(
      () => checkRateLimit("evil-server", config),
      (err: unknown) => err instanceof CallGuardError && err.code === "SERVER_BLOCKED"
    );
  });

  await test("enforces rate limiting", async () => {
    resetGuards();
    const config: Partial<CallGuardConfig> = {
      maxCallsPerMinutePerServer: 2,
      maxConcurrentPerServer: 5,
      maxCallsPerSession: 100,
      callTimeoutMs: 5000,
      maxResponseBytes: 1_000_000,
      sanitizeInput: false,
      sanitizeOutput: false,
      blockedServers: [],
      trustedServers: [],
    };
    const executor = async () => ({ ok: true });

    await guardedCall("rl-srv", "t", {}, executor, config);
    await guardedCall("rl-srv", "t", {}, executor, config);

    let caught = false;
    try {
      await guardedCall("rl-srv", "t", {}, executor, config);
    } catch (err) {
      caught = err instanceof CallGuardError && err.code === "RATE_LIMIT";
    }
    assert.ok(caught, "Expected RATE_LIMIT CallGuardError on 3rd call");
  });

  await test("enforces timeout", async () => {
    resetGuards();
    const config: Partial<CallGuardConfig> = {
      callTimeoutMs: 100,
      maxCallsPerMinutePerServer: 100,
      maxConcurrentPerServer: 100,
      maxCallsPerSession: 100,
      maxResponseBytes: 1_000_000,
      sanitizeInput: false,
      sanitizeOutput: false,
      blockedServers: [],
      trustedServers: [],
    };
    const slowExecutor = () => new Promise((resolve) => setTimeout(resolve, 5000));

    let caught = false;
    try {
      await guardedCall("timeout-srv", "t", {}, slowExecutor, config);
    } catch (err) {
      caught = err instanceof CallGuardError && err.code === "TIMEOUT";
    }
    assert.ok(caught, "Expected TIMEOUT CallGuardError");
  });

  await test("enforces response size limit", async () => {
    resetGuards();
    const config: Partial<CallGuardConfig> = {
      callTimeoutMs: 5000,
      maxResponseBytes: 100,
      maxCallsPerMinutePerServer: 100,
      maxConcurrentPerServer: 100,
      maxCallsPerSession: 100,
      sanitizeInput: false,
      sanitizeOutput: false,
      blockedServers: [],
      trustedServers: [],
    };
    const bigExecutor = async () => ({ data: "x".repeat(1000) });

    let caught = false;
    try {
      await guardedCall("big-srv", "t", {}, bigExecutor, config);
    } catch (err) {
      caught = err instanceof CallGuardError && err.code === "RESPONSE_TOO_LARGE";
    }
    assert.ok(caught, "Expected RESPONSE_TOO_LARGE CallGuardError");
  });

  await test("tracks guard stats", async () => {
    resetGuards();
    const config: Partial<CallGuardConfig> = {
      callTimeoutMs: 5000,
      maxResponseBytes: 1_000_000,
      maxCallsPerMinutePerServer: 100,
      maxConcurrentPerServer: 100,
      maxCallsPerSession: 100,
      sanitizeInput: false,
      sanitizeOutput: false,
      blockedServers: [],
      trustedServers: [],
    };
    await guardedCall("stats-srv", "t", {}, async () => ({ ok: true }), config);
    const stats = getGuardStats();
    assert.equal(stats.totalSessionCalls, 1);
    assert.ok(stats.serverDetails["stats-srv"]);
  });

  // ——— Anomaly Detector ————————————————————————————————
  console.log("\n📦 Anomaly Detector");

  await test("detects burst calls", () => {
    resetAnomalyDetector();
    configureAnomalyDetector({ burstThreshold: 3 });
    const anomalies = [];
    for (let i = 0; i < 4; i++) {
      anomalies.push(...recordCall("tool", undefined, {}, true, 100));
    }
    assert.ok(anomalies.some((a) => a.type === "BURST_CALLS"));
  });

  await test("detects repeated failures", () => {
    resetAnomalyDetector();
    configureAnomalyDetector({ repeatedFailureThreshold: 3 });
    const anomalies = [];
    for (let i = 0; i < 3; i++) {
      anomalies.push(...recordCall("tool", "failing-srv", {}, false, 0));
    }
    assert.ok(anomalies.some((a) => a.type === "REPEATED_FAILURES"));
  });

  await test("detects SQL probing", () => {
    resetAnomalyDetector();
    const anomalies = recordCall("tool", undefined, {
      q: "SELECT * FROM users WHERE 1=1 UNION SELECT password FROM admin",
    }, true, 100);
    assert.ok(anomalies.some((a) => a.type === "PROBING_DETECTED"));
  });

  await test("detects command injection probing", () => {
    resetAnomalyDetector();
    const anomalies = recordCall("tool", undefined, {
      cmd: "; cat /etc/passwd",
    }, true, 100);
    assert.ok(anomalies.some((a) => a.type === "PROBING_DETECTED"));
  });

  await test("detects SSRF probing", () => {
    resetAnomalyDetector();
    const anomalies = recordCall("tool", undefined, {
      url: "http://169.254.169.254/latest/meta-data/",
    }, true, 100);
    assert.ok(anomalies.some((a) => a.type === "PROBING_DETECTED"));
  });

  await test("detects registration spam", () => {
    resetAnomalyDetector();
    configureAnomalyDetector({ maxRegistrationsPerHour: 3 });
    const anomalies = [];
    for (let i = 0; i < 4; i++) {
      anomalies.push(...recordCall("register_agent", undefined, { name: `bot-${i}` }, true, 100));
    }
    assert.ok(anomalies.some((a) => a.type === "REGISTRATION_SPAM"));
  });

  await test("records rate limit hits", () => {
    resetAnomalyDetector();
    const event = recordRateLimit("srv-1", "RATE_LIMIT");
    assert.equal(event.type, "RATE_LIMIT_HIT");
    assert.equal(event.severity, "medium");
  });

  await test("records trust score drops", () => {
    resetAnomalyDetector();
    const event = recordTrustScoreDrop("srv-1", 90, 50);
    assert.equal(event.type, "TRUST_SCORE_DROP");
    assert.equal(event.severity, "critical");
  });

  await test("returns anomaly stats", () => {
    resetAnomalyDetector();
    recordCall("tool", undefined, {}, true, 100);
    const stats = getAnomalyStats();
    assert.equal(stats.totalCalls, 1);
  });

  console.log(`\n📊 Results: ${passed} passed, ${failed} failed\n`);
  if (failed > 0) process.exit(1);
}

runTests().catch((err) => {
  console.error("Test runner failed:", err);
  process.exit(1);
});
