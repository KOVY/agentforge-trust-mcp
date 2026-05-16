/**
 * MCP Tool Call Guards — Application-level safety guards for proxied tool calls.
 *
 * NOT process-level sandboxing. This module enforces application-level guards:
 * rate limiting, timeout, payload size limits, allowlist/blocklist, and I/O
 * sanitization. For true process isolation, host the MCP server in a container
 * or namespace at the runtime/infrastructure layer.
 *
 * When `call_tool` proxies a request to an upstream MCP server, we can't
 * trust the response or trust that the upstream won't hang forever. This
 * module provides:
 *
 *   1. Timeout enforcement — kill calls that exceed a time limit
 *   2. Response size limits — prevent memory exhaustion from huge responses
 *   3. Rate limiting per server — prevent abuse of specific upstreams
 *   4. Allowlist/blocklist — restrict which servers can be called
 *   5. Input/output sanitization — strip dangerous patterns from payloads
 */

import { sanitizeFreeform } from "./input-validator.js";

// ─── Configuration ───────────────────────────────────────────────

export interface CallGuardConfig {
  /** Max time in ms for a single tool call (default: 30_000) */
  callTimeoutMs: number;
  /** Max response body size in bytes (default: 5_000_000 = 5MB) */
  maxResponseBytes: number;
  /** Max concurrent calls to the same server (default: 5) */
  maxConcurrentPerServer: number;
  /** Max total calls per server per minute (default: 60) */
  maxCallsPerMinutePerServer: number;
  /** Server IDs that are blocked from call_tool (default: []) */
  blockedServers: string[];
  /** Server IDs that bypass rate limiting (trusted, default: []) */
  trustedServers: string[];
  /** Whether to sanitize tool input before proxying (default: true) */
  sanitizeInput: boolean;
  /** Whether to sanitize tool response before returning (default: true) */
  sanitizeOutput: boolean;
  /** Max number of tool calls in a single session (default: 1000) */
  maxCallsPerSession: number;
}

const DEFAULT_CONFIG: CallGuardConfig = {
  callTimeoutMs: 30_000,
  maxResponseBytes: 5_000_000,
  maxConcurrentPerServer: 5,
  maxCallsPerMinutePerServer: 60,
  blockedServers: [],
  trustedServers: [],
  sanitizeInput: true,
  sanitizeOutput: true,
  maxCallsPerSession: 1000,
};

// ─── Rate Limiting ───────────────────────────────────────────────

interface RateLimitEntry {
  timestamps: number[];
  concurrent: number;
}

const rateLimitMap = new Map<string, RateLimitEntry>();

function cleanupOldTimestamps(entry: RateLimitEntry, windowMs: number): void {
  const cutoff = Date.now() - windowMs;
  entry.timestamps = entry.timestamps.filter((t) => t > cutoff);
}

function getOrCreateEntry(serverId: string): RateLimitEntry {
  let entry = rateLimitMap.get(serverId);
  if (!entry) {
    entry = { timestamps: [], concurrent: 0 };
    rateLimitMap.set(serverId, entry);
  }
  return entry;
}

// ─── Session tracking ────────────────────────────────────────────

let sessionCallCount = 0;

// ─── Guard Error ─────────────────────────────────────────────────

export class CallGuardError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly statusCode: number = 403
  ) {
    super(message);
    this.name = "CallGuardError";
  }
}

// ─── Guarded Call Result ─────────────────────────────────────────

export interface GuardedCallResult {
  /** The sanitized response data */
  data: unknown;
  /** Whether the call was allowed by the guards */
  allowed: boolean;
  /** Time taken in ms */
  durationMs: number;
  /** Response size in bytes (approximate) */
  responseSize: number;
  /** Any warnings generated during the call */
  warnings: string[];
}

// ─── Core Guards ─────────────────────────────────────────────────

/**
 * Check if a call to a specific server is allowed under current rate limits.
 */
export function checkRateLimit(serverId: string, config: CallGuardConfig): void {
  // Blocklist check
  if (config.blockedServers.includes(serverId)) {
    throw new CallGuardError(
      `Server "${serverId}" is blocked`,
      "SERVER_BLOCKED",
      403
    );
  }

  // Session limit
  if (sessionCallCount >= config.maxCallsPerSession) {
    throw new CallGuardError(
      `Session call limit reached (${config.maxCallsPerSession})`,
      "SESSION_LIMIT",
      429
    );
  }

  // Skip rate limiting for trusted servers
  if (config.trustedServers.includes(serverId)) {
    return;
  }

  const entry = getOrCreateEntry(serverId);

  // Concurrent check
  if (entry.concurrent >= config.maxConcurrentPerServer) {
    throw new CallGuardError(
      `Too many concurrent calls to server "${serverId}" (${config.maxConcurrentPerServer})`,
      "CONCURRENT_LIMIT",
      429
    );
  }

  // Rate limit check (sliding window)
  cleanupOldTimestamps(entry, 60_000);
  if (entry.timestamps.length >= config.maxCallsPerMinutePerServer) {
    throw new CallGuardError(
      `Rate limit exceeded for server "${serverId}" (${config.maxCallsPerMinutePerServer}/min)`,
      "RATE_LIMIT",
      429
    );
  }
}

/**
 * Wrap an HTTP call with application-level guards:
 * - Pre-call: rate limit, blocklist, input sanitization
 * - During call: timeout
 * - Post-call: response size limit, output sanitization
 */
export async function guardedCall(
  serverId: string,
  toolName: string,
  input: Record<string, unknown>,
  executor: () => Promise<unknown>,
  config: Partial<CallGuardConfig> = {}
): Promise<GuardedCallResult> {
  const cfg: CallGuardConfig = { ...DEFAULT_CONFIG, ...config };
  const warnings: string[] = [];
  const startTime = Date.now();

  // Pre-call checks
  checkRateLimit(serverId, cfg);

  // Input sanitization
  let sanitizedInput = input;
  if (cfg.sanitizeInput) {
    const result = sanitizeFreeform(input, `call_tool.${toolName}`);
    if (!result.valid) {
      warnings.push(...result.errors.map((e) => `Input sanitization: ${e.message} at ${e.path}`));
    }
    sanitizedInput = result.sanitized as Record<string, unknown>;
  }

  // Track concurrent + session
  const entry = getOrCreateEntry(serverId);
  entry.concurrent++;
  sessionCallCount++;
  entry.timestamps.push(Date.now());

  try {
    // Execute with timeout
    const response = await executeWithTimeout(executor, cfg.callTimeoutMs);

    // Response size check
    const responseStr = JSON.stringify(response);
    const responseSize = Buffer.byteLength(responseStr, "utf-8");

    if (responseSize > cfg.maxResponseBytes) {
      throw new CallGuardError(
        `Response too large (${responseSize} bytes, max ${cfg.maxResponseBytes})`,
        "RESPONSE_TOO_LARGE",
        502
      );
    }

    // Output sanitization
    let sanitizedOutput = response;
    if (cfg.sanitizeOutput) {
      const result = sanitizeFreeform(response, `response.${toolName}`);
      if (!result.valid) {
        warnings.push(...result.errors.map((e) => `Output sanitization: ${e.message} at ${e.path}`));
      }
      sanitizedOutput = result.sanitized;
    }

    return {
      data: sanitizedOutput,
      allowed: true,
      durationMs: Date.now() - startTime,
      responseSize,
      warnings,
    };
  } catch (err) {
    if (err instanceof CallGuardError) throw err;
    throw new CallGuardError(
      `Tool call failed: ${(err as Error).message}`,
      "CALL_FAILED",
      502
    );
  } finally {
    entry.concurrent--;
  }
}

/**
 * Execute a function with a timeout.
 */
function executeWithTimeout<T>(
  fn: () => Promise<T>,
  timeoutMs: number
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new CallGuardError(`Call timed out after ${timeoutMs}ms`, "TIMEOUT", 504));
    }, timeoutMs);

    fn()
      .then((result) => {
        clearTimeout(timer);
        resolve(result);
      })
      .catch((err) => {
        clearTimeout(timer);
        reject(err);
      });
  });
}

/**
 * Reset guard state (useful for testing or session reset).
 */
export function resetGuards(): void {
  rateLimitMap.clear();
  sessionCallCount = 0;
}

/**
 * Get current guard statistics.
 */
export function getGuardStats(): {
  activeServers: number;
  totalSessionCalls: number;
  serverDetails: Record<string, { concurrent: number; callsLastMinute: number }>;
} {
  const now = Date.now();
  const serverDetails: Record<string, { concurrent: number; callsLastMinute: number }> = {};

  for (const [serverId, entry] of rateLimitMap.entries()) {
    cleanupOldTimestamps(entry, 60_000);
    serverDetails[serverId] = {
      concurrent: entry.concurrent,
      callsLastMinute: entry.timestamps.length,
    };
  }

  return {
    activeServers: rateLimitMap.size,
    totalSessionCalls: sessionCallCount,
    serverDetails,
  };
}

/**
 * Create a CallGuardConfig from environment variables.
 *
 * Environment variables (all optional):
 *   MCP_CALL_TIMEOUT_MS       — call timeout in ms
 *   MCP_MAX_RESPONSE_BYTES    — max response size in bytes
 *   MCP_MAX_CONCURRENT        — max concurrent calls per server
 *   MCP_RATE_LIMIT_PER_MIN    — max calls per minute per server
 *   MCP_BLOCKED_SERVERS       — comma-separated server IDs to block
 *   MCP_TRUSTED_SERVERS       — comma-separated trusted server IDs
 *   MCP_SANITIZE_INPUT        — "true"/"false" (default: true)
 *   MCP_SANITIZE_OUTPUT       — "true"/"false" (default: true)
 *   MCP_MAX_CALLS_PER_SESSION — max calls per session
 */
export function guardConfigFromEnv(): Partial<CallGuardConfig> {
  const env = process.env;
  const config: Partial<CallGuardConfig> = {};

  if (env.MCP_CALL_TIMEOUT_MS) config.callTimeoutMs = parseInt(env.MCP_CALL_TIMEOUT_MS, 10);
  if (env.MCP_MAX_RESPONSE_BYTES) config.maxResponseBytes = parseInt(env.MCP_MAX_RESPONSE_BYTES, 10);
  if (env.MCP_MAX_CONCURRENT) config.maxConcurrentPerServer = parseInt(env.MCP_MAX_CONCURRENT, 10);
  if (env.MCP_RATE_LIMIT_PER_MIN) config.maxCallsPerMinutePerServer = parseInt(env.MCP_RATE_LIMIT_PER_MIN, 10);
  if (env.MCP_BLOCKED_SERVERS) config.blockedServers = env.MCP_BLOCKED_SERVERS.split(",").map((s) => s.trim());
  if (env.MCP_TRUSTED_SERVERS) config.trustedServers = env.MCP_TRUSTED_SERVERS.split(",").map((s) => s.trim());
  if (env.MCP_SANITIZE_INPUT) config.sanitizeInput = env.MCP_SANITIZE_INPUT === "true";
  if (env.MCP_SANITIZE_OUTPUT) config.sanitizeOutput = env.MCP_SANITIZE_OUTPUT === "true";
  if (env.MCP_MAX_CALLS_PER_SESSION) config.maxCallsPerSession = parseInt(env.MCP_MAX_CALLS_PER_SESSION, 10);

  return config;
}
