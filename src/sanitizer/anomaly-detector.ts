/**
 * MCP Runtime Anomaly Detector — Detects and logs suspicious patterns
 * in MCP tool call activity.
 *
 * Monitors:
 *   1. Unusual call frequency (burst detection)
 *   2. Repeated failures to specific servers
 *   3. Calls with patterns suggesting probing/scanning
 *   4. Unusual argument patterns (SQL injection, path traversal, etc.)
 *   5. Servers with suddenly changing trust scores
 *   6. High volume of register_agent calls (spam prevention)
 *
 * All anomalies are logged to stderr (MCP-safe) and can be forwarded
 * to the AgentForge API for centralized monitoring.
 */

import { writeFileSync, appendFileSync, mkdirSync, existsSync } from "node:fs";
import { join } from "node:path";

// ─── Types ────────────────────────────────────────────────────────

export type AnomalySeverity = "low" | "medium" | "high" | "critical";

export interface AnomalyEvent {
  timestamp: string;
  id: string;
  type: AnomalyType;
  severity: AnomalySeverity;
  source: string;
  message: string;
  details: Record<string, unknown>;
}

export type AnomalyType =
  | "BURST_CALLS"
  | "REPEATED_FAILURES"
  | "PROBING_DETECTED"
  | "INJECTION_ATTEMPT"
  | "SUSPICIOUS_SERVER"
  | "REGISTRATION_SPAM"
  | "UNUSUAL_ARGUMENTS"
  | "RATE_LIMIT_HIT"
  | "RESPONSE_ANOMALY"
  | "TRUST_SCORE_DROP";

export interface AnomalyConfig {
  /** Max calls in a 10-second window before triggering BURST_CALLS (default: 20) */
  burstThreshold: number;
  /** Consecutive failures before REPEATED_FAILURES (default: 5) */
  repeatedFailureThreshold: number;
  /** Max registration attempts per hour (default: 10) */
  maxRegistrationsPerHour: number;
  /** Whether to write anomalies to a log file (default: false) */
  logToFile: boolean;
  /** Directory for log files (default: ./logs) */
  logDirectory: string;
  /** Whether to send anomalies to AgentForge API (default: false) */
  reportRemote: boolean;
  /** Minimum severity to log (default: "low") */
  minSeverity: AnomalySeverity;
}

const DEFAULT_CONFIG: AnomalyConfig = {
  burstThreshold: 20,
  repeatedFailureThreshold: 5,
  maxRegistrationsPerHour: 10,
  logToFile: false,
  logDirectory: "./logs",
  reportRemote: false,
  minSeverity: "low",
};

const SEVERITY_ORDER: Record<AnomalySeverity, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

// ─── Internal State ───────────────────────────────────────────────

interface CallRecord {
  timestamp: number;
  tool: string;
  server?: string;
  success: boolean;
  durationMs: number;
}

interface ServerState {
  consecutiveFailures: number;
  totalCalls: number;
  totalFailures: number;
  lastCallTimestamp: number;
}

let callHistory: CallRecord[] = [];
const serverStates = new Map<string, ServerState>();
let registrationTimestamps: number[] = [];
let anomalyCount = 0;
let config: AnomalyConfig = { ...DEFAULT_CONFIG };

// ─── Event ID generation ─────────────────────────────────────────

function generateEventId(): string {
  anomalyCount++;
  const ts = Date.now().toString(36);
  const count = anomalyCount.toString(36);
  return `anom-${ts}-${count}`;
}

// ─── Detection helpers ───────────────────────────────────────────

function recentCallCount(windowMs: number): number {
  const cutoff = Date.now() - windowMs;
  return callHistory.filter((r) => r.timestamp > cutoff).length;
}

function cleanupOldRecords(): void {
  const cutoff = Date.now() - 300_000; // Keep 5 minutes of history
  callHistory = callHistory.filter((r) => r.timestamp > cutoff);
}

function cleanupRegistrations(): void {
  const cutoff = Date.now() - 3_600_000; // 1 hour
  registrationTimestamps = registrationTimestamps.filter((t) => t > cutoff);
}

// ─── Suspicious pattern detection ────────────────────────────────

const PROBING_PATTERNS: Array<{ pattern: RegExp; name: string }> = [
  // SQL injection probes
  { pattern: /(\b(union|select|insert|update|delete|drop|alter|exec)\b.*\b(from|into|table|where)\b)/i, name: "SQL_PROBE" },
  // LDAP injection
  { pattern: /(\)|\()[^)]*\)(\)|\()/, name: "LDAP_PROBE" },
  // Command injection probes
  { pattern: /[;&|`$]\s*(cat|ls|whoami|id|pwd|uname|env|printenv|wget|curl|nc|bash|sh|python|node|ruby|perl)\b/i, name: "CMD_PROBE" },
  // XML/XXE
  { pattern: /<!\[(cdata|entity)\b/i, name: "XXE_PROBE" },
  // SSRF
  { pattern: /(127\.0\.0\.1|localhost|169\.254\.169\.254|0\.0\.0\.0|\[::1\]|\[::\])/i, name: "SSRF_PROBE" },
  // Directory listing/enumeration
  { pattern: /\/etc\/(passwd|shadow|hosts|hostname)|\/proc\/self|\/var\/log/i, name: "FS_PROBE" },
];

function detectSuspiciousArgs(args: Record<string, unknown>): string[] {
  const found: string[] = [];
  const argsStr = JSON.stringify(args);

  for (const { pattern, name } of PROBING_PATTERNS) {
    if (pattern.test(argsStr)) {
      found.push(name);
    }
  }

  return found;
}

// ─── Core Detection ──────────────────────────────────────────────

/**
 * Record a tool call and check for anomalies.
 */
export function recordCall(
  tool: string,
  server: string | undefined,
  args: Record<string, unknown>,
  success: boolean,
  durationMs: number
): AnomalyEvent[] {
  const anomalies: AnomalyEvent[] = [];
  const now = Date.now();

  // Record call
  callHistory.push({ timestamp: now, tool, server, success, durationMs });
  cleanupOldRecords();

  // Update server state
  if (server) {
    const state = serverStates.get(server) ?? {
      consecutiveFailures: 0,
      totalCalls: 0,
      totalFailures: 0,
      lastCallTimestamp: 0,
    };
    state.totalCalls++;
    state.lastCallTimestamp = now;

    if (!success) {
      state.consecutiveFailures++;
      state.totalFailures++;
    } else {
      state.consecutiveFailures = 0;
    }

    serverStates.set(server, state);

    // Check repeated failures
    if (state.consecutiveFailures >= config.repeatedFailureThreshold) {
      anomalies.push(createEvent(
        "REPEATED_FAILURES",
        "high",
        server,
        `${config.repeatedFailureThreshold} consecutive failures on server "${server}"`,
        { consecutiveFailures: state.consecutiveFailures, totalFailures: state.totalFailures }
      ));
    }
  }

  // Burst detection (10-second window)
  if (recentCallCount(10_000) >= config.burstThreshold) {
    anomalies.push(createEvent(
      "BURST_CALLS",
      "medium",
      tool,
      `Burst detected: ${config.burstThreshold}+ calls in 10 seconds`,
      { recentCalls: recentCallCount(10_000), tool }
    ));
  }

  // Probing detection
  const probes = detectSuspiciousArgs(args);
  if (probes.length > 0) {
    anomalies.push(createEvent(
      "PROBING_DETECTED",
      "critical",
      tool,
      `Suspicious patterns in arguments: ${probes.join(", ")}`,
      { probes, argsPreview: JSON.stringify(args).substring(0, 500) }
    ));
  }

  // Registration spam
  if (tool === "register_agent") {
    registrationTimestamps.push(now);
    cleanupRegistrations();
    if (registrationTimestamps.length >= config.maxRegistrationsPerHour) {
      anomalies.push(createEvent(
        "REGISTRATION_SPAM",
        "high",
        "register_agent",
        `${config.maxRegistrationsPerHour}+ registrations in 1 hour`,
        { registrationCount: registrationTimestamps.length }
      ));
    }
  }

  // Unusual duration
  if (success && durationMs > 15_000) {
    anomalies.push(createEvent(
      "RESPONSE_ANOMALY",
      "low",
      tool,
      `Unusually slow response: ${durationMs}ms`,
      { durationMs, server }
    ));
  }

  // Log all anomalies
  for (const event of anomalies) {
    logAnomaly(event);
  }

  return anomalies;
}

/**
 * Record a rate limit hit.
 */
export function recordRateLimit(serverId: string, limitType: string): AnomalyEvent {
  const event = createEvent(
    "RATE_LIMIT_HIT",
    "medium",
    serverId,
    `Rate limit hit: ${limitType} for server "${serverId}"`,
    { limitType }
  );
  logAnomaly(event);
  return event;
}

/**
 * Record a trust score drop.
 */
export function recordTrustScoreDrop(
  serverId: string,
  previousScore: number,
  newScore: number
): AnomalyEvent {
  const drop = previousScore - newScore;
  const severity: AnomalySeverity = drop > 30 ? "critical" : drop > 15 ? "high" : "medium";

  const event = createEvent(
    "TRUST_SCORE_DROP",
    severity,
    serverId,
    `Trust score dropped ${drop} points (${previousScore} → ${newScore}) for server "${serverId}"`,
    { previousScore, newScore, drop }
  );
  logAnomaly(event);
  return event;
}

// ─── Event creation ──────────────────────────────────────────────

function createEvent(
  type: AnomalyType,
  severity: AnomalySeverity,
  source: string,
  message: string,
  details: Record<string, unknown>
): AnomalyEvent {
  return {
    timestamp: new Date().toISOString(),
    id: generateEventId(),
    type,
    severity,
    source,
    message,
    details,
  };
}

// ─── Logging ─────────────────────────────────────────────────────

function logAnomaly(event: AnomalyEvent): void {
  if (SEVERITY_ORDER[event.severity] < SEVERITY_ORDER[config.minSeverity]) {
    return;
  }

  // Always log to stderr (MCP-safe)
  const severityEmoji: Record<AnomalySeverity, string> = {
    low: "⚠️",
    medium: "🟡",
    high: "🔴",
    critical: "🚨",
  };

  console.error(
    `[anomaly] ${severityEmoji[event.severity]} ${event.type} | ${event.source} | ${event.message}`
  );

  // Optionally log to file
  if (config.logToFile) {
    try {
      if (!existsSync(config.logDirectory)) {
        mkdirSync(config.logDirectory, { recursive: true });
      }
      const logFile = join(config.logDirectory, `anomalies-${new Date().toISOString().split("T")[0]}.ndjson`);
      appendFileSync(logFile, JSON.stringify(event) + "\n", "utf-8");
    } catch {
      // Don't crash on log failure
    }
  }
}

// ─── Configuration ───────────────────────────────────────────────

/**
 * Configure the anomaly detector.
 */
export function configureAnomalyDetector(userConfig: Partial<AnomalyConfig>): void {
  config = { ...DEFAULT_CONFIG, ...userConfig };
}

/**
 * Get current anomaly detector statistics.
 */
export function getAnomalyStats(): {
  totalCalls: number;
  totalAnomalies: number;
  trackedServers: number;
  recentCalls10s: number;
  recentRegistrations1h: number;
} {
  return {
    totalCalls: callHistory.length,
    totalAnomalies: anomalyCount,
    trackedServers: serverStates.size,
    recentCalls10s: recentCallCount(10_000),
    recentRegistrations1h: registrationTimestamps.length,
  };
}

/**
 * Reset anomaly detector state (for testing).
 */
export function resetAnomalyDetector(): void {
  callHistory = [];
  serverStates.clear();
  registrationTimestamps = [];
  anomalyCount = 0;
}

/**
 * Create AnomalyConfig from environment variables.
 *
 * Environment variables (all optional):
 *   MCP_ANOMALY_BURST_THRESHOLD   — calls in 10s to trigger burst
 *   MCP_ANOMALY_FAILURE_THRESHOLD — consecutive failures
 *   MCP_ANOMALY_REG_LIMIT         — registrations per hour
 *   MCP_ANOMALY_LOG_TO_FILE       — "true"/"false"
 *   MCP_ANOMALY_LOG_DIR           — log directory
 *   MCP_ANOMALY_REPORT_REMOTE     — "true"/"false"
 *   MCP_ANOMALY_MIN_SEVERITY      — "low"/"medium"/"high"/"critical"
 */
export function anomalyConfigFromEnv(): Partial<AnomalyConfig> {
  const env = process.env;
  const cfg: Partial<AnomalyConfig> = {};

  if (env.MCP_ANOMALY_BURST_THRESHOLD) cfg.burstThreshold = parseInt(env.MCP_ANOMALY_BURST_THRESHOLD, 10);
  if (env.MCP_ANOMALY_FAILURE_THRESHOLD) cfg.repeatedFailureThreshold = parseInt(env.MCP_ANOMALY_FAILURE_THRESHOLD, 10);
  if (env.MCP_ANOMALY_REG_LIMIT) cfg.maxRegistrationsPerHour = parseInt(env.MCP_ANOMALY_REG_LIMIT, 10);
  if (env.MCP_ANOMALY_LOG_TO_FILE) cfg.logToFile = env.MCP_ANOMALY_LOG_TO_FILE === "true";
  if (env.MCP_ANOMALY_LOG_DIR) cfg.logDirectory = env.MCP_ANOMALY_LOG_DIR;
  if (env.MCP_ANOMALY_REPORT_REMOTE) cfg.reportRemote = env.MCP_ANOMALY_REPORT_REMOTE === "true";
  if (env.MCP_ANOMALY_MIN_SEVERITY) {
    const sev = env.MCP_ANOMALY_MIN_SEVERITY as AnomalySeverity;
    if (SEVERITY_ORDER[sev] !== undefined) cfg.minSeverity = sev;
  }

  return cfg;
}
