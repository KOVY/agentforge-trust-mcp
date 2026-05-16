/**
 * MCP Sanitization Layer — Public API
 *
 * Re-exports all sanitizer components:
 *   - Input validation (schema enforcement)
 *   - Call guards (rate limiting, timeout, response guards)
 *   - Anomaly detection (suspicious pattern logging)
 *
 * Usage:
 *   import { validateToolArgs, guardedCall, recordCall } from "./sanitizer/index.js";
 */

export {
  validateToolArgs,
  sanitizeFreeform,
  LIMITS,
  type ValidationRule,
  type ValidationResult,
  type ValidationError,
} from "./input-validator.js";

export {
  guardedCall,
  checkRateLimit,
  resetGuards,
  getGuardStats,
  guardConfigFromEnv,
  CallGuardError,
  type CallGuardConfig,
  type GuardedCallResult,
} from "./guards.js";

export {
  recordCall,
  recordRateLimit,
  recordTrustScoreDrop,
  configureAnomalyDetector,
  getAnomalyStats,
  resetAnomalyDetector,
  anomalyConfigFromEnv,
  type AnomalyEvent,
  type AnomalySeverity,
  type AnomalyType,
  type AnomalyConfig,
} from "./anomaly-detector.js";
