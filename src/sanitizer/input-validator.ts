/**
 * MCP Input Validator — Schema enforcement for MCP tool arguments.
 *
 * Every tool call is validated against its declared inputSchema before
 * the handler runs. This prevents:
 *   - Prototype pollution (__proto__, constructor, prototype keys)
 *   - Type coercion attacks (string → object injection)
 *   - Oversized payloads (DoS)
 *   - Missing required fields
 *   - Extra/unknown properties where strict mode is needed
 *
 * Zero external deps — pure TypeScript runtime validation.
 */

// ─── Types ────────────────────────────────────────────────────────

export interface ValidationRule {
  type: "string" | "number" | "boolean" | "object" | "array";
  required?: boolean;
  enum?: string[];
  minLength?: number;
  maxLength?: number;
  minimum?: number;
  maximum?: number;
  maxItems?: number;
  properties?: Record<string, ValidationRule>;
  items?: ValidationRule;
  additionalProperties?: boolean;
  pattern?: string;
  description?: string;
}

export interface ValidationResult {
  valid: boolean;
  errors: ValidationError[];
  sanitized: Record<string, unknown>;
}

export interface ValidationError {
  path: string;
  message: string;
  code: string;
}

// ─── Dangerous patterns ──────────────────────────────────────────

const DANGEROUS_KEYS = new Set([
  "__proto__",
  "constructor",
  "prototype",
  "__defineGetter__",
  "__defineSetter__",
  "__lookupGetter__",
  "__lookupSetter__",
  "toString",
  "valueOf",
  "hasOwnProperty",
  "isPrototypeOf",
  "propertyIsEnumerable",
]);

// Regex patterns that indicate injection attempts
const INJECTION_PATTERNS: Array<{ pattern: RegExp; name: string }> = [
  { pattern: /<script[\s>]/i, name: "SCRIPT_TAG" },
  { pattern: /javascript:/i, name: "JS_PROTOCOL" },
  { pattern: /on\w+\s*=/i, name: "EVENT_HANDLER" },
  { pattern: /\$\{.*\}/, name: "TEMPLATE_INJECTION" },
  // Path traversal
  { pattern: /\.\.[\/\\]/, name: "PATH_TRAVERSAL" },
  // Null byte
  { pattern: /\0/, name: "NULL_BYTE" },
  // Control characters (except \t \n \r)
  { pattern: /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/, name: "CONTROL_CHAR" },
];

// ─── Size limits ─────────────────────────────────────────────────

const MAX_STRING_LENGTH = 100_000; // 100KB per string field
const MAX_ARRAY_ITEMS = 10_000;
const MAX_OBJECT_KEYS = 500;
const MAX_TOTAL_PAYLOAD_SIZE = 1_000_000; // 1MB total
const MAX_NESTING_DEPTH = 10;

// ─── Validator ────────────────────────────────────────────────────

function pushError(
  errors: ValidationError[],
  path: string,
  message: string,
  code: string
): void {
  errors.push({ path, message, code });
}

/**
 * Validate a single value against a ValidationRule.
 */
function validateValue(
  value: unknown,
  rule: ValidationRule,
  path: string,
  errors: ValidationError[],
  depth: number
): unknown {
  // Depth check
  if (depth > MAX_NESTING_DEPTH) {
    pushError(errors, path, `Nesting depth exceeds ${MAX_NESTING_DEPTH}`, "NESTING_TOO_DEEP");
    return undefined;
  }

  // Null/undefined check
  if (value === null || value === undefined) {
    if (rule.required) {
      pushError(errors, path, "Value is required", "REQUIRED");
    }
    return undefined;
  }

  // Type check
  const actualType = Array.isArray(value) ? "array" : typeof value;
  if (actualType !== rule.type) {
    // Allow number coercion for strings that are valid numbers
    if (rule.type === "number" && typeof value === "string") {
      const num = Number(value);
      if (!isNaN(num) && isFinite(num)) {
        value = num;
      } else {
        pushError(errors, path, `Expected ${rule.type}, got ${actualType}`, "TYPE_MISMATCH");
        return undefined;
      }
    } else if (rule.type === "string" && typeof value === "number") {
      value = String(value);
    } else {
      pushError(errors, path, `Expected ${rule.type}, got ${actualType}`, "TYPE_MISMATCH");
      return undefined;
    }
  }

  // String validation
  if (rule.type === "string" && typeof value === "string") {
    // Length checks
    if (rule.minLength !== undefined && value.length < rule.minLength) {
      pushError(errors, path, `String too short (min ${rule.minLength})`, "MIN_LENGTH");
    }
    const maxLen = rule.maxLength ?? MAX_STRING_LENGTH;
    if (value.length > maxLen) {
      pushError(errors, path, `String too long (max ${maxLen})`, "MAX_LENGTH");
    }

    // Pattern check
    if (rule.pattern) {
      const regex = new RegExp(rule.pattern);
      if (!regex.test(value)) {
        pushError(errors, path, `Does not match pattern ${rule.pattern}`, "PATTERN_MISMATCH");
      }
    }

    // Enum check
    if (rule.enum && !rule.enum.includes(value)) {
      pushError(errors, path, `Must be one of: ${rule.enum.join(", ")}`, "ENUM_MISMATCH");
    }

    // Injection detection
    for (const { pattern, name } of INJECTION_PATTERNS) {
      if (pattern.test(value)) {
        pushError(errors, path, `Potential injection detected: ${name}`, "INJECTION_DETECTED");
      }
    }
  }

  // Number validation
  if (rule.type === "number" && typeof value === "number") {
    if (!isFinite(value)) {
      pushError(errors, path, "Number must be finite", "NON_FINITE");
    }
    if (rule.minimum !== undefined && value < rule.minimum) {
      pushError(errors, path, `Number too small (min ${rule.minimum})`, "MIN_VALUE");
    }
    if (rule.maximum !== undefined && value > rule.maximum) {
      pushError(errors, path, `Number too large (max ${rule.maximum})`, "MAX_VALUE");
    }
  }

  // Array validation
  if (rule.type === "array" && Array.isArray(value)) {
    const maxItems = rule.maxItems ?? MAX_ARRAY_ITEMS;
    if (value.length > maxItems) {
      pushError(errors, path, `Array too large (max ${maxItems} items)`, "MAX_ITEMS");
    }
    if (rule.items) {
      const sanitizedArr: unknown[] = [];
      for (let i = 0; i < Math.min(value.length, maxItems); i++) {
        const item = validateValue(value[i], rule.items, `${path}[${i}]`, errors, depth + 1);
        sanitizedArr.push(item);
      }
      return sanitizedArr;
    }
  }

  // Object validation
  if (rule.type === "object" && typeof value === "object" && value !== null && !Array.isArray(value)) {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj);

    if (keys.length > MAX_OBJECT_KEYS) {
      pushError(errors, path, `Too many keys (max ${MAX_OBJECT_KEYS})`, "MAX_KEYS");
    }

    const sanitized: Record<string, unknown> = {};
    const allowedKeys = rule.properties ? new Set(Object.keys(rule.properties)) : null;

    for (const key of keys) {
      // Dangerous key check
      if (DANGEROUS_KEYS.has(key)) {
        pushError(errors, `${path}.${key}`, `Dangerous key "${key}" is not allowed`, "DANGEROUS_KEY");
        continue;
      }

      // If properties are defined and additionalProperties is false, reject unknown keys
      if (allowedKeys && !allowedKeys.has(key) && rule.additionalProperties === false) {
        pushError(errors, `${path}.${key}`, `Unknown property "${key}"`, "UNKNOWN_PROPERTY");
        continue;
      }

      if (rule.properties && rule.properties[key]) {
        sanitized[key] = validateValue(obj[key], rule.properties[key], `${path}.${key}`, errors, depth + 1);
      } else {
        // Recursively sanitize unknown objects
        sanitized[key] = sanitizeValue(obj[key], `${path}.${key}`, errors, depth + 1);
      }
    }

    // Check required properties
    if (rule.properties) {
      for (const [key, propRule] of Object.entries(rule.properties)) {
        if (propRule.required && !(key in obj)) {
          pushError(errors, `${path}.${key}`, `Required property "${key}" is missing`, "MISSING_REQUIRED");
        }
      }
    }

    return sanitized;
  }

  return value;
}

/**
 * Sanitize a value without a specific schema — strip dangerous keys,
 * check for injection patterns, enforce size limits.
 */
function sanitizeValue(
  value: unknown,
  path: string,
  errors: ValidationError[],
  depth: number
): unknown {
  if (depth > MAX_NESTING_DEPTH) return undefined;
  if (value === null || value === undefined) return value;

  if (typeof value === "string") {
    if (value.length > MAX_STRING_LENGTH) {
      pushError(errors, path, `String exceeds max length ${MAX_STRING_LENGTH}`, "MAX_LENGTH");
      return value.substring(0, MAX_STRING_LENGTH);
    }
    for (const { pattern, name } of INJECTION_PATTERNS) {
      if (pattern.test(value)) {
        pushError(errors, path, `Potential injection: ${name}`, "INJECTION_DETECTED");
      }
    }
    return value;
  }

  if (typeof value === "number") {
    if (!isFinite(value)) {
      pushError(errors, path, "Non-finite number", "NON_FINITE");
      return 0;
    }
    return value;
  }

  if (typeof value === "boolean") return value;

  if (Array.isArray(value)) {
    if (value.length > MAX_ARRAY_ITEMS) {
      pushError(errors, path, `Array exceeds max items ${MAX_ARRAY_ITEMS}`, "MAX_ITEMS");
      return value.slice(0, MAX_ARRAY_ITEMS);
    }
    return value.map((item, i) => sanitizeValue(item, `${path}[${i}]`, errors, depth + 1));
  }

  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj);

    if (keys.length > MAX_OBJECT_KEYS) {
      pushError(errors, path, `Object exceeds max keys ${MAX_OBJECT_KEYS}`, "MAX_KEYS");
    }

    const sanitized: Record<string, unknown> = {};
    for (const key of keys) {
      if (DANGEROUS_KEYS.has(key)) {
        pushError(errors, `${path}.${key}`, `Dangerous key "${key}" stripped`, "DANGEROUS_KEY");
        continue;
      }
      sanitized[key] = sanitizeValue(obj[key], `${path}.${key}`, errors, depth + 1);
    }
    return sanitized;
  }

  return value;
}

/**
 * Estimate serialized size of a value.
 */
function estimateSize(value: unknown): number {
  try {
    return JSON.stringify(value).length;
  } catch {
    return Infinity;
  }
}

// ─── Public API ──────────────────────────────────────────────────

/**
 * Validate tool call arguments against a schema.
 *
 * Returns a ValidationResult with:
 *   - valid: boolean
 *   - errors: array of ValidationError objects
 *   - sanitized: the cleaned/sanitized arguments
 */
export function validateToolArgs(
  args: Record<string, unknown>,
  schema: Record<string, ValidationRule>
): ValidationResult {
  const errors: ValidationError[] = [];
  const sanitized: Record<string, unknown> = {};

  // Total payload size check
  const totalSize = estimateSize(args);
  if (totalSize > MAX_TOTAL_PAYLOAD_SIZE) {
    pushError(errors, "", `Payload too large (${totalSize} bytes, max ${MAX_TOTAL_PAYLOAD_SIZE})`, "PAYLOAD_TOO_LARGE");
    return { valid: false, errors, sanitized: {} };
  }

  // Validate each declared property
  for (const [key, rule] of Object.entries(schema)) {
    if (key in args) {
      sanitized[key] = validateValue(args[key], rule, key, errors, 0);
    } else if (rule.required) {
      pushError(errors, key, `Required argument "${key}" is missing`, "MISSING_REQUIRED");
    }
  }

  // Check for undeclared dangerous keys in the raw args
  for (const key of Object.keys(args)) {
    if (DANGEROUS_KEYS.has(key)) {
      pushError(errors, key, `Dangerous key "${key}" in arguments`, "DANGEROUS_KEY");
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    sanitized,
  };
}

/**
 * Lightweight sanitizer for free-form input (no schema).
 * Strips dangerous keys, enforces size limits, flags injections.
 */
export function sanitizeFreeform(
  value: unknown,
  path = "$"
): ValidationResult {
  const errors: ValidationError[] = [];
  const sanitized = sanitizeValue(value, path, errors, 0);
  return {
    valid: errors.length === 0,
    errors,
    sanitized: sanitized as Record<string, unknown>,
  };
}

/**
 * Re-export constants for external configuration.
 */
export const LIMITS = {
  MAX_STRING_LENGTH,
  MAX_ARRAY_ITEMS,
  MAX_OBJECT_KEYS,
  MAX_TOTAL_PAYLOAD_SIZE,
  MAX_NESTING_DEPTH,
} as const;
