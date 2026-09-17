/**
 * Serialization guard for cross-host command payloads.
 *
 * This is the fidelity patch for the biggest hole in the whole E2E approach.
 *
 * In production the UI extension runs on the host and the workspace extension
 * runs inside the dev container. A `vscode.commands.executeCommand` between
 * them crosses a process *and machine* boundary, so arguments and return
 * values are serialized by VS Code's RPC layer. Inside a single extension
 * host — which is exactly what `test/vscode-e2e` gives us — the same call is a
 * direct in-process function invocation and objects pass **by reference**.
 *
 * The consequence is that a payload carrying a `Buffer`, a `Date`, a `Map`, or
 * any class instance sails through the E2E test and breaks in production, with
 * a failure mode (silently mangled cert bytes) that is miserable to diagnose.
 * So every payload that crosses the host↔workspace seam is run through the
 * checks below, which model what the RPC layer would do to it.
 *
 * Two independent checks, because they fail on different things:
 *
 *   1. `findWireViolations` — a structural walk. Rejects anything that is not
 *      a JSON primitive, a plain object, or an array. This is what catches a
 *      `Buffer` field, because the value that comes back from a JSON round
 *      trip (`{type:"Buffer",data:[…]}`) is *not* equal to the original and,
 *      worse, a `Uint8Array` would come back from `structuredClone` looking
 *      perfectly fine while dying on the real wire.
 *   2. `assertRoundTripStable` — an actual `structuredClone` and an actual
 *      `JSON.parse(JSON.stringify(...))`, compared back against the original.
 *      Catches ordering/identity surprises the structural walk can't see, and
 *      is the check that would fire on a getter with side effects or a
 *      `toJSON` that rewrites the shape.
 *
 * ## The one thing deliberately tolerated: `undefined` properties
 *
 * `JSON.stringify` drops object keys whose value is `undefined`, and VS Code's
 * own RPC does the same. `CertMaterialV3` is full of optional fields that the
 * host sets to a literal `undefined` (`pemKeyBase64`, `rootPfxBase64`,
 * `dotNetStorePfxBase64`, …), so a strict `deepStrictEqual` would fail on
 * every real bundle for a difference that is semantically nil — every consumer
 * of these types tests with `?.` or `!== undefined`, for which an absent key
 * and an `undefined` key are identical.
 *
 * So the comparison treats "key absent" and "key present, value undefined" as
 * equal. It does NOT extend that tolerance to arrays: `undefined` in an array
 * becomes `null` after a JSON round trip, which is a real change of value and
 * is reported as a violation.
 */

export interface WireViolation {
  /** JSON-path-ish location of the offending value, e.g. `$.certs[0].pfx`. */
  path: string;
  reason: string;
}

/** Thrown by the `assert*` helpers. Carries the structured findings. */
export class WireGuardError extends Error {
  // Plain field rather than a constructor parameter property, so this module
  // also loads under Node's strip-only TypeScript support.
  readonly violations: readonly WireViolation[];

  constructor(message: string, violations: readonly WireViolation[] = []) {
    super(message);
    this.name = "WireGuardError";
    this.violations = violations;
  }
}

function describe(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  const t = typeof value;
  if (t !== "object") return t;
  const proto: unknown = Object.getPrototypeOf(value);
  if (proto === null) return "null-prototype object";
  const ctor = (proto as { constructor?: { name?: string } }).constructor;
  return ctor?.name ?? "object";
}

/**
 * Collect every reason `value` would not survive VS Code's host↔remote RPC
 * unchanged. An empty array means the payload is wire-safe.
 */
export function findWireViolations(
  value: unknown,
  rootPath = "$"
): WireViolation[] {
  const violations: WireViolation[] = [];
  // Tracks the current ancestor chain rather than every value ever seen, so
  // a payload that legitimately references the same string twice isn't
  // mistaken for a cycle.
  const ancestors = new Set<unknown>();

  const walk = (node: unknown, path: string, inArray: boolean): void => {
    if (node === null) return;

    const type = typeof node;

    if (type === "string" || type === "boolean") return;

    if (typeof node === "number") {
      // NaN / ±Infinity all serialize to `null`. Narrowed on `typeof node`
      // rather than the cached `type` so `node` really is a `number` here.
      if (!Number.isFinite(node)) {
        violations.push({
          path,
          reason: `non-finite number (${node}) serializes to null`,
        });
      }
      return;
    }

    if (type === "undefined") {
      if (inArray) {
        violations.push({
          path,
          reason: "undefined inside an array serializes to null",
        });
      }
      // As an object property it is dropped, which we treat as equivalent to
      // the key being absent. See the module docstring.
      return;
    }

    if (type === "bigint" || type === "symbol" || type === "function") {
      violations.push({
        path,
        reason: `${type} is not serializable across the host↔remote boundary`,
      });
      return;
    }

    // Objects and arrays from here down.
    if (ancestors.has(node)) {
      violations.push({ path, reason: "circular reference" });
      return;
    }
    ancestors.add(node);
    try {
      if (Array.isArray(node)) {
        node.forEach((item, i) => walk(item, `${path}[${i}]`, true));
        return;
      }

      const proto: unknown = Object.getPrototypeOf(node);
      if (proto !== Object.prototype && proto !== null) {
        // Buffer, Uint8Array, Date, Map, Set, RegExp, Error, and every class
        // instance land here. Some of these survive `structuredClone` intact,
        // which is precisely why the structural check exists alongside it —
        // VS Code's RPC is JSON-shaped, not structured-clone-shaped.
        violations.push({
          path,
          reason:
            `${describe(node)} is not a plain object; only JSON primitives, ` +
            "plain objects and arrays cross the host↔remote boundary intact",
        });
        return;
      }

      if (Object.getOwnPropertySymbols(node).length > 0) {
        violations.push({
          path,
          reason: "symbol-keyed properties are dropped on serialization",
        });
      }

      const record = node as Record<string, unknown>;
      if (Object.prototype.hasOwnProperty.call(record, "toJSON")) {
        violations.push({
          path,
          reason: "own `toJSON` rewrites the payload shape on serialization",
        });
      }

      for (const key of Object.keys(record)) {
        walk(record[key], `${path}.${key}`, false);
      }
    } finally {
      ancestors.delete(node);
    }
  };

  walk(value, rootPath, false);
  return violations;
}

/**
 * Deep equality where a missing key and a key holding `undefined` are the
 * same thing — see the module docstring for why that tolerance exists and
 * why it stops at array elements.
 */
export function equalIgnoringUndefined(a: unknown, b: unknown): boolean {
  if (Object.is(a, b)) return true;
  if (a === null || b === null) return false;
  if (typeof a !== "object" || typeof b !== "object") return false;

  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b)) return false;
    if (a.length !== b.length) return false;
    return a.every((item, i) => equalIgnoringUndefined(item, b[i]));
  }

  const ra = a as Record<string, unknown>;
  const rb = b as Record<string, unknown>;
  const keys = new Set([...Object.keys(ra), ...Object.keys(rb)]);
  for (const key of keys) {
    if (!equalIgnoringUndefined(ra[key], rb[key])) return false;
  }
  return true;
}

/**
 * Throw unless `value` is free of wire violations. `label` names the payload
 * in the failure message (e.g. `getAllCertMaterialV3 result`).
 */
export function assertWireSafe(label: string, value: unknown): void {
  const violations = findWireViolations(value);
  if (violations.length === 0) return;
  const detail = violations
    .map((v) => `  ${v.path}: ${v.reason}`)
    .join("\n");
  throw new WireGuardError(
    `${label} would not survive the host↔remote hop:\n${detail}`,
    violations
  );
}

/**
 * Throw unless `value` comes back unchanged from both a `structuredClone` and
 * a JSON round trip.
 */
export function assertRoundTripStable(label: string, value: unknown): void {
  let cloned: unknown;
  try {
    cloned = structuredClone(value);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    throw new WireGuardError(`${label} is not structured-cloneable: ${message}`);
  }
  if (!equalIgnoringUndefined(value, cloned)) {
    throw new WireGuardError(`${label} changed under structuredClone.`);
  }

  let json: unknown;
  try {
    json = JSON.parse(JSON.stringify(value)) as unknown;
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    throw new WireGuardError(`${label} is not JSON-serializable: ${message}`);
  }
  if (!equalIgnoringUndefined(value, json)) {
    throw new WireGuardError(
      `${label} changed under a JSON round trip. This payload would arrive ` +
        "mangled in a real dev container."
    );
  }
}

/**
 * The check to call on anything crossing the host↔workspace command seam:
 * structural walk first (better messages), then the real round trips.
 */
export function assertCrossHostPayload(label: string, value: unknown): void {
  assertWireSafe(label, value);
  assertRoundTripStable(label, value);
}
