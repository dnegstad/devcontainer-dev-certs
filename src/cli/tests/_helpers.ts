/**
 * Shared test helpers for the CLI test suite. Keep this file small —
 * anything that grows beyond a few utilities should move into a per-
 * concern helper module to keep imports honest.
 */

/**
 * Override `process.platform` for the duration of a test. Returns a
 * restore callback to call from `finally` (or `afterEach`) so the
 * stub doesn't leak into sibling tests. Tolerant of platforms where
 * the original descriptor is undefined.
 *
 * Note: Node makes `process.platform` non-writable but `configurable`,
 * so `Object.defineProperty` is the supported route. If a future Node
 * tightens this, the failure surfaces at the first test that calls
 * `stubPlatform` rather than hiding in a side channel.
 */
export function stubPlatform(value: NodeJS.Platform): () => void {
  const original = Object.getOwnPropertyDescriptor(process, "platform");
  Object.defineProperty(process, "platform", { value, configurable: true });
  return () => {
    if (original) Object.defineProperty(process, "platform", original);
  };
}
