/**
 * Shared test helpers for the UI extension test suite. Mirrors the
 * CLI workspace's `tests/_helpers.ts` — same contract, different
 * workspace, kept in sync by hand because no cross-workspace test-
 * helpers package exists.
 */

/**
 * Override `process.platform` for the duration of a test. Returns a
 * restore callback to call from `finally` (or `afterEach`) so the
 * stub doesn't leak into sibling tests. Tolerant of platforms where
 * the original descriptor is undefined.
 */
export function stubPlatform(value: NodeJS.Platform): () => void {
  const original = Object.getOwnPropertyDescriptor(process, "platform");
  Object.defineProperty(process, "platform", { value, configurable: true });
  return () => {
    if (original) Object.defineProperty(process, "platform", original);
  };
}
