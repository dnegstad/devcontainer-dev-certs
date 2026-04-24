/**
 * Pattern and guard for `userCertificates[].name` — used as a filename stem
 * in both the host temp-export dir and the container trust / extra-destination
 * paths. A crafted value containing path separators or `..` could escape the
 * intended directory, so we constrain it to a conservative allowlist.
 */
const CERT_NAME_RE = /^[A-Za-z0-9._-]+$/;
const CERT_NAME_MAX_LENGTH = 64;

export function isValidCertName(name: unknown): name is string {
  if (typeof name !== "string") return false;
  if (name.length === 0 || name.length > CERT_NAME_MAX_LENGTH) return false;
  if (name === "." || name === "..") return false;
  if (name.startsWith(".")) return false; // no dotfiles
  return CERT_NAME_RE.test(name);
}

/**
 * Throws a user-facing Error if the name isn't safe to use as a filename
 * stem. Callers should catch and surface the message.
 */
export function assertValidCertName(name: unknown): asserts name is string {
  if (!isValidCertName(name)) {
    throw new Error(
      `Invalid certificate name '${String(name)}': must match /^[A-Za-z0-9._-]+$/ ` +
        `(1-${CERT_NAME_MAX_LENGTH} chars, no path separators, no leading dot, not '.' or '..').`
    );
  }
}
