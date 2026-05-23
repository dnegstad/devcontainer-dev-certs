// Re-export shim: the canonical home for buildPfx / parsePfx is now
// `@devcontainer-dev-certs/shared`. Keeping this thin re-export so existing
// `./cert/pfx` imports across the UI extension (and its test suite) keep
// resolving without a sweeping rename.
export { buildPfx, parsePfx } from "@devcontainer-dev-certs/shared";
export type {
  BuildPfxOptions,
  ParsedPfx,
} from "@devcontainer-dev-certs/shared";
