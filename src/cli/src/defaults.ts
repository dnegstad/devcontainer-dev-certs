import * as os from "os";
import * as path from "path";

/**
 * CLI-wide defaults. Consolidated here so a future change to either
 * value lands in one place — previously the out-dir and container-mount
 * defaults were duplicated across `generate`, `bundle`, and `doctor`,
 * with no compiler help to keep them in sync.
 */

/** Host directory the CLI writes cert artifacts + `bundle.json` into. */
export const DEFAULT_OUT_DIR = path.join(os.homedir(), ".dev-certs");

/**
 * Container-side mount target the host out-dir is expected to be
 * bind-mounted to. Recorded into `bundle.json`'s `pfxPath` / `pemPath`
 * so the in-container installer reads from the right place. Users with
 * a custom mount layout can override per-invocation via
 * `--container-mount`.
 */
export const DEFAULT_CONTAINER_MOUNT = "/host-dev-certs";
