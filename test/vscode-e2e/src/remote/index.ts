/**
 * Entry point for the devcontainer level, loaded by the REMOTE extension host
 * inside the container (`--extensionTestsPath=vscode-remote://devcerts-e2e+…`).
 *
 * A separate bundle from `../index.ts` on purpose: the local suites lean on the
 * DEVCONTAINER_DEV_CERTS_TEST_REMOTE seam and a mkdtemp sandbox, and neither
 * exists here. This level asserts the opposite of the seam — that the gate
 * opens on a real `remoteName` — so mixing them would make each suite's
 * preconditions false for the other.
 */
// Must be the first import; see the note in ../index.ts.
import "reflect-metadata";
import { runRegistered } from "../runner";
import { registerDevcontainerTests } from "./suite";

export async function run(): Promise<void> {
  console.log("");
  console.log("devcontainer-dev-certs :: VS Code E2E (devcontainer)");
  console.log("");

  registerDevcontainerTests();

  const summary = await runRegistered();
  if (summary.failed > 0) {
    throw new Error(`${summary.failed} E2E test(s) failed`);
  }
}
