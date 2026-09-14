/**
 * Entry point VS Code loads via `--extensionTestsPath`.
 *
 * The contract is just `run(): Promise<void>` — resolve on success, reject on
 * failure. VS Code exits non-zero when it rejects.
 */
import { runRegistered } from "./runner";
import { registerActivationTests } from "./suites/activation";
import { registerCertFlowTests } from "./suites/certFlow";
import { registerSerializationTests } from "./suites/serialization";

export async function run(): Promise<void> {
  console.log("");
  console.log("devcontainer-dev-certs :: VS Code E2E");
  console.log("");

  registerActivationTests();
  registerCertFlowTests();
  registerSerializationTests();

  const summary = await runRegistered();
  if (summary.failed > 0) {
    throw new Error(`${summary.failed} E2E test(s) failed`);
  }
}
