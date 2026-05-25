import { setLogSink, type LogSink } from "@devcontainer-dev-certs/shared";

/**
 * Wires a console-backed sink into the shared logger so the platform / cert
 * layer's `log()` calls surface during CLI runs. Verbose mode forwards every
 * line to stderr (so stdout stays clean for `--json` / scripting use); quiet
 * mode swallows them entirely.
 */
export function installCliLogger(verbose: boolean): void {
  if (!verbose) {
    setLogSink(undefined);
    return;
  }
  const sink: LogSink = {
    appendLine(message: string): void {
      process.stderr.write(`${message}\n`);
    },
  };
  setLogSink(sink);
}
