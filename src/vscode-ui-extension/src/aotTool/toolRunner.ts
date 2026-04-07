import { execFile } from "child_process";
import { promisify } from "util";
import { log } from "../util/logger";

const execFileAsync = promisify(execFile);

export interface CertificateStatus {
  exists: boolean;
  isTrusted: boolean;
  thumbprint: string | null;
  notBefore: string | null;
  notAfter: string | null;
  version: number;
}

export class ToolRunner {
  constructor(private readonly toolPath: string) {}

  async generate(force: boolean = false): Promise<string> {
    const args = ["generate"];
    if (force) args.push("--force");
    const { stdout } = await this.run(args);
    return stdout.trim();
  }

  async trust(): Promise<string> {
    const { stdout } = await this.run(["trust"]);
    return stdout.trim();
  }

  async exportCert(
    format: "pfx" | "pem",
    outputDir: string,
    password?: string
  ): Promise<string> {
    const args = ["export", "--format", format, "--output", outputDir];
    if (password) args.push("--password", password);
    const { stdout } = await this.run(args);
    return stdout.trim();
  }

  async check(): Promise<CertificateStatus> {
    const { stdout } = await this.run(["check", "--json"]);
    return JSON.parse(stdout) as CertificateStatus;
  }

  async clean(): Promise<string> {
    const { stdout } = await this.run(["clean"]);
    return stdout.trim();
  }

  private async run(
    args: string[]
  ): Promise<{ stdout: string; stderr: string }> {
    log(`Running: ${this.toolPath} ${args.join(" ")}`);
    try {
      const result = await execFileAsync(this.toolPath, args, {
        timeout: 30000,
      });
      if (result.stdout) log(`stdout: ${result.stdout.trim()}`);
      return result;
    } catch (err: unknown) {
      const error = err as Error & { stdout?: string; stderr?: string };
      log(`Error: ${error.message}`);
      if (error.stderr) log(`stderr: ${error.stderr}`);
      throw error;
    }
  }
}
