/**
 * Backend abstraction shared by `ddc` (host CLI) and the VS Code host
 * extension. Lets both consumers pick between equivalent generators —
 * the bundled-in native cert primitives or the `dotnet dev-certs https`
 * CLI pass-through — without each having to reimplement the selection /
 * availability-detection logic.
 *
 * The interface is deliberately narrow: each backend exposes
 * `isAvailable()` and `generate()`. Trust is bundled into `generate()` so
 * backends like `dotnet` (which combines generate + trust into a single
 * shell invocation) don't need a separate trust hook.
 */

export type BackendKind = "native" | "dotnet";

export type BackendMode = BackendKind | "auto";

export interface GenerateOptions {
  /** Directory that receives PFX / PEM / key artifacts. */
  outDir: string;
  /** Skip the host trust step. PFX / PEM are still emitted. */
  noTrust: boolean;
}

export interface GenerateResult {
  /** Absolute host path of the PFX. */
  pfxPath: string;
  /** Absolute host path of the PEM cert. */
  pemPath: string;
  /** Absolute host path of the PEM key (null when backend didn't emit one). */
  pemKeyPath: string | null;
  /** SHA-1 thumbprint, uppercase hex. */
  thumbprint: string;
  /** Whether the host trust step ran and succeeded. */
  trusted: boolean;
  /**
   * Which backend actually produced the cert — meaningful when the caller
   * selected `auto` and wants to know which concrete kind was picked.
   */
  backendUsed: BackendKind;
}

/**
 * Backends implement generation (+ optional trust) and a platform-availability
 * probe. `auto` selection asks each candidate whether it's available and
 * picks per-platform preference.
 */
export interface Backend {
  readonly kind: BackendKind;
  /** Is this backend usable on the current host? */
  isAvailable(): Promise<boolean>;
  generate(options: GenerateOptions): Promise<GenerateResult>;
}
