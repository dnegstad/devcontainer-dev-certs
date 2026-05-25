/**
 * One of the three concrete backends `ddc` can use to generate (and trust)
 * a dev cert. `auto` is resolved at command-dispatch time into one of the
 * concrete kinds.
 */
export type BackendKind = "native" | "dotnet" | "aspire";

export type BackendMode = BackendKind | "auto";

export interface GenerateOptions {
  /** Directory that receives PFX / PEM / bundle.json artifacts. */
  outDir: string;
  /** Skip the host trust step. PFX / PEM are still emitted. */
  noTrust: boolean;
  /**
   * Container-side path the host out-dir maps to via a Docker mount —
   * recorded into bundle.json's `pfxPath` / `pemPath` so the in-container
   * installer reads from the right place. Defaults to `/host-dev-certs`.
   */
  containerMount: string;
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
  /** Backend that actually produced the cert (auto resolves to one of these). */
  backendUsed: BackendKind;
}

/**
 * Backends implement generation (+ optional trust) and platform-availability
 * detection. `auto` selection asks each candidate whether it's available and
 * picks per platform preference.
 */
export interface Backend {
  readonly kind: BackendKind;
  /** Is this backend usable on the current host? */
  isAvailable(): Promise<boolean>;
  generate(options: GenerateOptions): Promise<GenerateResult>;
}
