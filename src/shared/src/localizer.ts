/** Argument type accepted by `Localizer` — matches `vscode.l10n.t`'s. */
export type LocalizerArg = string | number | boolean;

/**
 * A function that resolves a template string + arguments into a localized
 * string. Signature-compatible with `vscode.l10n.t` so the host extension can
 * pass it through verbatim; non-VS-Code consumers (CLI, scripts, tests) use
 * the identity implementation below to keep the English source strings.
 */
export type Localizer = (template: string, ...args: LocalizerArg[]) => string;

/**
 * Default Localizer used when no host-supplied l10n is wired up. Performs
 * `{0}` placeholder substitution against `args` so the formatted output
 * matches what `vscode.l10n.t` produces in the no-translation-loaded case
 * — that's also the behavior the test l10n mock relies on, so platform
 * stores constructed without a localizer still emit the same log strings.
 */
export const identityLocalizer: Localizer = (template, ...args) =>
  template.replace(/\{(\w+)\}/g, (_match, key: string) => {
    const idx = Number(key);
    if (!Number.isNaN(idx)) {
      const value = args[idx];
      return value === undefined ? "" : String(value);
    }
    return "";
  });
