/**
 * The serialization guard.
 *
 * Within one extension host `executeCommand` passes objects by reference, so
 * a payload carrying a `Buffer` passes the vertical-slice test above and
 * breaks in a real dev container. Every payload that would cross the real
 * host↔remote hop is therefore checked against what VS Code's RPC layer would
 * do to it. See `../wireGuard.ts` for the rules and for why `undefined`
 * properties are the one tolerated difference.
 *
 * The suite opens with negative self-tests. Without them a green run is
 * ambiguous: a guard that silently accepted everything would look exactly the
 * same. These pin that the guard rejects the specific shapes that would break
 * in production.
 */
import * as vscode from "vscode";
import type { CertBundle } from "@devcontainer-dev-certs/shared";
import { assert, assertEqual, assertThrows, test } from "../runner";
import {
  assertCrossHostPayload,
  findWireViolations,
} from "../wireGuard";
import { sandbox } from "../env";
import { activateBoth } from "./activation";
import { fetchBundle } from "./certFlow";

export function registerSerializationTests(): void {
  const { userCertName } = sandbox();

  test("guard rejects a Buffer payload (self-test)", async () => {
    // The exact regression this whole suite exists for: `pfx` as raw bytes
    // instead of base64 is by-reference-fine and wire-fatal.
    await assertThrows(
      () =>
        assertCrossHostPayload("fake bundle", {
          certs: [{ name: "x", pfx: Buffer.from("hello") }],
        }),
      "not a plain object",
      "a Buffer in the payload must be rejected"
    );
  });

  test("guard rejects other non-JSON values (self-test)", async () => {
    const cases: [string, unknown, string][] = [
      ["Date", { notAfter: new Date() }, "not a plain object"],
      ["Map", { byName: new Map() }, "not a plain object"],
      ["Uint8Array", { der: new Uint8Array([1, 2]) }, "not a plain object"],
      ["class instance", { cert: new (class Cert {})() }, "not a plain object"],
      ["function", { onDone: () => undefined }, "function is not serializable"],
      ["bigint", { serial: 1n }, "bigint is not serializable"],
      ["NaN", { count: NaN }, "non-finite number"],
      ["undefined in array", { names: [undefined] }, "undefined inside an array"],
      ["own toJSON", { name: "x", toJSON: () => ({}) }, "toJSON"],
    ];
    for (const [label, payload, expected] of cases) {
      await assertThrows(
        () => assertCrossHostPayload(`fake ${label} payload`, payload),
        expected,
        `${label} must be rejected`
      );
    }

    // Circular references are their own failure mode — JSON.stringify throws
    // rather than returning something wrong.
    const circular: Record<string, unknown> = { name: "x" };
    circular["self"] = circular;
    await assertThrows(
      () => assertCrossHostPayload("circular payload", circular),
      "circular reference",
      "a cycle must be rejected"
    );
  });

  test("guard accepts a plain payload with undefined optionals (self-test)", () => {
    // The tolerated case. `CertMaterialV3` sets absent optionals to a literal
    // `undefined`, and VS Code's RPC drops those keys exactly as JSON does —
    // flagging it would make the guard fire on every real bundle.
    assertEqual(
      findWireViolations({
        certs: [{ name: "x", pemKeyBase64: undefined, trustInContainer: true }],
      }).length,
      0,
      "undefined-valued optional properties should be tolerated"
    );
  });

  test("V3 bundle survives the host↔remote hop unchanged", async () => {
    const bundle = await fetchBundle();
    assert(bundle.certs.length > 0, "bundle should not be empty");
    assertCrossHostPayload("getAllCertMaterialV3 result", bundle);
  });

  test("V2 bundle survives the host↔remote hop unchanged", async () => {
    // Still on the wire: the workspace extension falls back to V2 against a
    // pinned older host, so its shape has to hold up too.
    await activateBoth();
    const bundle = await vscode.commands.executeCommand<CertBundle>(
      "devcontainer-dev-certs.getAllCertMaterial",
      { includeDotNetDev: false, includeUserCerts: true }
    );
    assert(bundle !== undefined && bundle !== null, "host returned no V2 bundle");
    assertCrossHostPayload("getAllCertMaterial result", bundle);
  });

  test("command arguments survive the host↔remote hop unchanged", () => {
    // The request direction matters as much as the response: these objects
    // are built by the workspace extension and serialized on the way out.
    assertCrossHostPayload("getAllCertMaterial* args", {
      includeDotNetDev: false,
      includeUserCerts: true,
    });
  });

  test("the bundle is byte-identical after a JSON round trip", async () => {
    // A stronger, narrower statement than the guard makes: the base64 payload
    // fields are exactly what a container would decode. This is the property
    // that keeps a mangled certificate from being installed silently.
    const bundle = await fetchBundle();
    const material = bundle.certs.find((c) => c.name === userCertName);
    assert(material !== undefined, "configured user cert should be in bundle");

    const roundTripped = JSON.parse(JSON.stringify(bundle)) as typeof bundle;
    const after = roundTripped.certs.find((c) => c.name === userCertName);
    assert(after !== undefined, "cert should survive the round trip");

    for (const field of [
      "thumbprint",
      "pemCertBase64",
      "pemKeyBase64",
      "pfxBase64",
      "rootPfxBase64",
    ] as const) {
      assertEqual(after[field], material[field], `${field} after JSON round trip`);
    }
  });
}
