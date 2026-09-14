/**
 * A ~50-line test runner, used instead of pulling mocha in.
 *
 * VS Code's `--extensionTestsPath` contract is just "export `run(): Promise`,
 * reject on failure" — it has no opinion about the framework behind it. For a
 * spike, a runner this small is one fewer dependency in the tree and one fewer
 * thing to configure. Swapping in mocha later is a contained change: it only
 * touches this file and the `test()` import in the suites.
 */

export interface TestCase {
  name: string;
  fn: () => void | Promise<void>;
}

const cases: TestCase[] = [];

/** Register a test. Order of registration is order of execution. */
export function test(name: string, fn: () => void | Promise<void>): void {
  cases.push({ name, fn });
}

export interface RunSummary {
  passed: number;
  failed: number;
}

export async function runRegistered(): Promise<RunSummary> {
  let passed = 0;
  const failures: { name: string; error: unknown }[] = [];

  for (const testCase of cases) {
    const started = Date.now();
    try {
      await testCase.fn();
      passed++;
      console.log(`  ok   ${testCase.name} (${Date.now() - started}ms)`);
    } catch (err: unknown) {
      failures.push({ name: testCase.name, error: err });
      console.log(`  FAIL ${testCase.name} (${Date.now() - started}ms)`);
    }
  }

  if (failures.length > 0) {
    console.log("");
    for (const failure of failures) {
      console.log(`--- ${failure.name} ---`);
      const err = failure.error;
      console.log(err instanceof Error ? (err.stack ?? err.message) : String(err));
      console.log("");
    }
  }

  console.log("");
  console.log(`${passed} passed, ${failures.length} failed`);
  return { passed, failed: failures.length };
}

/** Minimal assertions, so the suites don't reach for node:assert's deep forms. */
export function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(`Assertion failed: ${message}`);
}

export function assertEqual<T>(actual: T, expected: T, message: string): void {
  if (!Object.is(actual, expected)) {
    throw new Error(
      `Assertion failed: ${message}\n  expected: ${String(expected)}\n  actual:   ${String(actual)}`
    );
  }
}

/** Assert that `fn` throws, and that the message mentions `contains`. */
export async function assertThrows(
  fn: () => unknown,
  contains: string,
  message: string
): Promise<void> {
  let threw: unknown;
  try {
    await fn();
  } catch (err: unknown) {
    threw = err ?? new Error("threw a falsy value");
  }
  if (threw === undefined) {
    throw new Error(`Assertion failed: ${message} (nothing was thrown)`);
  }
  const text =
    threw instanceof Error ? threw.message : JSON.stringify(threw) ?? "";
  if (!text.includes(contains)) {
    throw new Error(
      `Assertion failed: ${message}\n  expected the error to mention: ${contains}\n  got: ${text}`
    );
  }
}
