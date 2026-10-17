import assert from "node:assert/strict";
import { test } from "node:test";
import { findSecrets, isPlaceholder } from "../src/guard/secrets.ts";

const PEM_BODY_LINE = "MIIEowIBAAKCAQEAx7vKk3xHd2x0bbr5fUi1G8ZPxu2pV1qFm1aSKj3sBqiz9Sj1";

test("real-shaped tokens are found", () => {
  assert.equal(findSecrets("token=ghp_K9v2nR7qT4wZ8xL1mB6cJ3pF5hD0sYaGuEoIqw")[0]?.name, "github-token");
  assert.equal(findSecrets("AKIAQ3ZQ7XK2P9M4NW5B")[0]?.name, "aws-access-key");
  assert.equal(findSecrets(`-----BEGIN OPENSSH PRIVATE KEY-----\n${PEM_BODY_LINE}\n`)[0]?.name, "private-key-block");
});

test("a private key needs a body: header, a base64 line or a closed block", () => {
  const found = (text: string) => findSecrets(text).filter((h) => h.name === "private-key-block").length;
  // A real line break, an escaped one inside a string literal, and a closed block with a short body.
  assert.equal(found(`-----BEGIN RSA PRIVATE KEY-----\n${PEM_BODY_LINE}\n-----END RSA PRIVATE KEY-----`), 1);
  assert.equal(found(`const KEY = "-----BEGIN PRIVATE KEY-----\\n${PEM_BODY_LINE}\\n-----END PRIVATE KEY-----";`), 1);
  assert.equal(found("-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"), 1);
  assert.equal(found("-----BEGIN EC PRIVATE KEY-----MHQCAQEEIBkz3tJ7PGcXyJ0fZQ4bAbkq2d2nH1cK9rpvG1wZ8bXzoAcGBSuBBAAK-----END EC PRIVATE KEY-----"), 1);
  assert.equal(found(`-----BEGIN ENCRYPTED PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,A1B2\n\n${PEM_BODY_LINE}\n-----END ENCRYPTED PRIVATE KEY-----`), 1);
});

test("a bare PEM header is not a secret", () => {
  const found = (text: string) => findSecrets(text).filter((h) => h.name === "private-key-block").length;
  assert.equal(found("-----BEGIN OPENSSH PRIVATE KEY-----"), 0);
  assert.equal(found("grep -rn -- '-----BEGIN PRIVATE KEY-----' src/"), 0);
  assert.equal(found("export function isPrivateKey(s: string) { return s.startsWith('-----BEGIN PRIVATE KEY-----'); }"), 0);
  // Header and footer with code between them is a PEM parser, not a key.
  assert.equal(found("const PEM_HEADER = '-----BEGIN RSA PRIVATE KEY-----';\nconst PEM_FOOTER = '-----END RSA PRIVATE KEY-----';"), 0);
  // An empty block has no body.
  assert.equal(found("-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----"), 0);
  // The END marker must match the header's type.
  assert.equal(found("-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"), 0);
});

test("documentation placeholders are not secrets", () => {
  for (const p of ["ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "AKIAIOSFODNN7EXAMPLE", "sk-proj-your-key-here-your-key-here", "sk-ant-api03-REDACTED-REDACTED-REDACTED", "ghp_000000000000000000000000000000000000"]) {
    assert.equal(findSecrets(p).length, 0, p);
    assert.equal(isPlaceholder(p), true, p);
  }
});

test("the generic assignment pattern only asks", () => {
  const hits = findSecrets('password = "correct-horse-battery-staple-9"');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].severity, "ask");
});

test("a long run of a PEM header and no body decides quickly", () => {
  const text = "-----BEGIN PRIVATE KEY-----\n".repeat(5_000) + "x".repeat(100_000);
  const started = performance.now();
  assert.equal(findSecrets(text).length, 0);
  assert.ok(performance.now() - started < 500, `took ${Math.round(performance.now() - started)} ms`);
});
