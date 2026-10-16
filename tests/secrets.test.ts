import assert from "node:assert/strict";
import { test } from "node:test";
import { findSecrets, isPlaceholder } from "../src/guard/secrets.ts";

test("real-shaped tokens are found", () => {
  assert.equal(findSecrets("token=ghp_K9v2nR7qT4wZ8xL1mB6cJ3pF5hD0sYaGuEoIqw")[0]?.name, "github-token");
  assert.equal(findSecrets("AKIAQ3ZQ7XK2P9M4NW5B")[0]?.name, "aws-access-key");
  assert.equal(findSecrets("-----BEGIN OPENSSH PRIVATE KEY-----")[0]?.name, "private-key-block");
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
