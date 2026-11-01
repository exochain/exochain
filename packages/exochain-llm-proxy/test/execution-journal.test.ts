// Copyright 2026 Exochain Foundation
// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { mkdtemp, open, readFile, readdir, rm, stat } from "node:fs/promises";
import type { FileHandle } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { FileExecutionJournal } from "../src/execution-journal.js";

test("durable claims exclude concurrent attempts and survive a new journal instance", async () => {
  const directory = await mkdtemp(join(tmpdir(), "exo-execution-"));
  try {
    const key = "ab".repeat(32);
    const first = new FileExecutionJournal(directory);
    const second = new FileExecutionJournal(directory);
    const results = await Promise.all([first.claim(key), second.claim(key)]);
    assert.deepEqual(results.sort(), [false, true]);
    assert.equal(await new FileExecutionJournal(directory).claim(key), false);
    const names = await readdir(directory);
    assert.equal(names.length, 1);
    assert.equal(await readFile(join(directory, names[0]!), "utf8"), "claimed\n");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("journal rejects non-hash keys and fails closed on unavailable storage", async () => {
  const journal = new FileExecutionJournal("/dev/null/not-a-directory");
  for (const key of ["../secret", "", "A".repeat(64), "0".repeat(64)]) {
    await assert.rejects(journal.claim(key));
  }
  await assert.rejects(journal.claim("cd".repeat(32)));
});

test("concurrent first claims provision nested private directories and remain consumed", async () => {
  const root = await mkdtemp(join(tmpdir(), "exo-execution-nested-"));
  const directory = join(root, "tenant", "attempts");
  try {
    const keys = ["de".repeat(32), "ef".repeat(32)];
    assert.deepEqual(await Promise.all(keys.map((key) =>
      new FileExecutionJournal(directory).claim(key))), [true, true]);
    assert.equal((await stat(directory)).mode & 0o777, 0o700);
    assert.equal((await stat(join(root, "tenant"))).mode & 0o777, 0o700);
    for (const key of keys) {
      assert.equal((await stat(join(directory, `${key}.claim`))).mode & 0o777, 0o600);
      assert.equal(await new FileExecutionJournal(directory).claim(key), false);
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a failed parent-directory sync cannot authorize dispatch or release the claim", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "exo-execution-sync-"));
  const directory = join(root, "tenant", "attempts");
  const probe = await open(root, "r");
  const prototype = Object.getPrototypeOf(probe) as FileHandle;
  const originalSync = prototype.sync;
  let syncCalls = 0;
  const mock = t.mock.method(prototype, "sync", async function(this: FileHandle) {
    // File, leaf directory, then the parent naming the new leaf directory.
    if (++syncCalls === 3) throw new Error("parent directory sync failed");
    await originalSync.call(this);
  });
  try {
    const key = "ac".repeat(32);
    await assert.rejects(new FileExecutionJournal(directory).claim(key), /parent directory sync failed/);
    mock.mock.restore();
    assert.equal(await new FileExecutionJournal(directory).claim(key), false);
  } finally {
    mock.mock.restore();
    await probe.close();
    await rm(root, { recursive: true, force: true });
  }
});
