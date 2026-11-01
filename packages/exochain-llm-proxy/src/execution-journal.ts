// Copyright 2026 Exochain Foundation
// SPDX-License-Identifier: Apache-2.0
import { mkdir, open } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { LynkValidationError } from "./evidence.js";
import type { ExecutionJournal } from "./types.js";

/**
 * Conservative at-most-once dispatch journal on a durable POSIX filesystem.
 * All workers for a tenant must share this directory. Claims are never removed:
 * reconcile interrupted attempts externally rather than silently retrying effects.
 */
export class FileExecutionJournal implements ExecutionJournal {
  private readonly directory: string;

  constructor(directory: string) { this.directory = resolve(directory); }

  async claim(key: string): Promise<boolean> {
    if (!/^[0-9a-f]{64}$/.test(key) || /^0+$/.test(key)) {
      throw new LynkValidationError("execution journal requires a canonical nonzero hash key");
    }
    await mkdir(this.directory, { recursive: true, mode: 0o700 });
    let handle;
    try {
      handle = await open(join(this.directory, `${key}.claim`), "wx", 0o600);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EEXIST") return false;
      throw error;
    }
    try {
      await handle.writeFile("claimed\n");
      await handle.sync();
    } finally {
      await handle.close();
    }
    // Persist the claim's entry, then every parent entry naming this directory.
    // Another worker may have just created an ancestor, so mkdir's return value
    // cannot establish which parent entries are already durable.
    let path = this.directory;
    for (;;) {
      const directory = await open(path, "r");
      try { await directory.sync(); } finally { await directory.close(); }
      const parent = dirname(path);
      if (parent === path) break;
      path = parent;
    }
    return true;
  }
}
