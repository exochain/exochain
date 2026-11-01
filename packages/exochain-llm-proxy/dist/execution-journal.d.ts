import type { ExecutionJournal } from "./types.js";
/**
 * Conservative at-most-once dispatch journal on a durable POSIX filesystem.
 * All workers for a tenant must share this directory. Claims are never removed:
 * reconcile interrupted attempts externally rather than silently retrying effects.
 */
export declare class FileExecutionJournal implements ExecutionJournal {
    private readonly directory;
    constructor(directory: string);
    claim(key: string): Promise<boolean>;
}
//# sourceMappingURL=execution-journal.d.ts.map