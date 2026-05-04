/**
 * Consent bailment builder.
 *
 * A bailment represents scoped, time-bounded consent from a bailor to a
 * bailee. `BailmentBuilder` mirrors the Rust SDK's builder pattern and
 * produces a {@link BailmentProposal} whose `proposalId` is a content-
 * addressed SHA-256 over the canonical fields. Callers must provide the
 * HLC timestamp from their deterministic execution context; this SDK does
 * not read wall-clock time while constructing consent records.
 */
import type { Did, Hash256 } from '../types.js';
export interface HlcTimestamp {
    readonly physicalMs: number;
    readonly logical: number;
}
/** A validated bailment proposal. */
export interface BailmentProposal {
    readonly proposalId: Hash256;
    readonly bailor: Did;
    readonly bailee: Did;
    readonly scope: string;
    readonly durationHours: number;
    /** HLC physical milliseconds supplied by the caller. */
    readonly createdAt: number;
    /** HLC logical counter supplied by the caller. */
    readonly createdAtLogical: number;
}
/** Builder for a {@link BailmentProposal}. */
export declare class BailmentBuilder {
    #private;
    constructor(bailor: Did | string, bailee: Did | string);
    /** Set the scope string (e.g. `"data:medical"`). */
    scope(scope: string): this;
    /** Set the bailment duration in whole hours. */
    durationHours(hours: number): this;
    /** Set the caller-supplied HLC creation timestamp for this proposal. */
    createdAtHlc(physicalMs: number, logical?: number): this;
    /** Validate the builder state and produce a {@link BailmentProposal}. */
    build(): Promise<BailmentProposal>;
}
//# sourceMappingURL=bailment.d.ts.map