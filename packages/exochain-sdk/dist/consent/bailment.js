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
import { ConsentError } from '../errors.js';
import { validateDid } from '../identity/did.js';
import { sha256, bytesToHex } from '../crypto/hash.js';
const HLC_LOGICAL_MAX = 0xffff_ffff;
/** Builder for a {@link BailmentProposal}. */
export class BailmentBuilder {
    #bailor;
    #bailee;
    #scope;
    #durationHours;
    #createdAtHlc;
    constructor(bailor, bailee) {
        this.#bailor = typeof bailor === 'string' ? validateDid(bailor) : bailor;
        this.#bailee = typeof bailee === 'string' ? validateDid(bailee) : bailee;
    }
    /** Set the scope string (e.g. `"data:medical"`). */
    scope(scope) {
        this.#scope = scope;
        return this;
    }
    /** Set the bailment duration in whole hours. */
    durationHours(hours) {
        this.#durationHours = hours;
        return this;
    }
    /** Set the caller-supplied HLC creation timestamp for this proposal. */
    createdAtHlc(physicalMs, logical = 0) {
        this.#createdAtHlc = validateHlcTimestamp(physicalMs, logical);
        return this;
    }
    /** Validate the builder state and produce a {@link BailmentProposal}. */
    async build() {
        if (this.#scope === undefined) {
            throw new ConsentError('scope is required');
        }
        if (this.#scope.length === 0) {
            throw new ConsentError('scope must be non-empty');
        }
        if (this.#durationHours === undefined) {
            throw new ConsentError('durationHours is required');
        }
        const durationHours = validatePositiveSafeInteger(this.#durationHours, 'durationHours');
        if (this.#createdAtHlc === undefined) {
            throw new ConsentError('createdAtHlc is required');
        }
        const proposalId = await computeProposalId(this.#bailor, this.#bailee, this.#scope, durationHours, this.#createdAtHlc);
        return {
            proposalId,
            bailor: this.#bailor,
            bailee: this.#bailee,
            scope: this.#scope,
            durationHours,
            createdAt: this.#createdAtHlc.physicalMs,
            createdAtLogical: this.#createdAtHlc.logical,
        };
    }
}
/**
 * Deterministic content-addressed proposal ID. Layout uses NUL separators,
 * LE u64 duration/physical-ms values, and LE u32 logical counter.
 */
async function computeProposalId(bailor, bailee, scope, durationHours, createdAtHlc) {
    const enc = new TextEncoder();
    const bailorB = enc.encode(bailor);
    const baileeB = enc.encode(bailee);
    const scopeB = enc.encode(scope);
    const durationB = new Uint8Array(8);
    // Little-endian u64 encoding.
    const view = new DataView(durationB.buffer);
    view.setBigUint64(0, BigInt(durationHours), true);
    const createdPhysicalB = new Uint8Array(8);
    new DataView(createdPhysicalB.buffer).setBigUint64(0, BigInt(createdAtHlc.physicalMs), true);
    const createdLogicalB = new Uint8Array(4);
    new DataView(createdLogicalB.buffer).setUint32(0, createdAtHlc.logical, true);
    const total = bailorB.length +
        1 +
        baileeB.length +
        1 +
        scopeB.length +
        1 +
        durationB.length +
        1 +
        createdPhysicalB.length +
        1 +
        createdLogicalB.length;
    const payload = new Uint8Array(total);
    let offset = 0;
    payload.set(bailorB, offset);
    offset += bailorB.length;
    payload[offset++] = 0;
    payload.set(baileeB, offset);
    offset += baileeB.length;
    payload[offset++] = 0;
    payload.set(scopeB, offset);
    offset += scopeB.length;
    payload[offset++] = 0;
    payload.set(durationB, offset);
    offset += durationB.length;
    payload[offset++] = 0;
    payload.set(createdPhysicalB, offset);
    offset += createdPhysicalB.length;
    payload[offset++] = 0;
    payload.set(createdLogicalB, offset);
    const digest = await sha256(payload);
    return bytesToHex(digest);
}
function validatePositiveSafeInteger(value, field) {
    if (!Number.isSafeInteger(value) || value <= 0) {
        throw new ConsentError(`${field} must be a positive safe integer`);
    }
    return value;
}
function validateHlcTimestamp(physicalMs, logical) {
    if (!Number.isSafeInteger(physicalMs) || physicalMs <= 0) {
        throw new ConsentError('createdAtHlc physicalMs must be a positive safe integer');
    }
    if (!Number.isSafeInteger(logical) ||
        logical < 0 ||
        logical > HLC_LOGICAL_MAX) {
        throw new ConsentError(`createdAtHlc logical must be an integer between 0 and ${HLC_LOGICAL_MAX}`);
    }
    return { physicalMs, logical };
}
//# sourceMappingURL=bailment.js.map