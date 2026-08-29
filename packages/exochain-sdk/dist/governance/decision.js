// Copyright 2026 Exochain Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
/**
 * Governance decisions — build, cast votes, check quorum.
 *
 * Mirrors the Rust SDK's `governance` module. Decision IDs are content-
 * addressed (full BLAKE3 over a canonical CBOR title/description/proposer
 * frame), votes are appended in-order, and duplicate voters are rejected.
 */
import { GovernanceError } from '../errors.js';
import { validateDid } from '../identity/did.js';
import { blake3Hex } from '../crypto/hash.js';
const DECISION_ID_DOMAIN = 'exochain:decision-id:v2';
const CBOR_TEXT_INLINE_MAX = 23;
const CBOR_UINT8_MAX = 0xff;
const CBOR_UINT16_MAX = 0xffff;
const CBOR_UINT32_MAX = 4294967295;
const UTF8_ENCODER = new TextEncoder();
/** A full governance decision with accumulated votes. */
export class Decision {
    decisionId;
    title;
    description;
    proposer;
    status;
    class;
    #votes;
    constructor(args) {
        this.decisionId = args.decisionId;
        this.title = args.title;
        this.description = args.description;
        this.proposer = args.proposer;
        this.status = args.status ?? 'proposed';
        if (args.class !== undefined) {
            this.class = args.class;
        }
        this.#votes = [];
    }
    /** Read-only snapshot of votes cast so far. */
    get votes() {
        return this.#votes;
    }
    /**
     * Append a vote. Throws {@link GovernanceError} if the voter has already
     * voted on this decision.
     */
    castVote(vote) {
        for (const existing of this.#votes) {
            if (existing.voter === vote.voter) {
                throw new GovernanceError(`voter ${vote.voter} has already cast a vote`);
            }
        }
        this.#votes.push(vote);
    }
    /**
     * Tally the votes and report whether the approval count meets `threshold`.
     */
    checkQuorum(threshold) {
        if (!Number.isInteger(threshold) || threshold < 0) {
            throw new GovernanceError('threshold must be a non-negative integer');
        }
        let approvals = 0;
        let rejections = 0;
        let abstentions = 0;
        for (const v of this.#votes) {
            if (v.choice === 'approve')
                approvals++;
            else if (v.choice === 'reject')
                rejections++;
            else
                abstentions++;
        }
        return {
            met: approvals >= threshold,
            threshold,
            totalVotes: this.#votes.length,
            approvals,
            rejections,
            abstentions,
        };
    }
}
/** Builder for a {@link Decision}. */
export class DecisionBuilder {
    #title;
    #description;
    #proposer;
    #class;
    constructor(args) {
        this.#title = args.title;
        this.#description = args.description;
        this.#proposer =
            typeof args.proposer === 'string' ? validateDid(args.proposer) : args.proposer;
    }
    /** Attach an optional decision class (free-form label). */
    decisionClass(name) {
        this.#class = name;
        return this;
    }
    /** Validate and build the {@link Decision}. */
    async build() {
        if (this.#title.length === 0) {
            throw new GovernanceError('title must be non-empty');
        }
        const decisionId = await computeDecisionId(this.#title, this.#description, this.#proposer);
        const init = {
            decisionId,
            title: this.#title,
            description: this.#description,
            proposer: this.#proposer,
        };
        if (this.#class !== undefined) {
            init.class = this.#class;
        }
        return new Decision(init);
    }
}
async function computeDecisionId(title, description, proposer) {
    const canonical = encodeCanonicalTextArray([
        DECISION_ID_DOMAIN,
        title,
        description,
        proposer,
    ]);
    return blake3Hex(canonical);
}
function encodeCanonicalTextArray(values) {
    if (values.length !== 4) {
        throw new GovernanceError('decision ID CBOR frame must contain four values');
    }
    const byteLengths = values.map(utf8ByteLength);
    let allocationLength = 1;
    for (const byteLength of byteLengths) {
        allocationLength = checkedAllocationLength(allocationLength, canonicalTextHeaderLength(byteLength));
        allocationLength = checkedAllocationLength(allocationLength, byteLength);
    }
    const encoded = new Uint8Array(allocationLength);
    encoded[0] = 0x84;
    let offset = 1;
    for (let index = 0; index < values.length; index++) {
        const value = values[index];
        const byteLength = byteLengths[index];
        if (value === undefined || byteLength === undefined) {
            throw new GovernanceError('decision ID CBOR frame is incomplete');
        }
        offset = writeCanonicalTextHeader(encoded, offset, byteLength);
        const result = UTF8_ENCODER.encodeInto(value, encoded.subarray(offset, offset + byteLength));
        if (result.read !== value.length || result.written !== byteLength) {
            throw new GovernanceError('decision ID UTF-8 encoding was incomplete');
        }
        offset += byteLength;
    }
    if (offset !== allocationLength) {
        throw new GovernanceError('decision ID CBOR encoding length mismatch');
    }
    return encoded;
}
function utf8ByteLength(value) {
    let byteLength = 0;
    for (const character of value) {
        const codePoint = character.codePointAt(0);
        if (codePoint === undefined) {
            throw new GovernanceError('decision ID contains an invalid text value');
        }
        if (codePoint >= 0xd800 && codePoint <= 0xdfff) {
            throw new GovernanceError('decision ID text must be well-formed Unicode');
        }
        const scalarLength = codePoint <= 0x7f ? 1 : codePoint <= 0x7ff ? 2 : codePoint <= 0xffff ? 3 : 4;
        byteLength = checkedAllocationLength(byteLength, scalarLength);
    }
    return byteLength;
}
function canonicalTextHeaderLength(byteLength) {
    if (byteLength <= CBOR_TEXT_INLINE_MAX)
        return 1;
    if (byteLength <= CBOR_UINT8_MAX)
        return 2;
    if (byteLength <= CBOR_UINT16_MAX)
        return 3;
    if (byteLength <= CBOR_UINT32_MAX)
        return 5;
    throw new GovernanceError('decision ID text exceeds the supported CBOR length');
}
function checkedAllocationLength(current, increment) {
    if (!Number.isSafeInteger(current) ||
        !Number.isSafeInteger(increment) ||
        current < 0 ||
        increment < 0 ||
        current > CBOR_UINT32_MAX - increment) {
        throw new GovernanceError('decision ID CBOR payload exceeds safe allocation limits');
    }
    return current + increment;
}
function writeCanonicalTextHeader(target, offset, byteLength) {
    if (byteLength <= CBOR_TEXT_INLINE_MAX) {
        target[offset] = 0x60 | byteLength;
        return offset + 1;
    }
    if (byteLength <= CBOR_UINT8_MAX) {
        target[offset] = 0x78;
        target[offset + 1] = byteLength;
        return offset + 2;
    }
    if (byteLength <= CBOR_UINT16_MAX) {
        target[offset] = 0x79;
        target[offset + 1] = (byteLength >>> 8) & 0xff;
        target[offset + 2] = byteLength & 0xff;
        return offset + 3;
    }
    if (byteLength <= CBOR_UINT32_MAX) {
        target[offset] = 0x7a;
        target[offset + 1] = (byteLength >>> 24) & 0xff;
        target[offset + 2] = (byteLength >>> 16) & 0xff;
        target[offset + 3] = (byteLength >>> 8) & 0xff;
        target[offset + 4] = byteLength & 0xff;
        return offset + 5;
    }
    throw new GovernanceError('decision ID text exceeds the supported CBOR length');
}
//# sourceMappingURL=decision.js.map