import { TransportError } from './errors.js';
import { validateDid } from './identity/did.js';
const HASH256_RE = /^[0-9a-f]{64}$/;
const ECONOMY_OBJECT_KINDS = [
    'mission',
    'contribution_receipt',
    'legacy_receipt',
    'honorgood_ruleset',
    'value_contribution_node',
    'contribution_offer',
    'contribution_acceptance',
    'bailment_terms',
    'bailment_wrapper',
    'adoption_event',
    'use_event',
    'value_event',
    'mission_settlement',
    'automated_settlement_event',
];
function isRecord(value) {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}
function validationError(message) {
    return new TransportError(`gateway payload validation failed: ${message}`);
}
function validateJsonValue(value, path, seen) {
    if (value === null) {
        return;
    }
    switch (typeof value) {
        case 'string':
        case 'boolean':
            return;
        case 'number':
            if (!Number.isFinite(value)) {
                throw validationError(`${path} must be a finite JSON number`);
            }
            return;
        case 'object':
            if (seen.has(value)) {
                throw validationError(`${path} must not contain cycles`);
            }
            seen.add(value);
            if (Array.isArray(value)) {
                for (let index = 0; index < value.length; index++) {
                    validateJsonValue(value[index], `${path}[${index}]`, seen);
                }
            }
            else {
                for (const [key, item] of Object.entries(value)) {
                    validateJsonValue(item, `${path}.${key}`, seen);
                }
            }
            seen.delete(value);
            return;
        default:
            throw validationError(`${path} must be JSON-serializable`);
    }
}
export function assertJsonObject(value, context) {
    if (!isRecord(value)) {
        throw validationError(`${context} must be a JSON object`);
    }
    validateJsonValue(value, context, new WeakSet());
    return value;
}
function requireRecord(value, context) {
    if (!isRecord(value)) {
        throw validationError(`${context} must be a JSON object`);
    }
    return value;
}
function requireString(record, key, context) {
    const value = record[key];
    if (typeof value !== 'string') {
        throw validationError(`${context}.${key} must be a string`);
    }
    return value;
}
function requireBoolean(record, key, context) {
    const value = record[key];
    if (typeof value !== 'boolean') {
        throw validationError(`${context}.${key} must be a boolean`);
    }
    return value;
}
function requireFiniteNumber(record, key, context) {
    const value = record[key];
    if (typeof value !== 'number' || !Number.isFinite(value)) {
        throw validationError(`${context}.${key} must be a finite number`);
    }
    return value;
}
function requireJsonValue(record, key, context) {
    const value = record[key];
    validateJsonValue(value, `${context}.${key}`, new WeakSet());
    return value;
}
function requireEconomyObjectKind(record, key, context) {
    const value = requireString(record, key, context);
    if (!ECONOMY_OBJECT_KINDS.includes(value)) {
        throw validationError(`${context}.${key} must be a known economy object kind`);
    }
    return value;
}
function requireNonNegativeInteger(record, key, context) {
    const value = requireFiniteNumber(record, key, context);
    if (!Number.isSafeInteger(value) || value < 0) {
        throw validationError(`${context}.${key} must be a non-negative safe integer`);
    }
    return value;
}
export function validateHash256(value, context) {
    if (typeof value !== 'string' || !HASH256_RE.test(value)) {
        throw validationError(`${context} must be a 64-character lowercase hex hash`);
    }
    return value;
}
export function validateHealthResponse(value) {
    const record = requireRecord(value, 'health response');
    return {
        status: requireString(record, 'status', 'health response'),
        version: requireString(record, 'version', 'health response'),
        uptime: requireFiniteNumber(record, 'uptime', 'health response'),
    };
}
export function validateDidResponse(value, context) {
    const record = requireRecord(value, context);
    const did = requireString(record, 'did', context);
    try {
        return {
            did: validateDid(did),
        };
    }
    catch {
        throw validationError(`${context}.did must be a valid did:exo identifier`);
    }
}
export function validateHashResponse(value, key, context) {
    const record = requireRecord(value, context);
    return {
        [key]: validateHash256(record[key], `${context}.${key}`),
    };
}
export function validateQuorumResult(value, context) {
    const record = requireRecord(value, context);
    return {
        met: requireBoolean(record, 'met', context),
        threshold: requireNonNegativeInteger(record, 'threshold', context),
        totalVotes: requireNonNegativeInteger(record, 'totalVotes', context),
        approvals: requireNonNegativeInteger(record, 'approvals', context),
        rejections: requireNonNegativeInteger(record, 'rejections', context),
        abstentions: requireNonNegativeInteger(record, 'abstentions', context),
    };
}
export function validateDecisionState(value) {
    const record = requireRecord(value, 'decision response');
    const result = {
        decisionId: validateHash256(record.decisionId, 'decision response.decisionId'),
        status: requireString(record, 'status', 'decision response'),
    };
    if (record.quorum !== undefined) {
        result.quorum = validateQuorumResult(record.quorum, 'decision response.quorum');
    }
    return result;
}
export function validateEconomyRecordAnchor(value, context) {
    const record = requireRecord(value, context);
    return {
        anchor_hash: validateHash256(record.anchor_hash, `${context}.anchor_hash`),
        previous_anchor_hash: validateHash256(record.previous_anchor_hash, `${context}.previous_anchor_hash`),
        object_kind: requireEconomyObjectKind(record, 'object_kind', context),
        object_id: validateHash256(record.object_id, `${context}.object_id`),
        object_hash: validateHash256(record.object_hash, `${context}.object_hash`),
        created_at: requireJsonValue(record, 'created_at', context),
    };
}
export function validateEconomyObjectResponse(value, context) {
    const record = requireRecord(value, context);
    return {
        object: assertJsonObject(record.object, `${context}.object`),
        anchor: validateEconomyRecordAnchor(record.anchor, `${context}.anchor`),
    };
}
//# sourceMappingURL=validation.js.map