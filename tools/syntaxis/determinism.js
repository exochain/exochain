const crypto = require('crypto');

const BASIS_POINTS_DENOMINATOR = 10000;
const HLC_LOGICAL_MAX = 0xffff_ffff;

function normalizeHlc(value, fieldName = 'hlc') {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${fieldName} is required`);
  }

  const physicalMs = normalizePositiveInteger(value.physicalMs, `${fieldName}.physicalMs`);
  const logical = normalizeNonNegativeInteger(value.logical ?? 0, `${fieldName}.logical`);
  if (logical > HLC_LOGICAL_MAX) {
    throw new Error(`${fieldName}.logical must be between 0 and ${HLC_LOGICAL_MAX}`);
  }

  return { physicalMs, logical };
}

function timestampFromContext(context) {
  return normalizeHlc(context?.inputs?.timestampHlc ?? context?.timestampHlc, 'context.inputs.timestampHlc');
}

function hlcToString(value) {
  const hlc = normalizeHlc(value);
  return `${hlc.physicalMs}:${hlc.logical}`;
}

function advanceHlc(value, logicalTicks) {
  const hlc = normalizeHlc(value);
  const ticks = normalizeNonNegativeInteger(logicalTicks, 'logicalTicks');
  if (ticks === 0) {
    return hlc;
  }
  const logicalRange = BigInt(HLC_LOGICAL_MAX) + 1n;
  const nextLogical = BigInt(hlc.logical) + BigInt(ticks);
  if (nextLogical <= BigInt(HLC_LOGICAL_MAX)) {
    return { physicalMs: hlc.physicalMs, logical: Number(nextLogical) };
  }
  const carry = nextLogical / logicalRange;
  const physicalMs = BigInt(hlc.physicalMs) + carry;
  if (physicalMs > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error('advanced physicalMs must be a JavaScript safe integer');
  }
  const logical = nextLogical % logicalRange;
  return {
    physicalMs: Number(physicalMs),
    logical: Number(logical)
  };
}

function compareHlc(a, b) {
  const left = normalizeHlc(a, 'left');
  const right = normalizeHlc(b, 'right');
  if (left.physicalMs !== right.physicalMs) {
    return left.physicalMs < right.physicalMs ? -1 : 1;
  }
  if (left.logical === right.logical) {
    return 0;
  }
  return left.logical < right.logical ? -1 : 1;
}

function normalizeBasisPoints(value, fieldName, fallback) {
  const input = value === undefined || value === null ? fallback : value;
  const bps = normalizeNonNegativeInteger(input, fieldName);
  if (bps > BASIS_POINTS_DENOMINATOR) {
    throw new Error(`${fieldName} must be between 0 and ${BASIS_POINTS_DENOMINATOR} basis points`);
  }
  return bps;
}

function ratioBasisPoints(numerator, denominator) {
  const n = normalizeNonNegativeInteger(numerator, 'numerator');
  const d = normalizeNonNegativeInteger(denominator, 'denominator');
  if (d === 0) {
    return 0;
  }
  return Number((BigInt(n) * BigInt(BASIS_POINTS_DENOMINATOR)) / BigInt(d));
}

function canonicalJson(value) {
  return JSON.stringify(canonicalize(value));
}

function hashCanonical(value) {
  return crypto.createHash('sha256').update(canonicalJson(value)).digest('hex');
}

function deterministicId(prefix, value) {
  return `${prefix}_${hashCanonical(value).slice(0, 16)}`;
}

function canonicalize(value) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') {
    return value;
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || !Number.isInteger(value)) {
      throw new Error('canonical values must use finite integers; use basis points for fractional quantities');
    }
    if (!Number.isSafeInteger(value)) {
      throw new Error('canonical numeric values must be JavaScript safe integers');
    }
    return value;
  }
  if (typeof value === 'bigint') {
    return value.toString();
  }
  if (Array.isArray(value)) {
    return value.map(canonicalize);
  }
  if (typeof value === 'object') {
    const out = {};
    for (const key of Object.keys(value).sort()) {
      const child = value[key];
      if (child === undefined) {
        continue;
      }
      out[key] = canonicalize(child);
    }
    return out;
  }
  throw new Error(`unsupported canonical value type: ${typeof value}`);
}

function normalizePositiveInteger(value, fieldName) {
  const normalized = normalizeNonNegativeInteger(value, fieldName);
  if (normalized === 0) {
    throw new Error(`${fieldName} must be a positive integer`);
  }
  return normalized;
}

function normalizeNonNegativeInteger(value, fieldName) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${fieldName} must be a non-negative safe integer`);
  }
  return value;
}

module.exports = {
  BASIS_POINTS_DENOMINATOR,
  HLC_LOGICAL_MAX,
  advanceHlc,
  canonicalJson,
  compareHlc,
  deterministicId,
  hashCanonical,
  hlcToString,
  normalizeBasisPoints,
  normalizeHlc,
  ratioBasisPoints,
  timestampFromContext
};
