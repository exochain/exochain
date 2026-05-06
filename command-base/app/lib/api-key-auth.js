'use strict';

const crypto = require('crypto');

function headerValue(req, name) {
  const headers = (req && req.headers) || {};
  const value = headers[name];
  return typeof value === 'string' ? value : null;
}

function cookieValue(req, name) {
  const cookieHeader = headerValue(req, 'cookie');
  if (!cookieHeader) return null;

  for (const part of cookieHeader.split(';')) {
    const separator = part.indexOf('=');
    if (separator === -1) continue;
    const key = part.slice(0, separator).trim();
    if (key !== name) continue;
    const value = part.slice(separator + 1).trim();
    try {
      return decodeURIComponent(value);
    } catch (_err) {
      return value;
    }
  }

  return null;
}

function constantTimeEquals(expected, candidate) {
  if (!expected || !candidate) return false;
  if (typeof expected !== 'string' || typeof candidate !== 'string') return false;

  const expectedBytes = Buffer.from(expected, 'utf8');
  const candidateBytes = Buffer.from(candidate, 'utf8');
  if (expectedBytes.length !== candidateBytes.length) return false;

  return crypto.timingSafeEqual(expectedBytes, candidateBytes);
}

function isApiAuthenticated(req, apiKey) {
  return (
    constantTimeEquals(apiKey, headerValue(req, 'x-api-key')) ||
    constantTimeEquals(apiKey, cookieValue(req, 'cb_auth'))
  );
}

function buildAuthStatus(req, apiKey) {
  return {
    authenticated: isApiAuthenticated(req, apiKey),
    auth_required: true,
  };
}

module.exports = {
  buildAuthStatus,
  isApiAuthenticated,
};
