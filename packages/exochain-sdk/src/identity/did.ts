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
 * DID validation.
 *
 * The fabric uses the `did:exo:<method-specific-id>` format. Validation here
 * is intentionally lightweight: we require the prefix, a non-empty method-
 * specific identifier, and a restricted character set. Stronger checks (e.g.
 * resolution, existence on the fabric) are server-side concerns.
 */

import { IdentityError } from '../errors.js';
import type { Did } from '../types.js';

/** Regex for the method-specific portion after `did:exo:`. */
const METHOD_SPECIFIC = /^[a-zA-Z0-9._-]+$/;

/**
 * Validate a candidate DID string and return it branded as a {@link Did}.
 * Throws {@link IdentityError} if the input is not a well-formed `did:exo:`.
 */
export function validateDid(s: string): Did {
  if (typeof s !== 'string') {
    throw new IdentityError('DID must be a string');
  }
  if (!s.startsWith('did:exo:')) {
    throw new IdentityError(`DID must start with "did:exo:" (got "${s}")`);
  }
  const method = s.slice('did:exo:'.length);
  if (method.length === 0) {
    throw new IdentityError('DID method-specific identifier is empty');
  }
  if (!METHOD_SPECIFIC.test(method)) {
    throw new IdentityError(
      `DID method-specific identifier contains invalid characters: "${method}"`,
    );
  }
  return s as Did;
}

/** Type-guard form of {@link validateDid} that returns a boolean. */
export function isDid(s: string): s is Did {
  try {
    validateDid(s);
    return true;
  } catch {
    return false;
  }
}
