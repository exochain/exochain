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
 * Authority chain builder and validator.
 *
 * An authority chain is an ordered list of delegation links where each
 * `grantee` is the `grantor` of the next link. The chain terminates at a
 * specific actor. Mirrors the Rust SDK's `AuthorityChainBuilder` API.
 */

import { AuthorityError } from '../errors.js';
import type { Did } from '../types.js';
import { validateDid } from '../identity/did.js';

/** A single delegation link. */
export interface ChainLink {
  readonly grantor: Did;
  readonly grantee: Did;
  readonly permissions: readonly string[];
}

/** A fully validated authority chain. */
export interface ValidatedChain {
  readonly depth: number;
  readonly links: readonly ChainLink[];
  readonly terminal: Did;
}

/** Fluent builder for an authority chain. */
export class AuthorityChainBuilder {
  readonly #links: ChainLink[] = [];

  /** Append a delegation link. Returns `this` for chaining. */
  public addLink(
    grantor: Did | string,
    grantee: Did | string,
    permissions: readonly string[],
  ): this {
    const grantorDid = typeof grantor === 'string' ? validateDid(grantor) : grantor;
    const granteeDid = typeof grantee === 'string' ? validateDid(grantee) : grantee;
    this.#links.push({
      grantor: grantorDid,
      grantee: granteeDid,
      permissions: [...permissions],
    });
    return this;
  }

  /**
   * Validate the chain topology and return a {@link ValidatedChain}.
   *
   * Rules:
   * - At least one link.
   * - For each consecutive pair, `links[i].grantee === links[i+1].grantor`.
   * - The final `grantee` must equal `terminalActor`.
   */
  public build(terminalActor: Did | string): ValidatedChain {
    const terminal =
      typeof terminalActor === 'string' ? validateDid(terminalActor) : terminalActor;

    if (this.#links.length === 0) {
      throw new AuthorityError('authority chain is empty');
    }

    for (let i = 0; i < this.#links.length - 1; i++) {
      const a = this.#links[i];
      const b = this.#links[i + 1];
      if (a === undefined || b === undefined) continue;
      if (a.grantee !== b.grantor) {
        throw new AuthorityError(
          `broken delegation at index ${i}: ${a.grantee} !== ${b.grantor}`,
        );
      }
    }

    const last = this.#links[this.#links.length - 1];
    if (last === undefined) {
      throw new AuthorityError('authority chain is empty');
    }
    if (last.grantee !== terminal) {
      throw new AuthorityError(
        `terminal mismatch: chain ends at ${last.grantee} but terminal is ${terminal}`,
      );
    }

    return {
      depth: this.#links.length,
      links: [...this.#links],
      terminal,
    };
  }
}
