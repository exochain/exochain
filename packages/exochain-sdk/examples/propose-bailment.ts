/**
 * Example: build a bailment proposal offline.
 *
 * In a real application the resulting proposal would be submitted to the
 * gateway via `ExochainClient#consent.proposeBailment`.
 *
 * Run: node --experimental-strip-types examples/propose-bailment.ts
 */

import { Identity, BailmentBuilder } from '../dist/index.js';

async function main(): Promise<void> {
  // Two identities — the bailor (consent grantor) and the bailee (grantee).
  const alice = await Identity.generate('alice');
  const bob = await Identity.generate('bob');
  const createdAtPhysicalMs = 1_700_000_000_000;
  const createdAtLogical = 0;

  // Scoped, time-bounded consent from Alice to Bob.
  const proposal = await new BailmentBuilder(alice.did, bob.did)
    .scope('data:medical')
    .durationHours(24)
    .createdAtHlc(createdAtPhysicalMs, createdAtLogical)
    .build();

  console.log('Bailment proposal:');
  console.log('  proposalId:   ', proposal.proposalId);
  console.log('  bailor:       ', proposal.bailor);
  console.log('  bailee:       ', proposal.bailee);
  console.log('  scope:        ', proposal.scope);
  console.log('  durationHours:', proposal.durationHours);
  console.log('  createdAt:    ', proposal.createdAt);
  console.log('  createdAtLogical:', proposal.createdAtLogical);
}

main().catch((err: unknown) => {
  console.error(err);
  process.exit(1);
});
