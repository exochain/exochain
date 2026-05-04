"""Build a bailment consent proposal between two identities.

A bailment is a scoped, time-bounded delegation of custody. Here, Alice
delegates read access to her medical record to Bob for 48 hours.

Run:
    python examples/propose_bailment.py
"""

from __future__ import annotations

from exochain import BailmentBuilder, Identity


def main() -> None:
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    created_at_physical_ms = 1_700_000_000_000
    created_at_logical = 0

    proposal = (
        BailmentBuilder(alice.did, bob.did)
        .scope("read:medical-records")
        .duration_hours(48)
        .created_at_hlc(created_at_physical_ms, created_at_logical)
        .build()
    )

    print(f"Bailor:       {proposal.bailor}")
    print(f"Bailee:       {proposal.bailee}")
    print(f"Scope:        {proposal.scope}")
    print(f"Duration:     {proposal.duration_hours} hours")
    print(f"Created at:   {proposal.created_at} logical={proposal.created_at_logical}")
    print(f"Proposal id:  {proposal.proposal_id}")

    # The proposal id is a deterministic content hash.
    also = (
        BailmentBuilder(alice.did, bob.did)
        .scope("read:medical-records")
        .duration_hours(48)
        .created_at_hlc(created_at_physical_ms, created_at_logical)
        .build()
    )
    print(f"Deterministic: {proposal.proposal_id == also.proposal_id}")


if __name__ == "__main__":
    main()
