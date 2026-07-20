# IntelWar Social Layer — Concrete Features (v1)

Derived from SOCIAL_LAYER_FIRST_PRINCIPLES.md. Social is subordinate to arena, Log, and contests.

## Domain ownership (locked)

| Domain | Role |
|--------|------|
| **intelwar.org** | Mind War Theatre entrance only. Lightweight merit *signals* on campaigns may link out. No full social experience. |
| **intelwar.net** | Operational social + reputation + daily engagement + Living Log. Canonical home of 0dentity, coalitions, discovery. |

Canonical entry: `https://intelwar.net/` (hash `#social` scrolls to social layer).  
`intelwar.org/#social` must **not** render the full social surface.

## Feature map

| Feature | Purpose | Anti-pattern avoided |
|---------|---------|----------------------|
| **0dentity Passport** | Portable merit across surfaces; legible status | Follower count as currency |
| **Merit Ledger** | Primary signals from Log, contests, CrossCheck, filmstrip rigor | Likes / engagement velocity |
| **Coalitions** | Mission-aligned, dissolvable groups around campaigns | Permanent identity tribes |
| **Discovery** | Merit + relevance ranking; chronological/structural | Infinite algorithmic feed |
| **Context Tiers** | Exploratory / coalition / public contest visibility | Collapsing all context into one feed |
| **Recognition** | High-merit peer attestations of contribution | Mob applause / pile-ons |
| **Notifications** | Sparse, consequential, opt-in by tier | Engagement dopamine loops |

## Visibility tiers
1. `exploratory` — high-trust draft space; not public Record
2. `coalition` — mission group only
3. `public_contest` — arena-visible; may bind to Log
4. `record` — Living Log bound (consent + Kernel)

## Out of scope v1
- Infinite scroll feed
- Followers graph as primary UX
- Ad targeting / attention monetization
- Real-name mandate or pure anonymity without accountability hooks
- Hosting the full social layer on intelwar.org
