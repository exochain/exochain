# IntelWar Aesthetic Competition — Adjudication Result

Adjudicator: Aditi Sharma. Rubric applied unmodified from `/tmp/intelwar-adjudication-rubric.md` against the four entries as submitted. No application code was touched in producing this document.

---

## 0. Hard-fail disqualifications (read this first)

Two of the four doctrines are **disqualified from contributing to the coherence pass entirely** under rubric §3's three-strikes rule. This is not a close call — both trip the same named hard-fail condition on the doctrine's own load-bearing elements, repeatedly, not incidentally.

| Doctrine | Disqualifying condition | Where it fires (≥3 required, both clear it) |
|---|---|---|
| **Editorial Institute** | "Instrument Serif, or any humanist/literary serif, used as the primary display or body typeface... never as the brand voice." | `--font-display: "Newsreader"...` — used for the wordmark (#2, italic), the hero headline (#3), the section-title masthead treatment (#7), and the status-line "editor's note" voice (#13/#20). Four hits. Newsreader is precisely the brand voice here, not a labeled quotation. |
| **Precision Cartography** | "Inter or Roboto used as the hero/display typeface... permitted only as an invisible fallback deep in a font-family stack, never as the named, foregrounded choice." | `--font-sans: "Inter"...` is the *only* sans in the system and is named/foregrounded for the wordmark (#2), headline (#3), section titles (#7), and is declared outright as the doctrine's typography-scale answer (#17: "one sans... for every display and body role"). Four hits, and the doctrine's own §17 write-up uses language ("the correct register") that the rubric itself flags as the failure mode. |

Both doctrines are internally polished — that's exactly why this matters. Polish does not redeem a wrong premise (§1). They are scored below for the record and to check their self-reported axes, but **neither can win any element**, per §3's explicit text ("disqualified from contributing to the coherence pass entirely"), and neither appears in the final CSS.

That leaves **Harvey Charcoal** and **Brutalist Provenance Ledger** as the only two eligible donors.

---

## 1. A finding that changes the whole shape of this adjudication

Both surviving doctrines made the *identical* accessibility mistake, independently: they each shipped one deliberately-dim "faint" text token (`--paper-faint` in Harvey at `rgba(paper, 0.4)`, `--fg-faint` in Brutal at a flat `#64645f`) and then reused that single token for real, load-bearing body text — hero lede, section support copy, the Living Log provenance/meta line, the footer, and form labels. On paper (§4, not by eye): both composite to roughly **3.3–3.4:1** against their near-black grounds. That clears the 3:1 "large text" bar but fails the **4.5:1 normal-text bar** required for all five of those elements, which are set well under 24px.

This is the single most important catch in this review. It looks fine on a bright monitor at typical brightness; it will not hold up for a meaningful share of real users, and it is exactly the kind of thing "a11y contrast: 9/10" self-scores should have caught and didn't (see §5 below).

**Disposition:** rather than disqualify either doctrine's structural recipe for those five elements outright, I corrected the one broken value at its root (`--paper-faint` alpha raised from `0.4` to `0.58`, verified ≥5.7:1 against every surface tier it touches) and let Harvey's own original recipes for lede/support/meta/footer/label stand once the underlying defect is fixed — per §6.5, reconciling a color *value* is a legitimate substitution; reconciling Brutal's alternative for those same elements would have required swapping its typeface too (monospace → the foundation's sans), which is more than a value swap and not warranted once the real blocker is gone. Full correction is documented in §3 below and applied in `/tmp/intelwar-winning-styles.css`.

---

## 2. Foundation chosen for the coherence pass

Per §6.1/§6.2, one doctrine must supply the color tokens (#18) **and** the typography scale (#17), and one doctrine sets the motion vocabulary (#19). All three foundation elements go to the same doctrine so the system doesn't fracture:

- **Color tokens (#18) + Typography scale (#17) + Motion language (#19): Harvey Charcoal.**
  Harvey is the only entry that actually delivers the brief's own explicit ask — a real, named, foregrounded "strong elegant sans" (Instrument Sans) for display/body, with IBM Plex Mono reserved *purposefully* for data/provenance, one indigo accent expressed in three disciplined forms (fill/text/wash), and a single non-bouncing easing curve. Brutal is more radical and, on its own terms, more differentiated — but it has no sans register at all, which directly fails the rubric's own text for element #17 ("the elegant sans is the correct register").

Three corrections were required to Harvey's foundation before it was accepted as-is (all applied in the final CSS, all simple value substitutions, none requiring a structural rewrite):

1. **`--paper-faint` alpha `0.4` → `0.58`.** The single fix that resolves five separate accessibility failures at once (lede #4, section support #8, meta/provenance #12, footer #16, form labels #14). Verified ≥5.7:1 against `--ink-0`, `--ink-1`, and `--ink-2`.
2. **`--signal-muted: #a98a72` deleted.** This token was declared in Harvey's `:root` but never wired to any of the 20 elements — dead weight, and its hex value sits uncomfortably close to the rejected terracotta/clay family. A token that exists but does nothing is still a liability the next contributor might reach for. Gone.
3. **`--dur-reveal` `640ms` → `380ms`.** Harvey's entrance animation is well-behaved (single fade+rise, deceleration curve, run-once, no loop) but its own duration overshoots §5's 200–400ms entrance band by 60%. The curve was right; the number was slow. Corrected, stagger steps tightened to 60ms so the full hero sequence lands under 600ms total.

---

## 3. Per-element winners (1–20)

| # | Element | Winner | Score /5 | Why (one line) |
|---|---|---|---|---|
| 1 | Page background / atmospheric plane | **Harvey** | 4 | Only entry that gives the rubric's actual ask — "depth without flatness" — via one near-invisible wash; Brutal's fully flat ground is clean but literally misses the "depth" half of the criterion. |
| 2 | Brand mark (wordmark) | **Harvey** | 4 | Set in the elegant sans as the brief demands, deliberate underline rule, no icon-in-square; Brutal's mono wordmark is distinctive but is explicitly off the sans register the brief calls for. |
| 3 | Hero headline | **Harvey** | 4 | Correct ~40–60ch measure, commands without shouting; Brutal's is well-executed but runs under-length (34ch) and, again, off the sans register. |
| 4 | Hero lede | **Harvey** *(post-correction)* | 4 | Originally hard-failed AA via the broken `--paper-faint`; once that token is fixed at the root, Harvey's own recipe is the better fit for the foundation's sans voice — porting Brutal's version instead would have meant swapping its typeface too, which is more than a value substitution (§6.5). |
| 5 | Primary CTA | **Brutal** | 5 | The single strongest idea across all 20 elements: grayscale by default, indigo appears *only* on hover/focus — the most literal, disciplined reading of "accent spent with intent" in the whole field. Reconciled onto Harvey's `--paper`/`--ink-0`/`--accent` tokens, sans-case label instead of mono-uppercase. |
| 6 | Secondary/ghost CTA | **Brutal** | 4 | Same accent-only-on-interaction mechanic as its primary, slightly higher default text-contrast margin than Harvey's ghost. Reconciled to foundation tokens + sans label. |
| 7 | Section title | **Harvey** | 4 | On-scale, on-family, inline (not full-width) accent rule; Brutal's numbered-ledger idea is nice but the number sits in the (pre-correction) faint token and the heading itself is off-register mono. |
| 8 | Section support text | **Harvey** *(post-correction)* | 4 | Same story as #4 — the only reason Brutal was briefly ahead was Harvey's broken token, which is now fixed. |
| 9 | Living Log panel container | **Brutal** | 5 | The `LOG // APPEND-ONLY` header-strip label turns the panel into a labeled instrument, not a generic card — genuine wayfinding value, zero JSX cost. Reconciled to Harvey's `--ink-2`/`--hairline`/`--radius-md`. |
| 10 | Log entry row | **Brutal** | 5 | Left gutter stays transparent at rest and turns accent-colored only on hover/focus-within — the whole "accent means you can act here" doctrine expressed at row level. Reconciled to `--accent`/`--hairline`. |
| 11 | Simulated badge | **Brutal** | 5 | Bracket-tag treatment (`[Simulated]`) carries zero color signal at all and reads as a ledger annotation, not a warning light — the most literal possible satisfaction of "not alarming, text label present." Reconciled to `--paper-dim`/`--hairline-strong`, IBM Plex Mono (already shared by both foundations). |
| 12 | Meta chips / provenance line | **Harvey** *(post-correction)* | 4 | Mono, `·`-separated, no pill chips (a "pill cluster" is explicitly on the parent's avoid-list — Carto's pill-bordered meta chips would have failed this on sight even before its typeface disqualification). Was AA-failing pre-correction; passes at ≥5.8:1 now. |
| 13 | Consent status indicator | **Harvey** | 4 | Accent rail + text state (`active`/`inactive` from existing JSX) ships complete today; Brutal's fuller glyph-swap idea is honestly flagged by its own author as needing a future `data-state` attribute that doesn't exist yet — implementability tie-break. |
| 14 | Form label + input + select | **Harvey** *(post-correction)* | 4 | Input/select recipe (filled, hairline border, accent focus ring) was already clean; the label color was the one casualty of the faint-token bug, now fixed. No placeholder-as-label anywhere. |
| 15 | Ink/action button + secondary | **Brutal** | 5 | Same grayscale/accent-on-interaction discipline as the hero CTAs, carried through to the in-app Grant/Revoke buttons — the strongest system-wide consistency payoff in the whole mashup. Reconciled to foundation tokens. |
| 16 | Footer | **Harvey** *(post-correction)* | 4 | Colophon rhythm, mono caption, top hairline — was AA-failing pre-correction on the same broken token, now fixed. |
| 17 | Typography scale | **Harvey** | 5 | **FOUNDATION.** The only entry with an actual "elegant sans" register plus mono reserved purposefully for data — exactly what this element is scored against. |
| 18 | Color tokens | **Harvey** | 4 | **FOUNDATION** (corrected). Four ink elevations, three text tiers, one accent in three forms, singular accent family — clean architecture once `--paper-faint` and the dead `--signal-muted` token are fixed. |
| 19 | Motion language | **Harvey** | 3→4 | **FOUNDATION** (corrected). No bounce, no overshoot, run-once entrance, no ambient loop — but its own `640ms` exceeded the §5 entrance band, corrected to `380ms`. Brutal's alternative has a permanently-blinking 1s cursor on the brand mark, which is exactly the kind of always-visible ambient loop §5 warns against ("never draw the eye away from content"); Harvey's flaw was a number, Brutal's was a behavior — the number was cheaper to fix. |
| 20 | Empty/loading/error states | **Brutal** *(copy recommended, CSS deferred to foundation)* | 5 (copy) | Brutal's three terminal-style lines (`> reading log stream…`, `! log api unavailable — …`, `— no entries recorded —`) are the most concrete, on-tone answer to this element — but applying them requires editing the hardcoded strings in `LivingLogViewer.jsx`, which is out of scope for a CSS-only pass. The CSS treatment shipped now is Harvey's foundation `.status-line` styling (which already reads correctly against the *current* hardcoded copy); Brutal's exact strings are flagged in `/tmp/intelwar-winning-copy.md` as a trivial, structure-free follow-up edit for the parent to apply directly if desired. |

**Result: no element required a "no entry passes" verdict once the root-cause token fix was applied.** Five elements briefly looked like gaps (#4, #8, #12, #14, #16) purely because of one bad alpha value shared by both surviving doctrines; fixing that value at the source resolved all five simultaneously rather than requiring five separate patched-together recipes.

---

## 4. Self-scored axes vs. independent view

Per §7.5 — flagging where a doctrine's self-score outran the element-level evidence.

| Doctrine | Axis | Self-score | Adjudicator's independent view | Flag |
|---|---|---|---|---|
| Harvey Charcoal | intellectual dignity | 9 | 8 | — |
| | differentiation | 8 | 6 | Honest self-score, if anything slightly generous; it's the safest, most convergent-with-"tasteful default" of the four. |
| | **a11y contrast** | **9** | **4** | 🚩 **Substantially overstated.** Six elements (#4, #8, #12, #13-adjacent footer, #14, #16) ran on a token that measures ~3.3:1 against near-black — below the 4.5:1 normal-text minimum. This should have been caught by the doctrine's own "passes §4 contrast math on paper" standard for element #18 and wasn't. |
| | implementability | 10 | 10 | Agreed — genuinely drop-in against the existing class names, zero new dependencies. |
| Editorial Institute | intellectual dignity | 9 | 7 | Disqualification undercuts the premise regardless of execution quality. |
| | differentiation | 9 | 5 | 🚩 The distinctiveness comes entirely from the serif-as-brand-voice choice, which is the specific thing §3 bans. Distinctive ≠ eligible. |
| | a11y contrast | 8 | 6 | Doctrine's own write-up admits "not lab-measured... held at 8 pending verification" — an honest hedge, but the hedge itself should have been a signal to actually check before submitting. |
| | implementability | 9 | 9 | Plausible on the CSS-mechanics merits; moot since disqualified. |
| Precision Cartography | intellectual dignity | 9 | 7 | Strong instrument-panel conceit, undone by the typeface premise. |
| | **differentiation** | **9** | **6** | 🚩 **Overstated.** The rubric's own language calls Inter-as-hero "the most common system sans... a failure of nerve, not a neutral choice" — that is the opposite of a differentiation claim. |
| | a11y contrast | 9 | 7 | To its credit, the one doctrine that got its "faint" composite math right (lede clears ~4.6:1) — better contrast discipline than either surviving doctrine, just disqualified on a different axis entirely. |
| | implementability | 9 | 8 | Plausible; moot since disqualified. |
| Brutalist Provenance Ledger | intellectual dignity | 9 | 9 | Agreed — the restraint genuinely reads as the credential it claims to be. |
| | differentiation | 9 | 9 | Agreed — the monospace-only, accent-only-on-interaction stance is the hardest-to-copy premise in the field. |
| | **a11y contrast** | **9** | **5** | 🚩 **Substantially overstated**, and for the *identical* reason as Harvey — `--fg-faint` fails 4.5:1 on meta/footer/label. Also ships a permanently-looping 1s cursor blink on the brand mark that sits uneasily against §5's ambient-motion rule, something a 9/10 self-score on "a11y contrast" wouldn't catch but a careful motion audit should have flagged separately. |
| | implementability | 10 | 9 | Very close to accurate — genuinely clean, CSS-only, but the loading/error/empty copy that makes #20 sing does need a (trivial, content-only) JSX text edit to fully land. |

**Pattern worth naming directly:** both doctrines that survived to the coherence pass over-claimed their own accessibility rigor by an identical, specific mechanism (one under-opacity "faint" text tier, reused everywhere secondary text appears). That is not a coincidence of two independent design choices — it's a shared blind spot in how "quiet/restrained" gets operationalized as "just turn the opacity down," and it is the exact kind of thing that looks correct in a screenshot and fails the moment someone actually runs the numbers. Screenshots lie; contrast ratios don't.

---

## 5. What ships

- `/tmp/intelwar-winning-styles.css` — complete drop-in `styles.css`, Harvey foundation + the six Brutal-sourced elements reconciled onto it, all three foundation corrections applied, `prefers-reduced-motion` honored.
- `/tmp/intelwar-winning-index-fonts.html` — Instrument Sans + IBM Plex Mono link tags (Harvey's foundation choice; replaces the current DM Sans/Instrument Serif import).
- `/tmp/intelwar-winning-copy.md` — hero brand/headline/lede strings, CTA label decision (kept as-is), and the flagged optional `LivingLogViewer.jsx` state-copy follow-up.

No application source was modified in producing any of this. Implementation is the parent's explicitly separate, authorized step (§7.6).

---

## Implementation note (2026-07-18)

Landed in `apps/intelwar-net` as Harvey foundation + Brutal interaction layer.
Additional instrument-strip labels applied to `.tv`, `.ai`, and consent panels so
every surface element participates in the winning system.
Preview: `npm --prefix apps/intelwar-net run preview`.
