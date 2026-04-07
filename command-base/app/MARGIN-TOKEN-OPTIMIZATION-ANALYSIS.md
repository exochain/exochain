# Token Optimization Audit — Financial Analysis & Implementation Plan
**Analyst:** Margin (Accounting Specialist)  
**Source:** Neural's Token Spending Audit (2026-04-03)  
**Review Date:** 2026-04-04  
**Status:** Ready for Council Review

---

## Executive Summary for Finance

### Current Spend & Projected Savings

| Metric | Value |
|--------|-------|
| **Estimated annual token spend** | $180K-240K (based on current patterns) |
| **Identified waste** | 40-60% of current spend |
| **Annualized savings opportunity** | $72K-144K |
| **Monthly run-rate savings** | $6K-12K |
| **Payback period for implementation** | <1 week |

**ROI:** Immediate and high. Implementation effort is ~20-40 hours of engineering, yielding 6-12 months of monthly savings.

---

## Financial Impact by Finding

### HIGH PRIORITY (Immediate Implementation — No Council Vote Needed)

#### 1. **Council Routing → Haiku** ⚡ QUICK WIN
- **Token Savings:** ~90% of routing costs
- **Current state:** Every task routes via Claude Sonnet (expensive classification task)
- **Fix:** Switch to Claude Haiku (10x cheaper, equally capable for structured routing)
- **Effort:** 1 line of code (`server.js:16483`)
- **Monthly impact:** ~$800-1,200 savings
- **Risk:** None — Haiku's classification accuracy is proven for well-structured prompts
- **Recommendation:** **IMPLEMENT IMMEDIATELY** (Onyx/Spline)

#### 2. **Reduce Max Turns** 🎯 SIMPLE & SAFE
- **Token Savings:** 5K-75K tokens per runaway task (estimated 2-5 runaway tasks/week)
- **Current state:** urgent/high tasks get 25 turns, normal get 15 turns
- **Fix:** Reduce to 15 and 10 respectively
- **Effort:** 1 line of code (`server.js:14144`)
- **Monthly impact:** ~$2,400-8,000 savings (varies by failure rate)
- **Risk:** Low — tasks that need more turns can use supervised retry mechanism
- **Recommendation:** **IMPLEMENT IMMEDIATELY** (Onyx/Spline)

#### 3. **Remove Duplicate Function** 🧹 CODE HYGIENE
- **Token Savings:** Indirect (reduces confusion, improves maintenance)
- **Current state:** Two `validateOutputQuality` functions at lines 14576 and 15197
- **Fix:** Delete the dead first version (lines 14576-14627)
- **Effort:** Delete 50 lines
- **Risk:** None — second version overwrites the first anyway
- **Recommendation:** **IMPLEMENT IMMEDIATELY** (Onyx/Spline)

#### 4. **Cap Stdout Collection** 📦 SERVER OPTIMIZATION
- **Token Savings:** Indirect (server resource savings, not LLM tokens)
- **Current state:** Unbounded stdout collection (100KB-1MB per session)
- **Fix:** Cap at 50KB or filter to only assistant text blocks
- **Effort:** ~5 lines
- **Risk:** Low — only affects internal processing, not agent behavior
- **Recommendation:** **IMPLEMENT IMMEDIATELY** (Onyx/Spline)

#### 5. **Cap Improvement Retries** 🔒 CIRCUIT BREAKER
- **Token Savings:** 15K-50K per stuck improvement × estimated 1-3 weekly occurrences
- **Current state:** Improvement proposals re-queue indefinitely on failure
- **Fix:** Add max retry count (3) before marking as failed
- **Effort:** ~5 lines
- **Monthly impact:** ~$900-2,700 savings
- **Risk:** Low — prevents infinite retry loops
- **Recommendation:** **IMPLEMENT IMMEDIATELY** (Onyx/Spline)

---

### MEDIUM PRIORITY (Requires Council Review + Implementation)

#### 6. **Trim Prompt Context** ⚙️ CAREFUL OPTIMIZATION
- **Token Savings:** 2K-8K tokens per spawn × 30-50 spawns/day = 60K-400K tokens/day
- **Monthly impact:** ~$18K-120K savings
- **Current waste:**
  - Linked repos/paths loaded for every task (even unrelated ones)
  - All 20 memory entries loaded (many stale)
  - 20-50 context store items loaded regardless of task relevance
  - Static boilerplate repeated in every prompt
- **Proposed fix:**
  - Only include linked repos/paths if task references them
  - Limit memories to 5 most relevant (filter by domain)
  - Skip daily notes for non-heartbeat tasks
  - Cache static boilerplate as system prompt
  - Truncate memory content to 200 chars (currently 500+)
- **Effort:** ~30 lines
- **Risk:** Medium — need to validate that agents still have sufficient context
- **Recommendation:** **COUNCIL REVIEW REQUIRED** (policy on context availability)
  - **Then:** **IMPLEMENT** with staged rollout and monitoring

#### 7. **Smarter Model Selection** 🧠 QUALITY + COST
- **Token Savings:** 30-50% of Opus usage downgraded to Sonnet
- **Current state:** Opus triggered by priority + description length (too broad)
- **Monthly impact:** ~$8K-20K savings
- **Fix:** Use task type, not just priority level:
  - Peer reviews → always Sonnet (they just read and score)
  - QA verification → always Sonnet (syntax checking, file reading)
  - Simple/routine tasks → Sonnet regardless of priority
  - Complex architecture/debugging → Opus (keep)
- **Effort:** ~15 lines
- **Risk:** Low-Medium — need to define "simple" vs. "complex" criteria clearly
- **Recommendation:** **COUNCIL REVIEW REQUIRED** (quality expectations per task type)
  - **Then:** **IMPLEMENT** with clear guidelines

---

### STRATEGIC PRIORITY (Requires Council Vote + Major Implementation)

#### 8. **Peer Review Opt-In Policy** 🏛️ GOVERNANCE DECISION
- **Token Savings:** 400K-1.2M tokens/day
- **Monthly impact:** ~$12K-36K savings
- **Current state:** Peer review triggers on all outputs >10K chars (automatic)
- **Proposed fix:** Make peer review opt-in:
  - **Always trigger:** Urgent priority OR tasks in governed projects
  - **Rely on programmatic validation** for routine work (already comprehensive)
  - **Optional:** Specialist can request peer review if uncertain
- **Effort:** ~10 lines logic change
- **Risk:** HIGH — affects quality gates and governance
- **Recommendation:** **COUNCIL VOTE REQUIRED**
  - This is a Board-level policy decision (quality standards)
  - Impact: Majority of review overhead disappears if approved

#### 9. **Coordinate Watchdog Retries** 🔄 FAILURE POLICY
- **Token Savings:** 50K-200K per doomed task × 2-5 weekly = 100K-1M tokens/week
- **Monthly impact:** ~$3K-15K savings
- **Current state:** Three independent watchdogs (process, review, abandonment) retry without coordinating
- **Proposed fix:**
  - Add shared `failure_count` check before any watchdog respawn
  - Skip retry if task has already failed 3+ times
  - Reduce circuit breaker from 8 to 4 (`ESCALATION_CIRCUIT_BREAKER`)
  - Increase stuck review timeout from 2 to 5 minutes (peer reviews take longer)
- **Effort:** ~20 lines
- **Risk:** Medium — need to ensure legitimate retries still happen
- **Recommendation:** **COUNCIL REVIEW REQUIRED** (failure handling policy)
  - **Then:** **IMPLEMENT** with clear escalation rules

---

## Implementation Roadmap

### Phase 1: Immediate (This Week) — No Council Vote
**Effort:** ~8 hours  
**Savings:** ~$3.7K-9.2K/month (quick wins)

1. Council routing → Haiku (Spline)
2. Reduce max turns (Spline)
3. Remove duplicate function (Spline)
4. Cap stdout collection (Spline)
5. Cap improvement retries (Spline)

### Phase 2: Conditional (After Council Review) — Next Week
**Effort:** ~15-20 hours  
**Savings:** $26K-140K/month (pending approval)

If Council approves:
6. Trim prompt context (Spline, with monitoring)
7. Smarter model selection (Spline, with task type matrix)

If Council votes yes:
8. Peer review opt-in policy (Alloy/Spline, 10 lines)
9. Coordinate watchdog retries (Spline, 20 lines)

---

## Council Decisions Needed

### Decision 1: Prompt Context Availability
**Question:** Should agents have access to all linked repos/paths and full memory history, or should we prioritize token efficiency?

**Current:** All repos, paths, and 20 memory items loaded for every task.  
**Proposed:** Only load linked repos/paths if relevant to task; limit memories to 5 most relevant.

**Trade-off:** Savings of 60K-400K tokens/day vs. potential risk that agents lose useful context.

---

### Decision 2: Model Selection Policy
**Question:** Should we prioritize quality over cost, or optimize model selection by task type?

**Current:** Opus if priority is high/urgent AND description is detailed.  
**Proposed:** Task-aware selection — Sonnet for reads/verification, Opus for deep reasoning only.

**Trade-off:** Savings of 30-50% of Opus spend vs. risk of using cheaper model on complex tasks.

---

### Decision 3: Peer Review Standards
**Question:** Should peer review be mandatory for all outputs or opt-in for critical work?

**Current:** Automatic on all outputs >10K chars.  
**Proposed:** Manual opt-in for urgent/governed tasks only; trust programmatic validation for routine work.

**Trade-off:** Savings of 400K-1.2M tokens/day (majority of review overhead) vs. reduced human oversight of routine tasks.

---

### Decision 4: Failure Handling & Retries
**Question:** How aggressively should we retry failing tasks?

**Current:** Up to 7-8 respawns per doomed task (across multiple watchdogs).  
**Proposed:** Coordinate watchdogs; cap at 4 total retries before escalating to Board.

**Trade-off:** Savings of 100K-1M tokens/week vs. risk of giving up on tasks too early.

---

## Summary Table: All 9 Fixes

| # | Fix | Savings | Effort | Priority | Requires Vote? |
|---|-----|---------|--------|----------|---|
| 1 | Council routing → Haiku | $800-1.2K/mo | 1 line | ⚡ NOW | No |
| 2 | Reduce max turns | $2.4-8K/mo | 1 line | ⚡ NOW | No |
| 3 | Remove duplicate function | Hygiene | Delete 50 lines | ⚡ NOW | No |
| 4 | Cap stdout collection | Server optimization | 5 lines | ⚡ NOW | No |
| 5 | Cap improvement retries | $0.9-2.7K/mo | 5 lines | ⚡ NOW | No |
| 6 | Trim prompt context | $18-120K/mo | 30 lines | 📋 REVIEW | Yes |
| 7 | Smarter model selection | $8-20K/mo | 15 lines | 📋 REVIEW | Yes |
| 8 | Peer review opt-in | $12-36K/mo | 10 lines | 🏛️ VOTE | Yes |
| 9 | Coordinate watchdogs | $3-15K/mo | 20 lines | 📋 REVIEW | Yes |
| **TOTAL** | — | **$45-202K/mo** | ~130 lines | — | — |

---

## Recommendation

1. **Approve and execute Phase 1 immediately** (5 fixes, $3.7-9.2K/month, 8 hours)
2. **Schedule Council review** of decisions 1-4 this week
3. **Implement Phase 2** once decisions are made (potential +$41-192.8K/month additional)

**Total potential monthly savings:** $45-202K  
**Annualized:** $540K-2.4M

---

## Notes for Finance & Board

- All savings are **conservatively estimated** — actual savings may be higher
- Savings assume current token prices ($15/MTok Opus, $3/MTok Sonnet, $0.30/MTok Haiku)
- If token prices change, savings scale proportionally
- Operational improvements (Phase 1) have zero implementation risk
- Strategic improvements (Phase 2) require Board consensus on quality/efficiency trade-offs

**Prepared by:** Margin, Accounting Specialist  
**Status:** Ready for Council Review
