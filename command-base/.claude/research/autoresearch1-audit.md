# Autoresearch1 — Deep Audit

**Date:** 2026-03-26
**Auditor:** Pax (Senior Researcher)
**Repo:** https://github.com/mstewartbz/autoresearch1
**Upstream:** https://github.com/karpathy/autoresearch (Andrej Karpathy)
**Local clone:** `/Users/maxstewart/Desktop/The Team/repos/autoresearch1`

---

## 1. What Is This Project?

Autoresearch is Andrej Karpathy's experiment in **fully autonomous AI-driven ML research**. The core premise: give an AI coding agent (Claude, Codex, etc.) a small but real LLM training setup, then let it run experiments *autonomously* — modifying code, training, evaluating, keeping or discarding results — while the human sleeps.

Max's repo is a **direct fork** of `karpathy/autoresearch` (59,400 stars, 8,234 forks as of today). The fork appears unmodified from upstream — no custom branches, no divergent commits. It's a clean copy ready for experimentation.

The project is deliberately minimalist: 3 files, 1 GPU, 1 metric, 1 file the agent edits. Everything runs in a tight 5-minute training loop. The agent is instructed to loop forever, trying architecture/hyperparameter changes, keeping improvements and discarding regressions.

---

## 2. Complete File Inventory

| File | Lines | Purpose | Editable? |
|------|-------|---------|-----------|
| `train.py` | 630 | GPT model, optimizer (MuonAdamW), training loop, hyperparameters | **YES** (agent only) |
| `prepare.py` | 389 | Data download, BPE tokenizer training, dataloader, evaluation harness | NO (read-only) |
| `program.md` | 114 | Agent instructions — the "skill file" that programs the AI researcher | YES (human only) |
| `pyproject.toml` | 27 | Dependencies and UV config | NO |
| `analysis.ipynb` | ~120 | Jupyter notebook for visualizing experiment results | Utility |
| `progress.png` | - | Sample progress chart (83 experiments, 15 kept improvements) | Output |
| `.python-version` | 1 | Python 3.10 | Config |
| `.gitignore` | 24 | Ignores results.tsv, .venv, CLAUDE.md, dev/ | Config |

**Total codebase: ~1,133 lines across the 3 core files.**

---

## 3. Technology Stack

| Layer | Technology | Version/Details |
|-------|-----------|-----------------|
| Language | Python | 3.10+ |
| Package manager | uv | Astral's fast Python package manager |
| Deep learning | PyTorch | 2.9.1 (CUDA 12.8) |
| Flash Attention | kernels (FA3) | `varunneal/flash-attention-3` (Hopper) or `kernels-community/flash-attn3` (other NVIDIA) |
| Tokenizer training | rustbpe | Rust-based BPE tokenizer |
| Tokenizer runtime | tiktoken | OpenAI's tokenizer library |
| Data format | Parquet | Via pyarrow |
| Numerics | NumPy | 2.2.6+ |
| Analysis | pandas + matplotlib | For results visualization |
| Data source | HuggingFace | `karpathy/climbmix-400b-shuffle` dataset |
| AI Agent | Claude/Codex | Any coding agent that can read `program.md` |
| Precision | bfloat16 | Mixed precision via torch.amp |

---

## 4. End-to-End Workflow / Pipeline

### Phase 1: One-Time Setup
```
uv sync                    # Install dependencies
uv run prepare.py          # Download data shards + train BPE tokenizer
```
- Downloads parquet shards from HuggingFace (`climbmix-400b-shuffle`)
- Trains a BPE tokenizer (8,192 vocab size) using `rustbpe`
- Saves to `~/.cache/autoresearch/`

### Phase 2: Agent Setup
```
User prompts agent: "Read program.md and let's kick off a new experiment!"
```
Agent then:
1. Agrees on a run tag (e.g., `mar26`)
2. Creates branch `autoresearch/<tag>`
3. Reads all 3 core files for context
4. Verifies data exists in `~/.cache/autoresearch/`
5. Initializes `results.tsv` (header only)
6. Runs baseline `train.py` (unmodified, 5 min)

### Phase 3: Autonomous Experiment Loop (RUNS FOREVER)
```
LOOP:
  1. Review current git state and past results
  2. Conceive an experimental idea (architecture, hyperparameters, optimizer, etc.)
  3. Edit train.py to implement the idea
  4. git commit the change
  5. Run: uv run train.py > run.log 2>&1  (5-minute fixed time budget)
  6. Extract val_bpb from run.log
  7. If improved → KEEP (advance branch)
     If worse → DISCARD (git reset to previous commit)
     If crashed → log crash, attempt fix or skip
  8. Log result to results.tsv
  9. GOTO 1 (never stop, never ask human)
```

### Phase 4: Human Reviews Results
- Human wakes up to `results.tsv` with ~100 experiments logged
- Run `analysis.ipynb` to visualize progress
- The git branch contains only the successful improvements (clean history)

---

## 5. Key Features

### 5.1 The GPT Architecture (in train.py)
- **Transformer-based GPT model** with configurable depth, width, heads
- **Grouped Query Attention (GQA)** — `n_kv_head` can differ from `n_head`
- **Flash Attention 3** via the `kernels` library — auto-detects Hopper vs. other NVIDIA GPUs
- **Rotary Position Embeddings (RoPE)** with configurable base frequency
- **Value Embeddings (ResFormer)** — alternating layers get input-dependent value residuals with gated mixing
- **Sliding Window Attention** — configurable pattern (e.g., `SSSL` = 3 short-window layers + 1 full-context layer)
- **RMS Normalization** throughout
- **ReluSquared activation** in MLP (not GELU — `F.relu(x).square()`)
- **Logit soft-capping** at 15 to prevent explosion
- **Residual stream scaling** — per-layer learnable `resid_lambdas` and `x0_lambdas` (skip connection to initial embeddings)

### 5.2 The Optimizer (MuonAdamW)
A hybrid optimizer combining two strategies:
- **Muon** for 2D matrix parameters — uses Nesterov momentum + "Polar Express" orthogonalization (Newton-Schulz iterations) + NorMuon variance reduction + cautious weight decay
- **AdamW** for everything else — embeddings, unembeddings, scalars, value embeddings
- Separate learning rates per parameter group (6 distinct groups)
- Learning rate scaled proportionally to `1/sqrt(model_dim/768)`
- All compiled with `torch.compile` for performance

### 5.3 Training Configuration
| Parameter | Default Value |
|-----------|---------------|
| DEPTH | 8 layers |
| ASPECT_RATIO | 64 (model_dim = depth * 64) |
| HEAD_DIM | 128 |
| TOTAL_BATCH_SIZE | 524,288 tokens (~512K) |
| DEVICE_BATCH_SIZE | 128 |
| MAX_SEQ_LEN | 2,048 |
| TIME_BUDGET | 300 seconds (5 minutes) |
| VOCAB_SIZE | 8,192 (from tokenizer) |
| Precision | bfloat16 |

### 5.4 Learning Rate Schedule
- Warmup: configurable ratio (default 0%)
- Constant phase in the middle
- Warmdown: 50% of budget by default, cosine decay to 0
- Muon momentum ramps from 0.85 to 0.95 over first 300 steps
- Weight decay decays linearly to 0

### 5.5 The Agent Protocol (program.md)
- **NEVER STOP** — the agent runs indefinitely until manually interrupted
- **Keep/Discard/Crash** decision framework
- **results.tsv** as structured experiment log (TSV, 5 columns)
- **Git-based experiment tracking** — each experiment is a commit, branch advances only on improvement
- **Simplicity criterion** — improvements that add ugly complexity are rejected; simplifications are celebrated
- **VRAM is a soft constraint** — some increase OK for meaningful gains
- **10-minute kill timeout** if a run hangs

### 5.6 Analysis Notebook
- Loads `results.tsv`
- Plots val_bpb over time with running minimum frontier
- Labels each kept experiment with its description
- Shows hit rate (kept vs. total experiments)
- Ranks improvements by delta magnitude

---

## 6. How It Automates Research

The automation is NOT in the Python code — it's in the **agent instructions** (`program.md`). The repo is a "skill" that any AI coding agent can execute:

1. **The agent reads `program.md`** as its operating manual
2. **The agent reads `train.py` and `prepare.py`** for full context on the model and constraints
3. **The agent generates hypotheses** about what might improve val_bpb (architecture changes, LR tuning, optimizer tweaks, etc.)
4. **The agent implements each hypothesis** by editing `train.py`
5. **The agent evaluates** by running training and reading the metric
6. **The agent makes keep/discard decisions** based on val_bpb comparison
7. **The agent tracks everything** in git commits and results.tsv

The human's role is to:
- Write/iterate on `program.md` (the "research org code")
- Launch the agent and walk away
- Review results when they come back

This is a paradigm shift: **you're not writing ML code, you're programming the AI that writes ML code.**

---

## 7. APIs and External Services

| Service | Purpose | How Used |
|---------|---------|----------|
| HuggingFace Datasets | Training data | Downloads parquet shards from `karpathy/climbmix-400b-shuffle` |
| kernels (PyPI) | Flash Attention 3 kernels | `get_kernel()` fetches precompiled CUDA kernels from HuggingFace repos |
| Git/GitHub | Experiment tracking | Branch-per-run, commit-per-experiment |
| Claude/Codex/etc. | The AI agent | Reads program.md, edits train.py, runs experiments |

**No API keys needed.** Everything is open-source/open-data. The AI agent is provided by whatever coding tool the user runs (Claude Code, OpenAI Codex CLI, etc.).

---

## 8. Output Format

### Per-Experiment Output (stdout → run.log)
```
---
val_bpb:          0.997900
training_seconds: 300.1
total_seconds:    325.9
peak_vram_mb:     45060.2
mfu_percent:      39.80
total_tokens_M:   499.6
num_steps:        953
num_params_M:     50.3
depth:            8
```

### Cumulative Results (results.tsv)
Tab-separated, 5 columns:
```
commit    val_bpb     memory_gb   status    description
a1b2c3d   0.997900    44.0        keep      baseline
b2c3d4e   0.993200    44.2        keep      increase LR to 0.04
```

### Visual Output (progress.png via analysis.ipynb)
A scatter plot showing all experiments with:
- Green dots for kept improvements
- Gray dots for discarded experiments
- Step line showing running best (frontier)
- Annotations describing each kept change

---

## 9. Evidence from the Progress Chart

The included `progress.png` shows a **real run of 83 experiments with 15 kept improvements**:

| Experiment | val_bpb | Description |
|-----------|---------|-------------|
| Baseline | ~0.998 | Starting point |
| #2 | ~0.991 | Halve total batch 524K→262K (more steps) |
| #4 | ~0.990 | Warmdown 0.5→0.7 (more cooldown) |
| #7 | ~0.989 | Add 5% warmup |
| #9 | ~0.987 | (unlabeled) |
| ~#15 | ~0.985 | Depth 9, aspect ratio 57 |
| ~#20 | ~0.984 | x0_lambda init 0.1→0.05 |
| ~#25 | ~0.983 | Unembedding LR 0.004→0.008 |
| ~#30 | ~0.982 | SSSSSL window pattern |
| ~#35 | ~0.981 | Short window 1/4 context |
| ~#40 | ~0.980 | Short window 1/8 context (256 tokens) |
| ~#45 | ~0.979 | Embedding LR 0.6→0.8 |
| ~#63 | ~0.978 | RoPE base frequency 10000→50000 |
| ~#65 | ~0.978 | RoPE base frequency 50000→100000 / 200000 |
| ~#75 | ~0.977 | Random seed 42→137 |

**Total improvement: ~0.021 BPB (2.1% relative) across 83 autonomous experiments.**

Key observations:
- Most gains came from batch size, schedule, and architecture (depth/width) changes
- Later gains came from fine-tuning RoPE frequency and window patterns
- The hit rate for improvements: 15/83 = 18% — most experiments don't help
- The agent found non-obvious improvements like changing RoPE base frequency by 5-20x

---

## 10. Adaptation Opportunities for The Team Dashboard

### 10.1 Direct Integration — "Autonomous Research Agent" Widget
The autoresearch paradigm could power an autonomous research capability within The Team:
- **Task type: "autonomous-research"** — a long-running background task
- Gray delegates to Pax or a specialized ML subagent
- The subagent reads a `program.md`-style skill file and runs experiments
- Results stream into the dashboard in real-time

### 10.2 The "Skill File" Pattern
`program.md` is a powerful pattern we could adopt broadly:
- **Each team member gets skill files** that define their autonomous operating procedures
- Instead of Gray giving step-by-step instructions every time, members read their skill files
- Skill files are human-editable markdown that programs AI behavior
- This is already partially what the team profiles (`pax.md`, `lumen.md`, etc.) do — but `program.md` shows how to make them much more operational (with explicit loops, decision criteria, logging formats)

### 10.3 Experiment Tracking in the Database
The `results.tsv` pattern maps directly to our SQLite database:
- New table: `experiments` (id, task_id, commit_hash, metric_name, metric_value, status, description, created_at)
- Track autonomous AI experiments the same way we track tasks
- Dashboard widget showing experiment progress charts (like `analysis.ipynb` but live)

### 10.4 The Keep/Discard Decision Framework
The binary keep/discard + git reset pattern is applicable beyond ML:
- **Any iterative improvement task** could use this: code optimization, prompt engineering, design iteration
- The agent tries something, measures it against a metric, keeps or discards
- Git provides the rollback mechanism
- This could be a general-purpose "autonomous iteration" mode for any team member

### 10.5 Requirements for Running Autoresearch
If Max wants to actually run this:
- **Hardware:** Single NVIDIA GPU required (H100 ideal, but forks exist for Mac/AMD/Windows)
- **No Mac support in this fork** — would need one of the notable forks (miolini/autoresearch-macos or trevin-creator/autoresearch-mlx) for Apple Silicon
- **Time commitment:** Each run is 5 minutes, but the whole point is to leave it running overnight (100+ experiments)
- **Cost:** Only compute cost — no API keys, no paid services
- **Agent cost:** The AI agent itself (Claude Code, Codex, etc.) has its own cost for the coding agent session

### 10.6 "Research Dashboard" Concept
A potential dashboard feature that borrows from autoresearch:
- **Live experiment feed** — shows what the autonomous agent is currently trying
- **Progress chart** — real-time updating version of progress.png
- **Results table** — sortable/filterable version of results.tsv
- **Agent logs** — streaming view of what the agent is thinking/doing
- **Controls** — start/stop/pause the research loop, set constraints
- **Multi-agent view** — run multiple research streams in parallel (different seeds, different starting points)

### 10.7 Broader "AutoX" Pattern
Autoresearch proves a general pattern: **AI agent + fixed evaluation metric + autonomous loop = overnight results**. This could be applied to:
- **AutoPrompt** — agent iterates on prompt engineering with A/B metrics
- **AutoDesign** — agent iterates on CSS/layout with user satisfaction scores
- **AutoSEO** — agent iterates on content with search ranking signals
- **AutoTest** — agent writes tests, runs them, keeps passing ones, discards failing attempts
- Any domain where you can define a clear metric and give the agent freedom to iterate

---

## 11. Strengths of the Codebase

1. **Radical simplicity** — 3 files, 1 GPU, 1 metric. No configs, no CLI flags, no distributed training
2. **Self-contained** — no external services beyond data download. Everything runs locally
3. **Clean separation** — fixed evaluation (prepare.py) vs. mutable experiment (train.py) vs. agent instructions (program.md)
4. **State-of-the-art techniques** — Flash Attention 3, Muon optimizer, Value Embeddings (ResFormer), RoPE, sliding window attention, logit soft-capping
5. **Reproducible** — fixed time budget means experiments are directly comparable
6. **Git-native tracking** — experiment history is the git history
7. **Human-readable agent protocol** — program.md is plain English, easy to modify and iterate on

## 12. Risks and Limitations

1. **NVIDIA-only** — requires CUDA GPU. No Mac/CPU support in this fork
2. **No safety rails** — the agent can make train.py do anything (within Python/PyTorch). No sandboxing beyond "disable all permissions" advice
3. **Single metric** — val_bpb is the only objective. No multi-objective optimization
4. **No distributed training** — single GPU only
5. **Context window risk** — if the agent's context fills up with experiment logs, it may lose track of what it's tried
6. **No persistent memory** — the agent starts fresh each session (though results.tsv provides some continuity)
7. **Cost uncertainty** — an overnight Claude Code session could be expensive depending on usage

---

## 13. Summary

Autoresearch is Karpathy's proof-of-concept for **AI agents doing ML research autonomously**. It's elegant in its simplicity: a 630-line training script, a 389-line evaluation harness, and a 114-line markdown file that programs the AI researcher. The agent edits code, trains models, evaluates results, and makes keep/discard decisions — all without human intervention.

Max's fork is a clean copy of the upstream repo. It has not been modified yet. The included progress chart shows what a real run looks like: 83 experiments, 15 kept improvements, ~2% BPB improvement achieved overnight.

For The Team, the most valuable takeaway is not the ML code itself — it's the **autonomous agent loop pattern** and the **skill file paradigm**. These could be adapted into a general-purpose "autonomous iteration" capability for any team member working on any measurable optimization task.
