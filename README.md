# aftermath

> Scan Git repos for AI-agent footprints — abandoned branches, polluted trees, suspicious commits.

**v0.1 — Git artifact scanner. Read-only. Single binary.**

---

## What it does

AI coding agents (Claude Code, Codex, Cursor, Aider, OpenClaw…) leave behind **structural side-effects** that no existing tool catches:

- **Git branches** that were an experiment and never cleaned up (`claude/refactor-attempt-3`)
- **Trees polluted by `git add -A`** — `.venv/`, `node_modules/`, `PR-*-description.md` drafts, `.env` leaks, symlinks
- **Commits authored by AI** that drift away from `main`

`aftermath` walks your repo and reports these with an evidence chain, a severity, and (when safe) a suggested command. It **never modifies your repo in v0.1.**

## Positioning

The "AI cleanup" space has been getting crowded (Apr 2026):

| Layer | What | Who does it |
|-------|------|-------------|
| L1 | Local caches / zombie processes / disk pressure | [brege/agent-janitor](https://github.com/brege/agent-janitor), [zclean](https://github.com/TheStack-ai/zclean), [storage_ballast](https://github.com/Dicklesworthstone/storage_ballast_helper) |
| L2 | Code slop (empty functions, fake docs, junk comments) | [deslop](https://github.com/agent-sh/deslop), [sloppy](https://github.com/braedonsaunders/sloppy), [AI-SLOP-Detector](https://github.com/flamehaven01/AI-SLOP-Detector) |
| **L3** | **Git artifacts / cloud resources / account behavior** | **`aftermath` (this repo)** |

`aftermath` **does not** compete with L1 or L2. We scan the things they don't.

## Install

```sh
# From source (v0.1 — no crates.io release yet)
cargo install --git https://github.com/chaosreload/aftermath
```

Or clone + build:

```sh
git clone https://github.com/chaosreload/aftermath
cd aftermath
cargo build --release
./target/release/aftermath --version
```

Requirements: Rust 1.93+. libgit2 is vendored; no system library needed.

## Usage

```sh
# Write default config (optional)
aftermath init

# Scan current repo
aftermath scan

# Scan a specific path
aftermath scan /path/to/repo

# Only run one scanner
aftermath scan --kind=tree
aftermath scan --kind=branch

# Different output formats
aftermath scan --format=json
aftermath scan --format=markdown > aftermath.md

# Filter by severity
aftermath scan --min-severity=high

# Explain a finding by id
aftermath scan --format=json > .aftermath/last-report.json
aftermath explain aft-git-084efa --report .aftermath/last-report.json
```

## Example output

```
$ aftermath scan
aftermath: 3 findings

  [aft-git-084efa] high     tree       Forbidden path tracked in repo: '.venv' (matches '.venv/')
  [aft-git-cefb98] low      tree       Forbidden path tracked in repo: 'PR-694-description.md' (matches 'PR-*-description.md')
  [aft-git-70bd56] low      branch     Local branch 'claude/refactor-attempt': 0d old, behind default by 1 commits
```

Each finding ships with a deterministic id (stable across runs), an evidence chain, and a suggested action:

```json
{
  "id": "aft-git-084efa",
  "scanner": "tree",
  "severity": "high",
  "locator": ".venv",
  "title": "Forbidden path tracked in repo: '.venv' (matches '.venv/')",
  "evidence": [
    {"type": "path",            "value": ".venv"},
    {"type": "matched_pattern", "value": ".venv/"},
    {"type": "seen_in",         "value": "HEAD"},
    {"type": "filemode_octal",  "value": "40000"}
  ],
  "suggested_action": {
    "kind": "safe_to_delete",
    "reason": "'.venv' is a well-known artifact; safe to remove from tracking.",
    "suggested_command": "git rm --cached -r '.venv' && echo '.venv' >> .gitignore"
  }
}
```

## Configuration

Drop a `.aftermath.toml` in your repo root. See `aftermath init` for defaults. Highlights:

```toml
[branch_scanner]
ai_prefixes = ["claude/", "codex/", "agent/", "aider/", "openclaw/", "ai-"]
ai_emails   = ["noreply@anthropic.com", "noreply@openai.com"]
stale_days  = 30

[tree_scanner]
patterns = [
  { pattern = ".venv/",              severity = "high",     action = "safe-to-delete" },
  { pattern = "node_modules/",       severity = "high",     action = "safe-to-delete" },
  { pattern = ".env",                severity = "critical", action = "review" },
  { pattern = "PR-*-description.md", severity = "low",      action = "report" },
]
max_tracked_bytes = 1048576   # flag anything bigger (binary heuristic)
flag_symlinks     = true
recent_commits    = 20
```

## Why v0.1 is tiny

This is a deliberate PoC. Ship small → validate on real repos → let contributor ideas pick the roadmap.

v0.1 scope:
- ✅ `branch_scanner` — AI-prefix / stale / behind-main detection
- ✅ `tree_scanner` — `.gitignore`-style patterns + size + symlink checks
- ⏳ `reflog_scanner` — AI commits discoverable only via reflog (v0.1.x)
- ⏳ `author_scanner` — commit author distribution analysis (v0.1.x)

Roadmap:
- **v0.2** — cloud resource scanner (AWS Lambda / IAM / S3)
- **v0.3** — `aftermath apply` (with confirmations) + OpenClaw skill packaging

See [spec](https://github.com/chaosreload/aftermath/blob/main/SPEC.md) (to be added).

## Design principles

Lifted from [Jeff Emanuel's storage_ballast](https://github.com/Dicklesworthstone/storage_ballast_helper):

1. **Safety before aggressiveness.** v0.1 is read-only. Period.
2. **Predict, then act.** Findings carry impact estimates (size, behind-count, author).
3. **Deterministic decisions.** Same input → same finding id.
4. **Explainability mandatory.** Every finding has an evidence chain.
5. **Fail conservative.** Unsure? Report only.

## Acknowledgements

- **[brege/agent-janitor](https://github.com/brege/agent-janitor)** — `.gitignore`-style manifest inspiration. Brege occupies the name first and did it right for L1; we sit adjacent.
- **[Jeff Emanuel's storage_ballast](https://github.com/Dicklesworthstone/storage_ballast_helper)** — the engineering philosophy crib-sheet.
- **[`flamehaven01/AI-SLOP-Detector`](https://github.com/flamehaven01/AI-SLOP-Detector)** (involuntarily) — motivated us to be explicit that we do *not* score code quality, that's a different problem.

## License

MIT. See [LICENSE](LICENSE).
