# Changelog

## 0.1.1 — 2026-05-01

### Fixed
- tree scanner: nested matches under a forbidden directory pattern now collapse into
  a single finding with a `child_count` evidence entry (resolves 6x duplication of
  `.venv/`, `node_modules/`, etc.).
- tree scanner: large-binary heuristic now defaults to `low` severity and skips
  common documentation prefixes (`docs/`, `assets/`, `public/`, `static/`, `media/`,
  `images/`, `img/`, `website/`). Override via `large_binary_skip_prefixes` in
  `.aftermath.toml`.

## 0.1.0 — 2026-04-20

Initial release. Read-only Git artifact scanner with branch, tree, reflog, and author scanners.
