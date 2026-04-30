# Contributing to aftermath

v0.1 is a PoC. The most useful contributions right now:

## Good first contributions

- **Scan your own repos and open an issue** with interesting / false-positive findings.
- **Add a `.aftermath.toml` preset** for a framework you know (Django / Next.js / Terraform).
- **Write an integration test** that synthesizes a polluted repo and asserts findings.

## v0.1.x — help wanted

- Implement `reflog_scanner` (scan `git reflog` for AI-authored commits not on any branch).
- Implement `author_scanner` (commit author distribution analysis).
- Add a `--baseline <file>` flag to ignore previously-acknowledged findings.
- `.aftermath.toml` schema validation with clap-verbosity.

## Development

```sh
git clone https://github.com/chaosreload/aftermath
cd aftermath
cargo test
cargo fmt --check
cargo clippy -- -D warnings
cargo build --release
./target/release/aftermath scan /path/to/polluted/repo
```

## Commits

Use conventional commits:

- `feat(scanner/branch): add X`
- `fix(tree): handle Y`
- `docs(readme): Z`

One scanner per commit where possible. Keep commits under ~300 LOC.

## Code of conduct

Be kind. Be precise. If you find a bug, open an issue with a minimal repro. If you're not sure, ask.

## License

By contributing you agree your work is licensed under MIT.
