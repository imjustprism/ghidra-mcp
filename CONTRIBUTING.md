# Contributing

Thanks for taking an interest in `ghidra-mcp`.

## Before you start

- Open an issue for large features or API changes so design can land first.
- Keep PRs focused: one concern per PR.
- Match the existing style. This codebase prefers **short, type-safe code** and **zero source comments** (names/types carry meaning; MCP and CLI help live in attributes / `clap` / `schemars`).

## Dev setup

1. Install **JDK 21**, **Maven 3.9+**, **Rust stable (≥ 1.85)**, and **Ghidra 12.1.2**.
2. Stage Ghidra jars:

   ```powershell
   cd plugin
   .\setup-libs.ps1 -GhidraHome "$env:GHIDRA_HOME"
   ```

3. Build:

   ```bash
   cargo build
   cd plugin && mvn -B package
   ```

## Checks (must pass)

```bash
# Rust
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked

# Optional license/advisory gate
cargo deny check

# Java
cd plugin && mvn -B test package
```

Windows full rebuild + extension install:

```powershell
$env:GHIDRA_HOME = "C:\path\to\ghidra_12.1.2_PUBLIC"
.\deploy.ps1
```

## Layout

| path | what lives here |
| --- | --- |
| `src/` | Rust MCP bridge (`tools.rs` is the tool surface) |
| `plugin/src/main/java/...` | Ghidra plugin + HTTP handlers |
| `plugin/src/test/java/...` | unit tests that do not need a live Ghidra UI |
| `ghidra-scripts/` | optional headless helpers |
| `tools/` | repo maintenance scripts |

## Adding a tool

1. Implement the HTTP handler / analysis helper in the Java plugin.
2. Register the route in the appropriate `*Handlers` class.
3. Expose the MCP tool in `src/tools.rs` with `#[tool(...)]` + `schemars` descriptions.
4. Update the tool tables in `README.md` if the public surface changed
   (`python tools/_gen_readme_tools.py` rewrites the `## Tools` section; unit tests enforce catalog sync).
5. Add unit tests where pure logic can be tested without Ghidra.

## What not to commit

- Build outputs (`target/`, `plugin/target/`, `plugin/lib/`, zips, jars, exes)
- Local agent/editor rules (`.rules`, `.claude/`, `.cursor/`, …)
- Secrets, tokens, personal absolute paths, machine-specific deploy defaults
- Design dump notes / personal scratch docs

See [`.gitignore`](.gitignore) and [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions are licensed under the **Apache License 2.0**, the same as the rest of this repository.
