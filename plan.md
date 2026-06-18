# ghidra-mcp — Feature Shipping Tracker

Living checklist. Each unchecked feature ships on its own branch → PR for review, then gets checked off here. Detailed design in [docs/master-plan.md](docs/master-plan.md).

Legend: `[x]` shipped · `[~]` in progress (open PR) · `[ ]` planned · API status `[V]`erified / `[N]`eeds-verify / `[X]` extension-required.

---

## Baseline (on main)
- [x] Type & symbol auto-recovery cluster — `analyze_program`, `list_analyzers`, `set_analysis_option`, `apply_data_type`, `create_function`, `propagate_function_types`, `struct_set_field`, `struct_delete_field`
- [x] Master plan + competitive research (`docs/master-plan.md`)

## Phase 1 — Ergonomics & throughput
- [x] `batch_set_prototype` + `batch_set_variable_type` — batch type editing
- [x] `batch_apply_data_type` — batch typed-data application
- [x] `function_summary_bundle` — one-call context pack (decompile + sig + callers + callees + strings)
- [x] `set_variables` — atomic name+proto+all-locals on one function
- [ ] Error envelope `{ok,value?,error?,hint?}` → MCP `isError` `[V]`
- [x] Expose `fmt`/verbosity knob to the bridge — `fmt` (tsv/csv/json/verbose) on every paginated read tool
- [ ] MCP progress notifications for long scans/analysis `[N]`

## Phase 2 — Protocol leap + type recovery
- [x] MCP **resources** (program info/current-function/current-address, live debugger status) — subscription/notifications still TODO
- [x] MCP **prompts** (survey_binary, analyze_function, solve_crackme, triage_malware, recover_types)
- [x] Progressive disclosure — `search_tools` + `get_tool_schema` (catalog introspection via the live tool router)
- [x] `function_completeness` scoring 0–100
- [x] `find_undocumented` — least-documented work queue
- [x] `apply_naming_convention` (snake/screaming_snake/camel/pascal, dry-run by default)
- [x] `recover_rtti_classes` — list recovered C++ classes + vftables + method counts
- [ ] `apply_fid_signatures` `[N]`
- [x] `list_data_type_archives` — list available type archives
- [x] `apply_gdt` — merge a .gdt type archive into the program (sandboxed path; shared FileGuard)
- [ ] `import_pdb` / `import_dwarf` `[N]`
- [ ] `propose_struct_from_accesses` — locate FillOutStructureCmd jar first `[X]`

## Phase 3 — Headless + scripting + live mastery
- [ ] Headless server host (no GUI) `[N]`
- [ ] Docker image `[N]`
- [ ] Script execution (`run_ghidra_script`/`run_script_source`/`list_scripts`) — gated `[N]`
- [ ] **P0 scanner rewrite** — Trace-DB reads, parallel, freshness tags `[N]`
- [x] `read_pointer_path` — multi-level pointer-chain resolver (CheatEngine-style); `pointer_scan` still TODO
- [x] `pointer_scan` — static reverse pointer scan (pointer-aligned, budgeted; feeds read_pointer_path)
- [ ] Hardware watchpoints `break_read`/`break_write` `[N]`
- [ ] `watch_add`/`watch_poll`/`watch_remove` `[N]`
- [x] Scan GC + freeze auto-stop — TTL eviction of abandoned completed scans (freeze already auto-stops on target death)
- [ ] Time-travel: `list_snapshots`/`goto_snapshot`/`value_at_snapshot`/`find_last_write` `[N]`
- [x] Persistent emulator — `emu_start/step/run_to/registers/set_register/read_memory/write_memory/close` (stateful sessions + TTL GC); `emulate_function(args)` done

## Phase 4 — Differentiators
- [x] `function_hash` — structural mnemonic/shape hash for matching/dedup
- [x] multi-program basics (`list_open_programs`, `select_program`)
- [ ] cross-binary `program` param / `open_program` from disk `[N]`
- [ ] `diff_functions` / `diff_programs` (Version Tracking) `[X]`
- [ ] BSim: `bsim_index_program` / `bsim_query_function` / `bsim_query_program` `[X]`
- [ ] `propagate_matches` (copy names/types across matched binaries) `[N]`
- [ ] Z3 concolic: `solve_branch_constraints` / `find_path_to_address` `[X]`
- [ ] Taint: `taint_forward` / `taint_backward` `[N]`
- [ ] Coverage: `load_coverage` / `trace_to_coverage` / `coverage_report` / `coverage_diff` `[N]`
- [x] `xref_graph` — Mermaid one-hop reference graph
- [x] `namespace_graph` — Mermaid namespace/class hierarchy
- [x] `cfg_metrics` — block/edge/cyclomatic/loop complexity
- [x] `dominator_tree` — immediate-dominator per basic block
- [x] Interactive HTML graph — `xref_graph_html` (self-contained, offline, pan/zoom/hover)
- [x] `find_crypto_constants` — AES/SHA/MD5 constant detection
- [x] `find_syscalls` — direct syscall/sysenter/int2e stub detection + SSN
- [x] `find_anti_vm` — VM/sandbox artifact string detection
- [x] `cfg_obfuscation_score` — CFG-flattening / obfuscation scoring
- [x] `decode_strings_auto` — brute-force single-byte XOR/ADD/SUB string recovery
- [x] `find_dynamic_api_resolution` — GetProcAddress/LoadLibrary/Ldr*/dlopen call sites
- [x] `unpack_assist` — packer/protector detection score (entropy + RWX + imports + packer sections)
- [ ] Malware double-down: `iat_rebuild`, `yara_scan` `[N]`
- [ ] Optional Frida backend `[X]`

## Engineering hardening (alongside)
- [x] File-IO sandbox — `import_memory_dump`/`export_binary` gated to an allow-listed dir (logged)
- [x] Bound executor — concurrent requests capped at CPU count (semaphore) to limit program access
- [x] `patch_bytes` opt-in disassembly + `search_bytes` cursor (next_cursor footer + start resume)
- [x] Rust connect-vs-upstream error classification (map_err: connect/timeout/4xx with hints)
- [x] README sync guard — tests assert tool count + every tool name match the live router catalog (caught 3 undocumented tools)
