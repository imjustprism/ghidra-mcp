# ghidra-mcp — Feature Shipping Tracker

Living checklist. Each unchecked feature ships on its own branch → PR for review, then gets checked off here. Detailed design in [docs/master-plan.md](docs/master-plan.md).

Legend: `[x]` shipped · `[~]` in progress (open PR) · `[ ]` planned · API status `[V]`erified / `[N]`eeds-verify / `[X]` extension-required.

---

## Baseline (on main)
- [x] Type & symbol auto-recovery cluster — `analyze_program`, `list_analyzers`, `set_analysis_option`, `apply_data_type`, `create_function`, `propagate_function_types`, `struct_set_field`, `struct_delete_field`
- [x] Master plan + competitive research (`docs/master-plan.md`)

## Phase 1 — Ergonomics & throughput
- [ ] `batch_set_prototype` + `batch_set_variable_type` + `batch_apply_data_type` — atomic multi-field editing `[V]`
- [ ] `function_summary_bundle` — one-call context pack (decompile + sig + callers + callees + strings + constants) `[V]`
- [ ] `set_variables` — atomic name+proto+all-locals on one function `[V]`
- [ ] Error envelope `{ok,value?,error?,hint?}` → MCP `isError` `[V]`
- [ ] Expose `fmt`/verbosity knob to the bridge `[V]`
- [ ] MCP progress notifications for long scans/analysis `[N]`

## Phase 2 — Protocol leap + type recovery
- [ ] MCP **resources** (subscribable live state: registers/stack/watch/scan) `[N]`
- [ ] MCP **prompts** (survey_binary, analyze_function, solve_crackme, triage_malware, recover_types) `[N]`
- [ ] Progressive disclosure (`list_tool_groups`/`search_tools`/`get_tool_schema`) `[N]`
- [ ] `function_completeness` scoring 0–100 `[V]`
- [ ] `find_next_undocumented` + self-driving loop `[V]`
- [ ] `apply_naming_convention` (PascalCase/Hungarian/snake) `[V]`
- [ ] `recover_rtti_classes` `[V]`
- [ ] `apply_fid_signatures` `[N]`
- [ ] `apply_gdt` / `list_data_type_archives` `[N]`
- [ ] `import_pdb` / `import_dwarf` `[N]`
- [ ] `propose_struct_from_accesses` — locate FillOutStructureCmd jar first `[X]`

## Phase 3 — Headless + scripting + live mastery
- [ ] Headless server host (no GUI) `[N]`
- [ ] Docker image `[N]`
- [ ] Script execution (`run_ghidra_script`/`run_script_source`/`list_scripts`) — gated `[N]`
- [ ] **P0 scanner rewrite** — Trace-DB reads, parallel, freshness tags `[N]`
- [ ] `pointer_scan` / `read_pointer_path` `[N]`
- [ ] Hardware watchpoints `break_read`/`break_write` `[N]`
- [ ] `watch_add`/`watch_poll`/`watch_remove` `[N]`
- [ ] Scan GC + freeze auto-stop `[V]`
- [ ] Time-travel: `list_snapshots`/`goto_snapshot`/`value_at_snapshot`/`find_last_write` `[N]`
- [ ] Persistent emulator `emu_start/step/run_to/...` + `emulate_function(args)` `[V]`

## Phase 4 — Differentiators
- [ ] `function_hash` + cross-binary multi-program (`open_program`/`select_program`, `program` param) `[N]`
- [ ] `diff_functions` / `diff_programs` (Version Tracking) `[X]`
- [ ] BSim: `bsim_index_program` / `bsim_query_function` / `bsim_query_program` `[X]`
- [ ] `propagate_matches` (copy names/types across matched binaries) `[N]`
- [ ] Z3 concolic: `solve_branch_constraints` / `find_path_to_address` `[X]`
- [ ] Taint: `taint_forward` / `taint_backward` `[N]`
- [ ] Coverage: `load_coverage` / `trace_to_coverage` / `coverage_report` / `coverage_diff` `[N]`
- [ ] Interactive HTML graph + `xref_graph`/`namespace_graph`/`dominator_tree`/`cfg_metrics` `[V]`
- [ ] Malware double-down: `unpack_assist`, `iat_rebuild`, `find_syscalls`, `decode_strings_auto`, `yara_scan`, `find_crypto_constants`, `find_anti_vm`, `cfg_obfuscation_score` `[N]`
- [ ] Optional Frida backend `[X]`

## Engineering hardening (alongside)
- [ ] File-IO sandbox + mutation audit log `[V]`
- [ ] Bound executor / program lock for off-EDT reads `[V]`
- [ ] `patch_bytes` opt-in disassembly + `search_bytes` cursor `[V]`
- [ ] Rust connect-vs-upstream error classification `[V]`
- [ ] README auto-gen from route table + handler/e2e tests `[V]`
