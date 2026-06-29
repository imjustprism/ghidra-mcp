# Master Upgrade + Merge Plan (2026-06-29)

Goal: upgrade every tool to next-gen using existing engine primitives (MBA-deobf + opaque-pred
engine, write-tracking emulator, taint, live plane, protector/VM analysis, constraint extraction),
and merge overlapping tools into fewer, more powerful ones. Current count: **199**.

> GUARDRAILS for every merge: merges are **breaking API changes**. Do them in one batch (Phase B),
> update README tables in the same commit, and keep `readme_tool_count_matches_catalog` and
> `every_tool_has_a_readme_table_row` GREEN. After Phase B re-state the new total in README §Tools.
> Additive upgrades (Phase A/C) must not change a tool's name/required params unless noted.

---

## Phase A — Additive next-gen upgrades (NO API break) — do first

Each adds an opt-in flag/output column; default behavior unchanged. Risk: Low unless noted.

- [ ] `decompile_minimal` gains `deobf=true`: auto-run MBA `simplify_expression` + opaque-pred pruning
      (`find_opaque_predicates`) + `idiom_simplifier` comments inline. Reuses deobf engine. Risk: Med.
- [ ] `list_strings` gains `include=defined|stack|encoded|decoded|all`: folds `find_stack_strings`,
      `find_encoded_strings`, `recover_decoded_strings` into one stream w/ a `kind` column. Risk: Med.
- [ ] `get_xrefs_from`/`get_function_xrefs` gain `resolve_indirect=true`: resolve vtable/callback/
      dispatch targets via `vtable_scan` + emulator single-step of the indirect site. Risk: Med (live/emu).
- [x] `make_signature` gains `mode=bytes|semantic`: semantic = emulate on N fixed input vectors, hash
      outputs+tracked-writes (write-tracking emulator) → recompile-robust fingerprint. Risk: Med.
- [ ] `diff_functions`/`diff_programs`/`function_hash` gain `mode=structural|semantic`: semantic I/O
      hash via emulation (matches across instruction-substitution). Reuses `emulate_function`. Risk: Med.
- [ ] `propose_struct_from_accesses` gains `probabilistic=true`: OSPREY-lite weighted field-type MAP
      (size/sign/arith-vs-deref/xref). Risk: Low.
- [ ] `search_bytes`/`find_signature` gain `from_decompiler=ADDR`: derive an AOB straight from the
      instruction bytes at a decompiler line (AOB-from-decompiler). Risk: Low.
- [ ] `find_opaque_predicates` gains `prove=true`: concolic confirmation via `extract_constraints` →
      z3 (through `ghidra_eval`/python); UNSAT one side ⇒ proven ⇒ optional auto-patch. Risk: Med (z3 dep).
- [ ] `neutralize_anti_debug` gains `vectors=api|tls|seh|timing|all`: taint TLS/SEH/rdtsc/CPUID sinks
      and patch benign. Reuses `list_tls_callbacks` + taint. Risk: Med (needs sample to verify).
- [ ] `recover_decoded_strings` gains `annotate=true`: write plaintext as decompiler comments at each
      caller xref (FLOSS-annotate). Risk: Low.
- [ ] `function_completeness`/`find_undocumented` gain `exclude_libs=true`: filter FID/lib matches so the
      14k queue collapses to the app's own code. Pairs with `apply_fid_signatures`. Risk: Low.
- [ ] `emulate_function` gains `api_stubs=true`: canned returns for common imports (alloc→scratch ptr)
      so more decoders complete without the live plane. Risk: Med.
- [ ] `extract_constraints` gains `solve=true`: SMT-solve to a success path (concolic `solve_check`).
      Crackme/license ROI. Risk: Med (z3 dep, path explosion on loops — flag it).
- [ ] Cross-cutting: every read tool already has `fmt`/`offset`/`limit`/`program`; audit the few that
      lack `fmt` and backfill. Add a consistent `hint` field to error payloads (e.g. taint
      "nearest modeled op @X"). Risk: Low.

---

## Phase B — Merges (BREAKING; do together + README sync in same commit)

For each: new name, absorbed tools, selector param, gain. Net reduction noted.

- [ ] **`decompile`** ← `decompile_function` + `decompile_function_by_address` + `decompile_minimal`.
      Selector: accepts `name|address`; flags `clean`, `deobf`. Gain: one entry point, deobf built in.
      **−2**.
- [x] **`rename`** ← rename_function + rename_function_by_address + rename_data + rename_variable.
      Selector: `kind=function|data|variable` (+ accepts name|address for function). Gain: one rename
      verb. **−3**.
- [x] **`xrefs`** ← get_xrefs_to + get_xrefs_from + get_function_xrefs. Selector:
      `direction=to|from|both`, target=name|address. Gain: directionally symmetric, `resolve_indirect`.
      **−2**.
- [x] **`callgraph`** ← `callgraph` + `callgraph_dot`. Selector: `fmt=mermaid|dot` (fold into existing
      `fmt`). **−1**.
- [x] **`xref_graph`** ← `xref_graph` + `xref_graph_html`. Selector: `fmt=mermaid|html`. **−1**.
- [ ] **`search`** ← `search_bytes` + `find_string` + `find_signature`. Selector:
      `kind=bytes|string|signature` (sig dialect stays a sub-param). Gain: one search surface,
      cursor-resumable, `from_decompiler`. **−2**.
- [ ] **`emu_session`** ← `emu_step` + `emu_run_to` + `emu_registers` + `emu_set_register` +
      `emu_read_memory` + `emu_write_memory` + `emu_close`. Selector: `op=step|run_to|regs|setreg|read|
      write|close` on an `emu_id`. Keep `emu_start` separate (it returns the id). Gain: 7→1 verbs on a
      session handle. **−6**. (Skeptical: only do if clients tolerate a verb-dispatch tool; otherwise keep.)
- [x] **`coverage`** ← `coverage_report` + `coverage_diff` + `trace_to_coverage`. Selector:
      `op=report|diff|from_trace`. **−2**.
- [x] **`struct_field`** ← `struct_set_field` + `struct_delete_field`. Selector: `op=set|delete`. **−1**.
- [x] **`freeze`** ← `freeze_value` + `unfreeze_value` + `list_frozen`. Selector: `op=on|off|list`. **−2**.
- [x] **`scan`** ← `value_scan` + `next_scan` + `scan_results` + `scan_close`. Selector:
      `op=first|next|results|close` on a `scan_id`. CE-style lifecycle in one tool. **−3**.
- [x] **`list_functions`** ← absorbs `list_methods` via with_address. These are near-dupes (names vs
      names+addresses). Merge to `list_functions` with `with_address=true|false`; drop `list_methods`. **−1**.

**Total reduction if all done: ~26 tools (199 → ~173).** Conservative subset (skip emu_session/scan
verb-dispatch): ~13 (199 → ~186).

### DON'T-MERGE (flag — would hurt usability)

- `read_bytes` vs `hex_dump` — different output contracts (raw hex vs formatted). Keep distinct.
- `set_decompiler_comment` vs `set_disassembly_comment` — distinct comment planes; a `kind` param is
  more error-prone than two clear verbs.
- The `batch_*` family (`batch_rename`/`batch_set_comment`/`batch_set_prototype`/
  `batch_set_variable_type`/`batch_apply_data_type`) — each takes a different payload schema;
  collapsing to one `batch(op,...)` makes the schema a union and worse to call. Keep separate. (Could
  add a single `apply_changes` orchestrator later, additively.)
- `debugger_*` (live) vs `emu_*` (emulated) vs `live_*` (CE plane) — three different execution
  backends. Do NOT merge across backends; only merge within a backend (emu_session above).
- `taint_forward` vs `taint_backward` — could be one `taint(direction=)`, but the two are conceptually
  crisp and heavily used; merging buys little. LOW priority, defer.
- `import_dwarf`/`import_pdb`/`apply_fid_signatures`/`import_c_header`/`apply_gdt` — distinct sources/
  formats; a `source=` union obscures required params. Keep.

---

## Phase C — Deeper novel upgrades (build on engine; some need dep/target)

- [ ] **`analyze_virtualization` → `vm_dispatcher_map` + `vm_handler_summary`** (D1/D2): enumerate
      handler table + per-handler effect via emu fuzz/diff. Needs a live/decompressed VM target. Risk: High.
- [ ] **`cfg_obfuscation_score` → `unflatten_function`** (O4): dispatcher+state-var via taint, emulate
      each block to next-state → recovered edge map (comments first). Needs OLLVM target. Risk: High.
- [ ] **`recover_rtti_classes`/`propagate_function_types` → cross-call type unification** (arg↔param
      equality graph). Reuses propagate. Risk: Med.
- [ ] **`find_crypto_constants` → crypto-primitive ID** by data-flow-graph shape (Feistel/SPN) +
      const set; key/IV extraction via taint+emu at the call boundary (live plane for runtime keys). Risk: High.
- [ ] **Grounded rename** layer: `function_summary_bundle` evidence → LLM names → ACCEPT only if the
      name references a string/import actually used (verify-gate) → `batch_rename`. Needs LLM wiring. Risk: Med.
- [ ] **`unpack_assist` → `unpack_dump_live`** (Y4): live_attach → run past unpack stub → dump →
      `import_memory_dump`. Sidesteps emulator step ceiling. Needs running target. Risk: Med.
- [ ] **Pass-framework backbone** (docs/re-engine-design.md §0): land `ExprIR`/`ExprNormalizer`/
      `AnalysisPass`/`PassManager`/`KnowledgeBase`/`EquivalenceChecker` (MBA + opaque-pred already use
      the checker). Expose **`list_passes` / `run_pass` / `query_ir` + `deobfuscate_function`** preset.
      New passes register once, reachable with zero new wiring. Risk: High (architectural). Do after a
      flattened/VM verification target exists.

---

## Cross-cutting next-gen

- [ ] Unifying **analysis-pass layer**: route `decompile deobf`, `unflatten_function`, `vm_*`,
      `mba/opaque` through one `PassManager` so they compose to a fixpoint and persist facts in a
      `KnowledgeBase` (project user-data), projected via `analysis_note`.
- [ ] Consistent **error hints** everywhere (nearest-address suggestions, "run analyze_program first",
      "needs live target"). Reuse the taint-snap pattern.
- [ ] Confirm `fmt`/pagination/`program` on 100% of read tools (most already have it).

---

## Execution order

1. Phase A items (additive, ship continuously, no README count change).
2. Phase B as ONE batch + README table + count-test fix.
3. Phase C gated on deps (z3-via-ghidra_eval, LLM) and verification targets (OLLVM/VMP sample,
   running process).
