# ghidra-mcp — Deep Audit & Next-Gen Plan

Scope: full read of the Rust bridge (`src/`, 2340 LOC) and the Ghidra Java plugin (`plugin/src/main`, ~5400 LOC), plus deepwiki/web research on Ghidra 11.3–12.x and competing RE MCPs. Goal: a concrete path from "solid static + working debugger" to a category-defining RE MCP.

Today: 104 Rust tools, 102 plugin routes. Two tiers — `rmcp` stdio bridge to a localhost HTTP plugin running `com.sun.net.httpserver` on virtual threads, with Ghidra access marshalled to the Swing thread inside transactions.

---

## 1. Architecture verdict

Clean, disciplined, and honest. Strengths worth preserving:

- Strict Rust posture: `unsafe forbid`, `unwrap/expect/panic = deny`, `panic = abort`, LTO release. Param-serialization is well-tested.
- Plugin separation by concern (handlers / analysis / util / http) with a small route table and a single `Responses.Table` writer supporting tsv/csv/json/verbose.
- Transaction discipline: writes go through `runOnSwingTx` (start/end transaction on the EDT). Reads use streams.
- Debugger is real (Trace RMI via `FlatDebuggerAPI`), not stubs — launch/attach, read/write memory, registers, breakpoints, step, freeze, value-scan all wired.

The bones are good. The gaps are concentrated in: (a) one severe perf bug, (b) an unauthenticated control surface, (c) an inconsistent error channel, (d) resource leaks, and (e) missing the feature classes that competitors win on.

---

## 2. Bugs & correctness (ranked)

### P0 — Live value-scan forces a synchronous RMI re-read per chunk
`DebuggerHandlers.runScan` (plugin `DebuggerHandlers.java:586`) loops every region in 1 MB chunks calling `dbg.readMemory(addr, want, monitor)`. `FlatDebuggerAPI.readMemory` forces a **live** target read over Trace RMI (protobuf round-trip to the agent) and the whole scan runs on a **single** `ghidra-mcp-scan` thread. On a 1.6 GB target that is ~1600 serialized RMI round-trips — the stall recorded in memory.

Fix (in order of payoff):
1. Read already-synced bytes from the Trace DB at the current snap: `trace.getMemoryManager().getBytes(snap, addr, ByteBuffer)`. Only force a live read for ranges whose `TraceMemoryState` is `UNKNOWN`.
2. Restrict default ranges to writable/heap/data regions; skip module image ranges unless `all=true` (already partially done — push it further, and skip guard/reserved regions).
3. Prefetch a whole region with one bulk live read, then scan in-process (you already do chunked reads; make the chunk = region and reuse the buffer).
4. Parallelize across regions with a bounded pool; coalesce hits.
5. Tag every hit with freshness (`KNOWN`/`UNKNOWN`) so the model never reasons on stale bytes.

### P1 — `scans` map never evicted (unbounded memory)
`DebuggerHandlers.scans` (`:68`) grows forever; each session holds up to `SCAN_MAX_HITS = 200_000` addresses. No TTL, no LRU, no removal on `next_scan` convergence. Add a TTL + max-session cap + explicit `scan_close`.

### P1 — Freeze timer leaks and clobbers control mode
`applyFrozen` (`:511`) calls `enterTargetControl(trace)` every 250 ms, forcing global `ControlMode.RW_TARGET` 4×/sec — this overrides whatever mode the user picked in the GUI. The timer never stops when the target dies or the last entry is unfrozen (`ensureFreezeTimer` starts it; nothing cancels it). Stop the timer when `frozen.isEmpty()` or target not alive; set control mode once, not per tick.

### P1 — Error channel is inconsistent (errors masquerade as success)
Handlers split into two error styles: some `throw IllegalArgumentException` → HTTP 400 → Rust maps to `invalid_params` (correct), but many return human strings like `"No program loaded"` / `"Decompilation failed"` with HTTP **200** → Rust `ok_text` → the model receives a *successful* tool result whose body is an error. The LLM can't reliably distinguish. Standardize a structured envelope and map failures to MCP `isError`.

### P2 — `createEnum` rejects unsigned 64-bit values
`EditHandlers.createEnum` (`:511`) uses `Long.decode(value)`, which throws on `0x8000000000000000`+ (size-8 unsigned enums). Use `Long.parseUnsignedLong` / `BigInteger` for size 8.

### P2 — `patch_bytes` always re-disassembles
`BytesHandlers.patchBytes` (`:166`) runs `DisassembleCommand` after every write, even when patching data/strings — produces bogus code units. Make disassembly opt-in (`disassemble=true`) or detect whether the target was code.

### P2 — `search_bytes` re-scans from start every page
`BytesHandlers.searchBytes` walks from `memory.getMinAddress()` and counts to `offset+limit` on every call; paging deep is O(page·matches). Acceptable for small N, but a cursor/continuation token would make it linear.

### P3 — Rust connection errors are opaque; timeout doc drift
`tools.rs::map_err` turns a connection-refused (`reqwest::Error`) into a generic `internal_error`. Classify "cannot reach Ghidra" distinctly with a fix hint. Also: README says `--timeout-secs` default `10`; `main.rs:15` is `60`. README also says "89 tools"; actual is 104. Fix the drift.

### P3 — Concurrency vs Ghidra thread-safety
The HTTP executor is virtual-thread-per-task (unbounded). Read handlers stream the FunctionManager/SymbolTable **off** the EDT while write handlers mutate on the EDT — Ghidra domain objects are not safe for concurrent read-during-write without the program lock. In practice writes serialize on the EDT, but a long read concurrent with a write can see inconsistent state or throw. Take `program.getLock()` for reads, or route all program access through one serialized worker.

---

## 3. Safety & security

The plugin is an **unauthenticated local control plane** for: arbitrary file read (`import_memory_dump` reads any path), arbitrary file write (`export_binary` writes any path), binary patching, **live process** memory/register writes, debugger launch/attach, and value freezing. Anything that can issue a localhost HTTP request — another local process, or a web page via a simple cross-origin `POST` form (no preflight on `application/x-www-form-urlencoded`) — can drive all of it. DNS-rebinding/CSRF against `127.0.0.1:8080` is a realistic vector.

Hardening:
- **Auth token**: require `Authorization: Bearer <token>` (generated per session, surfaced in Tool Options and passed via the Rust flag/env). Reject unauthenticated requests.
- **CSRF/rebind guard**: reject requests whose `Origin`/`Referer` is a browser origin; validate `Host` is loopback. Cheap, kills the browser vector.
- **File-IO sandbox**: gate `import_memory_dump`/`export_binary` behind an allow-listed directory option (default: project dir) or an explicit "enable file IO" toggle.
- **Destructive-op gating**: live writes (`live_write_memory/register`, `freeze_value`, `patch_bytes`, `nop_range`, `xor_decrypt`) should support a dry-run/confirm contract and an audit log of every mutation (addr, old→new, who).
- Good already: `unsafe` forbidden, `panic=abort`, loopback default, `neutralize_anti_debug` dry-run-by-default.

---

## 4. Speed

- Scanner: see P0.
- No batching: every edit is one HTTP round-trip + one transaction. Competitors collapse N edits into one call/transaction (~90% fewer round-trips). Biggest easy win after the scanner.
- Plugin has a `DecompileCache`; the Rust side caches nothing and can't (stateless). Keep cache plugin-side, key by program hash, expose `cache_stats`.
- `fmt`/`verbosity` is implemented in `Responses` but never sent by the bridge — dead capability. Expose it so the model can request compact tsv vs json.
- Long scans block on `scan_results` polling; emit MCP **progress notifications** instead.

---

## 5. Next-gen feature plan — the new era

Eleven themes. Each maps to confirmed Ghidra services.

### T1. Batch & transaction API (highest ROI, pure static)
`batch_rename`, `batch_set_comment`, `batch_set_variable_type`, `batch_set_prototype`, `batch_decompile`. One transaction, one round-trip, partial-failure report. Turns a 50-call labeling pass into one call.

### T2. MCP primitives beyond tools (protocol leap)
- **Resources** — subscribable live state: `ghidra://debugger/registers`, `ghidra://debugger/watch/{addr}`, `ghidra://program/current-function`. Emit `notifications/resources/updated` on stop. This is the clean answer to "turn-based LLM vs live process."
- **Prompts** — guided workflows as slash commands: `survey_binary`, `analyze_function`, `trace_live_value`, `solve_crackme`.
- **Structured output** — rmcp 0.8 supports structured/JSON tool results; return typed objects, not text blobs, so the model parses reliably. Pair with the error-envelope fix.
- **Progressive disclosure** — `list_tool_groups`/`search_tools`/`get_schema` so 100+ tools don't blow the context window.
- Bump `ProtocolVersion` off the pinned `V_2024_11_05`.

### T3. Scanner rewrite + CheatEngine-complete (live)
Trace-DB reads (P0) plus `pointer_scan`/`read_pointer_path` (rebasable chains rooted in module ranges), hardware watchpoints (`break_read`/`break_write` = "find what writes here"), `watch_add`/`watch_poll` via `TraceMemoryManager.getStateChanges`, and session GC. This makes the tool strictly better than CheatEngine because hits carry back-translated static addresses for labeling.

### T4. Function similarity & diffing (biggest competitor gap)
- `function_hash` / `diff_functions` / `diff_programs` via **BSim** + **Version Tracking** (`VersionTrackingService`).
- `bsim_query_function` against a known-binary DB to de-anonymize stripped code.
- Multi-program substrate: `list_open_programs` / `select_program` (diffing needs two programs open).

### T5. Type & symbol auto-recovery (Ghidra has it; none is exposed)
- `apply_fid_signatures` (`FunctionIDService`) — auto-name CRT/library code.
- `apply_gdt` / `list_data_type_archives` (`ApplyFunctionDataTypesCmd`).
- `import_pdb` (`PdbUniversalAnalyzer`) / `import_dwarf` (`DWARFImporter`).
- `recover_rtti_classes` (`RttiAnalyzer`) → class structs + vftables + namespaces.
- `propose_struct_from_accesses` (`FillOutStructureCmd`) — p-code-driven struct recovery from usage.
- `propagate_types` — commit decompiler-inferred prototypes via `HighFunctionDBUtil`.

### T6. Emulation & symbolic
- Persistent steppable session: `emu_start/step/run_to/read/write` (`EmulatorHelper`), upgrading the one-shot `emulate`.
- `emulate_function_with_args` — calling-convention arg injection.
- `solve_branch_constraints` / `find_path_to_address` — Ghidra 12 `SymbolicSummaryZ3` + bundled libz3; `SymbolicPropagator` to upgrade `extract_constraints` beyond syntactic cmp/branch pairing.

### T7. Visualization (extend the Mermaid lead)
Already emits Mermaid callgraph/CFG/struct. Add `xref_graph`, `namespace_graph` (module-altitude), dominator tree, `cfg_metrics` (cyclomatic complexity, loop back-edges), and an interactive HTML graph served from the existing plugin port. `AttributedGraphExporter` (GEXF/GraphML) for huge graphs.

### T8. Time-travel (unique differentiator — Trace DB already is one)
`list_snapshots` / `goto_snapshot` / `value_at_snapshot` / `register_at_snapshot` / `find_last_write(addr)`. The Trace DB is already a time-indexed store; this is mostly surfacing. Beats CheatEngine and IDA, which have no equivalent.

### T9. Coverage
`load_coverage` (drcov/EZCOV), `trace_to_coverage` (native from the Trace), `coverage_report` / `coverage_diff`, and overlay coverage % on the callgraph nodes. No Ghidra MCP does this.

### T10. AI-native, self-driving RE
`function_completeness` (0–100 score from naming/types/comments coverage), `find_next_undocumented` (drives a coverage loop), `summarize_function` + `apply_function_understanding` (thin context-bundle read → atomic apply; the LLM is the namer). Auto-rename pipeline: FID → demangle → propagate types → score.

### T11. Optional Frida backend
`frida_hook_function` / `frida_stalker_trace` / `frida_read/write/scan` for inline `Interceptor.attach` hooks and `Stalker` coverage. Adds a dependency — keep it a complementary, opt-in backend behind the same bridge, not a hard requirement.

---

## 6. Engineering hardening (cross-cutting)

- **Error envelope**: one typed result `{ok, value?, error?, hint?}`; map `error` to MCP `isError`. Stop returning errors as HTTP 200.
- **Auth + CSRF guard + file-IO sandbox** (Section 3).
- **Session lifecycle**: TTL/LRU for `scans`; freeze auto-stop on empty/dead target; close hooks on `dispose`.
- **Program access discipline**: bound the HTTP executor or serialize program access; take the program lock for off-EDT reads.
- **Rust**: classify connection vs upstream errors; align timeout default + tool count with README; expose `fmt`/`verbosity`; adopt structured output; bump protocol version.
- **Tests**: plugin has util unit tests — add handler-level tests against an in-memory `Program` (rename/patch/create_struct happy + failure paths) and a Rust end-to-end test hitting a mock plugin for every route. Add a fuzz test for `parsePairs`/hex parsing.
- **Docs**: regenerate the README tool table from the route table (single source of truth) to prevent drift.

---

## 7. Phased roadmap

**Phase 0 — Correctness & safety (days).** P0 scanner rewrite (Trace-DB reads); scans GC + freeze timer fix; error envelope + map to `isError`; auth token + CSRF/Host guard; file-IO sandbox option; README drift fixes; `createEnum` 64-bit; opt-in disassembly on patch.

**Phase 1 — Ergonomics & throughput (1–2 weeks).** Batch API (T1); structured output + `fmt`/verbosity exposure (T2 partial); MCP progress notifications for scans; decompile-cache stats; protocol bump.

**Phase 2 — MCP primitives & type recovery (2–4 weeks).** Resources + Prompts + progressive disclosure (T2); FID/GDT/PDB/DWARF/RTTI/FillOutStructure (T5); completeness scoring + self-driving loop (T10).

**Phase 3 — Live mastery (3–6 weeks).** Pointer-scan + watchpoints + watch_poll (T3); time-travel (T8); persistent emulator (T6 part); coverage import + overlay (T9).

**Phase 4 — Differentiators (ongoing).** BSim/Version-Tracking diffing + multi-program (T4); Z3 concolic (T6); interactive graph view (T7); optional Frida (T11).

The through-line: Phase 0 makes it safe and fast; Phase 1–2 make it the most ergonomic RE MCP; Phase 3–4 make it the only one with native time-travel, coverage overlay, CheatEngine-grade live scanning, and cross-binary diffing in one surface.
