# ghidra-mcp — Master Plan: Next-Gen RE / Malware MCP

Goal: the single most capable reverse-engineering MCP in existence — beating LaurieWired, bethington, and ida-mcp on coverage while keeping our lead in malware triage, live debugging, and CheatEngine-grade dynamic RE.

State at time of writing: **113 tools** (113 plugin routes, 113 Rust tools, 1:1). Rust stdio bridge ↔ Ghidra Java plugin (`com.sun.net.httpserver` on virtual threads, program access marshalled to the Swing EDT inside transactions). Verified live against `Alicia.exe` (x86 LE 32, image base 0x400000, analyzed). Debugger path real (TraceRMI / dbgeng) but attach is finicky (accept-timeout on the dbgeng launcher).

This plan supersedes the scope of `next-gen-audit-and-plan.md` (kept for the bug/correctness audit) and folds in fresh competitive research (DeepWiki + web, June 2026).

---

## 1. Competitive landscape (researched)

| Project | Tools | Stack | Headless/Docker | Standout strengths | Weaknesses |
| --- | --- | --- | --- | --- | --- |
| **LaurieWired/GhidraMCP** | ~26 | Python (FastMCP) bridge + Java plugin, GUI only | No | Popular, simple, stdio+SSE | No batch, no scripting, no struct editing, no analysis control, no multi-program, no debugger |
| **bethington/ghidra-mcp** | ~193 (claimed up to 249) | Python bridge + Java, 12 service classes | **Yes (headless server + Docker, CI/CD)** | Batch ops + atomic `set_variables`; struct/union/enum editing w/ Hungarian notation; **Ghidra script create/run/delete**; cross-binary SHA-256 function hashing + doc propagation; completeness scoring 0-100%; multi-program (`program` param); convention enforcement (PascalCase) | Weak/no live debugger; moderate malware tooling; no CheatEngine-style scanning; no time-travel; no coverage |
| **ida-mcp 2.0** (jtsylve) | ~190 | Headless IDA + FastMCP | **Yes (headless)** | 36 **MCP resources**, 8 **prompts**, multi-binary simultaneous analysis, full type system | IDA-only (licensed), no Ghidra trace/time-travel, no native CheatEngine scanning |
| **ghidra-mcp (us)** | **113** | **Rust** bridge + Java | Not yet | **Live debugger (16) + CheatEngine-style scan/freeze (11)**, **malware triage (13)**, AOB signatures, type-recovery cluster (8, just added), Mermaid viz, strict Rust posture, auth+CSRF guard | No headless/docker, no scripting, no BSim/diffing, no resources/prompts, no coverage, no time-travel surfaced |

**Where we already lead:** dynamic RE. No competitor has our combination of TraceRMI live debugging + freeze + live value scan + static↔dynamic address translation + AOB signature engine + malware triage suite. That is the moat. Everything below either closes a parity gap or extends the moat.

**Where we are behind (the parity gaps to close):**
1. Headless mode + Docker (both leaders have it; we don't)
2. Script execution (bethington has create/run/delete; we have none)
3. MCP resources + prompts (ida-mcp has 36 + 8; we have 0)
4. Cross-binary diffing & function hashing / multi-program (both leaders; we don't)
5. Batch breadth + atomic multi-field edits (we have rename/comment; they have prototypes, variables, types)
6. Completeness scoring + convention enforcement (self-driving loop; we don't)
7. Coverage import/overlay (nobody mature; open lane)

---

## 2. The protocol leap (MCP primitives — highest leverage)

We expose only **tools**. Modern MCP gives three more primitives that change what an LLM can do with a live target. This is the single biggest "next-gen" multiplier.

### 2.1 Resources (subscribable live state)
Turn the turn-based LLM into a live observer. Expose read-only, subscribable URIs that push `notifications/resources/updated`:
- `ghidra://program/info`, `ghidra://program/current-function`, `ghidra://program/current-selection`
- `ghidra://debugger/registers`, `ghidra://debugger/stack`, `ghidra://debugger/threads`, `ghidra://debugger/modules`
- `ghidra://debugger/watch/{addr}` — emits on every stop / state change
- `ghidra://scan/{id}` — live candidate count as a scan refines
This is the clean answer to "the process is running but the model only acts in turns." `rmcp` supports resources; wire them to trace stop events and `TraceMemoryManager.getStateChanges`.

### 2.2 Prompts (guided RE workflows as slash commands)
Ship curated multi-step playbooks the client surfaces as commands:
- `survey_binary` — imports → strings → entry → high-entropy → suspicious APIs → summary
- `analyze_function` — decompile → xrefs → types → rename → comment loop
- `solve_crackme` — find check fn → extract constraints → emulate → propose key
- `trace_live_value` — value_scan → next_scan loop → freeze → find-what-writes
- `triage_malware` — anti-debug → api-hashes → encoded-strings → stack-strings → unpack
- `recover_types` — RTTI → FID → propagate → fill-struct → score

### 2.3 Structured output + progressive disclosure
- Return typed JSON tool results (rmcp 0.8 structured content) instead of text blobs; pair with the **error envelope** (`{ok, value?, error?, hint?}` mapped to MCP `isError`) so errors stop masquerading as HTTP-200 successes.
- `list_tool_groups` / `search_tools` / `get_tool_schema` so 130+ tools don't blow the context window. Bump `ProtocolVersion` off the pinned `V_2024_11_05`.
- Expose the already-implemented `fmt`/verbosity knob (tsv/csv/json/verbose) to the bridge — currently dead capability.

---

## 3. Deployment: headless + Docker + scripting (parity must-have)

### 3.1 Headless server
Stand up the same HTTP surface from a `GhidraScript`/`HeadlessAnalyzer` host so the MCP runs with no GUI — for CI, batch triage, and agent fleets. Reuse the exact handler classes; only the program/tool provisioning differs (a headless `PluginTool` shim or direct `Project`/`Program` injection). Bethington and ida-mcp both ship this; it is table stakes.

### 3.2 Docker image
Package Ghidra + extension + Rust bridge; expose the port; mount a project dir. One `docker run` to a working MCP.

### 3.3 Script execution (huge capability unlock)
- `run_ghidra_script(name, args)` — execute a bundled/managed `GhidraScript` (GhidraScriptUtil + run on a script task).
- `run_script_source(lang, body)` — inline Java or Jython/PyGhidra source, sandboxed, with captured stdout/result.
- `list_scripts` / `save_script` / `delete_script` — manage a script library.
Security: gate behind an explicit "enable scripting" toggle (arbitrary code exec); off by default; audit every run. This single feature lets the LLM leverage the entire GhidraScript ecosystem and write its own one-offs.

---

## 4. Feature catalog by domain

Legend for API status: **[V]** verified against staged jars, **[N]** needs javap/source verification, **[X]** requires a Ghidra extension/external dep.

### A. Static core — enrichment of what we have
- `function_completeness` **[V]** — 0–100 score from naming/type/comment/xref coverage (drives self-driving loop).
- `function_summary_bundle` **[V]** — one call returns decompile + signature + callers + callees + strings + constants for a function (the "context pack" the LLM needs to name it). Cuts 6 round-trips to 1.
- `apply_function_understanding` **[V]** — atomic apply of {name, prototype, var renames, comment} from one object.
- `data_xref_graph` / `namespace_graph` / `dominator_tree` / `cfg_metrics` (cyclomatic complexity, loop back-edges) **[V]**.
- `search_decompiled` — regex over decompiled C across functions (cache-backed) **[N]**.
- `strings_xref_rollup` — every string with its referencing functions in one pass **[V]**.

### B. Type & symbol auto-recovery (T5) — PARTIALLY DONE
Done (this iteration): `analyze_program`, `list_analyzers`, `set_analysis_option`, `apply_data_type`, `create_function`, `propagate_function_types`, `struct_set_field`, `struct_delete_field`.
Remaining:
- `recover_rtti_classes` **[V]** — enable RTTI analyzer + analyze, then surface recovered classes/vftables/namespaces (RttiAnalyzer; via analysis control + symbol/namespace traversal). Big for C++ games like Alicia.
- `apply_fid_signatures` **[N]** — FunctionIDService auto-name CRT/library code.
- `apply_gdt` / `list_data_type_archives` **[N]** — ApplyFunctionDataTypesCmd against bundled GDTs.
- `import_pdb` **[N]** (PdbUniversalAnalyzer) / `import_dwarf` **[N]** (DWARFImporter).
- `propose_struct_from_accesses` **[X]** — FillOutStructureCmd/Helper is **NOT in our staged jars**; locate the feature jar (likely Decompiler internals) before implementing. (Recorded gap.)
- `auto_recover_pipeline` — FID → demangle → propagate types → RTTI → score, one call.

### C. Batch & transactions (T1) — extend
Have: `batch_rename`, `batch_set_comment`. Add:
- `batch_set_prototype`, `batch_set_variable_type`, `batch_apply_data_type`, `batch_create_label`, `batch_decompile` **[V]**.
- `set_variables` (atomic multi-field on one function: name+proto+all locals in one tx) — match bethington's atomic editor.
- Partial-failure report per item; one transaction, one round-trip.

### D. Analysis & scripting control
- Analysis control: DONE (`analyze_program` / `list_analyzers` / `set_analysis_option`). Add `analyze_address_set` (targeted re-analysis) **[V]** and `analysis_log` (surface analyzer messages) **[N]**.
- Scripting: Section 3.3.

### E. Function similarity & cross-binary diffing (T4) — biggest competitor lane we can own
- `function_hash` **[N]** — stable structural hash (mnemonic/pcode-normalized) per function; cross-binary identity. Mirror bethington's SHA-256 hashing.
- `diff_functions(addrA, progB:addrB)` / `diff_programs(progB)` **[X]** — Version Tracking service (`VersionTrackingService`) + correlators.
- `bsim_index_program` / `bsim_query_function` / `bsim_query_program` **[X]** — BSim feature-vector DB (Ghidra decompiler emits the vectors); de-anonymize stripped code against a known-binary DB. Fuzzy-matches across compiler/version/arch where FID can't.
- `propagate_matches` — copy names/types/comments from matched src to dst (kills repeat work across binary versions).
- Multi-program substrate: `list_open_programs` / `select_program` / `open_program(path)` **[N]** + a `program` param on every tool (diffing needs two programs open). This also delivers the multi-program parity gap.

### F. Emulation & symbolic / concolic (T6)
- Persistent steppable emulator: `emu_start/step/run_to/read_reg/write_reg/read_mem/write_mem/snapshot` **[V]** (EmulatorHelper) — upgrades the one-shot `emulate`.
- `emulate_function(addr, args[])` **[V]** — calling-convention arg injection, capture return + side effects (great for hash/decrypt routines, crackme checks).
- `solve_branch_constraints` / `find_path_to_address` **[X]** — Ghidra 12 **SymbolicSummaryZ3** extension (needs Z3 4.13.0) — concolic: concrete-follows-path, Z3 collects branch constraints; solve for inputs reaching a target. Upgrades the syntactic `extract_constraints` to real path solving.
- `taint_forward` / `taint_backward` **[N]** — P-code data-flow propagation (SymbolicPropagator) for "where does this value go / come from."

### G. Live RE / CheatEngine++ (T3) — extend the moat + fix P0
- **P0 scanner rewrite [critical]**: read already-synced bytes from the Trace DB at the current snap (`trace.getMemoryManager().getBytes(snap, addr, buf)`); only force live RMI reads for `UNKNOWN` ranges; prefetch whole regions; bounded-parallel across regions; tag hits with freshness. Kills the 1.6 GB stall.
- `pointer_scan` / `read_pointer_path` **[N]** — rebasable pointer chains rooted in module ranges (the thing CheatEngine users actually want; our hits carry back-translated static addresses for labeling — strictly better than CE).
- Hardware watchpoints: `break_read` / `break_write` (= "find what writes/reads this") **[N]**.
- `watch_add` / `watch_poll` / `watch_remove` **[N]** via `TraceMemoryManager.getStateChanges`.
- Scan session GC (TTL/LRU; close hooks), freeze timer auto-stop on empty/dead target (audit P1s).
- `disassemble_live` / `decompile_live` at a dynamic address (translate → static → decompile) **[V]**.

### H. Time-travel (T8) — unique differentiator (Trace DB already is one)
- `list_snapshots` / `goto_snapshot` / `value_at_snapshot` / `register_at_snapshot` **[N]**.
- `find_last_write(addr)` — walk the Trace DB time index for the most recent write. Beats CheatEngine and IDA, which have no equivalent. Mostly surfacing existing TraceDB capability.

### I. Coverage (T9) — open lane, nobody mature
- `load_coverage(drcov|ezcov)` **[N]** (DynamoRIO drcov / Pin), `trace_to_coverage` (native from the Trace), `coverage_report` / `coverage_diff`, overlay coverage % on callgraph/CFG nodes.

### J. Visualization (T7) — extend the Mermaid lead
- Have Mermaid callgraph/CFG/struct + DOT. Add `xref_graph`, `namespace_graph`, `dominator_tree`, and an **interactive HTML graph** served from the existing plugin port (clickable nodes → decompile). `AttributedGraphExporter` (GEXF/GraphML) for huge graphs.

### K. Malware / firmware / cracking — DOUBLE DOWN (our niche, lean in hard)
Have 13. Add:
- `unpack_assist` — detect packer (entropy + section heuristics), find OEP candidates (tail-jump after high-entropy), dump+rebuild assist **[N]**.
- `iat_rebuild` — reconstruct imports from a dumped image (resolve thunks via known module exports) **[N]**.
- `find_syscalls` / `find_direct_syscalls` — Hell's Gate / syscall-stub detection (`mov eax, ssn; syscall`) **[V]**.
- `decode_strings_auto` — try common schemes (xor/add/rc4/base64) on encoded blobs, score printable yield **[V]**.
- `yara_scan(rules)` — run YARA rules over program memory; report hits with function context **[N]**.
- `find_crypto_constants` — AES S-box, SHA/MD5 IVs, CRC tables, big-int primes (extend `find_magic_constants`) **[V]**.
- `capa_bridge` — map functions to MITRE ATT&CK / capa rules **[X]** (optional dep).
- `find_dynamic_api_resolution` — `GetProcAddress`/`LoadLibrary` chains + hash-loop resolvers (extend `find_api_hashes`).
- `find_anti_vm` / `find_anti_sandbox` — CPUID/timing/registry/MAC checks (sibling to `find_anti_debug`).
- `cfg_obfuscation_score` — flatten/opaque-predicate heuristics; flag obfuscated functions.

### L. AI-native self-driving RE (T10) — match + exceed bethington
- `function_completeness` (A) + `find_next_undocumented` — drives a coverage loop ("keep naming until the binary is N% documented").
- `apply_naming_convention` — enforce/auto-fix PascalCase fns, Hungarian struct fields, snake locals (bethington's convention enforcement) **[V]**.
- `suggest_renames` — propose names from strings/constants/imports a function touches (heuristic seed for the LLM).
- `documentation_report` — coverage dashboard (named %, typed %, commented %).

### M. Optional Frida backend (T11)
- `frida_hook_function` / `frida_stalker_trace` / `frida_read|write|scan` **[X]** — inline `Interceptor.attach` + `Stalker` coverage. Opt-in, complementary to TraceRMI, behind the same bridge. Adds a dep — keep optional.

---

## 5. Engineering hardening (cross-cutting, from the audit — do alongside)

- **Error envelope**: `{ok, value?, error?, hint?}` → MCP `isError`. Stop returning errors as HTTP 200 (LLM can't tell success from failure today).
- **Security**: file-IO sandbox for `import_memory_dump`/`export_binary` (allow-listed dir); dry-run/confirm + audit log for every mutation (addr, old→new); scripting toggle off by default. (Auth token + CSRF/Origin guard already shipped.)
- **Session lifecycle**: scan map TTL/LRU + `scan_close` (have) + cap; freeze timer auto-stop; dispose hooks.
- **Concurrency**: bound the virtual-thread executor or serialize program access; take `program.getLock()` for off-EDT reads (read-during-write hazard).
- **Correctness**: `patch_bytes` opt-in disassembly; `search_bytes` cursor/continuation; classify connect-vs-upstream errors in Rust with fix hints.
- **Docs/tests**: regenerate README tool table from the route table (single source of truth — kill drift); handler-level tests against an in-memory `Program`; Rust end-to-end against a mock plugin per route; fuzz `parsePairs`/hex parsing.
- **Progress**: MCP progress notifications for long scans/analysis instead of poll-only.

---

## 6. Phased roadmap

Targets are cumulative tool counts.

**Phase 0 — Correctness & safety (days).** Error envelope + `isError`; P0 scanner Trace-DB rewrite; scan GC + freeze auto-stop; file-IO sandbox + mutation audit log; `createEnum` 64-bit; opt-in patch disassembly; Rust error classification; README auto-gen. *(~113 tools, all hardened.)*

**Phase 1 — Ergonomics & throughput (1–2 wks).** Batch breadth (C) + `set_variables`; structured output + error envelope + `fmt` exposure; progress notifications; decompile-cache stats; protocol bump. *(~125)*

**Phase 2 — Protocol leap + type recovery (2–4 wks).** Resources + Prompts + progressive disclosure (Section 2); finish T5 (RTTI/FID/GDT/PDB/DWARF, FillOutStructure once jar located); completeness scoring + convention enforcement + self-driving loop (L). *(~150)*

**Phase 3 — Headless + scripting + live mastery (3–6 wks).** Headless server + Docker (Section 3); script execution; pointer-scan + watchpoints + watch_poll (G); time-travel (H); persistent emulator + `emulate_function` (F part). *(~175)*

**Phase 4 — Differentiators (ongoing).** BSim + Version Tracking diffing + multi-program/cross-binary hashing (E); Z3 concolic + taint (F); coverage import/overlay (I); interactive HTML graph (J); malware double-down (K); optional Frida (M). *(200+)*

Through-line: **Phase 0** makes it safe+fast → **1–2** make it the most ergonomic and protocol-modern RE MCP → **3** reaches headless/scripting parity while extending the live moat → **4** makes it the *only* surface with native time-travel + coverage overlay + CheatEngine-grade live scan + cross-binary BSim diffing + a first-class malware suite, all behind one Rust bridge.

---

## 7. Category-defining differentiators (what only we will have)

1. **Live + static fused**: every live hit (scan, watchpoint, time-travel write) carries a back-translated static address and auto-labels it. CheatEngine has no decompiler; IDA/Ghidra static tools have no native scanner. We do both, bridged.
2. **Time-travel RE over the Trace DB** surfaced as tools — `find_last_write`, snapshot queries. No competing MCP exposes this.
3. **CheatEngine-complete + better**: pointer scan, hardware watchpoints, freeze, value scan — plus labeling and decompilation CE can't do.
4. **Malware suite as a first-class niche**: anti-debug/anti-vm neutralization, API-hash + dynamic-resolution recovery, unpack/IAT-rebuild assist, crypto/syscall detection, YARA — depth no general RE MCP matches.
5. **Concolic on Ghidra's own Z3 emulator** for crackmes/key-recovery, wired to the constraint extractor.
6. **Self-driving coverage loop**: completeness scoring + find-next-undocumented + auto-recover pipeline, so the LLM documents a binary to a target % unattended.

The bones (strict Rust posture, transaction discipline, real TraceRMI debugger, auth/CSRF) are already there. This plan is the path from "best dynamic RE MCP" to "best RE MCP, period."
