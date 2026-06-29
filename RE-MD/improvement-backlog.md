# Improvement Backlog — autonomous tool-stress + RE deep-dive

Continuously appended during the autonomous loop (started 2026-06-28, overnight). Each entry is a
concrete, actionable improvement to the ghidra-mcp tooling, a novel RE method to implement, or a
verified RE finding on the target. Triaged so they can be fixed later in batches.

Target: bbf9b329.exe (Vape V4 launcher) — PE x64, image base 0x140000000, `.vlizer` = Oreans Code
Virtualizer (RWX, entropy 7.98), engine entry 0x140493158, LZMA stub FUN_1404932a1.

Legend: **[TOOL-FIX]** correctness/UX fix to an existing tool · **[TOOL-NEW]** new tool/capability ·
**[NOVEL]** novel RE method/technique to implement · **[FINDING]** verified RE finding ·
**[BUG]** confirmed bug.

---

## Novel RE methods to implement (from research agent, 2026-06-28)

Prioritized for P-Code/emulation-grounded, reusing existing primitives. Ship-first 5 marked ★.

**Devirtualization / VM:**
- **[NOVEL]** VM handler clustering + dispatcher fingerprint — normalized P-Code semantic hash per
  block (after MBA + opaque-pred simplify) → agglomerative cluster → dispatcher = block reached by
  most clusters via indirect jump. Builds on `function_hash` + MBA engine. **High** (recognize, not
  fully lift).
- **[NOVEL]** VIP/VSP recovery by backward SSA walk from indirect-jump/return targets (`taint_backward`
  + `pcode_function`). **Med**.
- **[NOVEL]** Trace-guided partial devirt: seed VIP at a handler, single-step `emu_*`, record
  reads/writes per opcode → per-opcode semantic summary. **Med** (full re-lift to clean C = Low).

**Generic unpacking:**
- ★ **[NOVEL]** Run-to-OEP write-then-execute monitor: emulate from EP, track written pages on STORE,
  stop on branch into a written page → OEP → dump → `import_memory_dump`. **High** for self-
  decompressors, **Low** for full VMProtect (needs Unicorn/Qiling). (Note: matches the Pass-1
  `unpack_dump_live` idea; the live-plane variant sidesteps the emulator step ceiling.)
- **[NOVEL]** Stolen-bytes / IAT reconstruction post-dump (`find_dynamic_api_resolution` + live plane). **Med**.

**Symbolic / concolic:**
- ★ **[NOVEL]** P-Code concolic path solver: symbolize args, interpret P-Code collecting path
  constraints, Z3 (via process / `ghidra_eval`) → concrete input reaching a target/branch. Builds on
  `extract_constraints` + `pcode_function`. **High** for small loop-light funcs (license/magic
  checks), **Low** on loops/heap (path explosion). [decision: z3-via-eval per prior choice]
- ★ **[NOVEL]** Concolic opaque-predicate confirmation: for each `find_opaque_predicates` candidate,
  ask the solver if both branches are SAT; UNSAT one side ⇒ proven opaque ⇒ auto-patch. **High** —
  upgrades the current probe-heuristic to proof-grade (directly addresses Pass-2's heuristic caveat).

**CFG-flattening recovery:**
- ★ **[NOVEL]** Auto-deflattening: detect dispatcher (high in-degree + switch on one var), find state
  var by backward slice, emulate each real block to its next-state assignment → reconstruct true CFG
  edges (comments/graph first, no auto-patch). Builds on `cfg_obfuscation_score` + `dominator_tree` +
  taint + emulator. **High** single-dispatcher OLLVM, **Med** nested.

**Type/structure recovery:**
- **[NOVEL]** Probabilistic field-type recovery (OSPREY-lite): weighted likelihoods per struct offset
  (size/sign/arith-vs-deref/xref) → MAP type. Extends `propose_struct_from_accesses`. **High**.
- **[NOVEL]** Value-Set Analysis for pointer/array disambiguation + array sizing. **Med**.
- **[NOVEL]** Cross-call type propagation by unification (arg↔param equality graph). Extends
  `propagate_function_types`. **High**.

**Function/library ID:**
- **[NOVEL]** Semantic (emulation) fingerprint: emulate on N fixed input vectors, hash
  (outputs+side-effects) → behavioral signature robust to instruction-substitution/recompilation.
  Builds on `emulate_function` + `make_signature`. **High** for pure/leaf fns.
- **[NOVEL]** BSim-style normalized P-Code n-gram vectors + ANN cosine search. **Med**.

**Anti-anti-analysis:**
- ★ **[NOVEL]** Auto-neutralize TLS-callback / exception-based (SEH/VEH) anti-debug: enumerate TLS
  callbacks + handlers, taint from IsDebuggerPresent/PEB/NtGlobalFlag/timing → branch sinks → patch
  benign. Extends `find_anti_debug`/`neutralize_anti_debug`. **High** (under-covered vectors).
- **[NOVEL]** rdtsc/QPC timing + CPUID-hypervisor check auto-patch. Extends `find_anti_vm`. **High**.

**Crypto/protocol:**
- **[NOVEL]** Crypto-primitive ID by data-flow-graph isomorphism + constant set (Feistel/SPN shape,
  rotate-mix), corroborate with `find_crypto_constants`. **Med-High** (standard ciphers).
- **[NOVEL]** Key/IV extraction via taint + emulation at the crypto call boundary (live plane for
  in-process keys). **High** when the call is reachable with realistic state.

**Verifiable LLM-assisted:**
- ★ **[NOVEL]** Grounded rename proposals: evidence bundle (body + xrefs + strings/consts/imports) →
  LLM names → ACCEPT ONLY IF grounded (name references a string/import actually used). The verify-gate
  is the novelty (rejects hallucinations). Extends `function_summary_bundle` + `batch_rename`. **High**.
- **[NOVEL]** Round-trip name/type validation via re-decompile-equivalence (apply guess → re-decompile
  → revert on new warnings/conflicts). **Med**.

**Don't-build-yet (Low):** full VMProtect→clean-C re-lift (needs LLVM-grade optimizer); concolic on
loop/heap-heavy funcs (path explosion); unguarded LLM type inference (F1<0.1 — only ship verified).

**Ship-first 5 (★):** run-to-OEP, concolic solver + opaque-proof, auto-deflattening, TLS/exception
anti-debug, grounded renames — all reuse existing primitives with honest High ceilings.

---

## Implemented (2026-06-29, autonomous)

- ✅ **[TOOL-FIX] taint snapping** (19352b4) — taint_forward/backward snap to nearest modeled p-code op.
- ✅ **[TOOL-FIX] find_magic_constants classify** (7f0e6ca) — meaning column (float masks / udiv magics /
  crypto / hash seeds / debug fills).
- ✅ **[TOOL-NEW] obfuscation_profile** (b8546d1) — one-call VIRTUALIZED/PACKED/CLEAN verdict.
- ✅ **[TOOL-NEW] vm_descriptor_table** (bf29934) — parse (call_site_RVA, bytecode_dest_RVA) dispatch
  table → function map. Verified live: the table has **17 entries** (refines the earlier 16 call-ref
  count — one call site wasn't marked as a call ref by Ghidra; the table is authoritative).
- Earlier this session: simplify_expression (MBA), find_opaque_predicates (+const-probe fix),
  analyze_virtualization, recover_decoded_strings, propose_struct base+const, idiom ×3, IAT xrefs,
  anti-debug sites, dynamic-api names, rtti ordering, vtable class, deploy.ps1 vcvars fix.

- ✅ **[TOOL-FIX] make_signature min_len** (9057635) — robustness floor (default 8B); no more
  fragile 3-byte "unique" sigs.

**Backlog remaining (each needs a resource, not readily buildable now):**
- `find_undocumented` lib-filter — needs FID integration (run `apply_fid_signatures` first to name
  libs, then the 14k queue shrinks); it's a workflow more than a code change.
- `vm_entry_report` — now largely subsumed by `vm_descriptor_table` (function names) +
  `analyze_virtualization`; marginal.
- Deobf passes (CFG-unflatten, devirt handler-summary) — need a flattened/VM target to verify.
- Concolic solver + opaque-proof — need z3 (decision: via ghidra_eval/python).
- Grounded LLM renames — need LLM integration with the verify-gate.

**To make the 4 new/changed tools live as MCP tools** (obfuscation_profile, vm_descriptor_table,
+ the min_len param on make_signature, + the taint/magic handler changes): one deploy.ps1 + full
Claude restart. All committed + replay-verified; just need the new binary/plugin loaded.

## Pass log (one block per pass)

### Pass 9 (2026-06-29) — tool stress + new tool
- `list_bookmarks` (5106; PE-dir + crack note) and `resolve_relative` (call->0x140493158) both clean.
- [FINDING] binary has an IMAGE_DIRECTORY_ENTRY_TLS but **0 TLS callbacks** (AddressOfCallBacks array
  head is null) — TLS dir is for TLS data/index only.
- ✅ [TOOL-NEW] **list_tls_callbacks** (728272f) — enumerate PE TLS callbacks (pre-entry anti-debug
  spot); parse verified live; 199 tools. No public Ghidra MCP has this.

### Heartbeat (2026-06-29 ~03:23) — no target, still converged

- `live_processes name=vape` empty. No new work; re-check in ~60 min.

### Heartbeat (2026-06-29 ~02:22) — no target, still converged

- `live_processes name=vape` empty. No new work; re-check in ~60 min.

### Heartbeat (2026-06-29 ~01:20) — no target, still converged

- `live_processes name=vape` empty. No new work; static analysis exhausted. Re-check in ~60 min.

### Heartbeat (2026-06-29 ~00:30) — still converged

- No `vape` process running (live-unpack route still blocked). Confirmed the runtime-materialization
  finding generalizes: descriptor entry 2's bytecode-dest `0x1409c9a76` is also all-zero static (like
  entry 1) — the per-function bytecode regions are uniformly runtime-only across the table. No new
  tool issues. Backing off to ~60 min; loop re-checks for a live target.

### Pass 8 — VM dispatch table fully parsed + convergence (2026-06-29)

- **[FINDING] Oreans dispatch structure fully reverse-engineered (static).** Descriptor table at
  `0x140493048` = **16 eight-byte entries**, each `(call_site_RVA u32, bytecode_dest_RVA u32)`:
  `0xabc6→0x9d85b8`, `0xdeb5→0x9c9a76`, `0xec0d→0x9c81b5`, `0xec7f→0x9ad571`, `0x485bb→0x9d8969`, …
  (16 total, then zero-padding to 0x1404930d0). **Verified**: the first column matches the 16
  `xref_graph` call sites of the engine EXACTLY (14000abc6/deb5/ec0d/...). Header at 0x140493000:
  +0x0 init flag (=1), +0x10 size 0x3310f9, +0x40 the table. The engine keys on the **return address
  (call-site RVA)** to find each function's entry. The bytecode-dest regions (e.g. 0x1409d85b8) are
  **all zero in the static image** — runtime-materialized → static devirt is definitively blocked,
  dynamic (live-attach + dump after decompression) is the only route. This is the cleanest possible
  static characterization of the VM.
- **[TOOL-NEW] `vm_descriptor_table`** (now fully specified by the above): given the engine's
  self-located header, parse `(call_site_RVA, bytecode_dest_RVA)` entries and join with
  `analyze_virtualization` + the containing function names → a complete "virtualized function →
  dispatch key → runtime bytecode address" map in one call. High value, fully static, ~exact spec.
- **[OK]** `xref_graph` renders clean Mermaid (engine callers), capped correctly. `hex_dump` paginates.

**VM RE CONVERGED (static frontier reached):** engine=self-locating LZMA decompressor (P1) · header+
descriptor table mapped + verified (P7/P8) · per-function bytecode is runtime-only (P8) · no running
process to dump (P6). Nothing more recoverable statically without (a) a running instance or (b) a
native/Unicorn emulator to finish the unpack. Backing off to a longer heartbeat that re-checks for a
live process.

### Pass 7 — VM header structure + signature tools (2026-06-29)

- **[FINDING]** The Oreans engine's self-located header is at `0x140493000` (engine does
  `POP RSI; SUB RSI,0x4f; SUB RSI,0x110` → RSI=0x140493000). Layout: **offset 0 = init flag** (`01` —
  already 1 in the static image, so `CMP [RSI],0; JZ` falls through to the decompression path at
  0x140493183, NOT the first-run branch), **offset 0x10 = 0x003310f9** (a size), **offset ~0x40 = a
  32-bit value table** (`0x0000abc6`, `0x009d85b8`, `0x0000deb5`, `0x009c9a76`, ...) that looks like
  per-virtualized-function bytecode offsets/sizes into the compressed blob. This is the VM's
  function-descriptor structure — the key to mapping each of the 16 entry sites to its bytecode.
- **[TOOL-NEW] `vm_descriptor_table`**: given a protector engine + its self-located header, parse the
  flag/size/offset table into a structured view (entry → blob offset/size). Would let the analyst map
  each `analyze_virtualization` entry to its payload region without hand-reading hex. **Med-High.**
- **[OK]** `make_signature` (engine → unique `9C 56 E8`), `hex_dump`, `basic_blocks`, `instruction_at`,
  `function_hash`, `list_functions` all functional.
- **[TOOL-FIX, minor]** `make_signature` trimmed to a **3-byte** "unique" sig (`9C 56 E8` =
  PUSHFQ;PUSH RSI;CALL). Technically unique now but fragile across recompiles/relocation. Add an
  optional `min_len`/robustness floor (e.g., require >= N non-wildcard bytes) so generated AOBs are
  durable, not just minimally-unique.

### Pass 6 — dynamic-route check + convergence (2026-06-28)

- **[FINDING]** `live_processes name=vape` → empty: no target instance running, so the live-plane
  unpack route (`unpack_dump_live`) is **not actionable tonight**. Net devirt status for this target:
  static unpack infeasible (interpreted P-Code emulator, step-bound) AND dynamic unpack blocked (no
  running process). The VM payload stays opaque without either a running instance or native emulation.
- **[OK]** `live_processes` works as a clean preflight (empty on no match, would show pid/openable/
  wow64/modules otherwise).
- **CONVERGENCE (this environment, tonight):** the loop has produced its high-value output —
  6 RE/tool passes + 19 novel methods. Further single-context passes would repeat. The remaining
  high-value work is **implementing the backlog** (which the user deferred to "later") and needs one
  of: (a) a running target process (enables live unpack/key-extraction), (b) an obfuscated/OLLVM/VMP
  sample (enables positively verifying the deobf passes), or (c) a Unicorn/native-emulation dependency
  (enables compute-heavy unpack). The scheduled wakeup will re-check (a) periodically.

### Pass 5 — VM-entry characterization (2026-06-28)

- **[FINDING]** The 11 functions that call the VM engine (`analyze_virtualization`) are the binary's
  **security-sensitive core**, not random code — Oreans selectively virtualized the high-value
  routines: FUN_14000ec00 (network-fetch chain → inject payload, per loop-state), FUN_1400b5a90,
  FUN_14000aba0/de90, FUN_1400485a0, FUN_140053930, FUN_1400db760/dca20, FUN_140170de0/1730d0/174c40.
  Their static bodies are bare VM-enter stubs; the real logic is in the packed payload. Recovering
  them needs the live-plane unpack (Pass-1 `unpack_dump_live`) or per-handler emulation (NOVEL devirt
  #3). **This is the devirt frontier for this target.**
- **[TOOL-NEW] `vm_entry_report`**: combine `analyze_virtualization` entries with each virtualized
  function's callers + referenced strings (cross-ref like `function_summary_bundle`) → "these N
  protected functions, here's the subsystem each belongs to (by caller/string context)". Turns the
  raw entry list into a prioritized devirt target list. Builds on existing primitives. **High.**

### Pass 4 — orientation tools (2026-06-28)

- **[OK]** `find_function_by_string "vape.gg"` → 4 funcs + reusable byte signatures (excellent
  orientation tool, as documented). `program_metadata` clean (14522 fns, 726923 instrs, analyzed).
  `find_undocumented`/`find_check_function`/`find_magic_constants` all paginate + filter correctly.

### Pass 3 — anti-analysis + triage tools (2026-06-28)

- **[OK] correct negatives** (confirm precision, no false positives): `find_api_hashes` fnv1a = 0
  (binary resolves by name via GetProcAddress — `find_dynamic_api_resolution` found 76), `find_syscalls`
  = 0 (no direct syscalls), `find_anti_vm` = 0 (game launcher, not sandbox-evasion). Good signal/noise.
- **[TOOL-FIX]** `find_undocumented` returns **14046** functions (score 0) — overwhelmingly
  statically-linked library code (Crypto++/SDL/GLFW/CRT). The labeling work-queue is swamped by libs.
  Add a filter to exclude known-library functions (FID/`apply_fid_signatures` matches, or a heuristic:
  in a lib namespace / matched by `make_signature` against a lib DB) so the queue focuses on the
  target's OWN code. Pairs with the function-ID novel methods (#12/#13).
- **[NOVEL→connect]** This 14k-lib problem is the strongest argument for shipping **library
  identification** (FLIRT/FID is staged but under-applied; semantic/BSim fingerprinting would auto-tag
  the libs and shrink the analyst's surface from 14k to the few hundred app functions).

### Pass 2 — tool stress-test (2026-06-28)

- **[TOOL-FIX]** `taint_forward` / `taint_backward` recurring friction: "no p-code operations at
  <addr> (not a modeled instruction target)". Hit on `taint_backward 0x1400503b3` (auth gate cmp) and
  `taint_forward 0x1404931dd` (engine MUL) — both are real instructions, but the decompiler's high
  p-code doesn't model every raw instruction address. Fix: snap to the nearest modeled op in the same
  statement (with a note), and/or accept a variable/varnode name, and/or list nearby modeled
  addresses in the error. This is the single most common taint UX failure.
- **[TOOL-FIX]** `find_magic_constants` returns raw immediates but doesn't **classify** them. On this
  binary it surfaced 828 hits dominated by `0x80000000`/`0x7fffffff` (float abs/neg sign masks). Add a
  meaning column for well-known constants: float sign masks, unsigned-division reciprocals (reuse
  `idiom_simplifier.recoverDivisor`), crypto constants (reuse `find_crypto_constants` set), common
  hash seeds (FNV 0x811c9dc5/0x01000193, etc.). Turns noise into semantic leads.
- **[FINDING]** `find_check_function` top candidate `FUN_1401814e0` (score 10, 4 success / 6 fail
  refs) — a crackme-style check worth modeling; lead for the licensing path.
- **[OK]** Verified working cleanly: `find_check_function`, `function_stack_frame`,
  `find_magic_constants`, `cfg_obfuscation_score`, `cfg_metrics`, `find_orphan_gaps`,
  `emulate_function`, `find_opaque_predicates` (post-fix), `simplify_expression`.

### Pass 1 — virtualization deep-dive (2026-06-28)

- **[FINDING]** Oreans engine `0x140493158` is a **self-locating LZMA-decompression bootstrap, NOT a
  flattened dispatcher**: `cfg_obfuscation_score` = 28, `likely_flattened=false`, 12 blocks. It
  decompresses the `.vlizer` payload at runtime; the real VM interpreter lives in the packed payload
  (not statically present). Self-location via `PUSHFQ; CALL $+5; POP RSI; SUB RSI,...` then `CMP
  [RSI],0; JZ <unpack>`.
- **[FINDING]** The engine **self-decompresses inside the P-Code emulator with no args**:
  `emulate_function 0x140493158` ran the full 300k step cap without faulting or returning (the
  unpack path is self-contained via RSI-relative addressing; doesn't deref the R8/RDX/R9 call args).
  So static emulation *starts* the unpack — but full decompression of the 11 MB payload is almost
  certainly **infeasible interpreted** (LZMA over 11 MB ≈ billions of p-code steps; the cap is 10M
  and stepping is slow).
- **[TOOL-NEW] `unpack_dump_live`** (highest-value devirt route for Oreans): `live_attach` a running
  instance → set a BP just after the engine's first call / detect the `.vlizer` write-then-settle →
  dump the decompressed region via read-memory → `import_memory_dump`. The P-Code emulator can't
  finish the unpack; the live process already did it. Builds on `live_attach`/`unpack_assist`/
  `import_memory_dump`.
- **[TOOL-NEW] native-emulation fallback (Unicorn-backed)** for compute-heavy unpack/decrypt the
  P-Code emulator can't finish in the step budget. Ceiling: large, but a real dependency add.
- **[TOOL-NEW] `obfuscation_profile`** (program-wide): combine `detect_protector` +
  `analyze_virtualization` + per-function `cfg_obfuscation_score` + `high_entropy_regions` into one
  verdict. Rationale below.
- **[TOOL-FIX]** `cfg_obfuscation_score` blind spot: a VM **engine scores LOW (28, not flattened)**
  yet is the most protected code in the binary. "Not flattened" ≠ "not obfuscated" for VM-based
  protection. The score should be cross-referenced with section membership (is the fn in a protector
  section?) and `analyze_virtualization` entry-targeting, or at least note this caveat in output.
- **[FINDING]** `find_orphan_gaps` = 964 gaps (code with no owning function) — candidate
  runtime-resolved thunks / VM artifacts; a lead generator, consistent with a protected binary.


### Pass 10 (2026-06-29) — novel upgrade to existing tool
- ✅ [TOOL-FIX/NOVEL] recover_decoded_strings now uses the emulator's built-in memory-write tracking
  (enableMemoryWriteTracking/getTrackedMemoryWriteSet) to scan EVERY written region (stack/heap/
  global), replacing the stack-window + return-ptr heuristics. Verified live: 10 real RAM write
  ranges captured, 17 p-code-temp ranges filtered. Commit 6661047. (API note: the filter class is
  not MemoryAccessFilter in this Ghidra; FilteredMemoryState + EmulatorHelper.enableMemoryWriteTracking
  is the correct path.)
- Next focus (user): keep finding NOVEL upgrades to EXISTING tools (not just new tools).

### Pass 11 (2026-06-29) — Phase-A upgrade
- ✅ make_signature mode=semantic (fa379ce): emulation behavioral fingerprint (return+writes+halt
  over 6 input vectors, FNV-hashed). Verified live: deterministic per fn, distinct across fns.
  First Phase-A item of the master upgrade plan shipped.

### Pass 12 (2026-06-29) — Phase-A upgrade
- ✅ diff_functions mode=semantic (behavioral I/O similarity via shared Emulator.behavior() helper).
  Verified live: self=100/100, cross=0/100. Refactored semanticFingerprint to share behavior().

### Pass 13 (2026-06-29) — Phase-B MERGE
- ✅ MERGE callgraph_dot → callgraph (format=mermaid|dot). Removed CallgraphDot struct/ToParams/tool +
  /callgraph_dot route + orphaned default_callgraph_depth; README -1 (199→198), Xrefs/CFG 23→22.
  clippy + README-sync green. First Phase-B merge landed; CallGraph.dot logic preserved.

### Pass 14 (2026-06-29) — Phase-B MERGE
- ✅ MERGE struct_set_field + struct_delete_field → struct_field (op=set|delete). Unified struct/tool;
  type now required only when op=set (validated bridge-side). README -1 (198→197), Type-recovery 19→18.
  clippy + README-sync green. Handler logic preserved (structSetField/structDeleteField unchanged).
