# RE Engine Design — deobfuscation / devirtualization roadmap

Synthesized from SOTA research (2026-06-28): devirtualization, MBA/opaque/CFF deobfuscation,
concolic+emulation decryption, and decompiler/IR architecture. Goal: evolve this Ghidra MCP from
~187 one-shot atomic tools into a composable analysis engine that can (semi-)automatically peel
obfuscation, recover virtualized semantics, and decrypt hidden data — grounded in what already
exists, realistic about what is achievable.

> Hard truth from the literature: full devirtualization/recompilation and defeating
> synthesis-hardened obfuscation (Loki-class MBA, key-dependent handlers) are open research
> problems, not shippable features. The achievable wins are *semantic recovery* (per-handler
> summaries, virtual-ISA disasm), *signature/synthesis/DSE simplification* of non-hardened code,
> and *emulation-driven decryption*. Build to the SOTA frontier; do not promise past it.

---

## 0. Architectural backbone (do this first — everything composes on it)

Every mature framework (Ghidra, Binary Ninja BNIL, angr/VEX, miasm, Triton) uses **multiple IR
tiers** (raw → lifted → SSA → typed → structured) and a **pass manager driving rules to a
fixpoint**. We should NOT invent a new IR. Sit on Ghidra's **high P-Code, which is already SSA**
(built by the decompiler's "heritage" pass), and add a thin term-rewrite view over it.

Refs: [Ghidra deepwiki](https://deepwiki.com/NationalSecurityAgency/ghidra) ·
[coreaction.cc `universalAction`](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Decompiler/src/decompile/cpp/coreaction.cc) ·
[NCC Group on Ghidra decompiler internals](https://www.nccgroup.com/research/earlyremoval-in-the-conservatory-with-the-wrench-exploring-ghidra-s-decompiler-internals-to-make-automatic-p-code-analysis-scripts/) ·
[BNIL multi-tier](https://deepwiki.com/Vector35/binaryninja-api) · [miasm expr engine](https://deepwiki.com/cea-sec/miasm) ·
[Joern CPG](https://deepwiki.com/joernio/joern).

**Components (Java plugin, layered UNDER the atomic tools):**

1. **`ExprIR`** — immutable expression-tree view over `HighFunction` varnodes; nodes mirror
   `PcodeOp` opcodes (`INT_ADD/XOR/MULT`, `LOAD`, `MULTIEQUAL`=phi). Def-use is free via
   `Varnode.getDef()` / `getDescendants()`. This is the miasm/Triton term-rewriting substrate.
   *Read-mostly:* passes that change semantics emit patches/annotations or re-decompile; they do
   not mutate p-code in place.
2. **`ExprNormalizer`** — registry of rewrite rules (associativity, identity, constant folding,
   MBA identities) applied to a canonicalized AST so patterns match regardless of term order.
3. **`AnalysisPass`** interface — `name() · groups() · requires() · int apply(PassContext)`
   returning a change count (0 = no-op), exactly like Ghidra's `Rule`/`Action`.
4. **`PassManager`** — ordered, group-tagged list (copy `universalAction`:
   `normalize → opaque-pred → mba-simplify → unflatten → devirt → cleanup`); run each group to
   fixpoint (`while sum(apply())>0 && iter<CAP`), `requires()` gives topological order.
5. **`KnowledgeBase`** (angr-style) — per-program typed-fact store (recovered switch tables,
   proven-dead branches, devirt targets, simplified expr per address). Passes read prior facts
   instead of recomputing; persist via Ghidra `PropertyMap` / program user-data so facts survive
   save. Reuse the existing `analysis_note` surface as the user-visible projection.
6. **`EquivalenceChecker`** — the trust layer: emulate two expr/block variants on N random input
   vectors (`emu_set_register`/`emu_read_memory`) to validate ANY rewrite before it is surfaced.
   Every simplification/devirt result must pass this.

**MCP surface (3 generic tools, not one-per-pass):** `list_passes`, `run_pass(function, pass|group)`,
`query_ir(function, query)` — plus a preset wrapper `deobfuscate_function` (a fixed pipeline). New
passes register once and are immediately reachable with zero new wiring.

YAGNI guard: build the minimum of this scaffold needed by the FIRST concrete pass, then grow it.
Do not ship the full framework speculatively.

---

## 1. Devirtualization track (Oreans / VMProtect / Themida)

VM protectors replace native code with bytecode for a bespoke interpreter: a **dispatcher** reads a
virtual IP (VIP), indexes a **handler table**, each **handler** mutates virtual registers + a
virtual stack (VSP). Two SOTA families: **static handler-lift + IR opt** (NoVmp→VTIL, Rolles) and
**trace DSE + simplification/synthesis** (Triton `T'=T+VM(T)`, VMHunt, Syntia/msynth).

Refs: [Rolles VMProtect](https://www.msreverseengineering.com/blog/2014/6/23/vmprotect-part-0-basics) ·
[NoVmp](https://github.com/can1357/NoVmp) + [VTIL](https://github.com/VTIL-Project/VTIL-Core) ·
[Salwan Triton devirt](https://github.com/JonathanSalwan/VMProtect-devirtualization) ·
[VMHunt CCS'18](https://faculty.ist.psu.edu/wu/papers/vmhunt-ccs18.pdf) ·
[Syntia USENIX'17](https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-blazytko.pdf) ·
[Loki (the hardening adversary)](https://publications.cispa.saarland/3590/1/USENIX22-Loki.pdf).

**Proposed capabilities** (build order; each extends the new `analyze_virtualization`):

| # | Tool | Algorithm sketch | Builds on | Feasibility |
|---|------|------------------|-----------|-------------|
| D1 | `vm_dispatcher_map` | from the VM engine entry, follow `read-byte(VIP)→indexed-load→BRANCHIND` to enumerate handler table base + handler addrs | `pcode_function`, xref graph | High *(static)* |
| D2 | `vm_handler_summary` | per handler: `emu_start`→fuzz vregs/VSP→diff `emu_registers`/`emu_read_memory`→derive effect (pop n, op, push) | stateful `emu_*` | High |
| D3 | `vm_context_infer` | `taint_forward` from entry; the pointer that monotonically advances = VIP, the one used as mem base for push/pop = VSP | `taint_*` | Medium |
| D4 | `vm_bytecode_disasm` | with table+summaries+VIP, single-step the emulator over bytecode → linear "virtual ISA" listing (the core deliverable) | D1–D3 | Medium |
| D5 | `devirt_trace_slice` | record `emu_run`/live trace → backward-slice to outputs (`T'=T+VM(T)`) → concise formula | `emu_*`, `taint_backward` | Lower (path coverage) |

**Target-specific note:** on THIS binary the engine entry `0x140493158` is inside `.vlizer`
(packed, entropy 7.98, not statically disassembled), so D1's *static* path won't fire until the
section self-decompresses at runtime. For Oreans CV specifically, drive D1–D4 over the **live
plane** (`live_attach`) after the unpack stub runs, or emulate from the unpack stub. Verified fact:
`analyze_virtualization` already isolates the 16 entry sites / 11 virtualized functions funneling to
that one engine — that is the seed for D1.

---

## 2. Deobfuscation track (MBA / opaque predicates / CFG flattening)

Peel order: junk/DCE+const-fold → opaque predicates → CFF unflatten → MBA simplify. Operate on
high P-Code SSA, verify rewrites with the `EquivalenceChecker`.

Refs: [MBA-Blast](https://www.usenix.org/system/files/sec21fall-liu-binbin.pdf) ·
[SiMBA](https://github.com/DenuvoSoftwareSolutions/SiMBA) · [GAMBA](https://arxiv.org/abs/2305.06763) ·
[gooMBA](https://hex-rays.com/blog/deobfuscation-with-goomba) · [msynth](https://github.com/mrphrazer/msynth) ·
[Binsec BB-DSE opaque preds](https://www.ndss-symposium.org/wp-content/uploads/2020/04/bar2020-23004-paper.pdf) ·
[d810 unflattening](https://www.eshard.com/blog/d810-a-journey-into-control-flow-unflattening) ·
[MODeflattener](https://mrt4ntr4.github.io/MODeflattener/).

| # | Tool | Algorithm sketch | Builds on | Feasibility |
|---|------|------------------|-----------|-------------|
| O1 | `mba_simplify` | SiMBA: for ≤6-var linear P-Code subtree, evaluate over all boolean tuples → signature vector → solve linear system vs bitwise basis; verify by emulation | `pcode_function`, `emulate_function`, `idiom_simplifier` | High (linear) |
| O2 | `synth_simplify` | black-box: `emulate_function` as I/O oracle → match precomputed expr DB (gooMBA-lite); handles nonlinear + VM-handler exprs | `emulate_function` + bundled DB | Medium (needs DB) |
| O3 | `find_opaque_predicates` | per branch, feed `extract_constraints` to SMT (z3 via `ghidra_eval`) or value-set from `taint_forward`; flag conditions that are constant; corroborate by emulating both targets | `extract_constraints`, `emu_run_to` | Medium |
| O4 | `unflatten_function` | already detect flattening (`cfg_obfuscation_score`); locate dispatcher+state var via `taint_backward` on switch var → `emu_start`/`emu_run_to` each block to harvest `(block,state)→next` → emit recovered edge map (comments first, no auto-patch) | `cfg_metrics`, `taint_*`, `emu_*` | Medium |
| O5 | `pcode_normalize` | const fold/propagate + DCE + algebraic identities over high P-Code; feeds O1–O4 | `ExprNormalizer` | High |

Hardening to respect: Loki's formally-verified key-dependent MBA cuts synthesis success to ~19%;
nonlinear/high-k MBAs blow up signature tables; two-way/nondeterministic opaque predicates defeat
DSE; merged dispatchers + aliased state defeat naive unflattening. Flag these in tool output rather
than emitting wrong simplifications.

---

## 3. Dynamic / decryption track (FLOSS-style + concolic + unpack)

Ghidra's P-Code emulator runs **no real OS/API/syscalls** — pure CPU+memory. Design around it: stub
known-API returns, or fall back to the **live plane** (`live_attach`) / recommend Unicorn+Qiling
externally for API-dependent code.

Refs: [FLOSS theory](https://github.com/mandiant/flare-floss/blob/master/doc/theory.md) ·
[Mandiant string deobf](https://cloud.google.com/blog/topics/threat-intelligence/automatically-extracting-obfuscated-strings/) ·
[capa](https://github.com/mandiant/capa) · [angr](https://deepwiki.com/angr/angr) ·
[Triton](https://deepwiki.com/JonathanSalwan/Triton) · [Qiling](https://deepwiki.com/qilingframework/qiling) ·
[PinDemonium generic unpack](https://blackhat.com/docs/us-16/materials/us-16-Mariani-Pindemonium-A-Dbi-Based-Generic-Unpacker-For-Windows-Executables-wp.pdf).

| # | Tool | Algorithm sketch | Builds on | Feasibility |
|---|------|------------------|-----------|-------------|
| Y1 | `recover_decoded_strings` | FLOSS model: score decoder candidates (crypto consts, XOR/arith density, tight loops) → for each call site place args, emulate w/ insn cap, diff output buffer pre/post for ASCII/UTF-16, attribute via xrefs | `emulate_function`, `find_check_function`, `decode_strings_auto` | High (best ROI) |
| Y2 | `annotate_decoded_strings` | join recovered plaintext ↔ caller (`get_function_xrefs`) → `set_decompiler_comment` inline at each use (FLOSS "annotate") | Y1 + comments | High |
| Y3 | `solve_check` | concolic-lite: `extract_constraints` to success path → SMT-solve (z3 via `ghidra_eval`) → concrete input; fallback brute via `emu_set_register`+`emu_run_to` | `extract_constraints`, `emu_*` | Medium (SMT dep) |
| Y4 | `unpack_dump_live` | `live_attach` → run past unpack stub / wait for entropy settle → dump unpacked image via read-memory → `import_memory_dump`; OEP heuristic | `live_*`, `unpack_assist`, `import_memory_dump` | Medium |
| Y5 | `emulate_stackstring` | drive `emu_start`→`emu_step` through a builder fn → scan stack frame (`function_stack_frame` bounds) for printable runs | `emu_*` | High |
| Y6 | `api_emu_stubs` | registry mapping common imports → canned emu returns (alloc→scratch ptr) so more decoders complete without the live plane | emu config | Medium |

---

## 4. Prioritized phases

> **STATUS 2026-06-28:** Phase-A `recover_decoded_strings` shipped. Phase-B MBA pillar SHIPPED +
> live-verified (`simplify_expression`: MbaExpr IR + LinearMba signature/Mobius solver + equivalence
> checker + MbaNormalize + SimpleForms oracle library + no-regression guard + MbaExtract; reduces
> `(x^y)+2*(x&y)`→`x+y` on the deployed engine). Opaque-predicate pillar SHIPPED
> (`find_opaque_predicates`: Predicate IR + probe classifier + PredicateExtract from CBRANCH p-code;
> validated on real branches). The equivalence-checker trust layer is in place and every rewrite is
> guarded by it. Remaining: CFG-unflatten (O4) and devirt (vm_dispatcher_map/handler_summary) — both
> are emulation/Ghidra-coupled with no pure unit-testable core, so deferred until a flattened/VM target
> is loaded to verify against. MSVC-linker build gotcha resolved (deploy.ps1 sources vcvars).

**Phase A — proof + ROI, minimal framework (build now):**
- `recover_decoded_strings` (Y1) + `annotate_decoded_strings` (Y2) — pure reuse of `emulate_function`,
  highest value/lowest risk, immediately useful on real malware/crackmes.
- `pcode_normalize` (O5) + `EquivalenceChecker` — the smallest slice of the §0 backbone, needed by
  everything downstream.
- `vm_dispatcher_map` (D1) + `vm_handler_summary` (D2) — extends the shipped `analyze_virtualization`;
  the devirt seed.

**Phase B — composable engine + simplification:**
- Land the `AnalysisPass`/`PassManager`/`KnowledgeBase` scaffold (§0) once 2-3 passes exist to justify it.
- `mba_simplify` (O1), `find_opaque_predicates` (O3), `unflatten_function` (O4).

**Phase C — frontier (research-grade, gate on demand):**
- `vm_context_infer` (D3) → `vm_bytecode_disasm` (D4); `synth_simplify` (O2) with a bundled DB;
  `solve_check` (Y3); `unpack_dump_live` (Y4). Requires an SMT dependency decision (z3 via
  `ghidra_eval` vs a bound solver) and accepts the Loki/path-explosion limits.

**Cross-cutting decisions needed from maintainer:**
- SMT: embed z3 (new dep) vs invoke via `ghidra_eval`/python vs skip symbolic and stay
  emulation/signature-only.
- Synthesis DB: bundle a precomputed msynth/gooMBA-style oracle table (size/license) vs generate.
- The pass-framework investment (§0) vs continuing as atomic tools.

## 5. Realism ledger (don't over-promise)
- Achievable: per-handler semantics, virtual-ISA disasm, linear-MBA simplification, opaque-pred
  detection on OLLVM-class, CFF edge recovery, emulation-driven string/stackstring decryption,
  live-plane unpack dump.
- Not achievable (state of the art): full recompilation/recovery of arbitrary VMs, defeating
  Loki-class synthesized key-dependent MBA, sound simplification under path explosion, decrypting
  data whose key comes from the runtime environment without executing it.

*Sources are inline; DeepWiki repo pages render client-side and were cross-checked against primary
READMEs/papers where the wiki body did not load.*
