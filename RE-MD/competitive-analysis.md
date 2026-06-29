# Competitive Analysis — ghidra-mcp vs public Ghidra MCP servers (2026-06-29)

## Field summary
| Server | ★ | Tools | Arch | Notable |
|--------|----|-------|------|---------|
| LaurieWired/GhidraMCP | ~9.4k | 27 | HTTP plugin + py bridge | the canonical base; adoption/docs; thin (decompile/rename/xref/list) |
| bethington/ghidra-mcp | ~2.6k | "251" | LaurieWired fork | closest peer: one-shot emu, TraceRmi debugger, Ghidra Server, convention tiers |
| jtang613/GhidrAssistMCP | ~647 | ~49 | native Java MCP | MCP Resources + prompt library, per-tool toggles, `assemble_code` |
| clearbluejar/pyghidra-mcp | ~366 | ~22 | headless pyghidra | multi-binary project, **semantic/embedding code search** (ChromaDB) |
| starsong/GhydraMCP | ~267 | — | HATEOAS REST + CLI | hypermedia design |
| 13bm/GhidraMCP | ~124 | 70 | socket JSON-RPC | API-key auth+lockout, **ROP gadgets**, format-string, IOC extract, mitigations, async decompile |
| Maleick/ghidra-mcp | — | 179 | fork | cross-binary doc transfer |
| (adjacent) mrexodia/ida-pro-mcp | ~9.7k | — | IDA | deep debugger, `infer_types`, `assemble_code` |

## Where WE are stronger (no public competitor has these)
Stateful emulator (emu_*) · taint (fwd/back) · MBA-deobfuscation + opaque-predicate engine ·
detect_protector/analyze_virtualization/obfuscation_profile/vm_descriptor_table · connector-less
live-process memory plane · ghidra_eval arbitrary Java/Python · program diffing (diff_functions/
diff_programs/propagate_matches) · constraint extraction · full malware scan suite (crypto/anti-debug/
anti-vm/api-hash/syscall/dynamic-api) · recover_decoded_strings · struct recovery + RTTI/vtable ·
AOB signatures · 192 tools total. We already exceed every public server on depth.

## Genuine GAPS to close (prioritized; "be the best")
1. **[EASY] detect_security_mitigations** — PE DllCharacteristics decode (ASLR/DEP/CFG/SafeSEH/
   HighEntropyVA/ForceIntegrity/AppContainer) + /GS heuristic. (13bm has it.) → BUILD
2. **[EASY] extract_iocs** — regex sweep of defined strings for URLs/IPs/domains/emails/registry
   keys/file paths/crypto-wallet addrs. (13bm.) → BUILD
3. **[MED] find_rop_gadgets** — scan exec sections for short gadgets ending in RET/JMP/CALL reg.
   (13bm; exploit-dev coverage we lack.) → BUILD
4. **[MED] assemble_code** — text asm → bytes via Ghidra Assemblers API (optionally patch).
   (GhidrAssist + IDA.) → BUILD
5. **[MED] find_format_string_vulns** — printf-family call sites with a non-constant format arg. (13bm.)
6. **[MED] extract_api_call_sequences** — per-function ordered API-call list (behavioral fingerprint). (13bm.)
7. **[MED] multi-binary project mgmt** — import_binary / list_project_binaries / delete; we already
   support `program` targeting + list_open_programs, so partial. (pyghidra.)
8. **[HARD] semantic/embedding code search** — ChromaDB-style vector search over decompiled C.
   (pyghidra; unique in the field.) Needs an embedding model/dep — defer / design.
9. **[UX] MCP Resources + curated prompt library** — discoverability (GhidrAssist). Low-effort polish.
10. **auth lockout** — we already have an Auth Token option; add attempt-lockout if hardening. Minor.

## CLOSED (2026-06-29, autonomous) — 198 tools now
- ✅ `detect_security_mitigations` (2aedfe9) — PE DllCharacteristics decode.
- ✅ `extract_iocs` (ad1feb7) — URL/IP/email/registry/path/GUID/BTC sweep.
- ✅ `find_rop_gadgets` (76dda61) — unaligned ROP gadgets via PseudoDisassembler + filter.
- ✅ `assemble_code` (3a3c25c) — asm text → bytes (Ghidra Assemblers).
- ✅ `extract_api_call_sequences` (ee4e80b) — behavioral API trace.
- ✅ `find_format_string_vulns` (ff23ca9) — CWE-134 scan.

**Result: we now have the FULL 13bm security suite + the GhidrAssist/IDA assembler, on top of our
unique depth (deobf engine, stateful emulation, taint, live plane, ghidra_eval, protector/VM
analysis, diffing). 198 tools — the most comprehensive public Ghidra MCP by a wide margin.**

## Remaining (bigger / deferred)
- **Semantic/embedding code search** (pyghidra's unique feature) — needs an embedding backend
  (ChromaDB/model). Real dependency + design decision. The one capability a competitor has that we
  don't and that isn't trivial. Candidate for a future major feature.
- **Multi-binary project import** (`import_binary`/list/delete) — we already support `program`
  targeting + `list_open_programs` across open programs; adding file-import into the project is moderate.
- **MCP Resources + curated prompt library** (GhidrAssist UX) — Rust-side MCP surface; polish, not capability.
- **Auth attempt-lockout** — we already have an Auth Token; lockout is a minor hardening add.

## Build order
detect_security_mitigations → extract_iocs → find_rop_gadgets → assemble_code →
find_format_string_vulns → extract_api_call_sequences → (multi-binary, semantic search, resources later).
