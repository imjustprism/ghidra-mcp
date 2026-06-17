# ghidra-mcp

[![CI](https://github.com/imjustprism/ghidra-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/imjustprism/ghidra-mcp/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](rust-toolchain.toml)
[![Ghidra](https://img.shields.io/badge/ghidra-12.0.1-red.svg)](https://ghidra-sre.org/)
[![JDK](https://img.shields.io/badge/jdk-21-green.svg)](https://adoptium.net/)

MCP server for Ghidra. Rust bridge + Ghidra Java plugin. Wires any MCP client (Claude Desktop, etc.) straight into a live Ghidra session.

> [!NOTE]
> Loopback-only by default. Never bind the plugin to a public interface.

## Quick start

| step | command |
| --- | --- |
| build bridge | `cargo build --release` |
| stage ghidra jars | `cd plugin && .\setup-libs.ps1` |
| build plugin | `mvn clean package` |
| install plugin | drag `plugin/target/ghidra-mcp-plugin-1.0.zip` into **File → Install Extensions** |
| enable plugin | **File → Configure → Developer → ghidra-mcp-plugin** |
| point client | set command to `target/release/ghidra-mcp.exe` |

## Client config

`%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "C:/path/to/ghidra-mcp.exe",
      "args": ["--ghidra-server", "http://127.0.0.1:8080/"]
    }
  }
}
```

## Flags

| flag | env | default |
| --- | --- | --- |
| `--ghidra-server` | `GHIDRA_SERVER` | `http://127.0.0.1:8080/` |
| `--timeout-secs` | `GHIDRA_TIMEOUT_SECS` | `60` |
| `--ghidra-token` | `GHIDRA_TOKEN` | unset |

`RUST_LOG=ghidra_mcp=debug` for verbose logs.

## Plugin options

**Edit → Tool Options → Ghidra MCP HTTP Server**

| option | default |
| --- | --- |
| Server Port | `8080` |
| Bind Address | `127.0.0.1` |
| Auth Token | empty (auth disabled) |
| File IO Directory | empty (file I/O disabled) |

## Tools

139 tools total.

Every paginated read tool accepts an optional `fmt` argument — `tsv` (default), `csv`, `json`, or `verbose` — alongside `offset`/`limit`.

<details>
<summary><b>Listing / metadata</b> (20)</summary>

| tool | purpose |
| --- | --- |
| `list_methods` | all functions |
| `list_classes` | namespace classes |
| `list_functions` | functions with addresses |
| `list_segments` | memory segments |
| `list_sections_detailed` | sections + RWX + entropy |
| `list_imports` | imported symbols |
| `list_exports` | exported symbols |
| `list_namespaces` | namespaces |
| `list_data_items` | defined data |
| `list_entry_points` | entry points |
| `list_strings` | defined strings |
| `search_functions_by_name` | substring match |
| `get_current_address` | cursor address |
| `get_current_function` | cursor function |
| `get_function_by_address` | resolve by address |
| `program_info` | language, arch, base, sha256 |
| `program_metadata` | full metadata map (compiler, format, flags) |
| `function_stack_frame` | stack vars for a fn |
| `list_relocations` | relocation entries (address, type, symbol) |
| `list_bookmarks` | analysis bookmarks (errors/warnings/notes) |

</details>

<details>
<summary><b>Decompile / disasm</b> (6)</summary>

| tool | purpose |
| --- | --- |
| `decompile_function` | C pseudocode by name |
| `decompile_function_by_address` | C pseudocode by address |
| `decompile_minimal` | pseudocode, cosmetic noise stripped |
| `disassemble_function` | raw asm |
| `instruction_at` | single insn |
| `pcode_function` | raw p-code per insn |

</details>

<details>
<summary><b>Xrefs / CFG</b> (14)</summary>

| tool | purpose |
| --- | --- |
| `get_xrefs_to` | callers / readers |
| `get_xrefs_from` | targets of a ref |
| `get_function_xrefs` | full refs for a fn |
| `list_callers` | direct callers |
| `list_callees` | direct callees |
| `basic_blocks` | CFG blocks |
| `function_string_refs` | strings referenced |
| `callgraph_dot` | Graphviz DOT call graph |
| `function_summary_bundle` | one-call context pack (decompile + callers + callees + strings) |
| `xref_graph` | Mermaid one-hop reference graph around an address |
| `namespace_graph` | Mermaid namespace/class hierarchy |
| `cfg_metrics` | block/edge/cyclomatic/loop complexity for a function |
| `dominator_tree` | immediate-dominator of each basic block |
| `function_hash` | structural hash (mnemonic + operand-shape) for matching/dedup |

</details>

<details>
<summary><b>Bytes / patching</b> (10)</summary>

| tool | purpose |
| --- | --- |
| `read_bytes` | raw hex |
| `hex_dump` | formatted dump |
| `search_bytes` | pattern search (cursor-resumable via `start`/`next_cursor`) |
| `find_string` | literal search |
| `patch_bytes` | write hex (opt-in re-disassembly) |
| `nop_range` | patch NOPs |
| `create_label` | add label |
| `xor_decrypt` | XOR a range |
| `import_memory_dump` | load bytes from file |
| `export_binary` | dump program |

</details>

<details>
<summary><b>Rename / types</b> (20)</summary>

| tool | purpose |
| --- | --- |
| `rename_function` | by name |
| `rename_function_by_address` | by address |
| `rename_data` | data symbol |
| `rename_variable` | local var |
| `set_decompiler_comment` | PRE comment |
| `set_disassembly_comment` | EOL comment |
| `set_function_prototype` | full prototype |
| `set_local_variable_type` | retype local |
| `create_struct` | new StructureDataType |
| `create_union` | new UnionDataType |
| `create_enum` | new EnumDataType |
| `import_c_header` | parse C header into types |
| `demangle_symbol` | demangle one C++ symbol |
| `demangle_all` | demangle + rename all |
| `batch_rename` | many renames, one transaction |
| `batch_set_comment` | many comments, one transaction |
| `batch_set_prototype` | many prototypes, one transaction |
| `batch_set_variable_type` | many local retypes, one transaction |
| `set_variables` | atomic name + prototype + locals on one function |
| `apply_naming_convention` | batch-normalize function names to snake/screaming_snake/camel/pascal (dry-run by default) |

</details>

<details>
<summary><b>Type recovery / analysis control</b> (13)</summary>

| tool | purpose |
| --- | --- |
| `analyze_program` | run/re-run Ghidra auto-analysis (RTTI, FID, demangler) |
| `list_analyzers` | analysis option names + on/off state |
| `set_analysis_option` | toggle an analyzer before analysis |
| `apply_data_type` | lay a type at an address (clears conflicts) |
| `create_function` | disassemble + create a function at an address |
| `propagate_function_types` | commit decompiler-inferred types/names to the DB |
| `recover_rtti_classes` | recovered C++ classes + vftable + method count |
| `list_data_type_archives` | available type archives (program/builtin/GDT) |
| `list_open_programs` | all open programs (name, active, sha256) |
| `select_program` | switch the active program by name/sha256 |
| `struct_set_field` | replace/insert a field in an existing struct |
| `struct_delete_field` | clear a field at an offset |
| `batch_apply_data_type` | apply many types, one transaction |

</details>

<details>
<summary><b>Self-driving RE</b> (2)</summary>

| tool | purpose |
| --- | --- |
| `function_completeness` | score one function 0-100 with a breakdown |
| `find_undocumented` | functions ranked least-documented first (work queue) |

</details>

<details>
<summary><b>Signatures / pattern scanning</b> (4)</summary>

| tool | purpose |
| --- | --- |
| `make_signature` | unique wildcarded AOB sig for an address |
| `find_signature` | scan memory for a pattern (IDA/x64dbg/CE/code+mask) |
| `resolve_relative` | resolve call/jmp/RIP-relative operand targets |
| `find_function_by_string` | string xref to function entry + signature |

</details>

<details>
<summary><b>Malware triage / analysis</b> (19)</summary>

| tool | purpose |
| --- | --- |
| `find_anti_debug` | known anti-dbg APIs |
| `neutralize_anti_debug` | patch anti-dbg calls to return 0 |
| `find_api_hashes` | resolve hashed imports |
| `find_encoded_strings` | xor-encoded blobs |
| `find_stack_strings` | stack-built strings |
| `high_entropy_regions` | packed/encrypted zones |
| `emulate` | pcode emulation |
| `find_check_function` | crackme check-fn locator |
| `extract_constraints` | cmp/branch constraints |
| `find_magic_constants` | magic immediate operands |
| `find_orphan_gaps` | code outside any function |
| `vtable_scan` | heuristic vtable finder |
| `idiom_simplifier` | annotate arithmetic idioms |
| `find_crypto_constants` | locate AES/SHA/MD5/CRC constant tables |
| `find_syscalls` | direct syscall/sysenter/int2e stubs + SSN |
| `find_anti_vm` | VM/sandbox artifact strings (VMware/VBox/QEMU/…) |
| `cfg_obfuscation_score` | CFG-flattening / obfuscation score for a function |
| `decode_strings_auto` | brute-force XOR/ADD/SUB key to recover encoded strings |
| `find_dynamic_api_resolution` | call sites of GetProcAddress/LoadLibrary/… |

</details>

<details>
<summary><b>Debugger</b> (16)</summary>

| tool | purpose |
| --- | --- |
| `debugger_status` | trace/target state |
| `debugger_list_targets` | debug targets |
| `debugger_list_modules` | loaded modules |
| `debugger_threads` | live threads |
| `debugger_stack_trace` | call stack of a thread |
| `debugger_registers` | frame registers |
| `debugger_read_memory` | live target memory |
| `debugger_list_breakpoints` | logical breakpoints |
| `debugger_set_breakpoint` | set breakpoint |
| `debugger_remove_breakpoint` | remove breakpoint |
| `debugger_continue` | resume target |
| `debugger_step_into` | step into |
| `debugger_step_over` | step over |
| `debugger_break` | interrupt target |
| `debugger_translate_static_to_dynamic` | static addr to live |
| `debugger_translate_dynamic_to_static` | live addr to static |

</details>

<details>
<summary><b>Live RE / CheatEngine-style</b> (11)</summary>

| tool | purpose |
| --- | --- |
| `debugger_list_offers` | available launchers/connectors |
| `debugger_launch` | launch/attach from the MCP |
| `live_write_memory` | write live process memory |
| `live_write_register` | write live register |
| `freeze_value` | hold a value (re-written ~4x/sec) |
| `unfreeze_value` | stop freezing |
| `list_frozen` | frozen addresses |
| `value_scan` | first scan of live memory |
| `next_scan` | refine candidates |
| `scan_results` | list candidates + static addrs |
| `scan_close` | free a scan session |

</details>

Also: `save_program`.

## Prompts

Guided RE workflows, surfaced as MCP prompts (slash commands in clients that support them).

| prompt | purpose |
| --- | --- |
| `survey_binary` | first-pass survey: layout, capabilities, IOCs, what to reverse next |
| `analyze_function` | deeply analyze + document one function (arg: `address`) |
| `triage_malware` | anti-analysis, capabilities, encoded data, crypto |
| `solve_crackme` | locate + solve a validation routine |
| `recover_types` | RTTI/FID/demangle/propagate across the program |

## Resources

Read-only program/debugger state, exposed as MCP resources (clients can read or attach them as context).

| uri | content |
| --- | --- |
| `ghidra://program/info` | language, arch, base, sha256 |
| `ghidra://program/current-function` | function at the cursor |
| `ghidra://program/current-address` | cursor address |
| `ghidra://debugger/status` | live trace/target state |

## Troubleshooting

| symptom | fix |
| --- | --- |
| bridge error `error sending request` | Ghidra not running, plugin not enabled, or wrong port |
| plugin absent from Configure dialog | check under **Developer** category, not default |
| port 8080 busy | change in Tool Options, match `--ghidra-server` |
| zip won't install | JDK21 required, Ghidra 12.0.1 required |

## License

Apache-2.0. See [LICENSE](LICENSE).
