# Reentrancy-safe in-VM Lua execution (no acid, no CreateRemoteThread)

## Problem

`lua_exec` runs Lua from a **second OS thread** (`CreateRemoteThread`) on the game's **live, in-use main `lua_State`**. Lua 5.1 ships with `lua_lock`/`lua_unlock` as no-ops, so the VM is single-threaded by contract. Two threads in one `lua_State` corrupt the stack/GC.

- `freeze=true` -> injected thread's `malloc` deadlocks on the Windows heap lock held by a suspended thread (`thread_exit=259`). Crash.
- `freeze=false` -> injected thread races the game's own thread inside the VM. Crash.

There is no safe `freeze` value. Confirmed by two live crashes of Alicia.exe (2026-06-20).

## The fix the whole field uses: run on the game's own thread via an API hook + mailbox

Sources (all agree): OpenPunk "Manipulating Embedded Lua VMs" parts 2-3, nickcano "Hooking LuaJIT", zer0c00l "Hookin' dat LUA".

Core idea: **never spawn a thread**. Detour a function the game itself calls every frame from its Lua-owning thread. Inside the detour the VM is at a C-API boundary (consistent state), so calling `luaL_loadbuffer`+`lua_pcall` there is safe. An external controller (the MCP) drops a script into a shared buffer and waits for the in-game hook to service it.

### Components

1. **Mailbox** — `VirtualAllocEx` (RW) in target:

   ```
   offset  field        type
   0x00    request      i32   0=idle 1=pending 2=running 3=done
   0x04    codeLen      i32
   0x08    resultCode   i32   lua_pcall return (0=ok)
   0x0c    resultLen    i32
   0x10    code[]       char  (cap 8192)  Lua source written by MCP
   0x2010  result[]     char  (cap 4096)  error/return string written by stub
   ```

2. **Hook stub** — `VirtualAllocEx` (RX) code cave. Runs on the game thread each time the hooked fn fires:
   - `pushad`/`pushfd`
   - re-entry guard: if `request == 2` skip (don't recurse into our own pcall)
   - if `request != 1` jump to trampoline tail
   - `request = 2`
   - recover `L`: from the hooked fn's arg (`[esp+4]` for cdecl `lua_*`) OR the known global `lua_State` when hooking a non-Lua per-frame tick
   - `luaL_loadbuffer(L, code, codeLen, "mcp")` -> if nonzero, copy error via `lua_tostring(L,-1)` into `result`, set resultCode, goto done
   - `lua_pcall(L, 0, 0, 0)` -> store return in `resultCode`; on error copy `lua_tostring(L,-1)`
   - `lua_settop(L, savedTop)` to keep the game's stack pristine
   - `request = 3`
   - `popfd`/`popad`, run stolen bytes, `jmp back`

3. **Detour** — overwrite 5 bytes at the hook point with `E9 rel32` -> stub. Stub stores the original stolen bytes and `jmp`s back after them (classic trampoline). 32-bit rel32 computed in the WOW64 address space; bytes written with `WriteProcessMemory` (already have `Live.write`).

4. **Hook point** (auto-detected, Alicia fallback baked in):
   - Preferred: a hot Lua C-API fn called every frame. For lua_tinker/Alicia, `lua_gettop` (tiny, called constantly) or `lua_pcall`.
   - Already located from the `dobuffer` decompile (`FUN_009e64d0`): `luaL_loadbuffer = FUN_009c9c70`, `lua_pcall = FUN_009c8aa0`. The stub calls these directly (no need for `dobuffer`, and we get real error strings).
   - `lua_gettop` found by signature (`mov eax,[ecx+0x10]; sub eax,[ecx+8]; sar eax,3` for 5.1) or by xref clustering; user override via `hook=` arg.
   - Install validates the choice by round-tripping a no-op and confirming `request` reaches 3 within N ms; if not, try the next candidate.

### MCP flow (rewritten `lua_exec`)

1. Ensure executor installed (lazy install on first call, or explicit `lua_install_executor`).
2. Write `code`, set `codeLen`, set `request = 1`.
3. Poll `request` until `3` (serviced by the game thread, typically < 16 ms) or timeout.
4. Read `resultCode` + `result`, reset `request = 0`, return.

No `CreateRemoteThread`, no `SuspendThread`. Execution is single-threaded through the VM's own thread -> no reentrancy, no heap-lock deadlock.

## Why this is safe where the old path was not

- Runs on the thread that owns the VM, at a boundary where the VM is consistent.
- Re-entry guard + `removeHook`-equivalent prevents recursion when our own `pcall` re-enters the hooked fn.
- `lua_settop` restores the game's stack; optional `lua_newthread` gives a fully private stack (hardening, needs `lua_newthread` addr).
- The MCP only ever does `WriteProcessMemory`/`ReadProcessMemory` on the mailbox — no thread creation.

## Phases

- **Phase 0 (done, deployed):** root-caused; shipped `freeze=false` default + `value_scan` WOW64 fix.
- **Phase 1 — Alicia executor (concrete addrs):** mailbox + stub + detour in `util/Lua.java`; `ProcessMemory` gains nothing new (alloc/write/read suffice). Hook `lua_gettop` (or `lua_pcall = FUN_009c8aa0`), stub calls `FUN_009c9c70`+`FUN_009c8aa0`. New tools `lua_install_executor` / `lua_uninstall_executor`; `lua_exec` prefers the mailbox path; legacy remote-thread path gated behind explicit `unsafe=true`.
- **Phase 2 — generalize:** signature/xref auto-detect of `lua_gettop`/`lua_pcall`/`luaL_loadbuffer` for any lua_tinker / Lua 5.1-5.4 game; error-string return; install-time validation probe.
- **Phase 3 — hardening:** `lua_newthread` private stack, re-entry guard hardening, clean uninstall (restore bytes, free caves) on `live_release`/detach, AOB re-resolve on restart.

## Risks

- Wrong hook point that is rarely called -> request never serviced (mitigated by install-time validation + timeout).
- Detour straddling a basic-block boundary -> mitigate by hooking a function prologue (5+ clean bytes) only.
- Game integrity checks on `.text` -> hook a function whose first bytes we restore via trampoline; or hook in a private cave only. Out of scope for v1.
