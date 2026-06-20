package io.github.imjustprism.ghidra.mcp.util;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Version-agnostic detection of an embedded Lua VM in a live process and arbitrary-Lua execution via a
 * remote shellcode thread. Detects Lua 5.1-5.4 (and LuaJIT) whether the VM is a loaded DLL (C API resolved
 * by export) or statically linked (located by signature). The lua_State finder is pointer-size aware and
 * does not assume any field offset: it keys off CommonHeader.tt == LUA_TTHREAD plus the
 * lua_State -> global_State -> mainthread == lua_State double back-reference, which holds across versions.
 */
public final class Lua {

    public static final int LUA_TTHREAD = 8;
    private static final long MIN_PTR = 0x10000L;

    private static final List<String> LUA_MODULES = List.of(
            "lua51.dll", "lua52.dll", "lua53.dll", "lua54.dll",
            "lua5.1.dll", "lua5.2.dll", "lua5.3.dll", "lua5.4.dll",
            "luajit.dll", "lua.dll");

    private static final byte[][] VERSION_NEEDLES = {
            "LuaJIT 2.".getBytes(StandardCharsets.US_ASCII),
            "Lua 5.4".getBytes(StandardCharsets.US_ASCII),
            "Lua 5.3".getBytes(StandardCharsets.US_ASCII),
            "Lua 5.2".getBytes(StandardCharsets.US_ASCII),
            "Lua 5.1".getBytes(StandardCharsets.US_ASCII),
    };

    public record Info(String version, boolean luaJit, int ptrSize, long moduleBase,
            long loadBuffer, long pcall, long doString) {

        public boolean hasDll() {
            return moduleBase != 0;
        }

        public boolean canExec() {
            return doString != 0 || (loadBuffer != 0 && pcall != 0);
        }
    }

    private Lua() {
    }

    public static Info detect(ProcessMemory rpm, int pid, int ptrSize) {
        for (var m : rpm.modules(pid)) {
            var name = m.name().toLowerCase();
            if (LUA_MODULES.contains(name)) {
                boolean jit = name.contains("luajit");
                var exports = rpm.exports(pid, m.base());
                return new Info(name, jit, ptrSize, m.base(),
                        firstExport(exports, m.base(), "luaL_loadbufferx", "luaL_loadbuffer"),
                        firstExport(exports, m.base(), "lua_pcallk", "lua_pcall"),
                        firstExport(exports, m.base(), "luaL_dostring"));
            }
        }
        var version = scanVersion(rpm, pid);
        return new Info(version, version != null && version.startsWith("LuaJIT"), ptrSize, 0, 0, 0, 0);
    }

    private static long firstExport(Map<String, Long> exports, long base, String... names) {
        if (exports == null) return 0;
        for (var n : names) {
            var rva = exports.get(n);
            if (rva != null) return base + rva;
        }
        return 0;
    }

    private static String scanVersion(ProcessMemory rpm, int pid) {
        var mods = rpm.modules(pid);
        if (mods.isEmpty()) return null;
        var main = mods.get(0);
        long base = main.base();
        long end = base + main.size();
        int chunk = 1 << 20;
        for (long addr = base; addr < end; addr += chunk) {
            int want = (int) Math.min(chunk, end - addr);
            byte[] data = rpm.read(pid, addr, want);
            if (data == null) continue;
            for (var needle : VERSION_NEEDLES) {
                if (indexOf(data, needle) >= 0) {
                    return new String(needle, StandardCharsets.US_ASCII);
                }
            }
        }
        return null;
    }

    public static long findState(ProcessMemory rpm, int pid, int ptrSize) {
        var mods = rpm.modules(pid);
        if (mods.isEmpty()) return 0;
        var main = mods.get(0);
        long base = main.base();
        long end = base + main.size();
        long maxPtr = ptrSize == 8 ? 0x7fffffffffffL : 0x7fff0000L;
        var seen = new HashSet<Long>();
        int chunk = 1 << 20;
        for (long addr = base; addr < end; addr += chunk) {
            int want = (int) Math.min(chunk, end - addr);
            byte[] data = rpm.read(pid, addr, want);
            if (data == null) continue;
            for (int i = 0; i + ptrSize <= data.length; i += ptrSize) {
                long v = readPtr(data, i, ptrSize);
                if (v < MIN_PTR || v > maxPtr || !seen.add(v)) continue;
                if (isLuaState(rpm, pid, v, ptrSize, maxPtr)) return v;
            }
        }
        return 0;
    }

    private static boolean isLuaState(ProcessMemory rpm, int pid, long state, int ptrSize, long maxPtr) {
        byte[] hdr = rpm.read(pid, state, 0x60);
        if (hdr == null || hdr.length < 0x60) return false;
        if ((hdr[ptrSize] & 0xff) != LUA_TTHREAD) return false;
        if (ptrSize == 4) {
            long top = readPtr(hdr, 0x08, 4);
            long base = readPtr(hdr, 0x0C, 4);
            long lG = readPtr(hdr, 0x10, 4);
            long stackLast = readPtr(hdr, 0x1C, 4);
            long stack = readPtr(hdr, 0x20, 4);
            if (!alignedPtr(stack, maxPtr) || !alignedPtr(base, maxPtr) || !alignedPtr(top, maxPtr)
                    || !alignedPtr(stackLast, maxPtr) || !alignedPtr(lG, maxPtr)) {
                return false;
            }
            if (stack > base || base > top || top > stackLast) return false;
            byte[] g = rpm.read(pid, lG, 0x100);
            if (g == null) return false;
            for (int go = 0; go + 4 <= g.length; go += 4) {
                if (readPtr(g, go, 4) == state) return true;
            }
            return false;
        }
        for (int off = ptrSize; off + ptrSize <= hdr.length; off += ptrSize) {
            long candidateG = readPtr(hdr, off, ptrSize);
            if (candidateG < MIN_PTR || candidateG > maxPtr) continue;
            byte[] g = rpm.read(pid, candidateG, 0x200);
            if (g == null) continue;
            for (int go = 0; go + ptrSize <= g.length; go += ptrSize) {
                if (readPtr(g, go, ptrSize) == state) return true;
            }
        }
        return false;
    }

    private static boolean alignedPtr(long v, long maxPtr) {
        return v >= MIN_PTR && v <= maxPtr && (v & 3) == 0;
    }

    public static final int EXEC_TIMEOUT = -3;
    private static final int STOLEN_LEN = 5;
    private static final int MAILBOX_SIZE = 0x4000;
    private static final int FN_OFF = 0x0C;
    private static final int STATE_OFF = 0x10;
    private static final int ARGMODE_OFF = 0x14;
    private static final int CODE_OFF = 0x20;
    private static final int R_RC = 0x3000;
    private static final int R_TT = 0x3004;
    private static final int R_PTR = 0x3008;
    private static final int R_LEN = 0x300C;
    private static final int R_DATA = 0x3010;
    private static final int NAME_OFF = 0x3020;
    private static final int CODE_CAP = R_RC - CODE_OFF;
    private static final int RESULT_CAP = 0x4000;
    private static final int LUA_TSTRING = 4;
    private static final int REQ_IDLE = 0;
    private static final int REQ_PENDING = 1;
    private static final int REQ_DONE = 3;
    private static final int ARGMODE_THREE = 1;

    public record ExecutorHandle(int pid, long mailbox, long stub, long hookPoint, long evalCave,
            byte[] original) {}

    public record ExecResult(int rc, int tt, byte[] data) {}

    public static ExecutorHandle install(ProcessMemory rpm, int pid, long state, long hookPoint,
            int ptrSize, byte[] original, long gettop, long loadbuffer, long pcall, long settop) {
        if (ptrSize != 4) {
            throw new IllegalStateException("safe lua executor currently supports 32-bit targets only");
        }
        if (original == null || original.length < STOLEN_LEN) {
            throw new IllegalStateException("cannot read hook point 0x" + Long.toHexString(hookPoint));
        }
        long mailbox = rpm.alloc(pid, MAILBOX_SIZE, false);
        if (mailbox == 0) throw new IllegalStateException("VirtualAllocEx(mailbox) failed");
        long stub = rpm.alloc(pid, 160, true);
        long evalCave = rpm.alloc(pid, 256, true);
        if (stub == 0 || evalCave == 0) {
            rpm.freeRemote(pid, mailbox);
            rpm.freeRemote(pid, stub);
            rpm.freeRemote(pid, evalCave);
            throw new IllegalStateException("VirtualAllocEx(stub/evalCave) failed");
        }
        byte[] header = new byte[CODE_OFF];
        putLe(header, FN_OFF, (int) evalCave);
        putLe(header, STATE_OFF, (int) state);
        putLe(header, ARGMODE_OFF, ARGMODE_THREE);
        rpm.write(pid, mailbox, header);
        rpm.write(pid, mailbox + NAME_OFF, new byte[]{'m', 'c', 'p', 0});
        rpm.write(pid, evalCave, buildEvalReturn(mailbox, gettop, loadbuffer, pcall, settop));
        byte[] sc = hookStub(mailbox, original, stub, hookPoint + STOLEN_LEN);
        byte[] detour = jmpRel32(hookPoint, stub);
        if (!rpm.write(pid, stub, sc) || !rpm.installHook(pid, hookPoint, detour, STOLEN_LEN)) {
            rpm.freeRemote(pid, stub);
            rpm.freeRemote(pid, evalCave);
            rpm.freeRemote(pid, mailbox);
            throw new IllegalStateException("failed to install hook at 0x" + Long.toHexString(hookPoint)
                    + " (could not catch all threads clear of the patch window)");
        }
        return new ExecutorHandle(pid, mailbox, stub, hookPoint, evalCave, original);
    }

    public static void uninstall(ProcessMemory rpm, ExecutorHandle h) {
        rpm.write(h.pid(), h.hookPoint(), h.original());
        rpm.freeRemote(h.pid(), h.stub());
        rpm.freeRemote(h.pid(), h.evalCave());
        rpm.freeRemote(h.pid(), h.mailbox());
    }

    public static ExecResult execMailbox(ProcessMemory rpm, ExecutorHandle h, long state, String code,
            int timeoutMs) {
        byte[] cb = code.getBytes(StandardCharsets.UTF_8);
        if (cb.length > CODE_CAP) throw new IllegalStateException("script exceeds " + CODE_CAP + " bytes");
        int pid = h.pid();
        long mb = h.mailbox();
        rpm.write(pid, mb + FN_OFF, i32le((int) h.evalCave()));
        rpm.write(pid, mb + STATE_OFF, i32le((int) state));
        rpm.write(pid, mb + ARGMODE_OFF, i32le(ARGMODE_THREE));
        rpm.write(pid, mb + R_TT, i32le(0));
        rpm.write(pid, mb + CODE_OFF, cb);
        rpm.write(pid, mb + 4, i32le(cb.length));
        rpm.write(pid, mb + 8, i32le(0));
        rpm.write(pid, mb, i32le(REQ_PENDING));
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < deadline) {
            byte[] r = rpm.read(pid, mb, 4);
            if (r != null && r.length >= 4 && le32(r, 0) == REQ_DONE) {
                byte[] res = rpm.read(pid, mb + R_RC, 0x14);
                int rc = le32(res, 0);
                int tt = le32(res, R_TT - R_RC);
                int len = le32(res, R_LEN - R_RC);
                long dataPtr = le32(res, R_DATA - R_RC) & 0xffffffffL;
                byte[] data = null;
                if (tt == LUA_TSTRING && len > 0 && dataPtr != 0) {
                    data = rpm.read(pid, dataPtr, Math.min(len, RESULT_CAP));
                }
                rpm.write(pid, mb, i32le(REQ_IDLE));
                return new ExecResult(rc, tt, data);
            }
            try {
                Thread.sleep(2);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        rpm.write(pid, mb, i32le(REQ_IDLE));
        return new ExecResult(EXEC_TIMEOUT, 0, null);
    }

    private static byte[] buildEvalReturn(long mb, long gettop, long loadbuffer, long pcall, long settop) {
        byte[] o = new byte[256];
        int p = 0;
        o[p++] = 0x55;                                              // push ebp
        o[p++] = (byte) 0x8B; o[p++] = (byte) 0xEC;               // mov ebp,esp
        o[p++] = 0x56; o[p++] = 0x57; o[p++] = 0x53;             // push esi,edi,ebx
        o[p++] = (byte) 0xBE; p = putLe(o, p, (int) mb);          // mov esi, mailbox
        o[p++] = (byte) 0xFF; o[p++] = 0x75; o[p++] = 0x08;       // push [ebp+8]  ; L
        o[p++] = (byte) 0xB8; p = putLe(o, p, (int) gettop);      // mov eax, gettop
        o[p++] = (byte) 0xFF; o[p++] = (byte) 0xD0;               // call eax
        o[p++] = (byte) 0x83; o[p++] = (byte) 0xC4; o[p++] = 0x04;
        o[p++] = (byte) 0x8B; o[p++] = (byte) 0xF8;               // mov edi, eax  ; top0
        o[p++] = 0x68; p = putLe(o, p, (int) (mb + NAME_OFF));    // push name
        o[p++] = (byte) 0xFF; o[p++] = 0x75; o[p++] = 0x10;       // push [ebp+0x10] ; len
        o[p++] = (byte) 0xFF; o[p++] = 0x75; o[p++] = 0x0C;       // push [ebp+0xC]  ; code
        o[p++] = (byte) 0xFF; o[p++] = 0x75; o[p++] = 0x08;       // push [ebp+8]    ; L
        o[p++] = (byte) 0xB8; p = putLe(o, p, (int) loadbuffer);
        o[p++] = (byte) 0xFF; o[p++] = (byte) 0xD0;
        o[p++] = (byte) 0x83; o[p++] = (byte) 0xC4; o[p++] = 0x10;
        o[p++] = (byte) 0x89; o[p++] = (byte) 0x86; p = putLe(o, p, R_RC);  // mov [esi+R_RC],eax
        o[p++] = (byte) 0x85; o[p++] = (byte) 0xC0;               // test eax,eax
        o[p++] = 0x75; int jLoadErr = p++;                        // jnz capture
        o[p++] = 0x6A; o[p++] = 0x00;                             // push 0  errfunc
        o[p++] = 0x6A; o[p++] = 0x01;                             // push 1  nresults
        o[p++] = 0x6A; o[p++] = 0x00;                             // push 0  nargs
        o[p++] = (byte) 0xFF; o[p++] = 0x75; o[p++] = 0x08;       // push L
        o[p++] = (byte) 0xB8; p = putLe(o, p, (int) pcall);
        o[p++] = (byte) 0xFF; o[p++] = (byte) 0xD0;
        o[p++] = (byte) 0x83; o[p++] = (byte) 0xC4; o[p++] = 0x10;
        o[p++] = (byte) 0x89; o[p++] = (byte) 0x86; p = putLe(o, p, R_RC);  // mov [esi+R_RC],eax
        int capture = p;
        o[p++] = (byte) 0x8B; o[p++] = 0x4D; o[p++] = 0x08;       // mov ecx,[ebp+8]   ; L
        o[p++] = (byte) 0x8B; o[p++] = 0x49; o[p++] = 0x08;       // mov ecx,[ecx+8]   ; top
        o[p++] = (byte) 0x83; o[p++] = (byte) 0xE9; o[p++] = 0x10; // sub ecx,16       ; TValue* (sizeof=16)
        o[p++] = (byte) 0x8B; o[p++] = 0x01;                      // mov eax,[ecx]     ; gc ptr (Value)
        o[p++] = (byte) 0x8B; o[p++] = 0x51; o[p++] = 0x08;       // mov edx,[ecx+8]   ; tt
        o[p++] = (byte) 0x89; o[p++] = (byte) 0x96; p = putLe(o, p, R_TT);  // mov [esi+R_TT],edx
        o[p++] = (byte) 0x89; o[p++] = (byte) 0x86; p = putLe(o, p, R_PTR); // mov [esi+R_PTR],eax
        o[p++] = (byte) 0x83; o[p++] = (byte) 0xFA; o[p++] = 0x04; // cmp edx,4
        o[p++] = 0x75; int jNotStr = p++;                        // jne done
        o[p++] = (byte) 0x8B; o[p++] = 0x50; o[p++] = 0x0C;       // mov edx,[eax+0xC] ; len
        o[p++] = (byte) 0x89; o[p++] = (byte) 0x96; p = putLe(o, p, R_LEN);
        o[p++] = (byte) 0x8D; o[p++] = 0x50; o[p++] = 0x10;       // lea edx,[eax+0x10] ; data
        o[p++] = (byte) 0x89; o[p++] = (byte) 0x96; p = putLe(o, p, R_DATA);
        int done = p;
        o[p++] = 0x57;                                            // push edi  ; top0
        o[p++] = (byte) 0xFF; o[p++] = 0x75; o[p++] = 0x08;       // push L
        o[p++] = (byte) 0xB8; p = putLe(o, p, (int) settop);
        o[p++] = (byte) 0xFF; o[p++] = (byte) 0xD0;
        o[p++] = (byte) 0x83; o[p++] = (byte) 0xC4; o[p++] = 0x08;
        o[p++] = 0x5B; o[p++] = 0x5F; o[p++] = 0x5E;             // pop ebx,edi,esi
        o[p++] = (byte) 0x8B; o[p++] = (byte) 0xE5;               // mov esp,ebp
        o[p++] = 0x5D;                                            // pop ebp
        o[p++] = (byte) 0xC3;                                     // ret
        o[jLoadErr] = (byte) (capture - (jLoadErr + 1));
        o[jNotStr] = (byte) (done - (jNotStr + 1));
        return Arrays.copyOf(o, p);
    }

    private static byte[] hookStub(long m, byte[] stolen, long stubAddr, long retAddr) {
        byte[] o = new byte[160];
        int p = 0;
        o[p++] = 0x60;                                              // pushad
        o[p++] = (byte) 0x9C;                                      // pushfd
        o[p++] = (byte) 0xBE; p = putLe(o, p, (int) m);           // mov esi, mailbox
        o[p++] = (byte) 0x83; o[p++] = 0x3E; o[p++] = 0x01;       // cmp [esi], 1
        o[p++] = 0x75; int jnePass = p++;                         // jne .pass (rel8)
        o[p++] = (byte) 0xC7; o[p++] = 0x06; o[p++] = 0x02; o[p++] = 0; o[p++] = 0; o[p++] = 0; // mov [esi],2
        o[p++] = (byte) 0x8B; o[p++] = 0x46; o[p++] = ARGMODE_OFF; // mov eax,[esi+0x14]
        o[p++] = (byte) 0x85; o[p++] = (byte) 0xC0;               // test eax,eax
        o[p++] = 0x74; int jzOne = p++;                           // jz .one (rel8)
        o[p++] = (byte) 0xFF; o[p++] = 0x76; o[p++] = 0x04;       // push [esi+4]  ; len
        o[p++] = (byte) 0x8D; o[p++] = 0x46; o[p++] = CODE_OFF;   // lea eax,[esi+0x20] ; code
        o[p++] = 0x50;                                            // push eax
        o[p++] = (byte) 0xFF; o[p++] = 0x76; o[p++] = STATE_OFF;  // push [esi+0x10] ; state
        o[p++] = (byte) 0x8B; o[p++] = 0x46; o[p++] = FN_OFF;     // mov eax,[esi+0xC] ; fn
        o[p++] = (byte) 0xFF; o[p++] = (byte) 0xD0;               // call eax
        o[p++] = (byte) 0x83; o[p++] = (byte) 0xC4; o[p++] = 0x0C; // add esp,0xC
        o[p++] = (byte) 0xEB; int jmpStore = p++;                 // jmp .store (rel8)
        int oneLabel = p;
        o[p++] = (byte) 0xFF; o[p++] = 0x76; o[p++] = STATE_OFF;  // .one: push [esi+0x10]
        o[p++] = (byte) 0x8B; o[p++] = 0x46; o[p++] = FN_OFF;     // mov eax,[esi+0xC]
        o[p++] = (byte) 0xFF; o[p++] = (byte) 0xD0;               // call eax
        o[p++] = (byte) 0x83; o[p++] = (byte) 0xC4; o[p++] = 0x04; // add esp,4
        int storeLabel = p;
        o[p++] = (byte) 0x89; o[p++] = 0x46; o[p++] = 0x08;       // .store: mov [esi+8],eax
        o[p++] = (byte) 0xC7; o[p++] = 0x06; o[p++] = 0x03; o[p++] = 0; o[p++] = 0; o[p++] = 0; // mov [esi],3
        int passLabel = p;
        o[p++] = (byte) 0x9D;                                     // .pass: popfd
        o[p++] = 0x61;                                            // popad
        for (byte b : stolen) o[p++] = b;                        // original prologue
        o[p++] = (byte) 0xE9; p = putLe(o, p, (int) (retAddr - (stubAddr + p + 4))); // jmp back
        o[jnePass] = (byte) (passLabel - (jnePass + 1));
        o[jzOne] = (byte) (oneLabel - (jzOne + 1));
        o[jmpStore] = (byte) (storeLabel - (jmpStore + 1));
        return Arrays.copyOf(o, p);
    }

    private static int putLe(byte[] b, int off, int v) {
        b[off] = (byte) v;
        b[off + 1] = (byte) (v >> 8);
        b[off + 2] = (byte) (v >> 16);
        b[off + 3] = (byte) (v >> 24);
        return off + 4;
    }

    private static byte[] jmpRel32(long from, long to) {
        var b = ByteBuffer.allocate(5).order(ByteOrder.LITTLE_ENDIAN);
        b.put((byte) 0xE9).putInt((int) (to - (from + 5)));
        return b.array();
    }

    private static byte[] i32le(int v) {
        return ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(v).array();
    }

    private static int le32(byte[] b, int off) {
        return (b[off] & 0xff) | ((b[off + 1] & 0xff) << 8)
                | ((b[off + 2] & 0xff) << 16) | ((b[off + 3] & 0xff) << 24);
    }

    public static int exec(ProcessMemory rpm, int pid, long state, long execFn, String code,
            int ptrSize, boolean freeze) {
        byte[] cb = code.getBytes(StandardCharsets.UTF_8);
        long codeAddr = rpm.alloc(pid, cb.length + 1, false);
        if (codeAddr == 0) throw new IllegalStateException("VirtualAllocEx(code) failed");
        long scAddr = 0;
        try {
            rpm.write(pid, codeAddr, cb);
            byte[] sc = ptrSize == 8
                    ? shellcode64(state, codeAddr, cb.length, execFn)
                    : shellcode32(state, codeAddr, cb.length, execFn);
            scAddr = rpm.alloc(pid, sc.length, true);
            if (scAddr == 0) throw new IllegalStateException("VirtualAllocEx(shellcode) failed");
            rpm.write(pid, scAddr, sc);
            if (freeze) rpm.suspendAll(pid);
            try {
                return rpm.callRemote(pid, scAddr, 0, 8000);
            } finally {
                if (freeze) rpm.resumeAll(pid);
            }
        } finally {
            if (scAddr != 0) rpm.freeRemote(pid, scAddr);
            rpm.freeRemote(pid, codeAddr);
        }
    }

    private static byte[] shellcode32(long state, long codeAddr, int len, long execFn) {
        var b = ByteBuffer.allocate(32).order(ByteOrder.LITTLE_ENDIAN);
        b.put((byte) 0x68).putInt(len);                       // push len
        b.put((byte) 0x68).putInt((int) codeAddr);            // push codeAddr
        b.put((byte) 0x68).putInt((int) state);               // push L
        b.put((byte) 0xB8).putInt((int) execFn);              // mov eax, execFn
        b.put((byte) 0xFF).put((byte) 0xD0);                  // call eax
        b.put((byte) 0x83).put((byte) 0xC4).put((byte) 0x0C); // add esp, 0xC
        b.put((byte) 0xC2).put((byte) 0x04).put((byte) 0x00); // ret 4
        return Arrays.copyOf(b.array(), b.position());
    }

    private static byte[] shellcode64(long state, long codeAddr, int len, long execFn) {
        var b = ByteBuffer.allocate(64).order(ByteOrder.LITTLE_ENDIAN);
        b.put((byte) 0x48).put((byte) 0xB9).putLong(state);          // mov rcx, L
        b.put((byte) 0x48).put((byte) 0xBA).putLong(codeAddr);       // mov rdx, codeAddr
        b.put((byte) 0x49).put((byte) 0xB8).putLong(len & 0xffffffffL); // mov r8, len
        b.put((byte) 0x48).put((byte) 0xB8).putLong(execFn);         // mov rax, execFn
        b.put((byte) 0x48).put((byte) 0x83).put((byte) 0xEC).put((byte) 0x28); // sub rsp, 0x28
        b.put((byte) 0xFF).put((byte) 0xD0);                         // call rax
        b.put((byte) 0x48).put((byte) 0x83).put((byte) 0xC4).put((byte) 0x28); // add rsp, 0x28
        b.put((byte) 0xC3);                                          // ret
        return Arrays.copyOf(b.array(), b.position());
    }

    private static long readPtr(byte[] b, int off, int ptrSize) {
        long v = 0;
        for (int i = 0; i < ptrSize; i++) v |= (b[off + i] & 0xffL) << (8 * i);
        return v;
    }

    private static int indexOf(byte[] hay, byte[] needle) {
        int limit = hay.length - needle.length;
        outer:
        for (int i = 0; i <= limit; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (hay[i + j] != needle[j]) continue outer;
            }
            return i;
        }
        return -1;
    }
}
