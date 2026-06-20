package io.github.imjustprism.ghidra.mcp.util;

import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.BaseTSD;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.Tlhelp32;
import com.sun.jna.platform.win32.WinDef;
import com.sun.jna.platform.win32.WinNT;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.win32.StdCallLibrary;
import com.sun.jna.win32.W32APIOptions;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public final class ProcessMemory {

    private interface ThreadCtl extends StdCallLibrary {
        ThreadCtl INSTANCE = Native.load("kernel32", ThreadCtl.class, W32APIOptions.DEFAULT_OPTIONS);

        int SuspendThread(WinNT.HANDLE thread);

        int ResumeThread(WinNT.HANDLE thread);

        int Wow64SuspendThread(WinNT.HANDLE thread);

        boolean Wow64GetThreadContext(WinNT.HANDLE thread, Pointer context);
    }

    private static final int THREAD_GET_CONTEXT = 0x0008;
    private static final int WOW64_CONTEXT_CONTROL = 0x00010001;
    private static final int WOW64_EIP_OFFSET = 0xB8;
    private static final int WOW64_CONTEXT_SIZE = 0x500;
    private static final int HOOK_INSTALL_ATTEMPTS = 40;

    private static final int PROCESS_CREATE_THREAD = 0x0002;
    private static final int ACCESS = WinNT.PROCESS_VM_READ | WinNT.PROCESS_VM_WRITE
            | WinNT.PROCESS_VM_OPERATION | WinNT.PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD;

    private static final int MEM_COMMIT = 0x1000;
    private static final int MEM_RESERVE = 0x2000;
    private static final int MEM_RELEASE = 0x8000;
    private static final int PAGE_READWRITE = 0x04;
    private static final int PAGE_EXECUTE_READWRITE = 0x40;
    private static final int THREAD_SUSPEND_RESUME = 0x0002;

    private static final int PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    private static final int PROCESS_PROBE = PROCESS_QUERY_LIMITED_INFORMATION | WinNT.PROCESS_VM_READ;
    public static final int ERROR_ACCESS_DENIED = 5;

    private static final int READABLE = 0xEE;
    private static final int WRITABLE = 0xCC;
    private static final int NO_ACCESS = 0x101;
    private static final long MIN_REGION = 0x10000L;
    private static final long MAX_USER_ADDR = 0x7fff0000L;
    private static final long MAX_REGION_BYTES = 512L * 1024 * 1024;

    private static final boolean LOADED = probe();

    private final Map<Integer, WinNT.HANDLE> handles = new ConcurrentHashMap<>();

    private static boolean probe() {
        try {
            return Kernel32.INSTANCE != null
                    && System.getProperty("os.name", "").toLowerCase().contains("win");
        } catch (Throwable t) {
            return false;
        }
    }

    public boolean available() {
        return LOADED;
    }

    public byte[] read(int pid, long address, int length) {
        if (!LOADED || length <= 0) return null;
        var handle = handle(pid);
        if (handle == null) return null;
        var buffer = new Memory(length);
        var read = new IntByReference(0);
        boolean ok = Kernel32.INSTANCE.ReadProcessMemory(
                handle, new Pointer(address), buffer, length, read);
        int n = read.getValue();
        if (!ok && n <= 0) {
            invalidate(pid);
            return null;
        }
        return buffer.getByteArray(0, Math.min(n, length));
    }

    public boolean write(int pid, long address, byte[] data) {
        if (!LOADED || data.length == 0) return false;
        var handle = handle(pid);
        if (handle == null) return false;
        var buffer = new Memory(data.length);
        buffer.write(0, data, 0, data.length);
        var written = new IntByReference(0);
        boolean ok = Kernel32.INSTANCE.WriteProcessMemory(
                handle, new Pointer(address), buffer, data.length, written);
        if (!ok || written.getValue() != data.length) {
            invalidate(pid);
            return false;
        }
        return true;
    }

    public record Region(long base, long size, boolean writable) {}

    public List<Region> enumerateRegions(int pid) {
        var out = new ArrayList<Region>();
        if (!LOADED) return out;
        var handle = handle(pid);
        if (handle == null) return out;
        var mbi = new WinNT.MEMORY_BASIC_INFORMATION();
        var mbiSize = new BaseTSD.SIZE_T(mbi.size());
        long addr = MIN_REGION;
        while (addr < MAX_USER_ADDR) {
            var written = Kernel32.INSTANCE.VirtualQueryEx(
                    handle, new Pointer(addr), mbi, mbiSize);
            if (written == null || written.intValue() == 0) break;
            long base = Pointer.nativeValue(mbi.baseAddress);
            long size = mbi.regionSize.longValue();
            if (size <= 0) break;
            int state = mbi.state.intValue();
            int prot = mbi.protect.intValue();
            if (state == WinNT.MEM_COMMIT && (prot & READABLE) != 0
                    && (prot & NO_ACCESS) == 0 && size <= MAX_REGION_BYTES) {
                out.add(new Region(base, size, (prot & WRITABLE) != 0));
            }
            long next = base + size;
            if (next <= addr) break;
            addr = next;
        }
        return out;
    }

    public record Process(int pid, String name) {}

    public record Module(String name, long base, long size) {}

    public List<Process> listProcesses() {
        var out = new ArrayList<Process>();
        if (!LOADED) return out;
        var snap = snapshot(Tlhelp32.TH32CS_SNAPPROCESS, 0);
        if (snap == null) return out;
        try {
            var pe = new Tlhelp32.PROCESSENTRY32();
            if (Kernel32.INSTANCE.Process32First(snap, pe)) {
                do {
                    out.add(new Process(pe.th32ProcessID.intValue(), cstr(pe.szExeFile)));
                } while (Kernel32.INSTANCE.Process32Next(snap, pe));
            }
        } finally {
            Kernel32.INSTANCE.CloseHandle(snap);
        }
        return out;
    }

    public List<Module> modules(int pid) {
        if (!LOADED) return List.of();
        int flags = Tlhelp32.TH32CS_SNAPMODULE.intValue() | Tlhelp32.TH32CS_SNAPMODULE32.intValue();
        var snap = snapshot(new WinDef.DWORD(flags), pid);
        if (snap == null) return List.of();
        var byBase = new java.util.LinkedHashMap<Long, Module>();
        try {
            var me = new Tlhelp32.MODULEENTRY32W();
            me.dwSize = new WinDef.DWORD(me.size());
            if (Kernel32.INSTANCE.Module32FirstW(snap, me)) {
                do {
                    long base = Pointer.nativeValue(me.modBaseAddr);
                    byBase.putIfAbsent(base, new Module(me.szModule(), base, me.modBaseSize.longValue()));
                } while (Kernel32.INSTANCE.Module32NextW(snap, me));
            }
        } finally {
            Kernel32.INSTANCE.CloseHandle(snap);
        }
        return new ArrayList<>(byBase.values());
    }

    public List<Integer> threadIds(int pid) {
        var out = new ArrayList<Integer>();
        if (!LOADED) return out;
        var snap = snapshot(Tlhelp32.TH32CS_SNAPTHREAD, 0);
        if (snap == null) return out;
        try {
            var te = new Tlhelp32.THREADENTRY32();
            if (Kernel32.INSTANCE.Thread32First(snap, te)) {
                do {
                    if (te.th32OwnerProcessID == pid) out.add(te.th32ThreadID);
                } while (Kernel32.INSTANCE.Thread32Next(snap, te));
            }
        } finally {
            Kernel32.INSTANCE.CloseHandle(snap);
        }
        return out;
    }

    public Map<String, Long> exports(int pid, long base) {
        var out = new java.util.HashMap<String, Long>();
        if (!LOADED) return out;
        byte[] hdr = read(pid, base, 0x400);
        if (hdr == null || hdr.length < 0x40) return out;
        int lfanew = i32(hdr, 0x3C);
        if (lfanew <= 0 || lfanew + 0x78 > hdr.length || hdr[lfanew] != 'P' || hdr[lfanew + 1] != 'E') {
            return out;
        }
        int opt = lfanew + 24;
        int magic = u16(hdr, opt);
        int ddOff = opt + (magic == 0x20b ? 0x70 : 0x60);
        long exportRva = i32(hdr, ddOff) & 0xffffffffL;
        if (exportRva == 0) return out;
        byte[] ed = read(pid, base + exportRva, 0x28);
        if (ed == null || ed.length < 0x28) return out;
        int numNames = i32(ed, 0x18);
        long addrFuncs = i32(ed, 0x1C) & 0xffffffffL;
        long addrNames = i32(ed, 0x20) & 0xffffffffL;
        long addrOrds = i32(ed, 0x24) & 0xffffffffL;
        if (numNames <= 0 || numNames > 100000) return out;
        byte[] names = read(pid, base + addrNames, numNames * 4);
        byte[] ords = read(pid, base + addrOrds, numNames * 2);
        if (names == null || ords == null) return out;
        for (int i = 0; i < numNames; i++) {
            long nameRva = i32(names, i * 4) & 0xffffffffL;
            byte[] ns = read(pid, base + nameRva, 96);
            if (ns == null) continue;
            int ord = u16(ords, i * 2);
            byte[] f = read(pid, base + addrFuncs + ord * 4L, 4);
            if (f == null) continue;
            out.put(cstr(ns), i32(f, 0) & 0xffffffffL);
        }
        return out;
    }

    private static int i32(byte[] b, int off) {
        return (b[off] & 0xff) | ((b[off + 1] & 0xff) << 8)
                | ((b[off + 2] & 0xff) << 16) | ((b[off + 3] & 0xff) << 24);
    }

    private static int u16(byte[] b, int off) {
        return (b[off] & 0xff) | ((b[off + 1] & 0xff) << 8);
    }

    public boolean isWow64(int pid) {
        if (!LOADED) return false;
        var h = handle(pid);
        if (h == null) return false;
        var res = new IntByReference(0);
        return Kernel32.INSTANCE.IsWow64Process(h, res) && res.getValue() != 0;
    }

    public int probeOpen(int pid) {
        if (!LOADED) return -1;
        var h = Kernel32.INSTANCE.OpenProcess(PROCESS_PROBE, false, pid);
        if (h == null || h.getPointer() == Pointer.NULL) return Kernel32.INSTANCE.GetLastError();
        Kernel32.INSTANCE.CloseHandle(h);
        return 0;
    }

    private static WinNT.HANDLE snapshot(WinDef.DWORD flags, int pid) {
        var h = Kernel32.INSTANCE.CreateToolhelp32Snapshot(flags, new WinDef.DWORD(pid));
        return (h == null || Pointer.nativeValue(h.getPointer()) == -1L) ? null : h;
    }

    private static String cstr(char[] c) {
        int n = 0;
        while (n < c.length && c[n] != 0) n++;
        return new String(c, 0, n);
    }

    private static String cstr(byte[] b) {
        int n = 0;
        while (n < b.length && b[n] != 0) n++;
        return new String(b, 0, n, java.nio.charset.StandardCharsets.US_ASCII);
    }

    public long alloc(int pid, int size, boolean executable) {
        if (!LOADED || size <= 0) return 0;
        var handle = handle(pid);
        if (handle == null) return 0;
        var p = Kernel32.INSTANCE.VirtualAllocEx(handle, null, new BaseTSD.SIZE_T(size),
                MEM_COMMIT | MEM_RESERVE, executable ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE);
        return p == null ? 0 : Pointer.nativeValue(p);
    }

    public void freeRemote(int pid, long address) {
        if (!LOADED || address == 0) return;
        var handle = handle(pid);
        if (handle == null) return;
        Kernel32.INSTANCE.VirtualFreeEx(handle, new Pointer(address), new BaseTSD.SIZE_T(0), MEM_RELEASE);
    }

    public int callRemote(int pid, long startAddress, long argument, int timeoutMs) {
        if (!LOADED) return -1;
        var handle = handle(pid);
        if (handle == null) return -1;
        var thread = Kernel32.INSTANCE.CreateRemoteThread(handle, null, 0,
                new Pointer(startAddress), argument == 0 ? Pointer.NULL : new Pointer(argument), 0, null);
        if (thread == null || thread.getPointer() == Pointer.NULL) return -2;
        try {
            Kernel32.INSTANCE.WaitForSingleObject(thread, timeoutMs);
            var exit = new IntByReference(0);
            Kernel32.INSTANCE.GetExitCodeThread(thread, exit);
            return exit.getValue();
        } finally {
            Kernel32.INSTANCE.CloseHandle(thread);
        }
    }

    public volatile String lastHookDiag = "";

    public boolean installHook(int pid, long addr, byte[] patch, int guardLen) {
        if (!LOADED) return false;
        for (int attempt = 0; attempt < HOOK_INSTALL_ATTEMPTS; attempt++) {
            var handles = new ArrayList<WinNT.HANDLE>();
            for (int tid : threadIds(pid)) {
                var h = Kernel32.INSTANCE.OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT, false, tid);
                if (h != null && h.getPointer() != Pointer.NULL) handles.add(h);
            }
            int suspended = 0;
            int ctxOk = 0;
            boolean inRange = false;
            for (var h : handles) {
                if (ThreadCtl.INSTANCE.Wow64SuspendThread(h) != -1) suspended++;
            }
            try {
                var ctx = new Memory(WOW64_CONTEXT_SIZE);
                for (var h : handles) {
                    ctx.clear();
                    ctx.setInt(0, WOW64_CONTEXT_CONTROL);
                    if (ThreadCtl.INSTANCE.Wow64GetThreadContext(h, ctx)) {
                        ctxOk++;
                        long eip = ctx.getInt(WOW64_EIP_OFFSET) & 0xffffffffL;
                        if (eip >= addr && eip < addr + guardLen) {
                            inRange = true;
                            break;
                        }
                    }
                }
                if (!inRange) {
                    boolean ok = write(pid, addr, patch);
                    lastHookDiag = "attempt=" + attempt + " threads=" + handles.size()
                            + " suspended=" + suspended + " ctxOk=" + ctxOk + " write=" + ok;
                    return ok;
                }
            } finally {
                for (var h : handles) {
                    ThreadCtl.INSTANCE.ResumeThread(h);
                    Kernel32.INSTANCE.CloseHandle(h);
                }
            }
            try {
                Thread.sleep(1);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        lastHookDiag = "FAILED: never found a clear patch window in " + HOOK_INSTALL_ATTEMPTS + " attempts";
        return false;
    }

    public void suspendAll(int pid) {
        forEachThread(pid, true);
    }

    public void resumeAll(int pid) {
        forEachThread(pid, false);
    }

    private void forEachThread(int pid, boolean suspend) {
        if (!LOADED) return;
        for (int tid : threadIds(pid)) {
            var h = Kernel32.INSTANCE.OpenThread(THREAD_SUSPEND_RESUME, false, tid);
            if (h == null || h.getPointer() == Pointer.NULL) continue;
            try {
                if (suspend) ThreadCtl.INSTANCE.SuspendThread(h);
                else ThreadCtl.INSTANCE.ResumeThread(h);
            } finally {
                Kernel32.INSTANCE.CloseHandle(h);
            }
        }
    }

    private WinNT.HANDLE handle(int pid) {
        return handles.computeIfAbsent(pid, p -> {
            var h = Kernel32.INSTANCE.OpenProcess(ACCESS, false, p);
            return (h == null || h.getPointer() == Pointer.NULL) ? null : h;
        });
    }

    private void invalidate(int pid) {
        var h = handles.remove(pid);
        if (h != null) Kernel32.INSTANCE.CloseHandle(h);
    }

    public void close() {
        if (!LOADED) return;
        for (var h : handles.values()) {
            try {
                Kernel32.INSTANCE.CloseHandle(h);
            } catch (Throwable ignored) {
            }
        }
        handles.clear();
    }
}
