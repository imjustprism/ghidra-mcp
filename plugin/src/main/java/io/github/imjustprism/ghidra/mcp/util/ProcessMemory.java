package io.github.imjustprism.ghidra.mcp.util;

import com.sun.jna.Memory;
import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.BaseTSD;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.WinNT;
import com.sun.jna.ptr.IntByReference;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public final class ProcessMemory {

    private static final int ACCESS = WinNT.PROCESS_VM_READ | WinNT.PROCESS_VM_WRITE
            | WinNT.PROCESS_VM_OPERATION | WinNT.PROCESS_QUERY_INFORMATION;

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
