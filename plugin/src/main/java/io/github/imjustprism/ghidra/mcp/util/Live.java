package io.github.imjustprism.ghidra.mcp.util;

import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Static façade over the connector-less live process, callable from ghidra_eval scripts so the AI can
 * read/write/scan the attached process with the full Ghidra API in scope. Bound by DebuggerHandlers on
 * live_attach; reads the current anchor PID dynamically so it survives self-healing re-resolution.
 */
public final class Live {

    public interface Source {
        ProcessMemory rpm();

        Integer pid();

        int pointerSize();
    }

    private static volatile Source source;

    private Live() {
    }

    public static void bind(Source s) {
        source = s;
    }

    public static boolean attached() {
        var s = source;
        return s != null && s.pid() != null && s.rpm().available();
    }

    public static int pid() {
        return require().pid();
    }

    public static int pointerSize() {
        return require().pointerSize();
    }

    public static byte[] read(long address, int length) {
        var s = require();
        var b = s.rpm().read(s.pid(), address, length);
        if (b == null) {
            throw new IllegalStateException("live read failed at 0x" + Long.toHexString(address)
                    + " (" + length + " bytes; unmapped or process exited)");
        }
        return b;
    }

    public static boolean write(long address, byte[] data) {
        var s = require();
        return s.rpm().write(s.pid(), address, data);
    }

    public static int readInt(long address) {
        return (int) le(read(address, 4), 4);
    }

    public static long readUInt(long address) {
        return le(read(address, 4), 4) & 0xffffffffL;
    }

    public static long readLong(long address) {
        return le(read(address, 8), 8);
    }

    public static long readPtr(long address) {
        return le(read(address, pointerSize()), pointerSize());
    }

    public static float readFloat(long address) {
        return Float.intBitsToFloat(readInt(address));
    }

    public static double readDouble(long address) {
        return Double.longBitsToDouble(readLong(address));
    }

    public static String readString(long address, int maxLength) {
        var b = read(address, maxLength);
        int n = 0;
        while (n < b.length && b[n] != 0) n++;
        return new String(b, 0, n, StandardCharsets.US_ASCII);
    }

    public static long ptrChain(long base, long... offsets) {
        long cur = base;
        for (long off : offsets) cur = readPtr(cur) + off;
        return cur;
    }

    public static void writeBytes(long address, byte[] data) {
        if (!write(address, data)) {
            throw new IllegalStateException("live write failed at 0x" + Long.toHexString(address));
        }
    }

    public static void writeInt(long address, int value) {
        writeBytes(address, new byte[]{(byte) value, (byte) (value >> 8),
                (byte) (value >> 16), (byte) (value >> 24)});
    }

    public static void writeFloat(long address, float value) {
        writeInt(address, Float.floatToRawIntBits(value));
    }

    public static List<ProcessMemory.Region> regions() {
        var s = require();
        return s.rpm().enumerateRegions(s.pid());
    }

    public static long alloc(int size) {
        var s = require();
        return s.rpm().alloc(s.pid(), size, false);
    }

    public static long allocExec(int size) {
        var s = require();
        return s.rpm().alloc(s.pid(), size, true);
    }

    public static void freeRemote(long address) {
        var s = require();
        s.rpm().freeRemote(s.pid(), address);
    }

    public static int callRemote(long startAddress, long argument) {
        var s = require();
        return s.rpm().callRemote(s.pid(), startAddress, argument, 8000);
    }

    private static Source require() {
        var s = source;
        if (s == null || s.pid() == null) {
            throw new IllegalStateException("No live session. Call live_attach first.");
        }
        return s;
    }

    private static long le(byte[] b, int n) {
        long v = 0;
        for (int i = 0; i < n && i < b.length; i++) v |= (b[i] & 0xffL) << (8 * i);
        return v;
    }
}
