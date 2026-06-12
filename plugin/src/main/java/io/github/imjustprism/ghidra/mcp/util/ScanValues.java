package io.github.imjustprism.ghidra.mcp.util;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

public final class ScanValues {

    public enum Type {
        I8(1), I16(2), I32(4), I64(8), F32(4), F64(8), STRING(1), WSTRING(2), BYTES(1);

        public final int width;

        Type(int width) {
            this.width = width;
        }
    }

    private ScanValues() {}

    public static Type parseType(String s) {
        if (s == null || s.isBlank()) return Type.I32;
        return switch (s.toLowerCase()) {
            case "i8", "byte", "int8" -> Type.I8;
            case "i16", "short", "int16" -> Type.I16;
            case "i32", "int", "int32", "dword" -> Type.I32;
            case "i64", "long", "int64", "qword" -> Type.I64;
            case "f32", "float" -> Type.F32;
            case "f64", "double" -> Type.F64;
            case "string", "str" -> Type.STRING;
            case "wstring", "utf16", "unicode", "wstr" -> Type.WSTRING;
            case "bytes", "aob", "hex" -> Type.BYTES;
            default -> throw new IllegalArgumentException("unknown scan type: " + s);
        };
    }

    public static byte[] encode(Type type, String value, boolean bigEndian) {
        var order = bigEndian ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;
        return switch (type) {
            case I8 -> new byte[]{(byte) parseLong(value)};
            case I16 -> ByteBuffer.allocate(2).order(order).putShort((short) parseLong(value)).array();
            case I32 -> ByteBuffer.allocate(4).order(order).putInt((int) parseLong(value)).array();
            case I64 -> ByteBuffer.allocate(8).order(order).putLong(parseLong(value)).array();
            case F32 -> ByteBuffer.allocate(4).order(order).putFloat(Float.parseFloat(value)).array();
            case F64 -> ByteBuffer.allocate(8).order(order).putDouble(Double.parseDouble(value)).array();
            case STRING -> value.getBytes(StandardCharsets.UTF_8);
            case WSTRING -> value.getBytes(bigEndian ? StandardCharsets.UTF_16BE : StandardCharsets.UTF_16LE);
            case BYTES -> Bufs.parseHex(value);
        };
    }

    public static double decodeNumber(Type type, byte[] buf, boolean bigEndian) {
        return decodeNumber(type, buf, 0, bigEndian);
    }

    public static double decodeNumber(Type type, byte[] buf, int off, boolean bigEndian) {
        if (off + type.width > buf.length) return Double.NaN;
        var bb = ByteBuffer.wrap(buf, off, type.width)
                .order(bigEndian ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);
        return switch (type) {
            case I8 -> bb.get();
            case I16 -> bb.getShort();
            case I32 -> bb.getInt();
            case I64 -> bb.getLong();
            case F32 -> bb.getFloat();
            case F64 -> bb.getDouble();
            case STRING, WSTRING, BYTES -> Double.NaN;
        };
    }

    private static long parseLong(String s) {
        var v = s.trim();
        return (v.startsWith("0x") || v.startsWith("0X"))
                ? Long.parseUnsignedLong(v.substring(2), 16) : Long.parseLong(v);
    }
}
