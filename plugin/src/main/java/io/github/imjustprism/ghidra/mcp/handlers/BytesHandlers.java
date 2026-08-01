package io.github.imjustprism.ghidra.mcp.handlers;

import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;
import io.github.imjustprism.ghidra.mcp.http.Http;
import io.github.imjustprism.ghidra.mcp.http.Page;
import io.github.imjustprism.ghidra.mcp.http.RouteTable;
import io.github.imjustprism.ghidra.mcp.util.Bufs;
import io.github.imjustprism.ghidra.mcp.util.DataTypes;
import io.github.imjustprism.ghidra.mcp.util.FileGuard;
import io.github.imjustprism.ghidra.mcp.util.Live;
import io.github.imjustprism.ghidra.mcp.util.LiveBases;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.ProcessMemory;
import io.github.imjustprism.ghidra.mcp.util.Responses;
import io.github.imjustprism.ghidra.mcp.util.Strings;

import java.nio.charset.StandardCharsets;
import java.util.Map;

public final class BytesHandlers {

    private final PluginContext ctx;

    public BytesHandlers(PluginContext ctx) {
        this.ctx = ctx;
    }

    private java.io.File requireAllowedPath(String path) {
        return FileGuard.requireAllowedPath(ctx, path);
    }

    public void register(RouteTable routes) {
        routes.getQuery("/read_bytes", q -> readBytes(q.get("address"), Http.parseIntOrDefault(q.get("length"), 64)));
        routes.getQuery("/hex_dump", q -> hexDump(q.get("address"), Http.parseIntOrDefault(q.get("length"), 128)));
        routes.getQuery("/search", q -> switch (q.getOrDefault("kind", "bytes")) {
            case "string" -> findString(q.get("query"), Page.from(q), q);
            case "text" -> findText(q.get("query"), Page.from(q), q);
            case "signature" -> io.github.imjustprism.ghidra.mcp.analysis.Signatures
                    .findSignature(ctx, q.get("query"), Page.from(q), q);
            default -> searchBytes(q.get("query"), Page.from(q), q);
        });
        routes.postForm("/patch_bytes", p -> patchBytes(p.get("address"), p.get("hex"),
                Http.parseBool(p.get("disassemble"), false)));
        routes.postForm("/nop_range", p -> nopRange(p.get("address"), Http.parseIntOrDefault(p.get("length"), 0)));
        routes.postForm("/export_binary", p -> exportBinary(p.get("path")));
        routes.postForm("/write_artifact", p -> writeArtifact(p.get("path"), p.get("content")));
        routes.postForm("/save_program", p -> saveProgram());
        routes.postForm("/xor_decrypt", p -> xorDecrypt(p.get("address"), Http.parseIntOrDefault(p.get("length"), 0), p.get("key")));
        routes.postForm("/import_memory_dump", p -> importMemoryDump(p.get("address"), p.get("path")));
    }

    public String readBytes(String addr, int length) {
        if (length <= 0 || length > 65536) throw new IllegalArgumentException("Length must be 1..65536");
        var live = tryLiveRead(addr, length);
        if (live != null) {
            return "0x" + Long.toHexString(live.address()) + "\t" + live.bytes().length + "\t"
                    + Bufs.hex(live.bytes(), live.bytes().length) + "\t# live";
        }
        return ctx.withAddress(addr, (program, a) -> {
            try {
                var buf = new byte[length];
                int read = program.getMemory().getBytes(a, buf, 0, length);
                return Responses.addr(a) + "\t" + read + "\t" + Bufs.hex(buf, read);
            } catch (Exception e) {
                var fallback = tryLiveRead(addr, length);
                if (fallback != null) {
                    return "0x" + Long.toHexString(fallback.address()) + "\t" + fallback.bytes().length + "\t"
                            + Bufs.hex(fallback.bytes(), fallback.bytes().length) + "\t# live";
                }
                throw new IllegalStateException("Error reading memory: " + e.getMessage(), e);
            }
        });
    }

    public String hexDump(String addr, int length) {
        if (length <= 0 || length > 65536) throw new IllegalArgumentException("Length must be 1..65536");
        var live = tryLiveRead(addr, length);
        if (live != null) return formatHexDump(live.address(), live.bytes(), live.bytes().length, true);
        return ctx.withAddress(addr, (program, a) -> {
            try {
                var buf = new byte[length];
                int read = program.getMemory().getBytes(a, buf, 0, length);
                return formatHexDump(a.getOffset(), buf, read, false);
            } catch (Exception e) {
                var fallback = tryLiveRead(addr, length);
                if (fallback != null) {
                    return formatHexDump(fallback.address(), fallback.bytes(), fallback.bytes().length, true);
                }
                throw new IllegalStateException("Error reading memory: " + e.getMessage(), e);
            }
        });
    }

    private record LiveBuf(long address, byte[] bytes) {}

    private static LiveBuf tryLiveRead(String addr, int length) {
        if (!Live.attached() || addr == null || addr.isBlank()) return null;
        boolean force = LiveBases.isPseudo(addr) || looksDynamic(addr);
        if (!force) return null;
        try {
            long va = LiveBases.resolve(new ProcessMemory(), Live.pid(), addr);
            var buf = Live.read(va, length);
            return new LiveBuf(va, buf);
        } catch (RuntimeException e) {
            if (LiveBases.isPseudo(addr)) throw e;
            return null;
        }
    }

    private static boolean looksDynamic(String addr) {
        var t = addr.trim();
        if (t.regionMatches(true, 0, "rva:", 0, 4)) return false;
        try {
            long v = t.startsWith("0x") || t.startsWith("0X")
                    ? Long.parseUnsignedLong(t.substring(2), 16)
                    : Long.parseUnsignedLong(t, 16);
            return v > 0x7_0000_0000L;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    private static String formatHexDump(long base, byte[] buf, int read, boolean live) {
        var sb = new StringBuilder(64 + (read / 16 + 1) * 76);
        sb.append("# format=hex; addr=hex; rows=16B");
        if (live) sb.append("; live");
        sb.append('\n');
        final char[] HEX = "0123456789abcdef".toCharArray();
        for (int off = 0; off < read; off += 16) {
            long line = base + off;
            int row = Math.min(16, read - off);
            sb.append(Long.toHexString(line)).append("  ");
            for (int i = 0; i < row; i++) {
                int b = buf[off + i] & 0xFF;
                sb.append(HEX[b >>> 4]).append(HEX[b & 0xF]).append(' ');
            }
            for (int pad = row; pad < 16; pad++) sb.append("   ");
            sb.append(" |");
            for (int i = 0; i < row; i++) {
                int b = buf[off + i] & 0xFF;
                sb.append(b >= 32 && b < 127 ? (char) b : '.');
            }
            sb.append("|\n");
        }
        return sb.toString();
    }

    public String searchBytes(String pattern, Page p, Map<String, String> q) {
        if (pattern == null || pattern.isBlank()) throw new IllegalArgumentException("Pattern is required");
        return ctx.withProgram(program -> {
            var normalized = pattern.replace(" ", "").toUpperCase();
            if (normalized.length() % 2 != 0) throw new IllegalArgumentException("Pattern must have even length");
            var bytes = new byte[normalized.length() / 2];
            var mask = new byte[bytes.length];
            for (int i = 0; i < bytes.length; i++) {
                var hi = normalized.charAt(i * 2);
                var lo = normalized.charAt(i * 2 + 1);
                if (hi == '?' && lo == '?') {
                    mask[i] = 0;
                } else if (hi == '?' || lo == '?') {
                    throw new IllegalArgumentException("Partial-nibble wildcards unsupported. Use full ?? bytes");
                } else {
                    bytes[i] = (byte) Integer.parseInt(normalized.substring(i * 2, i * 2 + 2), 16);
                    mask[i] = (byte) 0xFF;
                }
            }
            Memory memory = program.getMemory();
            var start = q.get("start");
            boolean cursorMode = start != null && !start.isBlank();
            Address cursor;
            if (cursorMode) {
                cursor = program.getAddressFactory().getAddress(start.trim());
                if (cursor == null) throw new IllegalArgumentException("Invalid start address: " + start);
            } else {
                cursor = memory.getMinAddress();
            }
            int off = cursorMode ? 0 : p.offset();
            var t = Responses.table(p, q, new String[]{"addr"});
            int found = 0, kept = 0;
            Address resume = null;
            var monitor = new ConsoleTaskMonitor();
            while (cursor != null) {
                Address next = memory.findBytes(cursor, bytes, mask, true, monitor);
                if (next == null) break;
                found++;
                if (found > off && kept < p.limit()) {
                    t.row(Responses.addr(next));
                    if (++kept == p.limit()) { resume = next.next(); break; }
                }
                cursor = next.next();
            }
            var body = t.total(found).build();
            if (Responses.pickFmt(q) == Responses.Fmt.JSON) {
                var nextCursor = resume == null ? "null" : '"' + resume.toString() + '"';
                return "{\"matches\":" + body + ",\"next_cursor\":" + nextCursor + "}";
            }
            if (resume != null) {
                body += "# next_cursor: " + resume + "\n";
            }
            return body;
        });
    }

    public String findString(String value, Page p, Map<String, String> q) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException("Value is required");
        return ctx.withProgram(program -> {
            var needle = value.toLowerCase();
            var t = Responses.table(p, q, new String[]{"addr", "value"});
            var w = new Responses.Window(p);
            var it = program.getListing().getDefinedData(true);
            while (it.hasNext()) {
                var data = it.next();
                if (data == null || !DataTypes.isStringLike(data)) continue;
                var s = data.getValue() != null ? data.getValue().toString() : "";
                if (!s.toLowerCase().contains(needle)) continue;
                if (!w.take()) continue;
                t.row(Responses.addr(data.getAddress()), Strings.escapeString(s));
            }
            return t.total(w.total()).build();
        });
    }

    public String findText(String value, Page p, Map<String, String> q) {
        if (value == null || value.isEmpty()) throw new IllegalArgumentException("query is required");
        return ctx.withProgram(program -> {
            var mem = program.getMemory();
            var monitor = new ConsoleTaskMonitor();
            var t = Responses.table(p, q, new String[]{"addr", "enc"});
            var w = new Responses.Window(p);
            int cap = p.offset() + p.limit();
            scanText(mem, monitor, value.getBytes(StandardCharsets.ISO_8859_1), "ascii", t, w, cap);
            scanText(mem, monitor, value.getBytes(StandardCharsets.UTF_16LE), "utf16le", t, w, cap);
            return t.total(w.total()).build();
        });
    }

    private static void scanText(Memory mem, ConsoleTaskMonitor monitor, byte[] bytes, String enc,
                                 Responses.Table t, Responses.Window w, int cap) {
        if (bytes.length == 0) return;
        var mask = new byte[bytes.length];
        java.util.Arrays.fill(mask, (byte) 0xFF);
        var cursor = mem.getMinAddress();
        while (cursor != null && w.total() < cap) {
            var hit = mem.findBytes(cursor, bytes, mask, true, monitor);
            if (hit == null) break;
            if (w.take()) t.row(Responses.addr(hit), enc);
            cursor = hit.next();
        }
    }

    public String patchBytes(String addr, String hex) {
        return patchBytes(addr, hex, false);
    }

    public String patchBytes(String addr, String hex, boolean disassemble) {
        if (addr == null || addr.isBlank()) throw new IllegalArgumentException("Address is required");
        if (hex == null || hex.isBlank()) throw new IllegalArgumentException("Hex bytes required");
        if (hex.replace(" ", "").length() % 2 != 0) throw new IllegalArgumentException("Hex must have even length");
        byte[] bytes;
        try {
            bytes = Bufs.parseHex(hex);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid hex: " + e.getMessage());
        }
        var program = ctx.currentProgram();
        if (program == null) throw new IllegalArgumentException("No program loaded");
        var error = new String[1];
        var disasmFailed = new boolean[1];
        var ok = ctx.runOnSwingTx(program, "Patch bytes", () -> {
            try {
                var a = program.getAddressFactory().getAddress(addr);
                if (a == null) { error[0] = "Invalid address: " + addr; return false; }
                var block = program.getMemory().getBlock(a);
                if (block == null) { error[0] = "No memory block at " + addr; return false; }
                var end = a.add(bytes.length - 1);
                boolean wasWrite = block.isWrite();
                if (!wasWrite) block.setWrite(true);
                try {
                    var listing = program.getListing();
                    listing.clearCodeUnits(a, end, false);
                    program.getMemory().setBytes(a, bytes);
                    if (disassemble) {
                        var disasm = new ghidra.app.cmd.disassemble.DisassembleCommand(a, null, true);
                        disasmFailed[0] = !disasm.applyTo(program, new ConsoleTaskMonitor());
                    }
                    return true;
                } finally {
                    if (!wasWrite) block.setWrite(false);
                }
            } catch (Exception e) {
                error[0] = e.getClass().getSimpleName() + ": " + e.getMessage();
                Msg.error(ctx.logOwner(), "patchBytes failed", e);
                return false;
            }
        });
        if (!ok) {
            throw new IllegalStateException(
                    "Failed to patch bytes: " + (error[0] != null ? error[0] : "unknown"));
        }
        var note = !disassemble ? "" : disasmFailed[0] ? " (re-disassembly failed)" : " (re-disassembled)";
        return "Patched %d bytes at %s%s".formatted(bytes.length, addr, note);
    }

    public String nopRange(String addr, int length) {
        if (length <= 0 || length > 4096) throw new IllegalArgumentException("Length must be 1..4096");
        var hex = new StringBuilder(length * 2);
        for (int i = 0; i < length; i++) hex.append("90");
        return patchBytes(addr, hex.toString());
    }

    public String xorDecrypt(String addr, int length, String keyHex) {
        if (addr == null || addr.isBlank()) throw new IllegalArgumentException("Address is required");
        if (length <= 0 || length > 0x100000) throw new IllegalArgumentException("Length must be 1..1048576");
        if (keyHex == null || keyHex.isBlank()) throw new IllegalArgumentException("Key hex required");
        if (keyHex.replace(" ", "").length() % 2 != 0) throw new IllegalArgumentException("Key hex must have even length");
        byte[] key;
        try {
            key = Bufs.parseHex(keyHex);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid key hex: " + e.getMessage());
        }
        var program = ctx.currentProgram();
        if (program == null) throw new IllegalArgumentException("No program loaded");
        var error = new String[1];
        var ok = ctx.runOnSwingTx(program, "XOR decrypt", () -> {
            try {
                var a = program.getAddressFactory().getAddress(addr);
                if (a == null) { error[0] = "Invalid address"; return false; }
                var block = program.getMemory().getBlock(a);
                if (block == null) { error[0] = "No memory block"; return false; }
                var buf = new byte[length];
                program.getMemory().getBytes(a, buf, 0, length);
                for (int i = 0; i < length; i++) buf[i] ^= key[i % key.length];
                boolean wasWrite = block.isWrite();
                if (!wasWrite) block.setWrite(true);
                try {
                    var end = a.add(length - 1);
                    program.getListing().clearCodeUnits(a, end, false);
                    program.getMemory().setBytes(a, buf);
                    return true;
                } finally {
                    if (!wasWrite) block.setWrite(false);
                }
            } catch (Exception e) {
                error[0] = e.getClass().getSimpleName() + ": " + e.getMessage();
                Msg.error(ctx.logOwner(), "xorDecrypt failed", e);
                return false;
            }
        });
        if (!ok) {
            throw new IllegalStateException(
                    "Failed: " + (error[0] != null ? error[0] : "unknown"));
        }
        return "XOR-decrypted %d bytes at %s with %d-byte key".formatted(length, addr, key.length);
    }

    public String importMemoryDump(String addr, String path) {
        if (addr == null || addr.isBlank()) throw new IllegalArgumentException("Address is required");
        if (path == null || path.isBlank()) throw new IllegalArgumentException("Path is required");
        var dump = requireAllowedPath(path);
        var program = ctx.currentProgram();
        if (program == null) throw new IllegalArgumentException("No program loaded");
        byte[] bytes;
        try {
            bytes = java.nio.file.Files.readAllBytes(dump.toPath());
        } catch (Exception e) {
            throw new IllegalStateException("Failed to read file: " + e.getMessage(), e);
        }
        var error = new String[1];
        var ok = ctx.runOnSwingTx(program, "Import memory dump", () -> {
            try {
                var a = program.getAddressFactory().getAddress(addr);
                if (a == null) { error[0] = "Invalid address"; return false; }
                var block = program.getMemory().getBlock(a);
                if (block == null) { error[0] = "No memory block at " + addr; return false; }
                var end = a.add(bytes.length - 1);
                boolean wasWrite = block.isWrite();
                if (!wasWrite) block.setWrite(true);
                try {
                    program.getListing().clearCodeUnits(a, end, false);
                    program.getMemory().setBytes(a, bytes);
                    return true;
                } finally {
                    if (!wasWrite) block.setWrite(false);
                }
            } catch (Exception e) {
                error[0] = e.getClass().getSimpleName() + ": " + e.getMessage();
                Msg.error(ctx.logOwner(), "importMemoryDump failed", e);
                return false;
            }
        });
        if (!ok) {
            throw new IllegalStateException(
                    "Failed: " + (error[0] != null ? error[0] : "unknown"));
        }
        return "Imported %d bytes from %s to %s".formatted(bytes.length, path, addr);
    }

    public String exportBinary(String path) {
        if (path == null || path.isBlank()) throw new IllegalArgumentException("Path is required");
        var out = requireAllowedPath(path);
        var program = ctx.currentProgram();
        if (program == null) throw new IllegalArgumentException("No program loaded");
        try {
            var parent = out.getParentFile();
            if (parent != null && !parent.exists() && !parent.mkdirs()) {
                throw new IllegalStateException("Failed to create parent directory: " + parent);
            }
            var exporter = new ghidra.app.util.exporter.BinaryExporter();
            var monitor = new ConsoleTaskMonitor();
            boolean ok = exporter.export(out, program, program.getMemory(), monitor);
            return ok
                    ? "Exported %d bytes to %s".formatted(out.length(), out.getAbsolutePath())
                    : "Export failed";
        } catch (Exception e) {
            Msg.error(ctx.logOwner(), "exportBinary failed", e);
            return "Export error: " + e.getClass().getSimpleName() + ": " + e.getMessage();
        }
    }

    public String writeArtifact(String path, String content) {
        if (path == null || path.isBlank()) throw new IllegalArgumentException("Path is required");
        var out = requireAllowedPath(path);
        try {
            var parent = out.getParentFile();
            if (parent != null && !parent.exists() && !parent.mkdirs()) {
                throw new IllegalStateException("Failed to create parent directory: " + parent);
            }
            var text = content == null ? "" : content;
            var bytes = text.getBytes(StandardCharsets.UTF_8);
            java.nio.file.Files.write(out.toPath(), bytes);
            return "Wrote " + bytes.length + " bytes to " + out.getAbsolutePath();
        } catch (Exception e) {
            Msg.error(ctx.logOwner(), "writeArtifact failed", e);
            throw new IllegalStateException("Write failed: " + e.getMessage(), e);
        }
    }

    public String saveProgram() {
        var program = ctx.currentProgram();
        if (program == null) throw new IllegalArgumentException("No program loaded");
        return ctx.runOnSwing(() -> {
            try {
                program.save("ghidra-mcp save", new ConsoleTaskMonitor());
                return true;
            } catch (Exception e) {
                Msg.error(ctx.logOwner(), "saveProgram failed", e);
                return false;
            }
        }) ? "Program saved" : "Save failed (see Ghidra log)";
    }
}
