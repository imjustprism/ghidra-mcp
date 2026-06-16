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
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;
import io.github.imjustprism.ghidra.mcp.util.Strings;

import java.util.Map;

public final class BytesHandlers {

    private final PluginContext ctx;

    public BytesHandlers(PluginContext ctx) {
        this.ctx = ctx;
    }

    public void register(RouteTable routes) {
        routes.getQuery("/read_bytes", q -> readBytes(q.get("address"), Http.parseIntOrDefault(q.get("length"), 64)));
        routes.getQuery("/hex_dump", q -> hexDump(q.get("address"), Http.parseIntOrDefault(q.get("length"), 128)));
        routes.getQuery("/search_bytes", q -> searchBytes(q.get("pattern"), Page.from(q), q));
        routes.getQuery("/find_string", q -> findString(q.get("value"), Page.from(q), q));
        routes.postForm("/patch_bytes", p -> patchBytes(p.get("address"), p.get("hex")));
        routes.postForm("/nop_range", p -> nopRange(p.get("address"), Http.parseIntOrDefault(p.get("length"), 0)));
        routes.postForm("/export_binary", p -> exportBinary(p.get("path")));
        routes.postForm("/save_program", p -> saveProgram());
        routes.postForm("/xor_decrypt", p -> xorDecrypt(p.get("address"), Http.parseIntOrDefault(p.get("length"), 0), p.get("key")));
        routes.postForm("/import_memory_dump", p -> importMemoryDump(p.get("address"), p.get("path")));
    }

    public String readBytes(String addr, int length) {
        if (length <= 0 || length > 65536) throw new IllegalArgumentException("Length must be 1..65536");
        return ctx.withAddress(addr, (program, a) -> {
            try {
                var buf = new byte[length];
                int read = program.getMemory().getBytes(a, buf, 0, length);
                return Responses.addr(a) + "\t" + read + "\t" + Bufs.hex(buf, read);
            } catch (Exception e) {
                throw new IllegalStateException("Error reading memory: " + e.getMessage(), e);
            }
        });
    }

    public String hexDump(String addr, int length) {
        if (length <= 0 || length > 65536) throw new IllegalArgumentException("Length must be 1..65536");
        return ctx.withAddress(addr, (program, a) -> {
            try {
                var buf = new byte[length];
                int read = program.getMemory().getBytes(a, buf, 0, length);
                var sb = new StringBuilder(64 + (read / 16 + 1) * 76);
                sb.append("# format=hex; addr=hex; rows=16B\n");
                final char[] HEX = "0123456789abcdef".toCharArray();
                for (int off = 0; off < read; off += 16) {
                    var line = a.add(off);
                    int row = Math.min(16, read - off);
                    sb.append(Responses.addr(line)).append("  ");
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
            } catch (Exception e) {
                throw new IllegalStateException("Error reading memory: " + e.getMessage(), e);
            }
        });
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
            var t = Responses.table(p, q, new String[]{"addr"});
            Address cursor = memory.getMinAddress();
            int cap = p.offset() + p.limit();
            int found = 0, off = p.offset(), kept = 0;
            var monitor = new ConsoleTaskMonitor();
            while (cursor != null && found < cap) {
                Address next = memory.findBytes(cursor, bytes, mask, true, monitor);
                if (next == null) break;
                found++;
                if (found > off && kept < p.limit()) { t.row(Responses.addr(next)); kept++; }
                cursor = next.next();
                if (cursor == null) break;
            }
            return t.total(found).build();
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

    public String patchBytes(String addr, String hex) {
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
                    boolean wasCode = listing.getInstructionContaining(a) != null;
                    listing.clearCodeUnits(a, end, false);
                    program.getMemory().setBytes(a, bytes);
                    if (wasCode) {
                        var disasm = new ghidra.app.cmd.disassemble.DisassembleCommand(a, null, true);
                        disasm.applyTo(program, new ConsoleTaskMonitor());
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
        return "Patched %d bytes at %s".formatted(bytes.length, addr);
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
        var program = ctx.currentProgram();
        if (program == null) throw new IllegalArgumentException("No program loaded");
        byte[] bytes;
        try {
            bytes = java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(path));
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
        var program = ctx.currentProgram();
        if (program == null) throw new IllegalArgumentException("No program loaded");
        try {
            var out = new java.io.File(path);
            var parent = out.getAbsoluteFile().getParentFile();
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
