package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import io.github.imjustprism.ghidra.mcp.util.DataTypes;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.Locale;
import java.util.Map;

/** PE compile-time / overlay / PDB / manifest facts for intake. */
public final class PeFacts {

    private PeFacts() {}

    public static String facts(PluginContext ctx, Map<String, String> q) {
        return ctx.withProgram(program -> {
            var t = Responses.table(q, new String[]{"k", "v"}, 16);
            t.row("name", program.getName());
            t.row("path", program.getExecutablePath() != null ? program.getExecutablePath() : "");
            var sha = program.getExecutableSHA256();
            if (sha != null) t.row("sha256", sha);
            t.row("image_base", Responses.addr(program.getImageBase()));
            t.row("compiler", program.getCompilerSpec().getCompilerSpecID().toString());
            fillPe(program, t);
            fillManifest(program, t);
            fillPdb(program, t);
            return t.build();
        });
    }

    static String fileTime(int unix) {
        if (unix <= 0) return "";
        return java.time.Instant.ofEpochSecond(Integer.toUnsignedLong(unix)).toString();
    }

    private static void fillPe(Program program, Responses.Table t) {
        var mem = program.getMemory();
        var base = program.getImageBase();
        try {
            int lfanew = mem.getInt(base.add(0x3c));
            var pe = base.add(lfanew & 0xffffffffL);
            if (mem.getInt(pe) != 0x00004550) {
                t.row("pe", "no");
                return;
            }
            t.row("pe", "yes");
            int ts = mem.getInt(pe.add(8));
            t.row("timedatestamp", "0x" + Integer.toHexString(ts));
            t.row("compiled", fileTime(ts));
            int sections = mem.getShort(pe.add(6)) & 0xffff;
            t.row("sections", sections);
            var opt = pe.add(24);
            int magic = mem.getShort(opt) & 0xffff;
            boolean plus = magic == 0x20b;
            t.row("pe_magic", plus ? "pe32+" : "pe32");
            int subsys = mem.getShort(opt.add(plus ? 0x5c : 0x44)) & 0xffff;
            t.row("subsystem", subsystemName(subsys));
            int dll = mem.getShort(opt.add(plus ? 0x5e : 0x46)) & 0xffff;
            t.row("dll_characteristics", "0x" + Integer.toHexString(dll));
        } catch (MemoryAccessException e) {
            t.row("pe", "unreadable: " + e.getMessage());
        }
    }

    private static void fillManifest(Program program, Responses.Table t) {
        var it = program.getListing().getDefinedData(true);
        while (it.hasNext()) {
            var d = it.next();
            if (d == null || !DataTypes.isStringLike(d) || d.getValue() == null) continue;
            var s = d.getValue().toString();
            if (s.contains("requestedExecutionLevel")) {
                t.row("manifest_admin", s.contains("requireAdministrator") ? "requireAdministrator" : "asInvoker/other");
                return;
            }
        }
        t.row("manifest_admin", "unknown");
    }

    private static void fillPdb(Program program, Responses.Table t) {
        var it = program.getListing().getDefinedData(true);
        while (it.hasNext()) {
            var d = it.next();
            if (d == null || !DataTypes.isStringLike(d) || d.getValue() == null) continue;
            var s = d.getValue().toString();
            if (s.length() > 5 && (s.endsWith(".pdb") || s.endsWith(".PDB"))) {
                t.row("pdb", s);
                return;
            }
        }
        for (var block : program.getMemory().getBlocks()) {
            if (!block.getName().toLowerCase(Locale.ROOT).contains("debug")) continue;
            t.row("debug_section", block.getName());
            return;
        }
    }

    private static String subsystemName(int s) {
        return switch (s) {
            case 1 -> "native";
            case 2 -> "windows_gui";
            case 3 -> "windows_cui";
            case 9 -> "windows_ce";
            default -> "0x" + Integer.toHexString(s);
        };
    }
}
