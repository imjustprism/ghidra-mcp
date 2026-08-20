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
            fillManifestAndPdb(program, t);
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
            // Subsystem sits at opt+0x44 in BOTH pe32 and pe32+: pe32+ drops
            // BaseOfData (-4) and widens ImageBase (+4), so the offset is a wash.
            int subsys = mem.getShort(opt.add(0x44)) & 0xffff;
            t.row("subsystem", subsystemName(subsys));
            int dll = mem.getShort(opt.add(0x46)) & 0xffff;
            t.row("dll_characteristics", "0x" + Integer.toHexString(dll));
            t.row("mitigations", dllCharacteristics(dll));
        } catch (MemoryAccessException e) {
            t.row("pe", "unreadable: " + e.getMessage());
        }
    }

    /**
     * Manifest and PDB both live in defined strings, so walk the listing once and
     * pick up both rather than paying for two full passes over the image.
     */
    private static void fillManifestAndPdb(Program program, Responses.Table t) {
        String manifest = null;
        String pdb = null;
        var it = program.getListing().getDefinedData(true);
        while (it.hasNext() && (manifest == null || pdb == null)) {
            var d = it.next();
            if (d == null || !DataTypes.isStringLike(d) || d.getValue() == null) continue;
            var s = d.getValue().toString();
            if (manifest == null && s.contains("requestedExecutionLevel")) {
                manifest = s.contains("requireAdministrator") ? "requireAdministrator" : "asInvoker/other";
            }
            if (pdb == null && s.length() > 5 && (s.endsWith(".pdb") || s.endsWith(".PDB"))) {
                pdb = s;
            }
        }

        t.row("manifest_admin", manifest != null ? manifest : "unknown");
        if (pdb != null) {
            t.row("pdb", pdb);
            return;
        }
        for (var block : program.getMemory().getBlocks()) {
            if (!block.getName().toLowerCase(Locale.ROOT).contains("debug")) continue;
            t.row("debug_section", block.getName());
            return;
        }
    }

    /** Decode the mitigation-relevant DllCharacteristics bits into a readable list. */
    private static String dllCharacteristics(int d) {
        var sb = new StringBuilder();
        if ((d & 0x0020) != 0) append(sb, "high_entropy_va");
        if ((d & 0x0040) != 0) append(sb, "dynamic_base");
        if ((d & 0x0080) != 0) append(sb, "force_integrity");
        if ((d & 0x0100) != 0) append(sb, "nx_compat");
        if ((d & 0x0200) != 0) append(sb, "no_isolation");
        if ((d & 0x0400) != 0) append(sb, "no_seh");
        if ((d & 0x0800) != 0) append(sb, "no_bind");
        if ((d & 0x1000) != 0) append(sb, "appcontainer");
        if ((d & 0x2000) != 0) append(sb, "wdm_driver");
        if ((d & 0x4000) != 0) append(sb, "guard_cf");
        if ((d & 0x8000) != 0) append(sb, "terminal_server_aware");
        return sb.isEmpty() ? "none" : sb.toString();
    }

    private static void append(StringBuilder sb, String s) {
        if (!sb.isEmpty()) sb.append('|');
        sb.append(s);
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
