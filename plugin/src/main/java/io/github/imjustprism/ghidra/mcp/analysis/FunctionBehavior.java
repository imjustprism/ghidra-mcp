package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import io.github.imjustprism.ghidra.mcp.http.Page;
import io.github.imjustprism.ghidra.mcp.util.Addresses;
import io.github.imjustprism.ghidra.mcp.util.DataTypes;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;
import io.github.imjustprism.ghidra.mcp.util.Strings;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Map;

/**
 * Compact malware-oriented function card: tags, APIs, defined + recovered
 * strings, JSON/HTTP/crypto hints. Use instead of dumping a 1500-line
 * std::string decompile.
 */
public final class FunctionBehavior {

    private FunctionBehavior() {}

    public static String summarize(PluginContext ctx, String addr, Page p, Map<String, String> q) {
        return ctx.withAddress(addr, (program, a) -> {
            var func = Addresses.functionAtOrContaining(program, a);
            if (func == null) throw new IllegalArgumentException("no function at " + addr);
            return build(program, func, p, q);
        });
    }

    static String build(Program program, Function func, Page p, Map<String, String> q) {
        var tags = new LinkedHashSet<String>();
        var rows = new ArrayList<String[]>();

        var listing = program.getListing();
        var refs = program.getReferenceManager();
        var iter = func.getBody().getAddresses(true);
        while (iter.hasNext()) {
            var from = iter.next();
            for (var r : refs.getReferencesFrom(from)) {
                var data = listing.getDataAt(r.getToAddress());
                if (data == null || !DataTypes.isStringLike(data) || data.getValue() == null) continue;
                var s = data.getValue().toString();
                rows.add(new String[]{"string", Responses.addr(from), s});
                tagFromText(s, tags);
            }
        }

        var hidden = HiddenStrings.scanFunction(program, func, "auto", 4);
        for (var h : hidden) {
            rows.add(new String[]{"hidden:" + h.algo(), h.loop(), h.value()});
            tagFromText(h.value(), tags);
        }

        var apiTable = ApiCallSequence.build(program, func, true, q);
        if (apiTable.contains("Internet") || apiTable.contains("Http") || apiTable.contains("WinHttp")) {
            tags.add("http");
        }
        if (apiTable.contains("BCrypt") || apiTable.contains("Crypt")) tags.add("crypto");
        if (apiTable.contains("VirtualAllocEx") || apiTable.contains("WriteProcessMemory")
                || apiTable.contains("CreateRemoteThread")) tags.add("inject");
        if (apiTable.contains("GetSystemFirmwareTable") || apiTable.contains("GetAdaptersAddresses")
                || apiTable.contains("GetVolumeInformation")) tags.add("hwid");
        if (apiTable.contains("IsDebuggerPresent") || apiTable.contains("NtQueryInformationProcess")
                || apiTable.contains("CheckRemoteDebugger")) tags.add("antidebug");

        var ins = listing.getInstructions(func.getBody(), true);
        while (ins.hasNext()) {
            var i = ins.next();
            for (int op = 0; op < i.getNumOperands(); op++) {
                for (var o : i.getOpObjects(op)) {
                    if (!(o instanceof Scalar sc)) continue;
                    long v = sc.getUnsignedValue();
                    if (HiddenStrings.isSplitMixConst(v)) {
                        tags.add("splitmix64");
                        rows.add(new String[]{"immediate", Responses.addr(i.getAddress()),
                                "splitmix64 0x" + Long.toHexString(v)});
                    }
                }
            }
        }

        var sb = new StringBuilder(2048);
        sb.append("# function_behavior ").append(func.getName()).append(' ')
                .append(Responses.addr(func.getEntryPoint())).append('\n');
        sb.append("tags\t").append(tags.isEmpty() ? "(none)" : String.join(",", tags)).append('\n');
        sb.append("size\t").append(func.getBody().getNumAddresses()).append(" bytes\n");

        sb.append("=== apis ===\n").append(apiTable);
        if (!apiTable.endsWith("\n")) sb.append('\n');

        var t = Responses.table(p, q, new String[]{"kind", "where", "value"});
        var w = new Responses.Window(p);
        for (var r : rows) {
            if (!w.take()) continue;
            t.row(r[0], r[1], Strings.escapeString(r[2]));
        }
        sb.append("=== artifacts ===\n").append(t.total(w.total()).build());
        return sb.toString();
    }

    static void tagFromText(String s, LinkedHashSet<String> tags) {
        if (s == null) return;
        var low = s.toLowerCase(Locale.ROOT);
        if (s.startsWith("/api/") || low.startsWith("http://") || low.startsWith("https://")) tags.add("http");
        if (low.contains("token") || low.contains("password") || low.contains("hwid")
                || low.contains("session") || low.contains("license") || low.contains("subscription")) {
            tags.add("auth");
        }
        if (low.contains("bearer") || s.contains("X-Request-Sig") || s.contains("X-Timestamp")) {
            tags.add("signed_http");
        }
        if (s.contains("SHA256") || s.contains("ChainingModeGCM") || s.contains("|drm")) tags.add("crypto");
        if (low.contains("debugger") || low.contains("x64dbg") || low.contains("ida")) tags.add("antidebug");
        if (low.contains(".exe") && low.contains("client")) tags.add("target_process");
    }
}
