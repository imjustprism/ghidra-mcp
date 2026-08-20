package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.listing.Function;
import io.github.imjustprism.ghidra.mcp.util.Addresses;
import io.github.imjustprism.ghidra.mcp.util.DecompileCache;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;

public final class DecompileMinimal {

    private DecompileMinimal() {}

    public static String run(PluginContext ctx, String addr) {
        return ctx.withAddress(addr, (program, a) -> {
            Function f = Addresses.functionAtOrContaining(program, a);
            if (f == null) throw new IllegalArgumentException("No function at or containing " + addr);
            String c = DecompileCache.decompile(program, f);
            return minimize(c);
        });
    }

    public static String minimize(String src) {
        if (src == null || src.isEmpty()) return src;
        String s = stripWarningBlocks(src);
        s = stripRedundantCasts(s);
        s = collapseBlankLines(s);
        return s;
    }

    /** minimize() plus drop std::string SSO / length-error noise that buries malware logic. */
    public static String minimizeStd(String src) {
        String s = minimize(src);
        if (s == null || s.isEmpty()) return s;
        var out = new StringBuilder(s.length());
        int i = 0;
        while (i < s.length()) {
            int nl = s.indexOf('\n', i);
            String line = nl < 0 ? s.substring(i) : s.substring(i, nl);
            i = nl < 0 ? s.length() : nl + 1;
            if (isStdNoise(line)) continue;
            out.append(line);
            if (nl >= 0) out.append('\n');
        }
        return collapseBlankLines(out.toString());
    }

    static boolean isStdNoise(String line) {
        var t = line.trim();
        if (t.isEmpty()) return false;
        return t.contains("__throw_length_error")
                || t.contains("basic_string::append")
                || t.contains("basic_string: construction from null")
                || t.contains("cannot create std::vector larger than max_size")
                || t.contains("vector::_M_default_append")
                || t.contains("vector::_M_realloc_insert")
                || t.contains("vector::_M_range_insert")
                || t.equals("std::__throw_bad_function_call();");
    }

    private static String stripWarningBlocks(String s) {
        var sb = new StringBuilder(s.length());
        int i = 0, n = s.length();
        while (i < n) {
            int start = s.indexOf("/* WARNING:", i);
            if (start < 0) { sb.append(s, i, n); break; }
            int end = s.indexOf("*/", start);
            if (end < 0) { sb.append(s, i, n); break; }
            sb.append(s, i, start);
            i = end + 2;
            while (i < n && (s.charAt(i) == ' ' || s.charAt(i) == '\t')) i++;
            if (i < n && s.charAt(i) == '\n') i++;
        }
        return sb.toString();
    }

    private static final String[] CAST_TYPES = {
        "int", "uint", "longlong", "ulonglong",
        "short", "ushort", "char", "uchar", "bool"
    };

    private static String stripRedundantCasts(String s) {
        String out = s;
        for (var t : CAST_TYPES) {
            String needle = "(" + t + ")";
            out = stripCastOverIdent(out, needle);
        }
        return out;
    }

    private static String stripCastOverIdent(String s, String needle) {
        var sb = new StringBuilder(s.length());
        int i = 0, n = s.length();
        while (i < n) {
            int hit = s.indexOf(needle, i);
            if (hit < 0) { sb.append(s, i, n); break; }
            int after = hit + needle.length();
            if (after < n && isIdentStart(s.charAt(after))) {
                int j = after;
                while (j < n && isIdentPart(s.charAt(j))) j++;
                String ident = s.substring(after, j);
                if (isKnownPrefix(ident)) {
                    sb.append(s, i, hit);
                    sb.append(ident);
                    i = j;
                    continue;
                }
            }
            sb.append(s, i, after);
            i = after;
        }
        return sb.toString();
    }

    private static boolean isKnownPrefix(String id) {
        return id.startsWith("iVar") || id.startsWith("uVar")
            || id.startsWith("cVar") || id.startsWith("bVar")
            || id.startsWith("sVar") || id.startsWith("lVar")
            || id.startsWith("param_") || id.startsWith("local_");
    }

    private static boolean isIdentStart(char c) {
        return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
    }

    private static boolean isIdentPart(char c) {
        return isIdentStart(c) || (c >= '0' && c <= '9');
    }

    private static String collapseBlankLines(String s) {
        var sb = new StringBuilder(s.length());
        int blank = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\n') {
                blank++;
                if (blank <= 2) sb.append(c);
            } else {
                if (c != '\r') blank = 0;
                sb.append(c);
            }
        }
        return sb.toString();
    }
}
