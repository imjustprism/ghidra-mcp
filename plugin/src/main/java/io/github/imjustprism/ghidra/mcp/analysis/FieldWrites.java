package io.github.imjustprism.ghidra.mcp.analysis;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

public final class FieldWrites {

    private static final Pattern PARAM = Pattern.compile("\\bparam_\\d+\\b");
    private static final Pattern PLUS_OFFSET = Pattern.compile("\\+\\s*(0x[0-9a-fA-F]+|\\d+)");
    private static final Pattern FIELD_OFFSET = Pattern.compile("field_([0-9a-fA-F]+)");

    public record Write(String kind, String offset, String lhs, String rhs) {}

    private FieldWrites() {}

    public static List<Write> extract(String decompiled) {
        var out = new ArrayList<Write>();
        if (decompiled == null || decompiled.isBlank()) return out;
        for (var raw : decompiled.split("\n")) {
            var line = raw.trim();
            int eq = assignmentIndex(line);
            if (eq < 0) continue;
            var lhs = line.substring(0, eq).trim();
            if (!lhs.contains("this") && !PARAM.matcher(lhs).find()) continue;
            var rhs = clean(line.substring(eq + 1));
            out.add(new Write(kind(lhs, rhs), offset(lhs), lhs, rhs));
        }
        return out;
    }

    private static int assignmentIndex(String line) {
        for (int i = 0; i < line.length(); i++) {
            if (line.charAt(i) != '=') continue;
            char prev = i == 0 ? '\0' : line.charAt(i - 1);
            char next = i + 1 == line.length() ? '\0' : line.charAt(i + 1);
            if (prev == '=' || prev == '!' || prev == '<' || prev == '>' || prev == '+' || prev == '-'
                    || next == '=') {
                continue;
            }
            return i;
        }
        return -1;
    }

    private static String clean(String rhs) {
        var s = rhs.strip();
        return s.endsWith(";") ? s.substring(0, s.length() - 1).strip() : s;
    }

    private static String kind(String lhs, String rhs) {
        var s = (lhs + " " + rhs).toLowerCase();
        return s.contains("vftable") || s.contains("vtable") ? "vtable" : "field";
    }

    private static String offset(String lhs) {
        var plus = PLUS_OFFSET.matcher(lhs);
        if (plus.find()) return normalize(plus.group(1));
        var field = FIELD_OFFSET.matcher(lhs);
        return field.find() ? "0x" + field.group(1).toLowerCase() : "";
    }

    private static String normalize(String s) {
        return s.startsWith("0x") || s.startsWith("0X")
                ? "0x" + s.substring(2).toLowerCase()
                : "0x" + Long.toHexString(Long.parseLong(s));
    }
}
