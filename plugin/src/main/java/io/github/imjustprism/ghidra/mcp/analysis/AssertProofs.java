package io.github.imjustprism.ghidra.mcp.analysis;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

public final class AssertProofs {

    public static final int UNKNOWN_SCALE = -1;

    private static final Pattern ASSERT_CALL = Pattern.compile(
            "(?:n_assert\\w*|n_verify\\w*|n_error\\w*|n_warning\\w*|FUN_[0-9a-fA-F]+)\\s*\\(\\s*"
                    + "\"((?:[^\"\\\\]|\\\\.)*)\"\\s*,\\s*"
                    + "\"((?:[^\"\\\\]|\\\\.)*\\.(?:cc|cpp|cxx|c|h|hpp))\"\\s*,\\s*"
                    + "(0x[0-9a-fA-F]+|[0-9]+)\\s*,\\s*"
                    + "\"((?:[^\"\\\\]|\\\\.)*)\"",
            Pattern.DOTALL);

    private static final Pattern THIS_FIELD = Pattern.compile("this->([A-Za-z_][A-Za-z0-9_]*)");

    private static final Pattern DECL = Pattern.compile(
            "^\\s{2,}([A-Za-z_][A-Za-z0-9_: ]*?)\\s*(\\**)\\s*([A-Za-z_][A-Za-z0-9_]*)\\s*(\\[[0-9]*\\])?\\s*;\\s*$");

    private static final Pattern ASSIGN = Pattern.compile(
            "^\\s*([A-Za-z_][A-Za-z0-9_]*)\\s*=\\s*(.+?);\\s*$");

    private static final Pattern CALL_CONV = Pattern.compile(
            "__(?:cdecl|thiscall|stdcall|fastcall|vectorcall|clrcall)\\b");

    private static final Pattern TLS_LOAD = Pattern.compile(
            "ThreadLocalStoragePointer.*_tls_index", Pattern.DOTALL);

    private static final Map<String, Integer> TYPE_SIZE = typeSizes();

    public record Site(String expr, String file, int line, String sig, int start, int end) {}

    public record Deref(String base, long offset, int width, boolean resolved, String text) {}

    public record Frame(Map<String, Integer> scales, List<Assign> assigns) {}

    public record Assign(String var, String rhs, int pos) {}

    private record Base(String name, long off, int scale, boolean resolved) {}

    private AssertProofs() {}

    private static Map<String, Integer> typeSizes() {
        var m = new HashMap<String, Integer>();
        for (var s : new String[]{"void", "bool", "char", "uchar", "byte", "sbyte", "undefined",
                "undefined1", "code"}) {
            m.put(s, 1);
        }
        for (var s : new String[]{"short", "ushort", "word", "undefined2", "wchar_t", "wchar16"}) {
            m.put(s, 2);
        }
        for (var s : new String[]{"int", "uint", "long", "ulong", "float", "dword", "undefined4",
                "int32_t", "uint32_t", "BOOL", "DWORD"}) {
            m.put(s, 4);
        }
        for (var s : new String[]{"longlong", "ulonglong", "double", "qword", "undefined8",
                "int64_t", "uint64_t", "size_t", "pointer", "LPVOID", "HANDLE"}) {
            m.put(s, 8);
        }
        return Map.copyOf(m);
    }

    public static List<Site> sites(String c) {
        var out = new ArrayList<Site>();
        if (c == null || c.isEmpty()) return out;
        var m = ASSERT_CALL.matcher(c);
        while (m.find()) {
            out.add(new Site(m.group(1), normalizePath(m.group(2)), parseNum(m.group(3)),
                    m.group(4), m.start(), m.end()));
        }
        return out;
    }

    public static String normalizePath(String raw) {
        if (raw == null) return "";
        var s = raw.replace("\\\\", "/").replace('\\', '/');
        var lower = s.toLowerCase(Locale.ROOT);
        for (var anchor : new String[]{"/code/", "/drasa_online/", "/nebula3/"}) {
            int i = lower.lastIndexOf(anchor);
            if (i >= 0) return s.substring(i + anchor.length());
        }
        int slash = s.lastIndexOf('/');
        return slash < 0 ? s : s.substring(slash + 1);
    }

    public static Frame frame(String c) {
        var scales = new HashMap<String, Integer>();
        var assigns = new ArrayList<Assign>();
        if (c == null || c.isEmpty()) return new Frame(scales, assigns);
        for (var p : signatureParams(c)) declare(scales, p);
        var lines = c.split("\n", -1);
        int pos = 0;
        boolean inDecls = false;
        boolean sawDecl = false;
        for (var line : lines) {
            var trimmed = line.trim();
            if (!inDecls && trimmed.equals("{")) {
                inDecls = true;
            } else if (inDecls) {
                var d = DECL.matcher(line);
                if (d.matches()) {
                    sawDecl = true;
                    declare(scales, d.group(1).trim() + " " + d.group(2) + " " + d.group(3));
                } else if (sawDecl && !trimmed.isEmpty()) {
                    inDecls = false;
                } else if (sawDecl) {
                    inDecls = false;
                }
            }
            var a = ASSIGN.matcher(line);
            if (a.matches()) assigns.add(new Assign(a.group(1), a.group(2).trim(), pos));
            pos += line.length() + 1;
        }
        return new Frame(scales, assigns);
    }

    private static void declare(Map<String, Integer> scales, String decl) {
        var t = decl.trim();
        if (t.isEmpty()) return;
        int stars = 0;
        var sb = new StringBuilder();
        for (int i = 0; i < t.length(); i++) {
            char ch = t.charAt(i);
            if (ch == '*') stars++;
            else sb.append(ch);
        }
        var parts = sb.toString().trim().split("\\s+");
        if (parts.length < 2) return;
        var name = parts[parts.length - 1];
        int bracket = name.indexOf('[');
        if (bracket >= 0) name = name.substring(0, bracket);
        if (name.isEmpty()) return;
        var base = parts[parts.length - 2];
        if (stars == 0) {
            scales.put(name, 1);
        } else if (stars >= 2) {
            scales.put(name, 8);
        } else {
            var sz = TYPE_SIZE.get(base);
            scales.put(name, sz == null ? UNKNOWN_SCALE : sz);
        }
    }

    private static List<String> signatureParams(String c) {
        var out = new ArrayList<String>();
        int brace = c.indexOf("\n{");
        var head = brace < 0 ? c : c.substring(0, brace);
        int open = head.indexOf('(');
        if (open < 0) return out;
        int close = matchParen(head, open);
        if (close < 0) return out;
        for (var p : splitTop(head.substring(open + 1, close), ',')) {
            var t = p.trim();
            if (!t.isEmpty() && !t.equals("void")) out.add(t);
        }
        return out;
    }

    public static String guardFor(String c, int assertStart) {
        int best = -1;
        for (var kw : new String[]{"if (", "if(", "while (", "while("}) {
            int i = c.lastIndexOf(kw, assertStart);
            if (i > best) best = i;
        }
        if (best < 0) return null;
        int open = c.indexOf('(', best);
        if (open < 0 || open > assertStart) return null;
        int close = matchParen(c, open);
        if (close < 0 || close > assertStart) return null;
        int braces = 0;
        for (int i = close + 1; i < assertStart; i++) {
            char ch = c.charAt(i);
            if (ch == '{') {
                if (++braces > 1) return null;
            } else if (!Character.isWhitespace(ch)) {
                return null;
            }
        }
        return c.substring(open + 1, close);
    }

    public static List<String> fieldsOf(String assertExpr) {
        var out = new LinkedHashSet<String>();
        if (assertExpr == null) return List.of();
        var m = THIS_FIELD.matcher(assertExpr);
        while (m.find()) out.add(m.group(1));
        return List.copyOf(out);
    }

    public static String ownerOf(String sig) {
        var path = memberPath(sig);
        int cut = lastTopScope(path);
        return cut < 0 ? "" : path.substring(0, cut).trim();
    }

    public static String memberOf(String sig) {
        var path = memberPath(sig);
        int cut = lastTopScope(path);
        return cut < 0 ? path : path.substring(cut + 2).trim();
    }

    public static String elementTypeOf(String owner) {
        if (owner == null) return "";
        int lt = owner.indexOf('<');
        if (lt < 0 || !owner.trim().endsWith(">")) return "";
        var inner = owner.substring(lt + 1, owner.lastIndexOf('>')).trim();
        return inner.startsWith("class ") ? inner.substring(6).trim()
                : inner.startsWith("struct ") ? inner.substring(7).trim() : inner;
    }

    private static String memberPath(String sig) {
        if (sig == null || sig.isBlank()) return "";
        var s = sig;
        var cc = CALL_CONV.matcher(s);
        int from = cc.find() ? cc.end() : 0;
        int depth = 0;
        for (int i = from; i < s.length(); i++) {
            char ch = s.charAt(i);
            if (ch == '<') depth++;
            else if (ch == '>') depth--;
            else if (ch == '(' && depth <= 0) return s.substring(from, i).trim();
        }
        return s.substring(from).trim();
    }

    private static int lastTopScope(String path) {
        int depth = 0;
        int last = -1;
        for (int i = 0; i + 1 < path.length(); i++) {
            char ch = path.charAt(i);
            if (ch == '<') depth++;
            else if (ch == '>') depth--;
            else if (ch == ':' && depth == 0 && path.charAt(i + 1) == ':') {
                last = i;
                i++;
            }
        }
        return last;
    }

    public static List<Deref> derefs(String expr, Frame frame, int pos) {
        var out = new ArrayList<Deref>();
        if (expr == null || expr.isEmpty()) return out;
        for (int i = 0; i < expr.length(); i++) {
            if (expr.charAt(i) != '*' || !isDerefStar(expr, i)) continue;
            var d = readDeref(expr, i, frame, pos);
            if (d == null) continue;
            boolean dup = false;
            for (var o : out) {
                if (o.base().equals(d.base()) && o.offset() == d.offset()) dup = true;
            }
            if (!dup) out.add(d);
        }
        return out;
    }

    private static boolean isDerefStar(String s, int i) {
        for (int j = i - 1; j >= 0; j--) {
            char ch = s.charAt(j);
            if (Character.isWhitespace(ch)) continue;
            return ch == '(' || ch == ',' || ch == '=' || ch == '!' || ch == '<' || ch == '>'
                    || ch == '&' || ch == '|' || ch == '+' || ch == '-' || ch == '?' || ch == ':'
                    || ch == '*' || ch == '{' || ch == ';';
        }
        return true;
    }

    private static Deref readDeref(String s, int star, Frame frame, int pos) {
        int i = skipSpace(s, star + 1);
        int width = 0;
        if (i < s.length() && s.charAt(i) == '(') {
            int close = matchParen(s, i);
            if (close < 0) return null;
            var inner = s.substring(i + 1, close);
            var castSize = castWidth(inner);
            if (castSize > 0) {
                width = castSize;
                i = skipSpace(s, close + 1);
                if (i >= s.length()) return null;
                if (s.charAt(i) == '(') {
                    int c2 = matchParen(s, i);
                    if (c2 < 0) return null;
                    return address(s.substring(i + 1, c2), width, frame, pos);
                }
                int end = identEnd(s, i);
                if (end == i) return null;
                return address(s.substring(i, end), width, frame, pos);
            }
            return address(inner, 0, frame, pos);
        }
        int end = identEnd(s, i);
        if (end == i) return null;
        var name = s.substring(i, end);
        var b = resolveBase(name, frame, pos);
        int w = frame.scales().getOrDefault(name, 0);
        return new Deref(b.name(), b.off(), w == UNKNOWN_SCALE ? 0 : w, b.resolved(), "*" + name);
    }

    private static Deref address(String inner, int width, Frame frame, int pos) {
        var t = inner.trim();
        while (t.startsWith("(") && matchParen(t, 0) == t.length() - 1) t = t.substring(1, t.length() - 1).trim();
        int plus = lastTopPlus(t);
        long index = 0;
        var baseExpr = t;
        if (plus > 0) {
            var right = t.substring(plus + 1).trim();
            var n = literal(right);
            if (n != null) {
                index = n;
                baseExpr = t.substring(0, plus).trim();
            }
        }
        var b = resolveBase(baseExpr, frame, pos);
        if (b.scale() == UNKNOWN_SCALE) {
            return new Deref(b.name(), b.off(), width, false, t);
        }
        return new Deref(b.name(), b.off() + index * b.scale(), width, b.resolved(), t);
    }

    private static Base resolveBase(String expr, Frame frame, int pos) {
        var t = expr.trim();
        while (t.startsWith("(") && matchParen(t, 0) == t.length() - 1) t = t.substring(1, t.length() - 1).trim();
        if (t.matches("\\(\\s*[A-Za-z_][A-Za-z0-9_ ]*\\s*\\)\\s*.+")) {
            int c = matchParen(t, 0);
            if (c > 0 && castWidth(t.substring(1, c)) == 0) t = t.substring(c + 1).trim();
        }
        if (t.matches("[A-Za-z_][A-Za-z0-9_]*")) {
            var alias = aliasOf(t, frame, pos);
            if (alias != null) return alias;
            var scale = frame.scales().get(t);
            if (scale != null) return new Base(t, 0, scale, true);
            return new Base(t, 0, 1, false);
        }
        if (t.startsWith("*")) {
            var d = readDeref(t, 0, frame, pos);
            if (d != null && d.resolved()) {
                return new Base(d.base() + "[" + hex(d.offset()) + "]", 0, 1, true);
            }
        }
        return new Base(t, 0, 1, false);
    }

    private static Base aliasOf(String name, Frame frame, int pos) {
        Assign hit = null;
        for (var a : frame.assigns()) {
            if (a.pos() >= pos) break;
            if (a.var().equals(name)) hit = a;
        }
        if (hit == null) return null;
        var rhs = hit.rhs();
        if (TLS_LOAD.matcher(rhs).find()) return new Base("tls", 0, 1, true);
        var t = rhs.trim();
        int castW = 0;
        if (t.startsWith("(")) {
            int c = matchParen(t, 0);
            if (c > 0) {
                castW = castWidth(t.substring(1, c));
                if (castW > 0) t = t.substring(c + 1).trim();
            }
        }
        if (t.matches("[A-Za-z_][A-Za-z0-9_]*")) {
            if (t.equals(name)) return null;
            var inner = aliasOf(t, frame, hit.pos());
            if (inner != null) return scaled(inner, name, frame);
            var sc = frame.scales().get(t);
            if (sc != null) return scaled(new Base(t, 0, sc, true), name, frame);
            return null;
        }
        if (t.contains("(") && !t.startsWith("*") && t.matches("[A-Za-z_][A-Za-z0-9_]*\\s*\\(.*")) return null;
        var d = address(t, castW, frame, hit.pos());
        if (!d.resolved()) return null;
        return scaled(new Base(d.base(), d.offset(), 1, true), name, frame);
    }

    private static Base scaled(Base b, String aliasName, Frame frame) {
        var sc = frame.scales().get(aliasName);
        return new Base(b.name(), b.off(), sc == null ? 1 : sc, true);
    }

    private static int castWidth(String inner) {
        var t = inner.trim();
        if (!t.endsWith("*")) return 0;
        var base = t.substring(0, t.length() - 1).trim();
        while (base.endsWith("*")) {
            base = base.substring(0, base.length() - 1).trim();
            return 8;
        }
        if (base.startsWith("unsigned ")) base = base.substring(9).trim();
        var sz = TYPE_SIZE.get(base);
        return sz == null ? (base.matches("[A-Za-z_][A-Za-z0-9_: ]*") ? 8 : 0) : sz;
    }

    public static int matchParen(String s, int open) {
        int depth = 0;
        for (int i = open; i < s.length(); i++) {
            char ch = s.charAt(i);
            if (ch == '(') depth++;
            else if (ch == ')' && --depth == 0) return i;
        }
        return -1;
    }

    private static int lastTopPlus(String s) {
        int depth = 0;
        int last = -1;
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            if (ch == '(' || ch == '[') depth++;
            else if (ch == ')' || ch == ']') depth--;
            else if (ch == '+' && depth == 0) last = i;
        }
        return last;
    }

    private static Long literal(String s) {
        var t = s.trim();
        try {
            if (t.startsWith("0x") || t.startsWith("0X")) return Long.parseLong(t.substring(2), 16);
            if (t.matches("[0-9]+")) return Long.parseLong(t);
        } catch (NumberFormatException e) {
            return null;
        }
        return null;
    }

    private static int parseNum(String s) {
        var n = literal(s);
        return n == null ? 0 : n.intValue();
    }

    private static int skipSpace(String s, int i) {
        int j = i;
        while (j < s.length() && Character.isWhitespace(s.charAt(j))) j++;
        return j;
    }

    private static int identEnd(String s, int i) {
        int j = i;
        while (j < s.length() && (Character.isLetterOrDigit(s.charAt(j)) || s.charAt(j) == '_')) j++;
        return j;
    }

    private static List<String> splitTop(String s, char sep) {
        var out = new ArrayList<String>();
        int depth = 0;
        int start = 0;
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            if (ch == '(' || ch == '<' || ch == '[') depth++;
            else if (ch == ')' || ch == '>' || ch == ']') depth--;
            else if (ch == sep && depth == 0) {
                out.add(s.substring(start, i));
                start = i + 1;
            }
        }
        out.add(s.substring(start));
        return out;
    }

    public static String hex(long v) {
        return v < 0 ? "-0x" + Long.toHexString(-v) : "0x" + Long.toHexString(v);
    }
}
