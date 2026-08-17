package io.github.imjustprism.ghidra.mcp.analysis;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

public final class NebulaNames {

    private static final Pattern QUALIFIED = Pattern.compile(
            "^[A-Za-z_][A-Za-z0-9_]*(::[A-Za-z_][A-Za-z0-9_]*)+$");
    private static final Pattern ATTR = Pattern.compile("^[a-z][a-z0-9_]{1,64}$");
    private static final Pattern MONEY = Pattern.compile("^money_[a-z0-9_]+$");
    private static final Set<String> ATTR_STOP = Set.of(
            "true", "false", "void", "this", "null", "int", "bool", "float", "char",
            "class", "const", "unsigned", "return", "none", "none_", "invalid",
            "origin", "notnull", "partial", "seqno", "unique", "dflt_value",
            "name", "type", "fourcc", "value", "index", "count", "size", "flags");

    private NebulaNames() {}

    public static boolean isFourCC(long v) {
        if (v <= 0 || v > 0xffff_ffffL) return false;
        int alpha = 0;
        for (int i = 0; i < 4; i++) {
            int b = (int) ((v >>> (8 * i)) & 0xff);
            if (b < 0x20 || b > 0x7e) return false;
            if (Character.isLetterOrDigit(b)) alpha++;
        }
        return alpha >= 2;
    }

    public static String fourCCAscii(long v) {
        char[] c = {
                (char) ((v >>> 24) & 0xff),
                (char) ((v >>> 16) & 0xff),
                (char) ((v >>> 8) & 0xff),
                (char) (v & 0xff)
        };
        return new String(c);
    }

    public static String fourCCHex(long v) {
        return "0x" + Long.toHexString(v & 0xffff_ffffL);
    }

    public static boolean isQualifiedClass(String s) {
        if (s == null) return false;
        var t = s.trim();
        if (t.length() < 3 || t.length() > 180) return false;
        if (t.indexOf('(') >= 0 || t.indexOf('<') >= 0 || t.indexOf(' ') >= 0) return false;
        if (t.indexOf('/') >= 0 || t.indexOf('\\') >= 0) return false;
        if (t.contains("__cdecl") || t.contains("__thiscall")) return false;
        return QUALIFIED.matcher(t).matches();
    }

    public static boolean isThisAssert(String s) {
        return s != null && s.contains("this->");
    }

    public static boolean looksLikeSourcePath(String s) {
        if (s == null || s.isBlank()) return false;
        var t = s.replace('\\', '/').toLowerCase(Locale.ROOT);
        boolean ext = t.endsWith(".cc") || t.endsWith(".cpp") || t.endsWith(".cxx")
                || t.endsWith(".h") || t.endsWith(".hpp") || t.endsWith(".c")
                || t.contains(".cc/") || t.contains(".h/");
        if (!ext) return false;
        return t.contains("/") || t.contains("nebula") || t.contains("drasa")
                || t.contains("jenkins") || t.contains("code");
    }

    public static boolean isFuncsig(String s) {
        if (s == null) return false;
        return s.contains("__cdecl") || s.contains("__thiscall")
                || s.contains("__stdcall") || s.contains("__fastcall");
    }

    public static boolean isAttrName(String s) {
        if (s == null) return false;
        var t = s.trim();
        if (!ATTR.matcher(t).matches()) return false;
        return !ATTR_STOP.contains(t);
    }

    public static boolean isMoneyAttr(String s) {
        return s != null && MONEY.matcher(s.trim()).matches();
    }

    public static boolean isMessagingClass(String s) {
        return isQualifiedClass(s) && s.startsWith("Messaging::")
                && s.indexOf("::", 11) < 0;
    }

    public static boolean isHandleMessageName(String name) {
        if (name == null) return false;
        return name.contains("HandleMessage") || name.endsWith("_HandleMessage");
    }

    public static boolean namespaceMatches(String owner, String filter) {
        if (filter == null || filter.isBlank()) return true;
        if (owner == null || owner.isBlank()) return false;
        var f = filter.trim();
        if (f.endsWith("::")) f = f.substring(0, f.length() - 2);
        var head = owner;
        int lt = head.indexOf('<');
        if (lt >= 0) head = head.substring(0, lt);
        var h = head.toLowerCase(Locale.ROOT);
        var fl = f.toLowerCase(Locale.ROOT);
        return h.equals(fl) || h.startsWith(fl + "::");
    }

    public static boolean containsIgnoreCase(String hay, String needle) {
        if (needle == null || needle.isBlank()) return true;
        if (hay == null) return false;
        return hay.toLowerCase(Locale.ROOT).contains(needle.trim().toLowerCase(Locale.ROOT));
    }

    public static List<String> namespaceChain(String owner) {
        var out = new ArrayList<String>();
        if (owner == null || owner.isBlank()) return out;
        int depth = 0;
        int start = 0;
        var soFar = new StringBuilder();
        for (int i = 0; i < owner.length(); i++) {
            char ch = owner.charAt(i);
            if (ch == '<') depth++;
            else if (ch == '>') depth--;
            else if (ch == ':' && depth == 0 && i + 1 < owner.length() && owner.charAt(i + 1) == ':') {
                var part = owner.substring(start, i).trim();
                if (!part.isEmpty()) {
                    if (soFar.length() > 0) soFar.append("::");
                    soFar.append(part);
                    out.add(soFar.toString());
                }
                start = i + 2;
                i++;
            }
        }
        var tail = owner.substring(start).trim();
        if (!tail.isEmpty()) {
            if (soFar.length() > 0) soFar.append("::");
            soFar.append(tail);
            out.add(soFar.toString());
        }
        return out;
    }

    public static String parentNamespace(String qualified) {
        var chain = namespaceChain(qualified);
        if (chain.size() < 2) return "";
        return chain.get(chain.size() - 2);
    }

    public static String leafName(String qualified) {
        if (qualified == null || qualified.isBlank()) return "";
        var chain = namespaceChain(qualified);
        if (chain.isEmpty()) return qualified;
        var last = chain.get(chain.size() - 1);
        int cut = last.lastIndexOf("::");
        return cut < 0 ? last : last.substring(cut + 2);
    }

    public static String pickClassName(List<String> strings) {
        String best = null;
        int bestScore = -1;
        for (var s : strings) {
            if (!isQualifiedClass(s)) continue;
            int score = 2;
            if (s.startsWith("Messaging::") || s.startsWith("Game::")
                    || s.startsWith("Properties::") || s.startsWith("UI::")
                    || s.startsWith("Skills::") || s.startsWith("Managers::")) {
                score += 2;
            }
            if (s.startsWith("Util::") || s.startsWith("Core::")) score -= 1;
            if (s.length() < 48) score += 1;
            if (score > bestScore) {
                bestScore = score;
                best = s;
            }
        }
        return best == null ? "" : best;
    }

    public static String pickFourCC(List<Long> immediates) {
        Long best = null;
        for (var v : immediates) {
            if (v == null || !isFourCC(v)) continue;
            if (best == null) best = v;
        }
        return best == null ? "" : fourCCHex(best);
    }
}
