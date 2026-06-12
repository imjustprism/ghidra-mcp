package io.github.imjustprism.ghidra.mcp.util;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class Json {

    private Json() {}

    public record JsonStr(String value, int next) {}

    public static List<Map<String, String>> parseObjectArray(String s) {
        var out = new ArrayList<Map<String, String>>();
        int i = 0;
        int n = s.length();
        i = skipWs(s, i);
        if (i >= n || s.charAt(i) != '[') throw new IllegalArgumentException("expected '['");
        i++;
        i = skipWs(s, i);
        if (i < n && s.charAt(i) == ']') return out;
        while (i < n) {
            i = skipWs(s, i);
            if (i >= n || s.charAt(i) != '{') throw new IllegalArgumentException("expected '{'");
            i++;
            var obj = new HashMap<String, String>();
            while (true) {
                i = skipWs(s, i);
                if (i < n && s.charAt(i) == '}') { i++; break; }
                var key = parseString(s, i);
                i = key.next;
                i = skipWs(s, i);
                if (i >= n || s.charAt(i) != ':') throw new IllegalArgumentException("expected ':'");
                i++;
                i = skipWs(s, i);
                String val;
                if (i < n && s.charAt(i) == '"') {
                    var v = parseString(s, i);
                    val = v.value;
                    i = v.next;
                } else {
                    int start = i;
                    while (i < n) {
                        char c = s.charAt(i);
                        if (c == ',' || c == '}' || Character.isWhitespace(c)) break;
                        i++;
                    }
                    val = s.substring(start, i);
                }
                obj.put(key.value, val);
                i = skipWs(s, i);
                if (i < n && s.charAt(i) == ',') { i++; continue; }
                if (i < n && s.charAt(i) == '}') { i++; break; }
                throw new IllegalArgumentException("expected ',' or '}'");
            }
            out.add(obj);
            i = skipWs(s, i);
            if (i < n && s.charAt(i) == ',') { i++; continue; }
            if (i < n && s.charAt(i) == ']') { i++; break; }
            throw new IllegalArgumentException("expected ',' or ']'");
        }
        return out;
    }

    public static JsonStr parseString(String s, int i) {
        int n = s.length();
        if (i >= n || s.charAt(i) != '"') throw new IllegalArgumentException("expected '\"'");
        i++;
        var sb = new StringBuilder();
        while (i < n) {
            char c = s.charAt(i);
            if (c == '"') return new JsonStr(sb.toString(), i + 1);
            if (c == '\\' && i + 1 < n) {
                char nx = s.charAt(i + 1);
                switch (nx) {
                    case 'n' -> sb.append('\n');
                    case 't' -> sb.append('\t');
                    case 'r' -> sb.append('\r');
                    case '"' -> sb.append('"');
                    case '\\' -> sb.append('\\');
                    case '/' -> sb.append('/');
                    default -> sb.append(nx);
                }
                i += 2;
            } else {
                sb.append(c);
                i++;
            }
        }
        throw new IllegalArgumentException("unterminated string");
    }

    public static int skipWs(String s, int i) {
        while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++;
        return i;
    }
}
