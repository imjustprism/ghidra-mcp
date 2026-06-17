package io.github.imjustprism.ghidra.mcp.util;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public enum NamingConvention {
    SNAKE,
    SCREAMING_SNAKE,
    CAMEL,
    PASCAL;

    public static NamingConvention from(String name) {
        if (name == null) return null;
        return switch (name.trim().toLowerCase(Locale.ROOT)) {
            case "snake", "snake_case" -> SNAKE;
            case "screaming_snake", "screaming", "upper_snake", "constant" -> SCREAMING_SNAKE;
            case "camel", "camelcase" -> CAMEL;
            case "pascal", "pascalcase" -> PASCAL;
            default -> null;
        };
    }

    public String apply(String identifier) {
        var tokens = tokenize(identifier);
        if (tokens.isEmpty()) return identifier;
        return switch (this) {
            case SNAKE -> joinLower(tokens, "_");
            case SCREAMING_SNAKE -> joinUpper(tokens);
            case CAMEL -> camel(tokens, false);
            case PASCAL -> camel(tokens, true);
        };
    }

    private static List<String> tokenize(String identifier) {
        var tokens = new ArrayList<String>();
        if (identifier == null) return tokens;
        var word = new StringBuilder();
        var chars = identifier.toCharArray();
        for (int i = 0; i < chars.length; i++) {
            char c = chars[i];
            if (!Character.isLetterOrDigit(c)) {
                flush(word, tokens);
                continue;
            }
            char prev = word.length() > 0 ? word.charAt(word.length() - 1) : 0;
            boolean upperBoundary = word.length() > 0
                    && Character.isUpperCase(c)
                    && (Character.isLowerCase(prev)
                        || Character.isDigit(prev)
                        || (i + 1 < chars.length && Character.isLowerCase(chars[i + 1])));
            boolean digitBoundary = word.length() > 0
                    && Character.isLetter(c)
                    && Character.isDigit(prev);
            if (upperBoundary || digitBoundary) flush(word, tokens);
            word.append(c);
        }
        flush(word, tokens);
        return tokens;
    }

    private static void flush(StringBuilder word, List<String> tokens) {
        if (word.length() == 0) return;
        tokens.add(word.toString());
        word.setLength(0);
    }

    private static String joinLower(List<String> tokens, String sep) {
        var sb = new StringBuilder();
        for (var t : tokens) {
            if (sb.length() > 0) sb.append(sep);
            sb.append(t.toLowerCase(Locale.ROOT));
        }
        return sb.toString();
    }

    private static String joinUpper(List<String> tokens) {
        var sb = new StringBuilder();
        for (var t : tokens) {
            if (sb.length() > 0) sb.append('_');
            sb.append(t.toUpperCase(Locale.ROOT));
        }
        return sb.toString();
    }

    private static String camel(List<String> tokens, boolean capitalizeFirst) {
        var sb = new StringBuilder();
        for (int i = 0; i < tokens.size(); i++) {
            var t = tokens.get(i).toLowerCase(Locale.ROOT);
            if (i == 0 && !capitalizeFirst) sb.append(t);
            else sb.append(Character.toUpperCase(t.charAt(0))).append(t.substring(1));
        }
        return sb.toString();
    }
}
