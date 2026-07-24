package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import io.github.imjustprism.ghidra.mcp.http.Page;
import io.github.imjustprism.ghidra.mcp.util.DataTypes;
import io.github.imjustprism.ghidra.mcp.util.Patterns;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public final class Signatures {

    private Signatures() {}

    private static final int DEFAULT_MAX_BYTES = 256;
    private static final int DEFAULT_MIN_BYTES = 8;
    private static final long NON_UNIQUE_CAP = 1000;

    public static String make(PluginContext ctx, String addrStr, int minLen, int maxLen, String format) {
        return ctx.withAddress(addrStr, (program, start) -> {
            var listing = program.getListing();
            var insn = listing.getInstructionContaining(start);
            if (insn == null) throw new IllegalArgumentException("No instruction at " + addrStr);
            var built = build(program.getMemory(), insn, bodyLimit(program, start),
                    minLen > 0 ? minLen : DEFAULT_MIN_BYTES,
                    maxLen > 0 ? maxLen : DEFAULT_MAX_BYTES);
            if (built == null) return "Could not read instruction bytes at " + addrStr;
            return header(built) + built.sig.render(format);
        });
    }

    public static String resolveRelative(PluginContext ctx, String addrStr) {
        return ctx.withAddress(addrStr, (program, a) -> {
            var insn = program.getListing().getInstructionContaining(a);
            if (insn == null) throw new IllegalArgumentException("No instruction at " + addrStr);
            var refs = insn.getReferencesFrom();
            if (refs.length == 0) {
                return "No address/relative operand at " + Responses.addr(insn.getAddress());
            }
            var t = Responses.table(Responses.Fmt.TSV,
                    new String[]{"op", "type", "target", "symbol"}, refs.length);
            var st = program.getSymbolTable();
            for (var r : refs) {
                var to = r.getToAddress();
                var sym = to == null ? null : st.getPrimarySymbol(to);
                t.row(r.getOperandIndex(), r.getReferenceType().getName(),
                        to == null ? "" : Responses.addr(to), sym == null ? "" : sym.getName());
            }
            return t.build();
        });
    }

    public static String findSignature(PluginContext ctx, String pattern, Page p, Map<String, String> q) {
        if (pattern == null || pattern.isBlank()) throw new IllegalArgumentException("Pattern is required");
        Patterns.Sig sig;
        try {
            sig = Patterns.parse(pattern);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Bad pattern: " + e.getMessage());
        }
        return ctx.withProgram(program -> {
            var mem = program.getMemory();
            var t = Responses.table(p, q, new String[]{"addr"});
            var w = new Responses.Window(p);
            var monitor = new ghidra.util.task.ConsoleTaskMonitor();
            int cap = p.offset() + p.limit();
            Address cursor = mem.getMinAddress();
            while (cursor != null && w.total() < cap) {
                Address hit = mem.findBytes(cursor, sig.bytes(), sig.mask(), true, monitor);
                if (hit == null) break;
                if (w.take()) t.row(Responses.addr(hit));
                cursor = hit.next();
            }
            return t.total(w.total()).build();
        });
    }

    public static String findFunctionByString(PluginContext ctx, String value, int max, String format, boolean regex,
            boolean withCallers) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException("Value is required");
        var pattern = regex ? compile(value) : null;
        var needle = regex ? null : value.toLowerCase();
        return ctx.withProgram(program -> {
            var listing = program.getListing();
            var mem = program.getMemory();
            var fm = program.getFunctionManager();
            var refMgr = program.getReferenceManager();
            int cap = max > 0 ? max : 20;
            var seen = new HashSet<Address>();
            var cols = withCallers
                    ? new String[]{"func", "func_addr", "xref", "str_addr", "matches", "signature", "callers", "caller_n"}
                    : new String[]{"func", "func_addr", "xref", "str_addr", "matches", "signature"};
            var t = Responses.table(Responses.Fmt.TSV, cols, cap);
            int found = 0;
            int strHits = 0;
            Address firstStr = null;
            var monitor = new ghidra.util.task.ConsoleTaskMonitor();
            var it = listing.getDefinedData(true);
            while (it.hasNext() && found < cap) {
                var data = it.next();
                if (data == null || !DataTypes.isStringLike(data)) continue;
                var sv = data.getValue() != null ? data.getValue().toString() : "";
                if (pattern != null ? !pattern.matcher(sv).find() : !sv.toLowerCase().contains(needle)) continue;
                strHits++;
                if (firstStr == null) firstStr = data.getAddress();
                for (var ref : refMgr.getReferencesTo(data.getAddress())) {
                    var fn = fm.getFunctionContaining(ref.getFromAddress());
                    if (fn == null || !seen.add(fn.getEntryPoint())) continue;
                    var insn = listing.getInstructionContaining(fn.getEntryPoint());
                    var built = insn == null ? null
                            : build(mem, insn, fn.getBody().getMaxAddress(), DEFAULT_MIN_BYTES, DEFAULT_MAX_BYTES);
                    if (withCallers) {
                        var callerFns = fn.getCallingFunctions(monitor);
                        var names = new ArrayList<String>(callerFns.size());
                        for (var c : callerFns) names.add(c.getName());
                        t.row(fn.getName(), Responses.addr(fn.getEntryPoint()),
                                Responses.addr(ref.getFromAddress()), Responses.addr(data.getAddress()),
                                built == null ? 0 : built.matches,
                                built == null ? "n/a" : built.sig.render(format),
                                String.join(",", names), names.size());
                    } else {
                        t.row(fn.getName(), Responses.addr(fn.getEntryPoint()),
                                Responses.addr(ref.getFromAddress()), Responses.addr(data.getAddress()),
                                built == null ? 0 : built.matches,
                                built == null ? "n/a" : built.sig.render(format));
                    }
                    if (++found >= cap) break;
                }
            }
            if (found > 0) return t.total(found).build();
            return strHits == 0
                    ? "No defined string contains: " + value
                    : strHits + " string(s) match \"" + value + "\" (e.g. " + Responses.addr(firstStr)
                            + ") but none are referenced from within a function";
        });
    }

    public static String exportOffsets(PluginContext ctx, String filter, boolean regex, boolean namedOnly,
            String format, Page page, Map<String, String> q) {
        return ctx.withProgram(program -> {
            Pattern pattern = null;
            String needle = null;
            if (filter != null && !filter.isBlank()) {
                if (regex) pattern = compile(filter);
                else needle = filter.toLowerCase();
            }
            long base = program.getImageBase().getOffset();
            boolean cpp = "cpp".equalsIgnoreCase(format) || "c".equalsIgnoreCase(format)
                    || "hpp".equalsIgnoreCase(format);
            var t = Responses.table(page, q, new String[]{"name", "rva", "va"});
            var w = new Responses.Window(page);
            var cppLines = new ArrayList<String>();
            for (var f : program.getFunctionManager().getFunctions(true)) {
                var name = f.getName();
                if (namedOnly && (Responses.isAutoName(name) || f.isThunk() || name.startsWith("thunk_"))) continue;
                if (pattern != null && !pattern.matcher(name).find()) continue;
                if (needle != null && !name.toLowerCase().contains(needle)) continue;
                long va = f.getEntryPoint().getOffset();
                long rva = va - base;
                var rvaHex = "0x" + Long.toHexString(rva);
                var vaHex = Responses.addr(f.getEntryPoint());
                if (cpp) {
                    if (!w.take()) continue;
                    cppLines.add("constexpr std::uint32_t " + sanitizeIdent(name) + " = " + rvaHex + ";");
                } else {
                    if (!w.take()) continue;
                    t.row(name, rvaHex, vaHex);
                }
            }
            if (cpp) {
                var sb = new StringBuilder(cppLines.size() * 48 + 64);
                sb.append("# export_offsets image_base=").append(Responses.addr(program.getImageBase()))
                        .append(" named_only=").append(namedOnly).append(" total=").append(w.total()).append('\n');
                for (var line : cppLines) sb.append(line).append('\n');
                return sb.toString();
            }
            return t.total(w.total()).build();
        });
    }

    private static String sanitizeIdent(String name) {
        var sb = new StringBuilder(name.length());
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
                sb.append(c);
            } else {
                sb.append('_');
            }
        }
        if (sb.isEmpty() || Character.isDigit(sb.charAt(0))) sb.insert(0, '_');
        return sb.toString();
    }

    private static Pattern compile(String regex) {
        try {
            return Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
        } catch (PatternSyntaxException e) {
            throw new IllegalArgumentException("bad regex: " + e.getMessage());
        }
    }

    private static Address bodyLimit(ghidra.program.model.listing.Program program, Address start) {
        var fn = program.getFunctionManager().getFunctionContaining(start);
        return fn == null ? null : fn.getBody().getMaxAddress();
    }

    private record Built(Patterns.Sig sig, long matches) {}

    private static Built build(Memory mem, Instruction insn, Address bodyMax, int minLen, int limit) {
        var bytes = new ArrayList<Byte>();
        var mask = new ArrayList<Byte>();
        while (insn != null && bytes.size() < limit) {
            if (bodyMax != null && insn.getAddress().compareTo(bodyMax) > 0) break;
            if (!appendInstruction(insn, bytes, mask)) break;
            var trimmed = trim(bytes, mask);
            if (trimmed.length() >= minLen && !trimmed.allWildcard()
                    && Patterns.countMatches(mem, trimmed, 2) == 1) {
                return new Built(trimmed, 1);
            }
            insn = insn.getNext();
        }
        if (bytes.isEmpty()) return null;
        var trimmed = trim(bytes, mask);
        return new Built(trimmed, Patterns.countMatches(mem, trimmed, NON_UNIQUE_CAP));
    }

    private static boolean appendInstruction(Instruction insn, List<Byte> outBytes, List<Byte> outMask) {
        byte[] b;
        try {
            b = insn.getBytes();
        } catch (MemoryAccessException e) {
            return false;
        }
        var proto = insn.getPrototype();
        var acc = new byte[b.length];
        for (int op = 0; op < insn.getNumOperands(); op++) {
            int type = insn.getOperandType(op);
            if (!OperandType.isAddress(type) && !OperandType.isDynamic(type)) continue;
            var m = proto.getOperandValueMask(op);
            if (m == null) continue;
            var mb = m.getBytes();
            for (int i = 0; i < acc.length && i < mb.length; i++) acc[i] |= mb[i];
        }
        for (int i = 0; i < b.length; i++) {
            outBytes.add(b[i]);
            outMask.add(acc[i] == (byte) 0xFF ? (byte) 0 : (byte) 0xFF);
        }
        return true;
    }

    private static Patterns.Sig trim(List<Byte> bytes, List<Byte> mask) {
        int end = mask.size();
        while (end > 0 && mask.get(end - 1) == 0) end--;
        var b = new byte[end];
        var m = new byte[end];
        for (int i = 0; i < end; i++) {
            b[i] = bytes.get(i);
            m[i] = mask.get(i);
        }
        return new Patterns.Sig(b, m);
    }

    private static String header(Built built) {
        var sig = built.sig;
        return "# bytes=%d; wildcards=%d; matches=%s; %s\n".formatted(
                sig.length(), sig.wildcards(),
                built.matches >= NON_UNIQUE_CAP ? ">=" + NON_UNIQUE_CAP : Long.toString(built.matches),
                built.matches == 1 ? "unique" : "NOT UNIQUE — widen scope or use find_function_by_string");
    }
}
