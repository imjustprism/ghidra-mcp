package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.util.task.ConsoleTaskMonitor;
import io.github.imjustprism.ghidra.mcp.util.Addresses;
import io.github.imjustprism.ghidra.mcp.util.DecompileCache;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class NebulaShapes {

    public record Shape(String kind, String header, String discriminator, long sizeOff,
                        long elemsOff, long width, String proof) {}

    private static final Shape[] TABLE = {
            new Shape("Util::Array", "util/array.h", "index < this->size", 0x08, 0x10, -1,
                    "GUIDE.md s3; capacity@0x00 grow@0x04 size@0x08 elements@0x10"),
            new Shape("Util::FixedArray", "util/fixedarray.h",
                    "this->elements && (index >= 0) && (index < this->size)", 0x00, 0x08, -1,
                    "GUIDE.md s3; size@0x00 elements@0x08"),
            new Shape("Core::Ptr", "core/ptr.h", "NULL pointer access in Ptr::operator->()!", -1, -1, 8,
                    "GUIDE.md s3; 8-byte pointer, pointee named by FUNCSIG"),
            new Shape("Math::point", "math/xnamath/xna_matrix44.h", "pos.w() > 0.0f", -1, -1, 16,
                    "GUIDE.md s3; 16 bytes, w > 0 distinguishes point from vector"),
            new Shape("Util::StringAtom", "util/stringatom.h", "0 != this->content", -1, -1, 8,
                    "GUIDE.md s3; 8-byte pointer into the interned atom table"),
    };

    private NebulaShapes() {}

    public static Shape byEvidence(String assertExpr, String file) {
        var expr = assertExpr == null ? "" : assertExpr;
        var f = file == null ? "" : file.toLowerCase(Locale.ROOT);
        for (var s : TABLE) {
            if (expr.equals(s.discriminator())) return s;
        }
        for (var s : TABLE) {
            if (!f.endsWith(s.header())) continue;
            if (expr.contains("this->size") || expr.contains("this->elements")
                    || expr.contains(s.discriminator()) || s.sizeOff() < 0) {
                return s;
            }
        }
        for (var s : TABLE) {
            if (expr.contains(s.discriminator())) return s;
        }
        return null;
    }

    public static Shape byKind(String kind) {
        if (kind == null || kind.isBlank()) return null;
        var k = kind.trim().toLowerCase(Locale.ROOT);
        for (var s : TABLE) {
            var name = s.kind().toLowerCase(Locale.ROOT);
            if (name.equals(k) || name.endsWith("::" + k)) return s;
        }
        return null;
    }

    public static String shapes(PluginContext ctx, String addr, String kind, Map<String, String> q) {
        if (addr == null || addr.isBlank()) return table(kind, q);
        return ctx.withAddress(addr, (program, a) -> {
            var func = Addresses.functionAtOrContaining(program, a);
            if (func == null) throw new IllegalArgumentException("no function at or containing " + addr);
            var rows = new LinkedHashMap<String, Object[]>();
            var notes = new ArrayList<String>();
            collect(program, func, DecompileCache.decompile(program, func), "self", rows, notes);
            int budget = 12;
            for (var callee : func.getCalledFunctions(new ConsoleTaskMonitor())) {
                if (budget-- <= 0) break;
                String cc;
                try {
                    cc = DecompileCache.decompile(program, callee);
                } catch (RuntimeException e) {
                    continue;
                }
                collect(program, callee, cc, callee.getName(), rows, notes);
            }
            var sb = new StringBuilder(1024);
            sb.append("# nebula_shape ").append(func.getName())
              .append(" entry=").append(Responses.addr(func.getEntryPoint())).append('\n');
            if (rows.isEmpty()) {
                sb.append("# no Nebula container assert found in this function or its direct callees\n");
                sb.append("# tip: point this at the accessor itself (operator[], Size, Begin) "
                        + "or call nebula_shape with no address for the proven shape table\n");
                return sb.toString();
            }
            for (var n : notes) sb.append("# ").append(n).append('\n');
            var t = Responses.table(q, new String[]{
                    "kind", "elem_type", "size_off", "elems_off", "width", "derived_size_off",
                    "derived_elems_off", "agrees", "via", "func", "assert", "source", "line", "funcsig"
            }, rows.size());
            for (var r : rows.values()) t.row(r);
            return sb.append(t.total(rows.size()).build()).toString();
        });
    }

    private static void collect(ghidra.program.model.listing.Program program,
            ghidra.program.model.listing.Function func, String c, String via,
            Map<String, Object[]> rows, List<String> notes) {
        var frame = AssertProofs.frame(c);
        for (var site : AssertProofs.sites(c)) {
            var shape = byEvidence(site.expr(), site.file());
            if (shape == null) continue;
            var owner = AssertProofs.ownerOf(site.sig());
            var elem = AssertProofs.elementTypeOf(owner);
            long derivedSize = -1;
            long derivedElems = -1;
            var guard = AssertProofs.guardFor(c, site.start());
            if (guard != null) {
                for (var d : AssertProofs.derefs(guard, frame, site.start())) {
                    if (!d.resolved()) continue;
                    if (d.width() == 4 && derivedSize < 0) derivedSize = d.offset();
                    if (d.width() == 8 && derivedElems < 0) derivedElems = d.offset();
                }
            }
            var agrees = agreement(shape, derivedSize, derivedElems);
            if ("conflict".equals(agrees)) {
                notes.add("CONFLICT " + shape.kind() + " in " + func.getName()
                        + ": table says size@" + AssertProofs.hex(shape.sizeOff())
                        + " elems@" + AssertProofs.hex(shape.elemsOff())
                        + " but this code dereferences size@" + AssertProofs.hex(derivedSize)
                        + " elems@" + AssertProofs.hex(derivedElems)
                        + " - do not trust either until resolved by hand");
            }
            var key = shape.kind() + "|" + elem + "|" + via;
            rows.putIfAbsent(key, new Object[]{
                    shape.kind(), elem,
                    shape.sizeOff() < 0 ? "" : AssertProofs.hex(shape.sizeOff()),
                    shape.elemsOff() < 0 ? "" : AssertProofs.hex(shape.elemsOff()),
                    shape.width() < 0 ? "" : AssertProofs.hex(shape.width()),
                    derivedSize < 0 ? "" : AssertProofs.hex(derivedSize),
                    derivedElems < 0 ? "" : AssertProofs.hex(derivedElems),
                    agrees, via, func.getName(), site.expr(), site.file(),
                    AssertProofs.hex(site.line()), site.sig()
            });
        }
    }

    private static String agreement(Shape shape, long derivedSize, long derivedElems) {
        if (shape.sizeOff() < 0 && shape.elemsOff() < 0) return "n/a";
        if (derivedSize < 0 && derivedElems < 0) return "unchecked";
        boolean sizeOk = derivedSize < 0 || derivedSize == shape.sizeOff();
        boolean elemsOk = derivedElems < 0 || derivedElems == shape.elemsOff();
        return sizeOk && elemsOk ? "yes" : "conflict";
    }

    private static String table(String kind, Map<String, String> q) {
        var wanted = byKind(kind);
        var list = new ArrayList<Shape>();
        if (wanted != null) list.add(wanted);
        else for (var s : TABLE) list.add(s);
        if (list.isEmpty()) {
            throw new IllegalArgumentException("unknown kind: " + kind
                    + " (known: Util::Array, Util::FixedArray, Core::Ptr, Math::point, Util::StringAtom)");
        }
        var t = Responses.table(q, new String[]{
                "kind", "header", "size_off", "elems_off", "width", "discriminator", "proof"
        }, list.size());
        for (var s : list) {
            t.row(s.kind(), s.header(),
                    s.sizeOff() < 0 ? "" : AssertProofs.hex(s.sizeOff()),
                    s.elemsOff() < 0 ? "" : AssertProofs.hex(s.elemsOff()),
                    s.width() < 0 ? "" : AssertProofs.hex(s.width()),
                    s.discriminator(), s.proof());
        }
        return "# nebula_shape proven Nebula3 container geometry\n"
                + "# every row is assert-anchored; pass address=<fn> to identify and cross-check a call site\n"
                + t.total(list.size()).build();
    }
}
