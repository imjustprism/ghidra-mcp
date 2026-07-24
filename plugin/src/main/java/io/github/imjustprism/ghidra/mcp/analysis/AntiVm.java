package io.github.imjustprism.ghidra.mcp.analysis;

import io.github.imjustprism.ghidra.mcp.http.Page;
import io.github.imjustprism.ghidra.mcp.util.DataTypes;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;
import io.github.imjustprism.ghidra.mcp.util.Strings;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class AntiVm {

    private record Indicator(String needle, String category) {}

    private static final List<Indicator> INDICATORS = List.of(
        new Indicator("vmware", "vmware"),
        new Indicator("vmtoolsd", "vmware"),
        new Indicator("vmmouse", "vmware"),
        new Indicator("vmhgfs", "vmware"),
        new Indicator("vmci", "vmware"),
        new Indicator("440bx", "vmware"),
        new Indicator("virtualbox", "virtualbox"),
        new Indicator("vboxguest", "virtualbox"),
        new Indicator("vboxservice", "virtualbox"),
        new Indicator("vboxtray", "virtualbox"),
        new Indicator("vboxmouse", "virtualbox"),
        new Indicator("vboxsf", "virtualbox"),
        new Indicator("qemu", "qemu"),
        new Indicator("bochs", "qemu"),
        new Indicator("xenvbd", "xen"),
        new Indicator("xennet", "xen"),
        new Indicator("vmbus", "hyperv"),
        new Indicator("hyper-v", "hyperv"),
        new Indicator("sandboxie", "sandbox"),
        new Indicator("sbiedll", "sandbox"),
        new Indicator("cuckoomon", "sandbox")
    );

    private static final List<Indicator> MAC_PREFIXES = List.of(
        new Indicator("000569", "mac_vmware"),
        new Indicator("000c29", "mac_vmware"),
        new Indicator("005056", "mac_vmware"),
        new Indicator("080027", "mac_vbox")
    );

    private AntiVm() {}

    public static String find(PluginContext ctx, Page p, Map<String, String> q) {
        return ctx.withProgram(program -> {
            var rows = new ArrayList<Object[]>();
            long off = p.offset();
            long lim = p.limit();
            long total = 0;
            var it = program.getListing().getDefinedData(true);
            while (it.hasNext()) {
                var data = it.next();
                if (data == null || !DataTypes.isStringLike(data)) continue;
                var value = data.getValue() != null ? data.getValue().toString() : "";
                if (value.isEmpty()) continue;
                var category = match(value.toLowerCase(Locale.ROOT));
                if (category == null) continue;
                if (total >= off && rows.size() < lim) {
                    rows.add(new Object[]{Responses.addr(data.getAddress()), category,
                            Strings.escapeString(value)});
                }
                total++;
            }
            var t = Responses.table(p, q, new String[]{"addr", "category", "value"});
            for (var r : rows) {
                t.row(r);
            }
            return t.total((int) Math.min(total, Integer.MAX_VALUE)).build();
        });
    }

    private static String match(String lower) {
        for (var ind : INDICATORS) {
            if (lower.contains(ind.needle())) return ind.category();
        }
        for (var mac : MAC_PREFIXES) {
            var compact = mac.needle();
            if (lower.contains(compact) || lower.contains(sep(compact, ':')) || lower.contains(sep(compact, '-'))) {
                return mac.category();
            }
        }
        return null;
    }

    private static String sep(String compact, char c) {
        return compact.substring(0, 2) + c + compact.substring(2, 4) + c + compact.substring(4, 6);
    }
}
