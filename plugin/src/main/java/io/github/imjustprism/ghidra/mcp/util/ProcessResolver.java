package io.github.imjustprism.ghidra.mcp.util;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

public final class ProcessResolver {

    public record Candidate(int pid, String name, boolean openable, int openError,
            boolean wow64, int moduleCount) {

        public boolean blockedByIntegrity() {
            return !openable && openError == ProcessMemory.ERROR_ACCESS_DENIED;
        }
    }

    private ProcessResolver() {
    }

    public static List<Candidate> resolve(ProcessMemory rpm, String name) {
        var wanted = normalize(name);
        var out = new ArrayList<Candidate>();
        for (var p : rpm.listProcesses()) {
            if (!normalize(p.name()).equals(wanted)) continue;
            int err = rpm.probeOpen(p.pid());
            boolean openable = err == 0;
            int modules = openable ? rpm.modules(p.pid()).size() : 0;
            out.add(new Candidate(p.pid(), p.name(), openable,
                    err, openable && rpm.isWow64(p.pid()), modules));
        }
        out.sort(Comparator
                .comparing(Candidate::openable)
                .thenComparingInt(Candidate::moduleCount)
                .thenComparingInt(Candidate::pid)
                .reversed());
        return out;
    }

    private static String normalize(String s) {
        if (s == null) return "";
        var t = s.trim().toLowerCase();
        int slash = Math.max(t.lastIndexOf('/'), t.lastIndexOf('\\'));
        if (slash >= 0) t = t.substring(slash + 1);
        return t.endsWith(".exe") ? t : t + ".exe";
    }
}
