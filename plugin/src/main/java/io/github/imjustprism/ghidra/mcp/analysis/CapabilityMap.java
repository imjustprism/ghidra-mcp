package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import io.github.imjustprism.ghidra.mcp.http.Page;
import io.github.imjustprism.ghidra.mcp.util.DataTypes;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;
import io.github.imjustprism.ghidra.mcp.util.Strings;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * capa-style capability map from imports + defined strings.
 * Next-gen intake: what the sample <i>can</i> do, before any decompile.
 */
public final class CapabilityMap {

    private static final String[][] API_CAPS = {
            {"VirtualAllocEx", "process_injection"},
            {"VirtualProtectEx", "process_injection"},
            {"WriteProcessMemory", "process_injection"},
            {"ReadProcessMemory", "process_injection"},
            {"CreateRemoteThread", "process_injection"},
            {"NtCreateThreadEx", "process_injection"},
            {"NtMapViewOfSection", "process_injection"},
            {"QueueUserAPC", "process_injection"},
            {"RtlCreateUserThread", "process_injection"},
            {"InternetConnectA", "c2_http"},
            {"InternetConnectW", "c2_http"},
            {"HttpSendRequestA", "c2_http"},
            {"HttpSendRequestW", "c2_http"},
            {"WinHttpConnect", "c2_http"},
            {"WinHttpSendRequest", "c2_http"},
            {"URLDownloadToFileA", "c2_http"},
            {"URLDownloadToFileW", "c2_http"},
            {"InternetOpenA", "c2_http"},
            {"InternetReadFile", "c2_http"},
            {"socket", "c2_socket"},
            {"connect", "c2_socket"},
            {"send", "c2_socket"},
            {"recv", "c2_socket"},
            {"WSAStartup", "c2_socket"},
            {"BCryptEncrypt", "crypto_symmetric"},
            {"BCryptDecrypt", "crypto_symmetric"},
            {"BCryptGenerateSymmetricKey", "crypto_symmetric"},
            {"CryptEncrypt", "crypto_symmetric"},
            {"CryptDecrypt", "crypto_symmetric"},
            {"BCryptCreateHash", "crypto_hash"},
            {"BCryptHashData", "crypto_hash"},
            {"CryptCreateHash", "crypto_hash"},
            {"CryptHashData", "crypto_hash"},
            {"BCryptGenRandom", "crypto_random"},
            {"CryptGenRandom", "crypto_random"},
            {"IsDebuggerPresent", "anti_debug"},
            {"CheckRemoteDebuggerPresent", "anti_debug"},
            {"NtQueryInformationProcess", "anti_debug"},
            {"NtSetInformationThread", "anti_debug"},
            {"OutputDebugStringA", "anti_debug"},
            {"GetSystemFirmwareTable", "hwid"},
            {"GetAdaptersAddresses", "hwid"},
            {"GetVolumeInformationW", "hwid"},
            {"GetVolumeInformationA", "hwid"},
            {"GetComputerNameA", "hwid"},
            {"GetComputerNameW", "hwid"},
            {"RegSetValueExA", "persistence"},
            {"RegSetValueExW", "persistence"},
            {"RegCreateKeyExA", "persistence"},
            {"RegCreateKeyExW", "persistence"},
            {"CreateServiceA", "persistence"},
            {"CreateServiceW", "persistence"},
            {"StartServiceA", "persistence"},
            {"StartServiceW", "persistence"},
            {"AdjustTokenPrivileges", "privilege"},
            {"OpenProcessToken", "privilege"},
            {"LookupPrivilegeValueA", "privilege"},
            {"GetAsyncKeyState", "keylog"},
            {"SetWindowsHookExA", "keylog"},
            {"SetWindowsHookExW", "keylog"},
            {"BitBlt", "screenshot"},
            {"GetDC", "screenshot"},
            {"CreateFileA", "file"},
            {"CreateFileW", "file"},
            {"WriteFile", "file"},
            {"DeviceIoControl", "driver_io"},
            {"CreateToolhelp32Snapshot", "process_enum"},
            {"EnumProcesses", "process_enum"},
            {"ShellExecuteA", "exec"},
            {"ShellExecuteW", "exec"},
            {"WinExec", "exec"},
            {"CreateProcessA", "exec"},
            {"CreateProcessW", "exec"},
            {"LoadLibraryA", "dyn_api"},
            {"LoadLibraryW", "dyn_api"},
            {"GetProcAddress", "dyn_api"},
            {"VirtualProtect", "self_mod"},
            {"RtlAddFunctionTable", "manual_map"},
    };

    private static final String[][] STR_CAPS = {
            {"currentversion\\run", "persistence"},
            {"windivert", "packet_divert"},
            {"subscription", "license"},
            {"hwid", "license"},
            {"sessionsecret", "license"},
            {"accesstoken", "license"},
            {"authorization: bearer", "license"},
            {"x-request-sig", "license"},
            {"|drm", "license"},
            {"debugger detected", "anti_debug"},
            {"x64dbg", "anti_debug"},
            {"vmware", "anti_vm"},
            {"virtualbox", "anti_vm"},
            {"sandboxie", "anti_vm"},
    };

    private CapabilityMap() {}

    public static String map(PluginContext ctx, Page p, Map<String, String> q) {
        return ctx.withProgram(program -> {
            var hits = collect(program);
            var t = Responses.table(p, q, new String[]{"capability", "confidence", "evidence", "where"});
            var w = new Responses.Window(p);
            for (var h : hits) {
                if (!w.take()) continue;
                t.row(h.cap, h.confidence, Strings.escapeString(h.evidence), h.where);
            }
            return "# capability_map " + uniqueCaps(hits).size() + " unique cap(s)\n"
                    + t.total(w.total()).build();
        });
    }

    static List<Hit> collect(Program program) {
        var out = new ArrayList<Hit>();
        var st = program.getSymbolTable();
        for (var pair : API_CAPS) {
            for (var prefix : new String[]{"", "_", "__imp_"}) {
                for (var sym : st.getSymbols(prefix + pair[0])) {
                    int n = countCalls(program, sym);
                    if (n <= 0 && !sym.isExternal()) continue;
                    out.add(new Hit(pair[1], n > 2 ? "high" : "med", pair[0] + " x" + Math.max(n, 1),
                            Responses.addr(sym.getAddress())));
                }
            }
        }
        var it = program.getListing().getDefinedData(true);
        while (it.hasNext()) {
            var d = it.next();
            if (d == null || !DataTypes.isStringLike(d) || d.getValue() == null) continue;
            var s = d.getValue().toString().toLowerCase(Locale.ROOT);
            for (var pair : STR_CAPS) {
                if (s.contains(pair[0])) {
                    out.add(new Hit(pair[1], "med", pair[0], Responses.addr(d.getAddress())));
                }
            }
        }
        return out;
    }

    static String classifyImport(String name) {
        if (name == null) return "";
        var n = name;
        if (n.startsWith("__imp_")) n = n.substring(6);
        if (n.startsWith("_")) n = n.substring(1);
        for (var pair : API_CAPS) {
            if (pair[0].equals(n)) return pair[1];
        }
        return "";
    }

    static List<String> uniqueCaps(List<Hit> hits) {
        var seen = new LinkedHashMap<String, Boolean>();
        for (var h : hits) seen.putIfAbsent(h.cap, Boolean.TRUE);
        return new ArrayList<>(seen.keySet());
    }

    private static int countCalls(Program program, Symbol sym) {
        int n = 0;
        for (var ref : program.getReferenceManager().getReferencesTo(sym.getAddress())) {
            if (ref.getReferenceType().isCall() || ref.getReferenceType().isData()) n++;
        }
        return n;
    }

    record Hit(String cap, String confidence, String evidence, String where) {}
}
