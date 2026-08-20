package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import io.github.imjustprism.ghidra.mcp.http.Page;
import io.github.imjustprism.ghidra.mcp.util.DataTypes;
import io.github.imjustprism.ghidra.mcp.util.Imports;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.Responses;
import io.github.imjustprism.ghidra.mcp.util.Strings;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * One-call license / C2 / HWID / crypto surface for a packed or obfuscated
 * client. Combines imports, defined strings, and recover_hidden_strings.
 */
public final class AuthSurface {

    private static final Pattern API_PATH = Pattern.compile("(/api/[A-Za-z0-9_./?-]{2,80})");
    private static final Pattern HOST = Pattern.compile(
            "\\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+(?:com|net|org|io|gg|dev|app|xyz)\\b",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern URL = Pattern.compile(
            "https?://[\\w.-]+(?::\\d+)?(?:/[^\\s\"']*)?", Pattern.CASE_INSENSITIVE);

    private static final String[] JSON_KEYS = {
            "username", "password", "hwid", "accessToken", "refreshToken", "sessionSecret",
            "token", "latestVersion", "subscription", "hwid_components", "cpuid",
            "smbios_uuid", "baseboard_serial", "disk_serials", "mac_addresses",
            "machine_guid", "volume_serial", "reason", "processes", "version"
    };

    private static final String[] HEADERS = {
            "Authorization", "Bearer", "X-Timestamp", "X-Nonce", "X-Request-Sig",
            "Content-Type", "application/json", "Accept:"
    };

    private static final String[] HTTP_APIS = {
            "InternetOpenA", "InternetOpenW", "InternetConnectA", "InternetConnectW",
            "HttpOpenRequestA", "HttpOpenRequestW", "HttpSendRequestA", "HttpSendRequestW",
            "HttpAddRequestHeadersA", "InternetReadFile", "WinHttpConnect", "WinHttpOpen",
            "WinHttpSendRequest", "URLDownloadToFileA", "URLDownloadToFileW"
    };

    private static final String[] CRYPTO_APIS = {
            "BCryptOpenAlgorithmProvider", "BCryptCreateHash", "BCryptHashData",
            "BCryptFinishHash", "BCryptGenerateSymmetricKey", "BCryptEncrypt",
            "BCryptDecrypt", "BCryptGenRandom", "CryptEncrypt", "CryptHashData",
            "CryptAcquireContextA"
    };

    private static final String[] HWID_APIS = {
            "GetSystemFirmwareTable", "GetVolumeInformationW", "GetVolumeInformationA",
            "GetAdaptersAddresses", "DeviceIoControl", "RegOpenKeyExW", "RegQueryValueExW",
            "GetComputerNameA", "GetComputerNameW"
    };

    private static final String[] INJECT_APIS = {
            "VirtualAllocEx", "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread",
            "NtQueryInformationProcess", "OpenProcess", "VirtualProtectEx"
    };

    private AuthSurface() {}

    public static String recover(PluginContext ctx, Page p, Map<String, String> q) {
        return ctx.withProgram(program -> {
            var hidden = HiddenStrings.scanProgram(program, "auto", 4);
            var defined = collectDefined(program);
            var texts = new ArrayList<String>();
            texts.addAll(defined);
            for (var h : hidden) texts.add(h.value());

            var rows = new ArrayList<String[]>();
            addApiRows(program, HTTP_APIS, "http_api", rows);
            addApiRows(program, CRYPTO_APIS, "crypto_api", rows);
            addApiRows(program, HWID_APIS, "hwid_api", rows);
            addApiRows(program, INJECT_APIS, "inject_api", rows);

            for (var t : texts) classifyText(t, rows);

            for (var h : hidden) {
                rows.add(new String[]{"hidden_string", h.func(), h.algo(), h.value()});
                if (h.value().startsWith("/")) {
                    rows.add(new String[]{"endpoint_path", h.func(), h.algo(), h.value()});
                }
            }

            var t = Responses.table(p, q, new String[]{"kind", "where", "detail", "value"});
            var w = new Responses.Window(p);
            var seen = new java.util.HashSet<String>();
            int total = 0;
            for (var r : rows) {
                var key = r[0] + "|" + r[3];
                if (!seen.add(key)) continue;
                total++;
                if (!w.take()) continue;
                t.row(r[0], r[1], r[2], Strings.escapeString(r[3]));
            }
            return "# recover_auth_surface hidden=" + hidden.size() + " defined_strings="
                    + defined.size() + "\n" + t.total(total).build();
        });
    }

    static void classifyText(String t, List<String[]> rows) {
        if (t == null || t.length() < 3) return;
        var m = URL.matcher(t);
        while (m.find()) rows.add(new String[]{"url", "string", "", m.group()});
        var h = HOST.matcher(t);
        while (h.find()) rows.add(new String[]{"host", "string", "", h.group()});
        var p = API_PATH.matcher(t);
        while (p.find()) rows.add(new String[]{"endpoint_path", "string", "", p.group()});
        var low = t.toLowerCase(Locale.ROOT);
        for (var k : JSON_KEYS) {
            if (low.contains(k.toLowerCase(Locale.ROOT))) {
                rows.add(new String[]{"json_key", "string", k, t.length() > 80 ? t.substring(0, 80) : t});
            }
        }
        for (var hdr : HEADERS) {
            if (t.contains(hdr)) rows.add(new String[]{"http_header", "string", hdr, t});
        }
        if (t.contains("|drm") || t.contains("|v1") || low.contains("pepper") || low.contains("hmac")) {
            rows.add(new String[]{"crypto_marker", "string", "", t});
        }
        if (low.contains("hwid") || low.contains("smbios") || low.contains("machineguid")) {
            rows.add(new String[]{"hwid_marker", "string", "", t});
        }
        if (t.equals("GET") || t.equals("POST") || t.equals("PUT") || t.equals("DELETE")) {
            rows.add(new String[]{"http_method", "imm", "", t});
        }
    }

    private static void addApiRows(Program program, String[] names, String kind, List<String[]> rows) {
        var st = program.getSymbolTable();
        var fm = program.getFunctionManager();
        for (var name : names) {
            for (var prefix : new String[]{"", "_", "__imp_"}) {
                for (var sym : st.getSymbols(prefix + name)) {
                    String where = Responses.addr(sym.getAddress());
                    int sites = 0;
                    String caller = "";
                    for (var ref : program.getReferenceManager().getReferencesTo(sym.getAddress())) {
                        if (!ref.getReferenceType().isCall()) continue;
                        sites++;
                        var fn = fm.getFunctionContaining(ref.getFromAddress());
                        if (fn != null && caller.isEmpty()) caller = fn.getName();
                    }
                    if (sites == 0) {
                        try {
                            sites = Imports.callSites(program, sym).size();
                        } catch (RuntimeException ignored) {
                            // keep 0
                        }
                    }
                    rows.add(new String[]{kind, caller.isEmpty() ? where : caller,
                            sites + " site(s)", name});
                }
            }
        }
    }

    private static List<String> collectDefined(Program program) {
        var out = new ArrayList<String>();
        var it = program.getListing().getDefinedData(true);
        while (it.hasNext()) {
            Data d = it.next();
            if (d == null || !DataTypes.isStringLike(d) || d.getValue() == null) continue;
            var s = d.getValue().toString();
            if (s.length() >= 3) out.add(s);
        }
        return out;
    }
}
