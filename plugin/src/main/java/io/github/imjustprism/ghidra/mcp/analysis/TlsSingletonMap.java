package io.github.imjustprism.ghidra.mcp.analysis;

import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.ProcessMemory;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.Map;

public final class TlsSingletonMap {

    private static final Object[][] SLOTS = {
            {0x58, "Game::ClientGameWorld*", "local player / world"},
            {0x60, "DrasaClient*", "client root"},
            {0x90, "Game::ClientActorManager*", "nearby entity list"},
            {0xa8, "ClientDestroyableManager*", "destroyables"},
            {0xb0, "ClientEventSystem*", "events"},
            {0xc0, "Game::ClientItemManager*", "world items"},
            {0xc8, "Game::ClientMonsterManager*", "monsters"},
            {0xd0, "Game::ClientNpcManager*", "npcs"},
            {0xe0, "Game::ClientPlayerManager*", "players"},
            {0xe8, "Game::ClientPropManager*", "props"},
            {0x140, "ConversionStoryMgr*", "conversion story"},
            {0x160, "Intrusion*", "intrusion / security"},
            {0x1e8, "LocationMapManager*", "minimap / location map"},
            {0x248, "StatusEffectMgr*", "status effects"},
            {0x250, "LocationEffectMgr*", "location effects"},
            {0x258, "TrapMgr*", "traps"},
            {0x268, "DrasaUIManager*", "UI root"},
            {0x2e0, "TransformDeviceBase*", "transform base"},
            {0x300, "CoreGraphics::TransformDevice*", "W2S projector Instance()"},
            {0x328, "D3D9RenderDevice*", "d3d9 device wrapper"},
            {0x330, "RenderDevice*", "frame begin/end"},
            {0x340, "Win32Display*", "wndproc path"},
            {0x348, "D3D9DisplayDevice*", "present / HWND"},
            {0x350, "DisplayDevice*", "display"},
            {0x360, "ShaderServer*", "shaders"},
            {0x3c0, "TextRenderer*", "engine text"},
            {0x520, "CoreUIRenderer*", "game UI render"},
            {0x5c0, "StagingSystem*", "staging"},
            {0x5c8, "TriggerManager*", "triggers"},
            {0x6b0, "Game::EntityManager*", "entity id space"},
            {0x6d0, "FactoryManager*", "entity create"},
    };

    private TlsSingletonMap() {}

    public static String map(PluginContext ctx, Map<String, String> q, ProcessMemory rpm, Integer livePid) {
        boolean wantLive = livePid != null && rpm != null && rpm.available();
        long tlsBase = 0;
        int tid = 0;
        int tlsIndex = 0;
        boolean live = false;
        String note = "static Nebula3/dro slot map (TLS offsets into module TLS block)";
        if (wantLive) {
            try {
                tlsIndex = rpm.tlsIndex(livePid, mainBase(rpm, livePid));
                var hit = rpm.findGameTls(livePid, tlsIndex, 0x58);
                if (hit != null) {
                    tlsBase = hit.tlsBase();
                    tid = hit.tid();
                    live = true;
                    note = "live tls_base=0x" + Long.toHexString(tlsBase) + " tid=" + tid
                            + " _tls_index=" + tlsIndex;
                } else {
                    note = "live pid=" + livePid + " but no thread with non-null TLS+0x58; static map only";
                }
            } catch (RuntimeException e) {
                note = "live resolve failed: " + e.getMessage() + "; static map only";
            }
        } else {
            note += "; call live_attach then re-run for live pointer column";
        }

        var cols = live
                ? new String[]{"slot", "type", "role", "ptr", "null"}
                : new String[]{"slot", "type", "role"};
        var t = Responses.table(q, cols, SLOTS.length);
        for (var row : SLOTS) {
            long off = ((Number) row[0]).longValue();
            if (live) {
                byte[] p = rpm.read(livePid, tlsBase + off, 8);
                long ptr = p == null ? 0 : u64(p);
                t.row(hex(off), row[1], row[2],
                        p == null ? "" : "0x" + Long.toHexString(ptr),
                        p == null || ptr == 0 ? "1" : "0");
            } else {
                t.row(hex(off), row[1], row[2]);
            }
        }
        return "# tls_singleton_map " + note + "\n"
                + "# resolve: TEB+0x58 -> tls_array; tls_base = tls_array[_tls_index]\n"
                + "# use address tls:0x90 on live read tools after live_attach\n"
                + t.total(SLOTS.length).build();
    }

    private static long mainBase(ProcessMemory rpm, int pid) {
        var mods = rpm.modules(pid);
        return mods.isEmpty() ? 0 : mods.get(0).base();
    }

    private static long u64(byte[] b) {
        long lo = (b[0] & 0xffL) | ((b[1] & 0xffL) << 8) | ((b[2] & 0xffL) << 16) | ((b[3] & 0xffL) << 24);
        long hi = (b[4] & 0xffL) | ((b[5] & 0xffL) << 8) | ((b[6] & 0xffL) << 16) | ((b[7] & 0xffL) << 24);
        return lo | (hi << 32);
    }

    private static String hex(long v) {
        return "0x" + Long.toHexString(v);
    }
}
