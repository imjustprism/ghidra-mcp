package io.github.imjustprism.ghidra.mcp.analysis;

import ghidra.program.model.listing.Program;
import io.github.imjustprism.ghidra.mcp.util.PluginContext;
import io.github.imjustprism.ghidra.mcp.util.ProcessMemory;
import io.github.imjustprism.ghidra.mcp.util.Responses;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.Map;

public final class TlsSingletonMap {

    static final String OPTIONS_NODE = "GhidraMCP TLS";
    static final String DERIVED_KEY = "derived";

    private static final Object[][] SLOTS = {
            {0x08, "Audio::AudioManager*", "audio"},
            {0x18, "Achievements::ClientAchievementManager*", "achievements"},
            {0x58, "Game::ClientGameWorld*", "local player / world"},
            {0x60, "Game::DrasaClient*", "client root"},
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
            {0x188, "Managers::ClientSettingsManager*", "settings"},
            {0x1e8, "LocationMapManager*", "minimap / location map"},
            {0x210, "Managers::ClientSteamManager*", "steam"},
            {0x218, "Map::ClientMapManager*", "map"},
            {0x248, "StatusEffectMgr*", "client status effects"},
            {0x250, "LocationEffectMgr*", "location effects"},
            {0x258, "TrapMgr*", "traps"},
            {0x260, "Talents::ClientTalentManager*", "client talents"},
            {0x268, "UI::DrasaUIManager*", "UI root"},
            {0x270, "UI::IngameWidget*", "ingame UI"},
            {0x2d8, "Models::VisResolver*", "visibility"},
            {0x2e0, "TransformDeviceBase*", "transform base"},
            {0x300, "CoreGraphics::TransformDevice*", "W2S projector Instance()"},
            {0x328, "D3D9RenderDevice*", "d3d9 device wrapper"},
            {0x330, "RenderDevice*", "frame begin/end"},
            {0x340, "Win32Display*", "wndproc path"},
            {0x348, "D3D9DisplayDevice*", "present / HWND"},
            {0x350, "DisplayDevice*", "display"},
            {0x360, "ShaderServer*", "shaders"},
            {0x398, "Resources::ResourceManager*", "resources"},
            {0x3c0, "TextRenderer*", "engine text"},
            {0x4e8, "Locale::LocaleServer*", "locale"},
            {0x520, "CoreUIRenderer*", "game UI render"},
            {0x5b0, "Managers::TemplateManager*", "templates"},
            {0x5c0, "StagingSystem*", "staging"},
            {0x5c8, "TriggerManager*", "triggers"},
            {0x5d8, "StatusEffects::StatusEffectManager*", "status effects"},
            {0x5e0, "Skills::SkillManager*", "skills"},
            {0x5f0, "Game::ItemManager*", "items"},
            {0x688, "Talents::TalentManager*", "talents"},
            {0x6b0, "Game::EntityManager*", "entity id space"},
            {0x6c8, "Game::GameTimeSource*", "game time"},
            {0x6d0, "FactoryManager*", "entity create"},
            {0x750, "Timing::CentralTime*", "central time"},
    };

    private TlsSingletonMap() {}

    public static String typeAt(long slot) {
        for (var row : SLOTS) {
            if (((Number) row[0]).longValue() == slot) return (String) row[1];
        }
        return null;
    }

    public static Map<Long, String> loadDerived(Program program) {
        var out = new LinkedHashMap<Long, String>();
        if (program == null) return out;
        var raw = program.getOptions(OPTIONS_NODE).getString(DERIVED_KEY, "");
        if (raw == null || raw.isBlank()) return out;
        for (var line : raw.split("\n")) {
            var t = line.trim();
            if (t.isEmpty()) continue;
            var parts = t.split("\t", 2);
            if (parts.length < 2) continue;
            try {
                var hex = parts[0].startsWith("0x") || parts[0].startsWith("0X")
                        ? parts[0].substring(2) : parts[0];
                out.put(Long.parseLong(hex, 16), parts[1].trim());
            } catch (NumberFormatException ignored) {
            }
        }
        return out;
    }

    public static String storeDerived(PluginContext ctx, Program program, Map<Long, String> add) {
        var merged = loadDerived(program);
        merged.putAll(add);
        var sb = new StringBuilder();
        var keys = new ArrayList<>(merged.keySet());
        keys.sort(Long::compare);
        for (var k : keys) {
            sb.append(hex(k)).append('\t').append(merged.get(k)).append('\n');
        }
        ctx.runOnSwingTx(program, "Persist derived TLS slots", () -> {
            program.getOptions(OPTIONS_NODE).setString(DERIVED_KEY, sb.toString());
            return true;
        });
        return "# persisted " + add.size() + " slot(s), table now " + merged.size()
                + " derived (save the program to keep)\n";
    }

    public static String map(PluginContext ctx, Map<String, String> q, ProcessMemory rpm, Integer livePid) {
        boolean wantLive = livePid != null && rpm != null && rpm.available();
        long tlsBase = 0;
        int tid = 0;
        int tlsIndex = 0;
        boolean live = false;
        // Every thread's TLS block, so a slot the game thread never constructed
        // can still be found on the thread that owns it.
        java.util.List<ProcessMemory.TlsHit> allTls = java.util.List.of();
        String note = "static Nebula3/dro slot map (TLS offsets into module TLS block)";
        if (wantLive) {
            try {
                tlsIndex = rpm.tlsIndex(livePid, mainBase(rpm, livePid));
                var hit = rpm.findGameTls(livePid, tlsIndex, 0x58);
                if (hit != null) {
                    tlsBase = hit.tlsBase();
                    tid = hit.tid();
                    live = true;
                    allTls = rpm.allThreadTls(livePid, tlsIndex);
                    note = "live tls_base=0x" + Long.toHexString(tlsBase) + " tid=" + tid
                            + " _tls_index=" + tlsIndex + " threads_with_tls=" + allTls.size();
                } else {
                    note = "live pid=" + livePid + " but no thread with non-null TLS+0x58; static map only";
                }
            } catch (RuntimeException e) {
                note = "live resolve failed: " + e.getMessage() + "; static map only";
            }
        } else {
            note += "; call live_attach then re-run for live pointer column";
        }

        var derived = loadDerived(ctx.currentProgram());
        var rows = mergeRows(derived);
        var cols = live
                ? new String[]{"slot", "type", "role", "source", "ptr", "null", "owner_tid"}
                : new String[]{"slot", "type", "role", "source"};
        var t = Responses.table(q, cols, rows.size());
        for (var row : rows) {
            long off = row.slot();
            if (!live) {
                t.row(hex(off), row.type(), row.role(), row.source());
                continue;
            }
            byte[] p = rpm.read(livePid, tlsBase + off, 8);
            long ptr = p == null ? 0 : u64(p);
            int owner = ptr != 0 ? tid : 0;
            if (ptr == 0) {
                // Not on the game thread — ask every other thread before calling
                // the slot empty.
                for (var other : allTls) {
                    if (other.tid() == tid) continue;
                    byte[] q2 = rpm.read(livePid, other.tlsBase() + off, 8);
                    if (q2 == null) continue;
                    long v = u64(q2);
                    if (v != 0) {
                        ptr = v;
                        owner = other.tid();
                        break;
                    }
                }
            }
            t.row(hex(off), row.type(), row.role(), row.source(),
                    ptr == 0 ? "" : "0x" + Long.toHexString(ptr),
                    ptr == 0 ? "1" : "0",
                    owner == 0 ? "" : Integer.toString(owner));
        }
        return "# tls_singleton_map " + note + "\n"
                + "# resolve: TEB+0x58 -> tls_array; tls_base = tls_array[_tls_index]\n"
                + "# owner_tid is the thread whose TLS block holds the pointer: these are "
                + "thread-local singletons, so render-side ones live on the render thread, "
                + "not the game thread\n"
                + "# use address tls:0x90 on live read tools after live_attach\n"
                + "# source=static is the baked table; derived is persist from "
                + "derive_tls_singletons apply=true\n"
                + t.total(rows.size()).build();
    }

    private record SlotRow(long slot, String type, String role, String source) {}

    private static java.util.List<SlotRow> mergeRows(Map<Long, String> derived) {
        var bySlot = new LinkedHashMap<Long, SlotRow>();
        for (var row : SLOTS) {
            long off = ((Number) row[0]).longValue();
            bySlot.put(off, new SlotRow(off, (String) row[1], (String) row[2], "static"));
        }
        for (var e : derived.entrySet()) {
            var have = bySlot.get(e.getKey());
            if (have == null) {
                bySlot.put(e.getKey(), new SlotRow(e.getKey(), e.getValue(),
                        "derived from 0 != Singleton", "derived"));
            } else if (!have.type().toLowerCase().contains(shortName(e.getValue()).toLowerCase())) {
                bySlot.put(e.getKey(), new SlotRow(e.getKey(), e.getValue(),
                        have.role() + " / conflict vs " + have.type(), "conflict"));
            }
        }
        var out = new ArrayList<>(bySlot.values());
        out.sort(Comparator.comparingLong(SlotRow::slot));
        return out;
    }

    private static String shortName(String owner) {
        var t = owner.endsWith("*") ? owner.substring(0, owner.length() - 1) : owner;
        int i = t.lastIndexOf("::");
        return i < 0 ? t : t.substring(i + 2);
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
